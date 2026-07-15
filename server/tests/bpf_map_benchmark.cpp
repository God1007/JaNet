// Linux 真实 BPF map 基准：按生产 ABI 创建 LRU_HASH / protected HASH / PERCPU_HASH。
// 测量 update/lookup/delete、容量压力和多线程 syscall；非 Linux 或非 root 明确输出 JSON skip。

#include "benchmark_support.hpp"

#include "flow_abi.h"

#include <arpa/inet.h>

#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#if defined(__linux__)
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/bpf.h>
#include <sys/resource.h>
#endif

namespace bench = weaknet_benchmark;

namespace {

// 构造统一的 skipped 结果：macOS、非 root 等环境只能明确跳过，不能用模拟 map 冒充通过。
std::string skippedDocument(const bench::Options& options,
                            const std::string& startedAt,
                            std::uint64_t durationNs,
                            const std::string& reason) {
    std::ostringstream output;
    output.imbue(std::locale::classic());
    output << '{'
           << "\"schema_version\":" << bench::jsonEscape(bench::kSchemaVersion) << ','
           << "\"component\":\"bpf_map_benchmark\","
           << "\"profile\":" << bench::jsonEscape(options.profile_name) << ','
           << "\"environment\":" << bench::environmentJson() << ','
           << "\"started_at\":" << bench::jsonEscape(startedAt) << ','
           << "\"duration_ms\":" << std::fixed << std::setprecision(3)
           << static_cast<double>(durationNs) / 1000000.0 << ','
           << "\"benchmarks\":[],"
           << "\"summary\":{"
           << "\"status\":\"skipped\","
           << "\"correctness_passed\":null,"
           << "\"benchmark_count\":0,"
           << "\"total_operations\":0,"
           << "\"errors\":0,"
           << "\"skip_reason\":" << bench::jsonEscape(reason)
           << "}}";
    return output.str();
}

#if defined(__linux__)

// 用逻辑用途区分三张 map；后续据此生成与生产 ABI 一致的 key/value。
enum class MapKind {
    FlowLru,
    ProtectedHash,
    InterfacePercpuHash,
};

// 创建真实内核 map 所需的完整规格。capacity 直接取 flow_abi.h 的生产上限。
struct MapSpec {
    MapKind kind;
    const char* logical_name;
    const char* kernel_name;
    bpf_map_type type;
    std::uint32_t key_size;
    std::uint32_t value_size;
    std::uint32_t capacity;
};

// 一个容量/并发组合；entries 是请求操作数，threads 是同时进入 syscall 的 worker 数。
struct WorkloadCase {
    std::uint64_t entries;
    std::uint32_t threads;
};

// 每个线程独占统计，避免压测热路径为了聚合指标额外争抢锁。
struct ThreadOperationStats {
    std::uint64_t successes = 0;
    std::uint64_t syscall_failures = 0;
    std::uint64_t value_mismatches = 0;
    std::map<int, std::uint64_t> errno_counts;
    std::vector<std::uint64_t> latencies;
};

// join 后合并出的单轮操作结果，同时保存 syscall 错误类型以核对容量契约。
struct OperationRun {
    bench::BenchmarkResult benchmark;
    std::uint64_t successes = 0;
    std::uint64_t syscall_failures = 0;
    std::uint64_t value_mismatches = 0;
    std::map<int, std::uint64_t> errno_counts;
};

// 每张新建 map 顺序执行 update、lookup、delete；计时仍按各阶段独立统计。
enum class MapOperation {
    Update,
    Lookup,
    Delete,
};

// 输出稳定的操作名，供 benchmark 名称和 JSON 明细复用。
const char* operationName(MapOperation operation) {
    switch (operation) {
        case MapOperation::Update: return "update";
        case MapOperation::Lookup: return "lookup";
        case MapOperation::Delete: return "delete";
    }
    return "unknown";
}

// 将内核枚举值转换为可读名称，避免报告只出现难解释的数字常量。
const char* mapTypeName(bpf_map_type type) {
    switch (type) {
        case BPF_MAP_TYPE_LRU_HASH: return "BPF_MAP_TYPE_LRU_HASH";
        case BPF_MAP_TYPE_HASH: return "BPF_MAP_TYPE_HASH";
        case BPF_MAP_TYPE_PERCPU_HASH: return "BPF_MAP_TYPE_PERCPU_HASH";
        default: return "BPF_MAP_TYPE_UNKNOWN";
    }
}

// Linux common-LRU 会把空闲节点按 CPU 批量搬到本地 free list。内核 v7.0 的
// LOCAL_FREE_TARGET 上限是 128，实际 target_free 为
// clamp((max_entries / possible_cpus) / 2, 1, 128)。当多个 CPU 并发插入且
// 调度不均时，一次补货可能先淘汰一批旧节点，而其他 CPU 仍保留未消费的本地
// free 节点，因此“所有 update 成功”并不保证瞬时枚举值严格等于 max_entries。
constexpr std::uint64_t kKernelLruLocalFreeTargetMax = 128;

// 复现 Linux common-LRU 的 target_free 计算，用它推导并发满容量时可解释的暂时 underfill。
std::uint64_t lruLocalFreeTarget(std::uint32_t capacity, int possibleCpus) {
    const std::uint64_t cpus = static_cast<std::uint64_t>(std::max(possibleCpus, 1));
    const std::uint64_t perCpuHalf = (static_cast<std::uint64_t>(capacity) / cpus) / 2U;
    return std::clamp<std::uint64_t>(perCpuHalf, 1U, kKernelLruLocalFreeTargetMax);
}

// 计算所有 possible CPU 本地 free list 最多暂存的未消费节点数，即 retention slack 严格上界。
std::uint64_t lruKernelRetentionSlackUpperBound(std::uint32_t capacity,
                                                int possibleCpus) {
    const std::uint64_t cpus = static_cast<std::uint64_t>(std::max(possibleCpus, 1));
    const std::uint64_t target = lruLocalFreeTarget(capacity, possibleCpus);
    // 每次 refill 后至少立即消费一个节点；每个 CPU 最多暂存 target-1 个。
    return std::min<std::uint64_t>(capacity, cpus * (target - 1U));
}

// 只有到达/超过容量的 LRU 才允许该实现相关 slack；HASH/PERCPU_HASH 必须严格等于容量。
std::uint64_t acceptedLruRetentionSlack(const MapSpec& spec,
                                        const WorkloadCase& workload,
                                        int possibleCpus) {
    if (spec.type != BPF_MAP_TYPE_LRU_HASH || workload.entries < spec.capacity) return 0;
    // 这是 Linux v7 common-LRU 当前实现的严格上界，不是对任意缺失的经验容忍值。
    // 若未来内核改变 batching 算法，门禁应失败并显式升级模型，不能静默放宽。
    return lruKernelRetentionSlackUpperBound(spec.capacity, possibleCpus);
}

// 精确核对失败总数和 errno 分布，防止把权限、ABI 等异常误判成预期容量失败。
bool errnoCountsExactly(const OperationRun& run, int expectedErrno,
                        std::uint64_t expectedCount) {
    if (run.syscall_failures != expectedCount) return false;
    if (expectedCount == 0) return run.errno_counts.empty();
    return run.errno_counts.size() == 1U &&
           run.errno_counts.begin()->first == expectedErrno &&
           run.errno_counts.begin()->second == expectedCount;
}

// 生成确定性且分布均匀的测试字段；它只用于造 key，不代表 Linux BPF map 的哈希算法。
std::uint64_t splitMix64(std::uint64_t value) {
    value += UINT64_C(0x9e3779b97f4a7c15);
    value = (value ^ (value >> 30U)) * UINT64_C(0xbf58476d1ce4e5b9);
    value = (value ^ (value >> 27U)) * UINT64_C(0x94d049bb133111eb);
    return value ^ (value >> 31U);
}

// 生成规范化生产 flow_key：结构体先清零，IPv4 地址尾部和 reserved/padding 保持确定值。
flow_key flowKey(std::uint64_t ordinal) {
    flow_key key{};
    key.family = ordinal % 4U == 0 ? FLOW_AF_INET6 : FLOW_AF_INET4;
    key.protocol = ordinal % 2U == 0 ? IPPROTO_TCP : IPPROTO_UDP;
    key.direction = ordinal % 3U == 0 ? FLOW_DIR_INGRESS : FLOW_DIR_EGRESS;
    key.ifindex = static_cast<flow_u32>(ordinal % 127U) + 1U;
    key.sport_be = htons(static_cast<std::uint16_t>(1024U + ordinal % 50000U));
    key.dport_be = htons(static_cast<std::uint16_t>(1U + (ordinal * 17U) % 65534U));
    std::uint64_t source = splitMix64(ordinal);
    std::uint64_t destination = splitMix64(ordinal ^ UINT64_C(0xd1b54a32d192ed03));
    const std::size_t bytes = key.family == FLOW_AF_INET4 ? 4U : 16U;
    for (std::size_t index = 0; index < bytes; ++index) {
        key.saddr[index] = static_cast<flow_u8>(source >> ((index % 8U) * 8U));
        key.daddr[index] = static_cast<flow_u8>(destination >> ((index % 8U) * 8U));
        if (index == 7U) {
            source = splitMix64(source);
            destination = splitMix64(destination);
        }
    }
    key.socket_cookie = ordinal + 1U;
    return key;
}

// PERCPU map 用户态 ABI 要求每个 CPU 的 value 槽按 8 字节对齐。
std::size_t roundUp8(std::size_t value) {
    return (value + 7U) & ~std::size_t(7U);
}

// 普通 map 传一个 value；PERCPU_HASH 一次 syscall 传 possible_cpus 个对齐后的 value。
std::size_t userspaceValueBytes(const MapSpec& spec, int possibleCpus) {
    if (spec.type != BPF_MAP_TYPE_PERCPU_HASH) return spec.value_size;
    return roundUp8(spec.value_size) * static_cast<std::size_t>(possibleCpus);
}

// 按 map 逻辑类型填充完整 key 字节，保证不同 ordinal 对应不同的业务键。
void fillKey(const MapSpec& spec, std::uint64_t ordinal, std::vector<std::uint8_t>& bytes) {
    std::fill(bytes.begin(), bytes.end(), 0);
    if (spec.kind == MapKind::FlowLru) {
        const flow_key key = flowKey(ordinal);
        std::memcpy(bytes.data(), &key, sizeof(key));
    } else if (spec.kind == MapKind::ProtectedHash) {
        const flow_u64 cookie = ordinal + 1U;
        std::memcpy(bytes.data(), &cookie, sizeof(cookie));
    } else {
        flow_iface_key key{};
        key.ifindex = static_cast<flow_u32>(ordinal + 1U);
        key.family = ordinal % 4U == 0 ? FLOW_AF_INET6 : FLOW_AF_INET4;
        key.protocol = ordinal % 2U == 0 ? IPPROTO_TCP : IPPROTO_UDP;
        key.direction = ordinal % 3U == 0 ? FLOW_DIR_INGRESS : FLOW_DIR_EGRESS;
        std::memcpy(bytes.data(), &key, sizeof(key));
    }
}

// 按生产 value ABI 填充值；PERCPU_HASH 为每个 possible CPU 写入各自槽位。
void fillValue(const MapSpec& spec,
               std::uint64_t ordinal,
               int possibleCpus,
               std::vector<std::uint8_t>& bytes) {
    std::fill(bytes.begin(), bytes.end(), 0);
    if (spec.kind == MapKind::FlowLru) {
        flow_value value{};
        value.bytes = ordinal + 1U;
        value.packets = ordinal % 1024U + 1U;
        value.first_seen_ns = ordinal + 100U;
        std::memcpy(bytes.data(), &value, sizeof(value));
    } else if (spec.kind == MapKind::ProtectedHash) {
        flow_protected_record record{};
        record.key = flowKey(ordinal);
        record.value.bytes = ordinal + 1U;
        record.value.packets = ordinal % 1024U + 1U;
        record.value.flags = FLOW_VALUE_PROTECTED;
        std::memcpy(bytes.data(), &record, sizeof(record));
    } else {
        const std::size_t stride = roundUp8(sizeof(flow_iface_counters));
        for (int cpu = 0; cpu < possibleCpus; ++cpu) {
            flow_iface_counters counters{};
            counters.bytes = ordinal + static_cast<std::uint64_t>(cpu) + 1U;
            counters.packets = ordinal % 1024U + 1U;
            std::memcpy(bytes.data() + static_cast<std::size_t>(cpu) * stride,
                        &counters, sizeof(counters));
        }
    }
}

// 为 smoke/standard/stress 生成去重后的容量阶梯，覆盖半容量、边界和超容量并发。
std::vector<WorkloadCase> workloadCases(bench::Profile profile, std::uint32_t capacity) {
    std::vector<WorkloadCase> cases;
    const auto add = [&](std::uint64_t entries, std::uint32_t threads) {
        entries = std::max<std::uint64_t>(1, entries);
        if (std::none_of(cases.begin(), cases.end(), [&](const WorkloadCase& value) {
                return value.entries == entries && value.threads == threads;
            })) {
            cases.push_back({entries, threads});
        }
    };
    switch (profile) {
        case bench::Profile::Smoke:
            add(std::min<std::uint64_t>(256, std::max<std::uint32_t>(1, capacity / 8U)), 1);
            add(std::min<std::uint64_t>(1024, std::max<std::uint32_t>(1, capacity / 2U)), 2);
            break;
        case bench::Profile::Standard:
            add(std::min<std::uint64_t>(1024, std::max<std::uint32_t>(1, capacity / 4U)), 1);
            add(std::min<std::uint64_t>(16384, std::max<std::uint32_t>(1, capacity / 2U)), 2);
            add(capacity, 1);
            add(capacity, 4);
            add(static_cast<std::uint64_t>(capacity) + std::max<std::uint32_t>(64, capacity / 8U), 4);
            break;
        case bench::Profile::Stress:
            add(std::max<std::uint32_t>(1, capacity / 2U), 1);
            add(capacity, 1);
            add(capacity, 4);
            add(static_cast<std::uint64_t>(capacity) * 2U, 8);
            add(static_cast<std::uint64_t>(capacity) * 4U, 8);
            break;
    }
    return cases;
}

// 压力越大采样越稀疏，避免逐 syscall 计时本身主导被测吞吐。
std::uint64_t latencyStride(bench::Profile profile) {
    switch (profile) {
        case bench::Profile::Smoke: return 1;
        case bench::Profile::Standard: return 8;
        case bench::Profile::Stress: return 32;
    }
    return 1;
}

// 通过 get_next_key 枚举真实驻留条目；hardLimit 防止异常迭代导致测试失控。
std::uint64_t countEntries(int fd, std::uint32_t keySize, std::uint64_t hardLimit, bool& complete) {
    std::vector<std::uint8_t> current(keySize);
    std::vector<std::uint8_t> next(keySize);
    const void* previous = nullptr;
    std::uint64_t count = 0;
    complete = true;
    while (bpf_map_get_next_key(fd, previous, next.data()) == 0) {
        ++count;
        if (count > hardLimit) {
            complete = false;
            return count;
        }
        current.swap(next);
        previous = current.data();
    }
    if (errno != ENOENT) complete = false;
    return count;
}

// 将 errno 计数序列化为“编号:含义”，便于区分预期 E2BIG/ENOENT 与真正系统错误。
std::string errnoCountsJson(const std::map<int, std::uint64_t>& counts) {
    std::ostringstream output;
    output << '{';
    bool first = true;
    for (const auto& entry : counts) {
        if (!first) output << ',';
        first = false;
        output << bench::jsonEscape(std::to_string(entry.first) + ":" + std::strerror(entry.first))
               << ':' << entry.second;
    }
    output << '}';
    return output.str();
}

// 在同一张真实 BPF map 上并发执行一种 syscall，并分别统计吞吐、抽样延迟和正确性。
OperationRun runOperation(int fd,
                          const MapSpec& spec,
                          const WorkloadCase& workload,
                          MapOperation operation,
                          int possibleCpus,
                          std::uint64_t sampleStride) {
    const std::size_t valueBytes = userspaceValueBytes(spec, possibleCpus);
    bench::StartGate gate(workload.threads);
    std::vector<std::thread> workers;
    std::vector<ThreadOperationStats> threadStats(workload.threads);
    workers.reserve(workload.threads);

    for (std::uint32_t threadIndex = 0; threadIndex < workload.threads; ++threadIndex) {
        workers.emplace_back([&, threadIndex] {
            // 用整除边界切分 [0, entries)，每个 ordinal 只被一个 worker 操作。
            const std::uint64_t first = workload.entries * threadIndex / workload.threads;
            const std::uint64_t last = workload.entries * (threadIndex + 1U) / workload.threads;
            ThreadOperationStats& stats = threadStats[threadIndex];
            stats.latencies.reserve(static_cast<std::size_t>((last - first) / sampleStride + 1U));
            std::vector<std::uint8_t> key(spec.key_size);
            std::vector<std::uint8_t> value(valueBytes);
            std::vector<std::uint8_t> expected(valueBytes);
            // key/value 和采样容器准备完毕后才进入 barrier，初始化成本不计入并发窗口。
            gate.workerWait();
            for (std::uint64_t ordinal = first; ordinal < last; ++ordinal) {
                fillKey(spec, ordinal, key);
                if (operation == MapOperation::Update) fillValue(spec, ordinal, possibleCpus, value);
                const bool sample = ordinal % sampleStride == 0;
                const auto operationBegin = sample ? bench::SteadyClock::now()
                                                   : bench::SteadyClock::time_point{};
                int rc = 0;
                if (operation == MapOperation::Update) {
                    // BPF_NOEXIST 固定容量语义：HASH/PERCPU_HASH 满时返回 E2BIG；
                    // LRU_HASH 满时应淘汰旧项并继续成功，而不是拒绝新 key。
                    rc = bpf_map_update_elem(fd, key.data(), value.data(), BPF_NOEXIST);
                } else if (operation == MapOperation::Lookup) {
                    rc = bpf_map_lookup_elem(fd, key.data(), value.data());
                } else {
                    rc = bpf_map_delete_elem(fd, key.data());
                }
                const int savedErrno = rc == 0 ? 0 : errno;
                if (sample) {
                    stats.latencies.push_back(
                        bench::elapsedNs(operationBegin, bench::SteadyClock::now()));
                }
                if (rc == 0) {
                    ++stats.successes;
                    if (operation == MapOperation::Lookup) {
                        fillValue(spec, ordinal, possibleCpus, expected);
                        if (value != expected) ++stats.value_mismatches;
                    }
                } else {
                    ++stats.syscall_failures;
                    ++stats.errno_counts[savedErrno];
                }
            }
        });
    }

    gate.waitUntilReady();
    // begin 位于“全部 worker ready”和“统一放行”之间，测到的是实际并发 syscall 窗口。
    const auto begin = bench::SteadyClock::now();
    gate.release();
    for (auto& worker : workers) worker.join();
    const std::uint64_t duration = bench::elapsedNs(begin, bench::SteadyClock::now());

    OperationRun run;
    run.benchmark.name = std::string(spec.logical_name) + "_" + operationName(operation);
    run.benchmark.operations = workload.entries;
    run.benchmark.threads = workload.threads;
    run.benchmark.duration_ns = duration;
    run.benchmark.latency_sample_stride = sampleStride;
    run.benchmark.latency_method = "sampled_bpf_syscall";
    for (auto& stats : threadStats) {
        run.successes += stats.successes;
        run.syscall_failures += stats.syscall_failures;
        run.value_mismatches += stats.value_mismatches;
        for (const auto& entry : stats.errno_counts) run.errno_counts[entry.first] += entry.second;
        bench::appendSamples(run.benchmark.latency_samples, std::move(stats.latencies));
    }
    return run;
}

// 生成单项 JSON 明细，并把名义容量、允许区间、实际淘汰与 errno 契约同时暴露出来。
std::string operationDetails(const MapSpec& spec,
                             const WorkloadCase& workload,
                             MapOperation operation,
                             int possibleCpus,
                             const OperationRun& run,
                             std::uint64_t finalEntries,
                             std::uint64_t expectedCapacityRejections,
                             std::uint64_t expectedMissingEntries,
                             std::uint64_t observedLruEvictions,
                             std::uint64_t acceptedRetentionSlack,
                             bool errnoContractPassed,
                             bool enumerationComplete) {
    const std::uint64_t expectedMaxEntries = operation == MapOperation::Delete
        ? 0
        : std::min<std::uint64_t>(workload.entries, spec.capacity);
    const std::uint64_t expectedMinEntries = operation == MapOperation::Delete
        ? 0
        : expectedMaxEntries - std::min(expectedMaxEntries, acceptedRetentionSlack);
    const bool lru = spec.type == BPF_MAP_TYPE_LRU_HASH;
    const std::uint64_t nominalLruEvictions = lru && workload.entries > spec.capacity
        ? workload.entries - spec.capacity
        : 0;
    const std::uint64_t observedRetentionUnderfill =
        lru && operation != MapOperation::Delete && finalEntries < expectedMaxEntries
            ? expectedMaxEntries - finalEntries
            : 0;
    std::ostringstream output;
    output << '{'
           << "\"map_name\":" << bench::jsonEscape(spec.logical_name) << ','
           << "\"map_type\":" << bench::jsonEscape(mapTypeName(spec.type)) << ','
           << "\"operation\":" << bench::jsonEscape(operationName(operation)) << ','
           << "\"key_bytes\":" << spec.key_size << ','
           << "\"kernel_value_bytes\":" << spec.value_size << ','
           << "\"userspace_value_transfer_bytes\":"
           << userspaceValueBytes(spec, possibleCpus) << ','
           << "\"possible_cpus\":" << possibleCpus << ','
           << "\"capacity\":" << spec.capacity << ','
           << "\"requested_entries\":" << workload.entries << ','
           << "\"capacity_pressure\":" << (workload.entries > spec.capacity ? "true" : "false") << ','
           << "\"capacity_boundary_or_pressure\":"
           << (workload.entries >= spec.capacity ? "true" : "false") << ','
           << "\"successful_syscalls\":" << run.successes << ','
           << "\"syscall_failures\":" << run.syscall_failures << ','
           << "\"expected_capacity_rejections\":" << expectedCapacityRejections << ','
           << "\"expected_missing_entries\":" << expectedMissingEntries << ','
           << "\"errno_contract_passed\":" << (errnoContractPassed ? "true" : "false") << ','
           << "\"value_mismatches\":" << run.value_mismatches << ','
           << "\"final_entries\":" << finalEntries << ','
           << "\"acceptable_min_final_entries\":" << expectedMinEntries << ','
           << "\"acceptable_max_final_entries\":" << expectedMaxEntries << ','
           << "\"lru_local_free_target\":"
           << (lru ? lruLocalFreeTarget(spec.capacity, possibleCpus) : 0) << ','
           << "\"lru_batch_model\":"
           << bench::jsonEscape(lru ? "linux-v7-common-lru-target-free"
                                    : "not-applicable") << ','
           << "\"lru_kernel_retention_slack_upper_bound\":"
           << (lru ? lruKernelRetentionSlackUpperBound(spec.capacity, possibleCpus) : 0) << ','
           << "\"accepted_lru_retention_slack_entries\":" << acceptedRetentionSlack << ','
           << "\"nominal_lru_evictions\":" << nominalLruEvictions << ','
           << "\"observed_lru_evictions\":" << observedLruEvictions << ','
           << "\"observed_lru_retention_underfill_entries\":"
           << observedRetentionUnderfill << ','
           << "\"enumeration_complete\":" << (enumerationComplete ? "true" : "false") << ','
           << "\"errno_counts\":" << errnoCountsJson(run.errno_counts)
           << '}';
    return output.str();
}

// 将 map 创建失败也记录成结构化 benchmark，避免只在 stderr 留下不可聚合信息。
bench::BenchmarkResult mapCreationFailure(const MapSpec& spec,
                                          const WorkloadCase& workload,
                                          int savedErrno) {
    bench::BenchmarkResult result;
    result.name = std::string(spec.logical_name) + "_create";
    result.operations = 1;
    result.threads = 1;
    result.errors = 1;
    std::ostringstream details;
    details << "{\"map_type\":" << bench::jsonEscape(mapTypeName(spec.type))
            << ",\"capacity\":" << spec.capacity
            << ",\"requested_entries\":" << workload.entries
            << ",\"errno\":" << savedErrno
            << ",\"error\":" << bench::jsonEscape(std::strerror(savedErrno)) << '}';
    result.details_json = details.str();
    return result;
}

// 创建三类生产规格 map，逐个容量档位执行操作并以“返回值 + 枚举状态”双重验收。
std::vector<bench::BenchmarkResult> benchmarkMaps(const bench::Options& options,
                                                  int possibleCpus) {
    const std::vector<MapSpec> specs{
        {MapKind::FlowLru, "current_sec_lru_hash", "bm_lru_flow", BPF_MAP_TYPE_LRU_HASH,
         sizeof(flow_key), sizeof(flow_value), FLOW_LRU_MAX_ENTRIES},
        {MapKind::ProtectedHash, "protected_flows_hash", "bm_protected", BPF_MAP_TYPE_HASH,
         sizeof(flow_u64), sizeof(flow_protected_record), FLOW_PROTECTED_MAX_ENTRIES},
        {MapKind::InterfacePercpuHash, "iface_totals_percpu_hash", "bm_percpu", BPF_MAP_TYPE_PERCPU_HASH,
         sizeof(flow_iface_key), sizeof(flow_iface_counters), FLOW_IFACE_MAX_ENTRIES},
    };
    std::vector<bench::BenchmarkResult> results;
    const std::uint64_t sampleStride = latencyStride(options.profile);

    for (const auto& spec : specs) {
        for (const WorkloadCase& workload : workloadCases(options.profile, spec.capacity)) {
            const int fd = bpf_map_create(spec.type, spec.kernel_name, spec.key_size,
                                          spec.value_size, spec.capacity, nullptr);
            if (fd < 0) {
                results.push_back(mapCreationFailure(spec, workload, errno));
                continue;
            }

            bpf_map_info information{};
            std::uint32_t informationSize = sizeof(information);
            const bool infoValid =
                bpf_obj_get_info_by_fd(fd, &information, &informationSize) == 0 &&
                information.type == static_cast<std::uint32_t>(spec.type) &&
                information.key_size == spec.key_size &&
                information.value_size == spec.value_size &&
                information.max_entries == spec.capacity;

            OperationRun update = runOperation(fd, spec, workload, MapOperation::Update,
                                               possibleCpus, sampleStride);
            bool enumerationComplete = false;
            const std::uint64_t afterUpdate =
                countEntries(fd, spec.key_size, static_cast<std::uint64_t>(spec.capacity) + 1U,
                             enumerationComplete);
            const bool lru = spec.type == BPF_MAP_TYPE_LRU_HASH;
            const std::uint64_t expectedEntries =
                std::min<std::uint64_t>(workload.entries, spec.capacity);
            const std::uint64_t retentionSlack =
                acceptedLruRetentionSlack(spec, workload, possibleCpus);
            const std::uint64_t minimumExpectedEntries =
                expectedEntries - std::min(expectedEntries, retentionSlack);
            const std::uint64_t expectedRejections =
                lru ? 0 : workload.entries - expectedEntries;
            // 非 LRU 到达容量后，每个额外 BPF_NOEXIST 插入必须精确返回 E2BIG；
            // LRU 的所有插入必须成功，容量由淘汰维持，不能把二者混为同一种“碰撞”。
            const bool updateErrnoContractPassed = errnoCountsExactly(
                update, expectedRejections == 0 ? 0 : E2BIG, expectedRejections);
            const std::uint64_t observedLruEvictions =
                lru && afterUpdate <= workload.entries ? workload.entries - afterUpdate : 0;
            std::uint64_t correctnessErrors = update.value_mismatches;
            // 内核哈希桶冲突不会让两个不同完整 key 互相覆盖；这里验收的是 map 容量与
            // 驻留语义。并发 common-LRU 仅允许 per-CPU local-free batching 推导出的 slack。
            if (!infoValid || !enumerationComplete || afterUpdate < minimumExpectedEntries ||
                afterUpdate > expectedEntries ||
                update.successes != (lru ? workload.entries : expectedEntries) ||
                !updateErrnoContractPassed) {
                ++correctnessErrors;
            }
            update.benchmark.errors = correctnessErrors;
            update.benchmark.details_json = operationDetails(
                spec, workload, MapOperation::Update, possibleCpus, update, afterUpdate,
                expectedRejections, observedLruEvictions, observedLruEvictions,
                retentionSlack, updateErrnoContractPassed, enumerationComplete);
            results.push_back(std::move(update.benchmark));

            // 超容量 LRU 已淘汰早期 key；HASH/PERCPU_HASH 则有预期拒绝。lookup/delete
            // 只在未超过容量的档位执行。并发 exact-capacity LRU 可能因内核 per-CPU
            // refill 批处理少量提前淘汰；这些缺失必须与 ENOENT 数量严格一一对应。
            if (workload.entries <= spec.capacity) {
                const std::uint64_t expectedMissingEntries =
                    workload.entries >= afterUpdate ? workload.entries - afterUpdate : 0;
                OperationRun lookup = runOperation(fd, spec, workload, MapOperation::Lookup,
                                                   possibleCpus, sampleStride);
                bool lookupEnumerationComplete = false;
                const std::uint64_t afterLookup = countEntries(
                    fd, spec.key_size, static_cast<std::uint64_t>(spec.capacity) + 1U,
                    lookupEnumerationComplete);
                const bool lookupErrnoContractPassed = errnoCountsExactly(
                    lookup, expectedMissingEntries == 0 ? 0 : ENOENT, expectedMissingEntries);
                lookup.benchmark.errors = lookup.value_mismatches;
                if (!lookupEnumerationComplete || afterLookup != afterUpdate ||
                    lookup.successes != afterUpdate || !lookupErrnoContractPassed) {
                    ++lookup.benchmark.errors;
                }
                lookup.benchmark.details_json = operationDetails(
                    spec, workload, MapOperation::Lookup, possibleCpus, lookup, afterLookup,
                    0, expectedMissingEntries, observedLruEvictions, retentionSlack,
                    lookupErrnoContractPassed, lookupEnumerationComplete);
                results.push_back(std::move(lookup.benchmark));

                OperationRun deletion = runOperation(fd, spec, workload, MapOperation::Delete,
                                                     possibleCpus, sampleStride);
                bool deleteEnumerationComplete = false;
                const std::uint64_t afterDelete = countEntries(
                    fd, spec.key_size, static_cast<std::uint64_t>(spec.capacity) + 1U,
                    deleteEnumerationComplete);
                const bool deleteErrnoContractPassed = errnoCountsExactly(
                    deletion, expectedMissingEntries == 0 ? 0 : ENOENT,
                    expectedMissingEntries);
                deletion.benchmark.errors = 0;
                if (!deleteEnumerationComplete || afterDelete != 0 ||
                    deletion.successes != afterUpdate || !deleteErrnoContractPassed) {
                    ++deletion.benchmark.errors;
                }
                deletion.benchmark.details_json = operationDetails(
                    spec, workload, MapOperation::Delete, possibleCpus, deletion, afterDelete,
                    0, expectedMissingEntries, observedLruEvictions, retentionSlack,
                    deleteErrnoContractPassed, deleteEnumerationComplete);
                results.push_back(std::move(deletion.benchmark));
            }
            close(fd);
        }
    }
    return results;
}

// 汇总所有 map/档位/操作，附带 possible CPU、memlock 和 RSS，形成可独立审计的结果文档。
std::string renderDocument(const bench::Options& options,
                           const std::string& startedAt,
                           std::uint64_t durationNs,
                           const std::vector<bench::BenchmarkResult>& results,
                           int possibleCpus,
                           bool memlockRaised) {
    std::uint64_t totalOperations = 0;
    std::uint64_t errors = 0;
    for (const auto& result : results) {
        totalOperations += result.operations;
        errors += result.errors;
    }
    struct rusage usage {};
    getrusage(RUSAGE_SELF, &usage);

    std::ostringstream output;
    output.imbue(std::locale::classic());
    output << '{'
           << "\"schema_version\":" << bench::jsonEscape(bench::kSchemaVersion) << ','
           << "\"component\":\"bpf_map_benchmark\","
           << "\"profile\":" << bench::jsonEscape(options.profile_name) << ','
           << "\"environment\":" << bench::environmentJson() << ','
           << "\"started_at\":" << bench::jsonEscape(startedAt) << ','
           << "\"duration_ms\":" << std::fixed << std::setprecision(3)
           << static_cast<double>(durationNs) / 1000000.0 << ','
           << "\"benchmarks\":[";
    for (std::size_t index = 0; index < results.size(); ++index) {
        if (index != 0) output << ',';
        output << bench::benchmarkJson(results[index]);
    }
    output << "],\"summary\":{"
           << "\"status\":" << bench::jsonEscape(errors == 0 ? "passed" : "failed") << ','
           << "\"correctness_passed\":" << (errors == 0 ? "true" : "false") << ','
           << "\"benchmark_count\":" << results.size() << ','
           << "\"total_operations\":" << totalOperations << ','
           << "\"errors\":" << errors << ','
           << "\"possible_cpus\":" << possibleCpus << ','
           << "\"memlock_limit_raise_succeeded\":" << (memlockRaised ? "true" : "false") << ','
           << "\"max_rss_kb\":" << usage.ru_maxrss
           << "}}";
    return output.str();
}

#endif  // defined(__linux__)

}  // namespace

// 程序入口负责平台/权限门禁、资源限制、执行与原子落盘；skip 和 fail 有不同 JSON 状态。
int main(int argc, char** argv) {
    bench::Options options;
    std::string error;
    if (!bench::parseOptions(argc, argv, options, error)) {
        std::cerr << error << '\n' << bench::usage(argv[0]) << '\n';
        return EXIT_FAILURE;
    }
    if (options.help) {
        std::cout << bench::usage(argv[0]) << '\n';
        return EXIT_SUCCESS;
    }

    const std::string startedAt = bench::iso8601NowUtc();
    const auto suiteBegin = bench::SteadyClock::now();

#if !defined(__linux__)
    // BPF map 是 Linux 内核对象；其他平台只能产出 skipped，不能以用户态容器替代。
    const std::string reason = "real BPF maps require Linux; no synthetic pass was claimed";
    const std::string json = skippedDocument(
        options, startedAt, bench::elapsedNs(suiteBegin, bench::SteadyClock::now()), reason);
    if (!bench::writeJsonAtomically(options.output_path, json, error)) {
        std::cerr << "bpf_map_benchmark: FAIL: " << error << '\n';
        return EXIT_FAILURE;
    }
    std::cout << "bpf_map_benchmark: SKIP profile=" << options.profile_name
              << " reason=requires_Linux output=" << options.output_path << '\n';
    return EXIT_SUCCESS;
#else
    if (geteuid() != 0) {
        const std::string reason =
            "real BPF map creation requires root/CAP_BPF; rerun with sudo make -C server benchmark-bpf-maps";
        const std::string json = skippedDocument(
            options, startedAt, bench::elapsedNs(suiteBegin, bench::SteadyClock::now()), reason);
        if (!bench::writeJsonAtomically(options.output_path, json, error)) {
            std::cerr << "bpf_map_benchmark: FAIL: " << error << '\n';
            return EXIT_FAILURE;
        }
        std::cout << "bpf_map_benchmark: SKIP profile=" << options.profile_name
                  << " reason=requires_root_or_CAP_BPF output=" << options.output_path << '\n';
        return EXIT_SUCCESS;
    }

    struct rlimit unlimited {RLIM_INFINITY, RLIM_INFINITY};
    // 老内核可能受 RLIMIT_MEMLOCK 限制；是否提升成功写入结果，创建失败仍由 benchmark 报错。
    const bool memlockRaised = setrlimit(RLIMIT_MEMLOCK, &unlimited) == 0;
    const int possibleCpus = libbpf_num_possible_cpus();
    std::vector<bench::BenchmarkResult> results;
    if (possibleCpus <= 0) {
        bench::BenchmarkResult failure;
        failure.name = "libbpf_possible_cpu_discovery";
        failure.operations = 1;
        failure.threads = 1;
        failure.errors = 1;
        failure.details_json = "{\"error\":\"libbpf_num_possible_cpus failed\"}";
        results.push_back(std::move(failure));
    } else {
        results = benchmarkMaps(options, possibleCpus);
    }
    const std::uint64_t duration = bench::elapsedNs(suiteBegin, bench::SteadyClock::now());
    const std::string json = renderDocument(
        options, startedAt, duration, results, std::max(possibleCpus, 0), memlockRaised);
    if (!bench::writeJsonAtomically(options.output_path, json, error)) {
        std::cerr << "bpf_map_benchmark: FAIL: " << error << '\n';
        return EXIT_FAILURE;
    }
    std::uint64_t errors = 0;
    for (const auto& result : results) errors += result.errors;
    std::cout << "bpf_map_benchmark: " << (errors == 0 ? "PASS" : "FAIL")
              << " profile=" << options.profile_name
              << " benchmarks=" << results.size()
              << " errors=" << errors
              << " output=" << options.output_path << '\n';
    return errors == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
#endif
}
