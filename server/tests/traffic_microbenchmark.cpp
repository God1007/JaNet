// WeakNet 用户态微基准：测核心计数/策略/路由算法和观测状态并发，并审计 FlowKey 字节语义。
// 结果只写到 --output 指定的单个 JSON；stdout 仅保留便于人工查看的一行 PASS/FAIL 摘要。

#include "benchmark_support.hpp"

#include "flow_abi.h"
#include "flow_observation_core.hpp"
#include "route_selection.hpp"
#include "traffic_observation_state.hpp"

#include <arpa/inet.h>

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <memory>
#include <numeric>
#include <set>
#include <sstream>
#include <string>
#include <thread>
#include <type_traits>
#include <unordered_set>
#include <utility>
#include <vector>

namespace bench = weaknet_benchmark;
namespace core = weaknet_grpc::traffic_core;
namespace route = weaknet_grpc::route_selection;

namespace {

// 防止编译器把“计算后只做校验”的热路径整体消除；它不参与正确性判断。
std::atomic<std::uint64_t> benchmarkSink{0};

// 三档 profile 的统一规模配置，覆盖串行核心算法、并发状态仓库和 FlowKey 样本量。
struct ProfileConfig {
    std::uint64_t core_iterations;
    std::uint64_t policy_iterations;
    std::uint64_t route_iterations;
    std::uint32_t route_entries;
    std::uint64_t state_operations_per_thread;
    std::uint32_t state_readers;
    std::uint32_t state_writers;
    std::uint64_t flow_keys;
    std::uint64_t latency_stride;
};

// 将公共 profile 映射为确定的负载规模，确保不同机器执行的是同一套操作数量。
ProfileConfig profileConfig(bench::Profile profile) {
    switch (profile) {
        case bench::Profile::Smoke:
            return {50000, 30000, 5000, 128, 10000, 2, 2, 10000, 4};
        case bench::Profile::Standard:
            return {500000, 300000, 30000, 512, 100000, 4, 4, 100000, 16};
        case bench::Profile::Stress:
            return {5000000, 3000000, 100000, 2048, 500000, 8, 8, 500000, 64};
    }
    return {50000, 30000, 5000, 128, 10000, 2, 2, 10000, 4};
}

// 串行微基准通用执行器：按 batch 抽样后除以实际 batch 大小，降低逐操作读时钟的扰动。
template <typename Operation>
bench::BenchmarkResult runSerial(const std::string& name,
                                 std::uint64_t operations,
                                 std::uint64_t sampleStride,
                                 Operation&& operation,
                                 const std::string& details = "{}") {
    bench::BenchmarkResult result;
    result.name = name;
    result.operations = operations;
    result.threads = 1;
    result.latency_sample_stride = sampleStride;
    result.latency_method = "amortized_batch_ns_per_operation";
    result.details_json = details;
    result.latency_samples.reserve(static_cast<std::size_t>(operations / sampleStride + 1));

    const auto begin = bench::SteadyClock::now();
    bench::SteadyClock::time_point batchBegin;
    for (std::uint64_t index = 0; index < operations; ++index) {
        if (index % sampleStride == 0) batchBegin = bench::SteadyClock::now();
        if (!operation(index)) ++result.errors;
        const bool batchComplete = (index + 1) % sampleStride == 0 || index + 1 == operations;
        if (batchComplete) {
            const std::uint64_t batchSize = index % sampleStride + 1;
            result.latency_samples.push_back(
                bench::elapsedNs(batchBegin, bench::SteadyClock::now()) / batchSize);
        }
    }
    result.duration_ns = bench::elapsedNs(begin, bench::SteadyClock::now());
    return result;
}

// 覆盖正常递增、计数回退、generation 切换和首次观测四类 counter delta 语义。
bench::BenchmarkResult benchmarkSafeCounterDelta(const ProfileConfig& config) {
    std::uint64_t sink = 0;
    auto result = runSerial(
        "safeCounterDelta",
        config.core_iterations,
        config.latency_stride,
        [&](std::uint64_t index) {
            const std::uint64_t selector = index & 3U;
            core::CounterSample previous{900 + index, 9 + index, 100, 7};
            core::CounterSample current{1000 + index, 10 + index, 100, 7};
            core::CounterDelta delta;
            bool correct = false;
            if (selector == 0) {
                delta = core::calculateCounterDelta(current, &previous, true);
                correct = delta.bytes == 100 && delta.packets == 1 &&
                          !delta.counter_reset && !delta.continuity_lost;
            } else if (selector == 1) {
                current = {7, 1, 101, 7};
                delta = core::calculateCounterDelta(current, &previous, true);
                correct = delta.bytes == 7 && delta.packets == 1 &&
                          delta.counter_reset && delta.continuity_lost;
            } else if (selector == 2) {
                current.generation = 8;
                delta = core::calculateCounterDelta(current, &previous, true);
                correct = delta.bytes == current.bytes && delta.packets == current.packets &&
                          delta.counter_reset && delta.continuity_lost;
            } else {
                delta = core::calculateCounterDelta(current, nullptr, false);
                correct = delta.bytes == current.bytes && delta.packets == current.packets &&
                          !delta.counter_reset && !delta.continuity_lost;
            }
            sink ^= delta.bytes + (delta.packets << 1U) + index;
            return correct;
        },
        "{\"implementation\":\"traffic_core::calculateCounterDelta\","
        "\"cases\":[\"monotonic\",\"decreased\",\"generation_changed\",\"new_entry\"]}");
    benchmarkSink.fetch_xor(sink, std::memory_order_relaxed);
    return result;
}

// 验证长流保护策略各信号的优先语义，同时测量策略判定热路径吞吐。
bench::BenchmarkResult benchmarkProtectionPolicy(const ProfileConfig& config) {
    core::LongFlowPolicy policy;
    policy.protected_cgroup_fragments = {"critical.slice"};
    const std::array<core::LongFlowCandidate, 6> candidates{{
        {299, 1000, 22, 443, "sshd", ""},
        {300, 1000, 10000, 22, "worker", ""},
        {300, 1000, 10000, 443, "sshd-session", ""},
        {300, 1000, 10000, 443, "worker", "/critical.slice/job"},
        {900, 1024, 10000, 443, "worker", ""},
        {300, 1000000, 10000, 443, "worker", ""},
    }};
    const std::array<std::uint32_t, 6> expected{{
        0,
        FLOW_POLICY_PORT,
        FLOW_POLICY_PROCESS,
        FLOW_POLICY_CGROUP,
        FLOW_POLICY_LONG_LOW_RATE,
        0,
    }};

    std::uint64_t sink = 0;
    auto result = runSerial(
        "long_flow_protection_policy",
        config.policy_iterations,
        config.latency_stride,
        [&](std::uint64_t index) {
            const std::size_t candidateIndex = static_cast<std::size_t>(index % candidates.size());
            const core::PolicyDecision decision =
                core::evaluateLongFlowPolicy(policy, candidates[candidateIndex]);
            sink += decision.reason_flags + static_cast<std::uint64_t>(decision.protect);
            return decision.reason_flags == expected[candidateIndex] &&
                   decision.protect == (expected[candidateIndex] != 0);
        },
        "{\"signals\":[\"duration_gate\",\"port\",\"process\",\"cgroup\","
        "\"extended_low_rate\"]}");
    benchmarkSink.fetch_add(sink, std::memory_order_relaxed);
    return result;
}

// 在扩大后的真实有序路由集合中反复选择默认出口，并确认 IPv4/IPv6 最优项不漂移。
bench::BenchmarkResult benchmarkRouteSelection(const ProfileConfig& config) {
    route::DefaultRouteTable table;
    std::set<int> upInterfaces;

    // 预置唯一最优的 main/IPv4 route；其余 route 扩大真实有序集合扫描规模。
    table.add({route::kFamilyIpv4, route::kTableMain, 0, 1, 0, 0, "10.0.0.1"});
    table.add({route::kFamilyIpv6, route::kTableMain, 1, 1, 0, 0, "fe80::1"});
    upInterfaces.insert(1);
    for (std::uint32_t index = 0; index < config.route_entries; ++index) {
        const int ifindex = static_cast<int>(index % 63U) + 2;
        route::RouteIdentity candidate;
        candidate.family = index % 3U == 0 ? route::kFamilyIpv6 : route::kFamilyIpv4;
        candidate.table = index % 5U == 0 ? route::kTableDefault : route::kTableMain;
        candidate.metric = index + 100;
        candidate.ifindex = ifindex;
        candidate.hops = static_cast<std::uint8_t>(index % 4U);
        candidate.gateway = "gateway-" + std::to_string(index);
        table.add(candidate);
        upInterfaces.insert(ifindex);
    }

    std::uint64_t sink = 0;
    std::ostringstream details;
    details << "{\"route_candidates\":" << table.size()
            << ",\"up_interfaces\":" << upInterfaces.size()
            << ",\"expected_ifindex\":1}";
    auto result = runSerial(
        "default_route_selection",
        config.route_iterations,
        config.latency_stride,
        [&](std::uint64_t) {
            const route::Selection selected = table.select(upInterfaces);
            sink += static_cast<std::uint64_t>(selected.ifindex) + selected.ipv4 + selected.ipv6;
            return selected.ifindex == 1 && selected.ipv4 && selected.ipv6;
        },
        details.str());
    benchmarkSink.fetch_add(sink, std::memory_order_relaxed);
    return result;
}

// 验证事务快照每次尝试前必须 reset，以及稳定、重试成功、耗尽预算三种结果。
bench::BenchmarkResult benchmarkTransactionalSnapshotRetry(const ProfileConfig& config) {
    std::uint64_t sink = 0;
    auto result = runSerial(
        "transactional_snapshot_retry",
        config.core_iterations / 2U,
        config.latency_stride,
        [&](std::uint64_t index) {
            const std::uint64_t scenario = index % 3U;
            std::uint64_t resets = 0;
            std::uint64_t attempts = 0;
            bool candidateWasReset = false;
            const bool success = core::retryTransactionalSnapshot(
                3,
                [&] {
                    ++resets;
                    candidateWasReset = true;
                },
                [&](std::size_t attemptIndex) {
                    if (!candidateWasReset) return false;
                    candidateWasReset = false;
                    ++attempts;
                    if (scenario == 0) return true;          // 稳定 generation，首轮提交。
                    if (scenario == 1) return attemptIndex == 1; // generation 改变，reset 后重试成功。
                    return false;                            // 每轮变化，耗尽重试预算。
                });
            sink += resets + attempts + static_cast<std::uint64_t>(success);
            if (scenario == 0) return success && resets == 1 && attempts == 1;
            if (scenario == 1) return success && resets == 2 && attempts == 2;
            return !success && resets == 3 && attempts == 3;
        },
        "{\"max_attempts\":3,\"cases\":[\"stable_first_attempt\","
        "\"generation_changed_then_retry_success\",\"retry_exhausted\"],"
        "\"reset_required_before_every_attempt\":true}");
    benchmarkSink.fetch_add(sink, std::memory_order_relaxed);
    return result;
}

// 同一轮并发状态压测拆成 publish/load 两个可独立汇报的结果。
struct StateResults {
    bench::BenchmarkResult publish;
    bench::BenchmarkResult load;
};

// 每个 worker 私有保存延迟与错误，结束后再汇总，避免统计锁污染被测状态仓库。
struct ThreadSamples {
    std::vector<std::uint64_t> latencies;
    std::uint64_t errors = 0;
};

// 让多 writer/readers 同时访问 TrafficObservationStateStore，并验证 stats/snapshot 原子一致。
StateResults benchmarkObservationState(const ProfileConfig& config) {
    weaknet_grpc::TrafficObservationStateStore store;
    NetTrafficAnalyzer::RealTimeStats seedStats;
    seedStats.generation = 1;
    seedStats.boundIfindex = 1;
    seedStats.valid = true;
    auto seedSnapshot = std::make_shared<TrafficSnapshot>();
    seedSnapshot->generation = 1;
    seedSnapshot->boundIfindex = 1;
    if (!store.publish(seedStats, seedSnapshot)) {
        throw std::runtime_error("failed to seed TrafficObservationStateStore");
    }

    const std::uint32_t totalThreads = config.state_readers + config.state_writers;
    // StartGate 在所有线程完成局部对象初始化后统一放行，线程创建时间不计入竞争窗口。
    bench::StartGate gate(totalThreads);
    std::vector<std::thread> threads;
    std::vector<ThreadSamples> writerSamples(config.state_writers);
    std::vector<ThreadSamples> readerSamples(config.state_readers);
    threads.reserve(totalThreads);

    for (std::uint32_t writer = 0; writer < config.state_writers; ++writer) {
        threads.emplace_back([&, writer] {
            auto& measurement = writerSamples[writer];
            measurement.latencies.reserve(static_cast<std::size_t>(
                config.state_operations_per_thread / config.latency_stride + 1));
            NetTrafficAnalyzer::RealTimeStats stats;
            stats.generation = static_cast<std::uint64_t>(writer) + 2;
            stats.boundIfindex = writer + 2;
            stats.valid = true;
            auto snapshot = std::make_shared<TrafficSnapshot>();
            snapshot->generation = stats.generation;
            snapshot->boundIfindex = stats.boundIfindex;
            gate.workerWait();
            bench::SteadyClock::time_point batchBegin;
            for (std::uint64_t index = 0; index < config.state_operations_per_thread; ++index) {
                if (index % config.latency_stride == 0) batchBegin = bench::SteadyClock::now();
                if (!store.publish(stats, snapshot)) ++measurement.errors;
                const bool batchComplete = (index + 1) % config.latency_stride == 0 ||
                                           index + 1 == config.state_operations_per_thread;
                if (batchComplete) {
                    const std::uint64_t batchSize = index % config.latency_stride + 1;
                    measurement.latencies.push_back(
                        bench::elapsedNs(batchBegin, bench::SteadyClock::now()) / batchSize);
                }
            }
        });
    }
    for (std::uint32_t reader = 0; reader < config.state_readers; ++reader) {
        threads.emplace_back([&, reader] {
            auto& measurement = readerSamples[reader];
            measurement.latencies.reserve(static_cast<std::size_t>(
                config.state_operations_per_thread / config.latency_stride + 1));
            gate.workerWait();
            bench::SteadyClock::time_point batchBegin;
            for (std::uint64_t index = 0; index < config.state_operations_per_thread; ++index) {
                if (index % config.latency_stride == 0) batchBegin = bench::SteadyClock::now();
                const auto state = store.load();
                const bool batchComplete = (index + 1) % config.latency_stride == 0 ||
                                           index + 1 == config.state_operations_per_thread;
                if (batchComplete) {
                    const std::uint64_t batchSize = index % config.latency_stride + 1;
                    measurement.latencies.push_back(
                        bench::elapsedNs(batchBegin, bench::SteadyClock::now()) / batchSize);
                }
                if (!state.snapshot ||
                    state.stats.generation != state.snapshot->generation ||
                    state.stats.boundIfindex != state.snapshot->boundIfindex) {
                    ++measurement.errors;
                }
            }
        });
    }

    gate.waitUntilReady();
    // publish/load 共用同一个 begin/end，两个结果的 duration 都表示同一段并发墙钟时间。
    const auto begin = bench::SteadyClock::now();
    gate.release();
    for (auto& thread : threads) thread.join();
    const std::uint64_t duration = bench::elapsedNs(begin, bench::SteadyClock::now());

    StateResults results;
    results.publish.name = "traffic_observation_state_publish_contended";
    results.publish.operations = config.state_operations_per_thread * config.state_writers;
    results.publish.threads = config.state_writers;
    results.publish.duration_ns = duration;
    results.publish.latency_sample_stride = config.latency_stride;
    results.publish.latency_method = "amortized_batch_ns_per_operation";
    results.load.name = "traffic_observation_state_load_contended";
    results.load.operations = config.state_operations_per_thread * config.state_readers;
    results.load.threads = config.state_readers;
    results.load.duration_ns = duration;
    results.load.latency_sample_stride = config.latency_stride;
    results.load.latency_method = "amortized_batch_ns_per_operation";

    for (auto& sample : writerSamples) {
        results.publish.errors += sample.errors;
        bench::appendSamples(results.publish.latency_samples, std::move(sample.latencies));
    }
    for (auto& sample : readerSamples) {
        results.load.errors += sample.errors;
        bench::appendSamples(results.load.latency_samples, std::move(sample.latencies));
    }
    std::ostringstream publishDetails;
    publishDetails << "{\"concurrent_writers\":" << config.state_writers
                   << ",\"concurrent_readers\":" << config.state_readers
                   << ",\"operations_per_thread\":" << config.state_operations_per_thread << '}';
    results.publish.details_json = publishDetails.str();
    results.load.details_json = publishDetails.str();
    return results;
}

// 确定性伪随机混合器，只用于扩散测试地址字段；不作为待评估的 map/hash 实现。
std::uint64_t splitMix64(std::uint64_t value) {
    value += UINT64_C(0x9e3779b97f4a7c15);
    value = (value ^ (value >> 30U)) * UINT64_C(0xbf58476d1ce4e5b9);
    value = (value ^ (value >> 27U)) * UINT64_C(0x94d049bb133111eb);
    return value ^ (value >> 31U);
}

// 从 ordinal 构造唯一且规范化的 56-byte flow_key，完整键相等才代表业务 key 碰撞。
flow_key makeCanonicalFlowKey(std::uint64_t ordinal) {
    // 值初始化是 key 契约的一部分：reserved 字节、隐式 padding 与 IPv4 地址尾部必须保持 0。
    flow_key key{};
    key.family = ordinal % 4U == 0 ? FLOW_AF_INET6 : FLOW_AF_INET4;
    key.protocol = ordinal % 2U == 0 ? IPPROTO_TCP : IPPROTO_UDP;
    key.direction = ordinal % 3U == 0 ? FLOW_DIR_INGRESS : FLOW_DIR_EGRESS;
    key.ifindex = static_cast<flow_u32>(ordinal % 127U) + 1U;
    key.sport_be = htons(static_cast<std::uint16_t>(1024U + ordinal % 50000U));
    key.dport_be = htons(static_cast<std::uint16_t>(1U + (ordinal * 17U) % 65534U));
    std::uint64_t source = splitMix64(ordinal);
    std::uint64_t destination = splitMix64(ordinal ^ UINT64_C(0xd1b54a32d192ed03));
    const std::size_t addressBytes = key.family == FLOW_AF_INET4 ? 4U : 16U;
    for (std::size_t index = 0; index < addressBytes; ++index) {
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

// 对完整 flow_key 字节计算用户态 FNV-1a 64-bit 摘要；仅作为分布代理，不等于内核 map hash。
std::uint64_t fnv1a64(const void* bytes, std::size_t size) {
    const auto* cursor = static_cast<const unsigned char*>(bytes);
    std::uint64_t hash = UINT64_C(14695981039346656037);
    for (std::size_t index = 0; index < size; ++index) {
        hash ^= cursor[index];
        hash *= UINT64_C(1099511628211);
    }
    return hash;
}

// 选取 2 的幂作为代理桶数，既便于位掩码取桶，也让不同 profile 的平均负载可比较。
std::size_t distributionBucketCount(std::uint64_t keys) {
    std::size_t desired = static_cast<std::size_t>(std::max<std::uint64_t>(256, keys / 4));
    std::size_t buckets = 1;
    while (buckets < desired && buckets < (1U << 20U)) buckets <<= 1U;
    return buckets;
}

// 用生日悖论近似计算 n 个均匀摘要中“至少一次摘要碰撞”的理论概率。
long double birthdayCollisionProbability(std::uint64_t values, unsigned int digestBits) {
    if (values < 2) return 0.0L;
    const long double digestSpace = std::ldexp(1.0L, static_cast<int>(digestBits));
    const long double pairs = static_cast<long double>(values) *
                              static_cast<long double>(values - 1U) / 2.0L;
    return -std::expm1(-pairs / digestSpace);
}

// 审计 FlowKey 唯一性、规范化、摘要碰撞与代理桶分布；四种“碰撞”口径必须分开解读。
bench::BenchmarkResult benchmarkFlowKeys(const ProfileConfig& config) {
    bench::BenchmarkResult result;
    result.name = "flow_key_generation_uniqueness_and_hash_distribution";
    result.operations = config.flow_keys;
    result.threads = 1;
    result.latency_sample_stride = config.latency_stride;
    result.latency_method = "amortized_batch_ns_per_operation";
    result.latency_samples.reserve(static_cast<std::size_t>(
        config.flow_keys / config.latency_stride + 1));

    // 1) full-byte key 重复：两个 56-byte 规范键完全相同，才是业务身份碰撞。
    std::unordered_set<std::string> uniqueKeys;
    uniqueKeys.reserve(static_cast<std::size_t>(config.flow_keys * 13U / 10U));
    // 2) digest collision：不同完整键得到相同 FNV 摘要；分别观察 64-bit 和截断 32-bit。
    std::unordered_set<std::uint64_t> uniqueFullDigests;
    std::unordered_set<std::uint32_t> uniqueLower32Digests;
    uniqueFullDigests.reserve(static_cast<std::size_t>(config.flow_keys * 13U / 10U));
    uniqueLower32Digests.reserve(static_cast<std::size_t>(config.flow_keys * 13U / 10U));
    // 3) bucket occupancy collision：多个摘要落入配置的代理桶，仅衡量分布，不代表键/摘要相等。
    const std::size_t bucketCount = distributionBucketCount(config.flow_keys);
    std::vector<std::uint64_t> bucketLoads(bucketCount, 0);
    std::uint64_t duplicateKeys = 0;
    std::uint64_t canonicalizationErrors = 0;

    const auto begin = bench::SteadyClock::now();
    bench::SteadyClock::time_point batchBegin;
    for (std::uint64_t index = 0; index < config.flow_keys; ++index) {
        if (index % config.latency_stride == 0) batchBegin = bench::SteadyClock::now();
        const flow_key key = makeCanonicalFlowKey(index);
        if (key.reserved0 != 0 || key.reserved1 != 0) ++canonicalizationErrors;
        if (key.family == FLOW_AF_INET4) {
            for (std::size_t byte = 4; byte < 16; ++byte) {
                if (key.saddr[byte] != 0 || key.daddr[byte] != 0) ++canonicalizationErrors;
            }
        }
        // std::string 保存原始定长字节（包括 0），不会像 C 字符串那样在首个 NUL 截断。
        const std::string raw(reinterpret_cast<const char*>(&key), sizeof(key));
        if (!uniqueKeys.insert(raw).second) ++duplicateKeys;
        const std::uint64_t digest = fnv1a64(&key, sizeof(key));
        uniqueFullDigests.insert(digest);
        uniqueLower32Digests.insert(static_cast<std::uint32_t>(digest));
        ++bucketLoads[static_cast<std::size_t>(digest) & (bucketCount - 1U)];
        const bool batchComplete = (index + 1) % config.latency_stride == 0 ||
                                   index + 1 == config.flow_keys;
        if (batchComplete) {
            const std::uint64_t batchSize = index % config.latency_stride + 1;
            result.latency_samples.push_back(
                bench::elapsedNs(batchBegin, bench::SteadyClock::now()) / batchSize);
        }
    }
    result.duration_ns = bench::elapsedNs(begin, bench::SteadyClock::now());
    result.errors = duplicateKeys + canonicalizationErrors;

    // 证明 reserved/IPv4 尾部若未清零会改变原始 map key，规范化不是纯样式要求。
    const flow_key canonical = makeCanonicalFlowKey(7);
    flow_key nonCanonical = canonical;
    nonCanonical.reserved0 = 0xa5;
    nonCanonical.reserved1 = UINT32_C(0xa5a5a5a5);
    for (std::size_t index = 4; index < 16; ++index) {
        nonCanonical.saddr[index] = 0xa5;
        nonCanonical.daddr[index] = 0xa5;
    }
    const bool reservedBytesChangeRawKey =
        std::memcmp(&canonical, &nonCanonical, sizeof(flow_key)) != 0;
    if (!reservedBytesChangeRawKey) ++result.errors;

    // socket_cookie 属于完整 identity：同五元组但 cookie 不同，仍必须是不同 key。
    flow_key sameFiveTupleDifferentCookie = canonical;
    ++sameFiveTupleDifferentCookie.socket_cookie;
    const bool cookieParticipatesInFullKey =
        std::memcmp(&canonical, &sameFiveTupleDifferentCookie, sizeof(flow_key)) != 0;
    if (!cookieParticipatesInFullKey) ++result.errors;

    // 4) Linux 内核桶冲突：内核仍会比较完整 key，不会把两个不同 key 视为同一项；
    // 本测试无法也不声称复现内核私有 hash，只报告用户态代理分布和真实 key 唯一性。
    const std::uint64_t nonEmptyBuckets = static_cast<std::uint64_t>(
        std::count_if(bucketLoads.begin(), bucketLoads.end(),
                      [](std::uint64_t load) { return load != 0; }));
    const std::uint64_t maxBucketLoad = *std::max_element(bucketLoads.begin(), bucketLoads.end());
    const std::uint64_t empiricalBucketCollisions = config.flow_keys - nonEmptyBuckets;
    const std::uint64_t fullDigestCollisions =
        config.flow_keys - static_cast<std::uint64_t>(uniqueFullDigests.size());
    const std::uint64_t lower32DigestCollisions =
        config.flow_keys - static_cast<std::uint64_t>(uniqueLower32Digests.size());
    const long double theoretical32 = birthdayCollisionProbability(config.flow_keys, 32);
    const long double theoretical64 = birthdayCollisionProbability(config.flow_keys, 64);
    const double mean = static_cast<double>(config.flow_keys) / static_cast<double>(bucketCount);
    double variance = 0.0;
    for (const std::uint64_t load : bucketLoads) {
        const double difference = static_cast<double>(load) - mean;
        variance += difference * difference;
    }
    variance /= static_cast<double>(bucketCount);
    const auto loadLatency = bench::summarizeLatencies(bucketLoads);
    constexpr std::size_t explicitFieldBytes =
        1 + 1 + 1 + 1 + 4 + 2 + 2 + 4 + 16 + 16 + 8;

    std::ostringstream details;
    details.imbue(std::locale::classic());
    details << '{'
            << "\"generated_keys\":" << config.flow_keys << ','
            << "\"unique_full_byte_keys\":" << uniqueKeys.size() << ','
            << "\"duplicate_full_byte_keys\":" << duplicateKeys << ','
            << "\"layout\":{"
            << "\"sizeof_bytes\":" << sizeof(flow_key) << ','
            << "\"alignof_bytes\":" << alignof(flow_key) << ','
            << "\"explicit_field_bytes\":" << explicitFieldBytes << ','
            << "\"implicit_padding_bytes\":" << sizeof(flow_key) - explicitFieldBytes << ','
            << "\"standard_layout\":"
            << (std::is_standard_layout<flow_key>::value ? "true" : "false") << ','
            << "\"trivially_copyable\":"
            << (std::is_trivially_copyable<flow_key>::value ? "true" : "false") << ','
            << "\"unique_object_representations\":"
            << (std::has_unique_object_representations<flow_key>::value ? "true" : "false") << ','
            << "\"canonical_reserved_and_ipv4_tail_zeroed\":"
            << (canonicalizationErrors == 0 ? "true" : "false") << ','
            << "\"noncanonical_reserved_bytes_change_raw_key\":"
            << (reservedBytesChangeRawKey ? "true" : "false") << ','
            << "\"raw_aliasing_requires_memcpy\":true},"
            << "\"identity_gates\":{"
            << "\"same_five_tuple_different_socket_cookie_distinct_full_key\":"
            << (cookieParticipatesInFullKey ? "true" : "false") << "},"
            << "\"digest_collision_analysis\":{"
            << "\"algorithm\":\"fnv1a64_full_56_bytes\","
            << "\"proxy_not_kernel_hash\":true,"
            << "\"birthday_probability_at_least_one_collision\":{"
            << "\"sample_size\":" << config.flow_keys << ','
            << "\"digest_32_bit\":" << std::scientific << std::setprecision(12)
            << static_cast<double>(theoretical32) << ','
            << "\"digest_64_bit\":" << std::scientific << std::setprecision(12)
            << static_cast<double>(theoretical64) << "},"
            << "\"empirical\":{"
            << "\"full_64_bit\":{"
            << "\"unique_digests\":" << uniqueFullDigests.size() << ','
            << "\"digest_collisions\":" << fullDigestCollisions << "},"
            << "\"lower_32_bit\":{"
            << "\"unique_digests\":" << uniqueLower32Digests.size() << ','
            << "\"digest_collisions\":" << lower32DigestCollisions << "}}},"
            << "\"empirical_hash_distribution\":{"
            << "\"algorithm\":\"fnv1a64_full_56_bytes_userspace_not_kernel_hash\","
            << "\"proxy_not_kernel_hash\":true,"
            << "\"buckets\":" << bucketCount << ','
            << "\"non_empty_buckets\":" << nonEmptyBuckets << ','
            << "\"mean_load\":" << std::fixed << std::setprecision(6) << mean << ','
            << "\"variance\":" << std::fixed << std::setprecision(6) << variance << ','
            << "\"p50_load\":" << loadLatency.p50_ns << ','
            << "\"p95_load\":" << loadLatency.p95_ns << ','
            << "\"p99_load\":" << loadLatency.p99_ns << ','
            << "\"max_load\":" << maxBucketLoad << ','
            << "\"bucket_occupancy_collisions\":" << empiricalBucketCollisions << ','
            << "\"collision_definition\":\"items beyond the first occupant per configured bucket; not digest collisions\"},"
            << "\"kernel_hash_collision_is_key_collision\":false,"
            << "\"collision_note\":"
            << bench::jsonEscape(
                   "Two distinct 56-byte keys may share a kernel hash bucket and are still distinct map keys; "
                   "a key collision means the canonical full key bytes are equal.")
            << '}';
    result.details_json = details.str();
    benchmarkSink.fetch_add(uniqueKeys.size() + maxBucketLoad, std::memory_order_relaxed);
    return result;
}

// 将七项微基准汇总成统一 schema，任何正确性错误都会把根 summary 标记为 failed。
std::string renderDocument(const bench::Options& options,
                           const std::string& startedAt,
                           std::uint64_t totalDurationNs,
                           const std::vector<bench::BenchmarkResult>& results) {
    std::uint64_t totalOperations = 0;
    std::uint64_t totalErrors = 0;
    for (const auto& result : results) {
        totalOperations += result.operations;
        totalErrors += result.errors;
    }

    std::ostringstream output;
    output.imbue(std::locale::classic());
    output << '{'
           << "\"schema_version\":" << bench::jsonEscape(bench::kSchemaVersion) << ','
           << "\"component\":\"traffic_userspace_microbenchmark\","
           << "\"profile\":" << bench::jsonEscape(options.profile_name) << ','
           << "\"environment\":" << bench::environmentJson() << ','
           << "\"started_at\":" << bench::jsonEscape(startedAt) << ','
           << "\"duration_ms\":" << std::fixed << std::setprecision(3)
           << static_cast<double>(totalDurationNs) / 1000000.0 << ','
           << "\"benchmarks\":[";
    for (std::size_t index = 0; index < results.size(); ++index) {
        if (index != 0) output << ',';
        output << bench::benchmarkJson(results[index]);
    }
    output << "],\"summary\":{"
           << "\"status\":" << bench::jsonEscape(totalErrors == 0 ? "passed" : "failed") << ','
           << "\"correctness_passed\":" << (totalErrors == 0 ? "true" : "false") << ','
           << "\"benchmark_count\":" << results.size() << ','
           << "\"total_operations\":" << totalOperations << ','
           << "\"errors\":" << totalErrors << ','
           << "\"optimization_sink\":" << benchmarkSink.load(std::memory_order_relaxed)
           << "}}";
    return output.str();
}

}  // namespace

// 依次执行核心算法、并发状态与 FlowKey 审计，最后原子写入唯一 JSON 结果。
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
    std::vector<bench::BenchmarkResult> results;
    try {
        const ProfileConfig config = profileConfig(options.profile);
        results.push_back(benchmarkSafeCounterDelta(config));
        results.push_back(benchmarkProtectionPolicy(config));
        results.push_back(benchmarkRouteSelection(config));
        results.push_back(benchmarkTransactionalSnapshotRetry(config));
        StateResults state = benchmarkObservationState(config);
        results.push_back(std::move(state.publish));
        results.push_back(std::move(state.load));
        results.push_back(benchmarkFlowKeys(config));
    } catch (const std::exception& exception) {
        std::cerr << "traffic_microbenchmark: FAIL: " << exception.what() << '\n';
        return EXIT_FAILURE;
    }
    const std::uint64_t duration =
        bench::elapsedNs(suiteBegin, bench::SteadyClock::now());
    const std::string json = renderDocument(options, startedAt, duration, results);
    if (!bench::writeJsonAtomically(options.output_path, json, error)) {
        std::cerr << "traffic_microbenchmark: FAIL: " << error << '\n';
        return EXIT_FAILURE;
    }

    std::uint64_t errors = 0;
    for (const auto& result : results) errors += result.errors;
    std::cout << "traffic_microbenchmark: " << (errors == 0 ? "PASS" : "FAIL")
              << " profile=" << options.profile_name
              << " benchmarks=" << results.size()
              << " errors=" << errors
              << " output=" << options.output_path << '\n';
    return errors == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
