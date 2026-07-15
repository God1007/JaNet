// Linux 特权集成测试：真实附加 TC、制造超过 LRU 容量的短流，并验证受保护低频 TCP 的生命周期。
// 可选 --profile/--output 会把并发 flow 压力的耗时、吞吐与进程资源写成统一 benchmark JSON。

#include "benchmark_support.hpp"
#include "net_traffic.h"

#include <arpa/inet.h>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <string>
#include <thread>
#include <vector>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/resource.h>

namespace bench = weaknet_benchmark;

namespace {

// 统一终止集成测试。namespace、veth、服务端子进程的回收由外层 Shell trap 保证。
[[noreturn]] void fail(const std::string& message) {
    std::cerr << "traffic_kernel_integration: FAIL: " << message << '\n';
    std::exit(EXIT_FAILURE);
}

// 将明确的 IPv4 和端口组装成 socket endpoint；地址非法时立即失败而非继续压测。
sockaddr_in endpoint(const std::string& address, uint16_t port) {
    sockaddr_in result{};
    result.sin_family = AF_INET;
    result.sin_port = htons(port);
    if (inet_pton(AF_INET, address.c_str(), &result.sin_addr) != 1) fail("invalid peer address");
    return result;
}

// 连接需要被保护的低频 TCP；短暂重试用于等待隔离 namespace 中的 peer listener 就绪。
int connectProtectedSocket(const sockaddr_in& peer) {
    for (int attempt = 0; attempt < 20; ++attempt) {
        const int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP);
        if (fd < 0) fail(std::string("TCP socket failed: ") + std::strerror(errno));
        if (connect(fd, reinterpret_cast<const sockaddr*>(&peer), sizeof(peer)) == 0) return fd;
        close(fd);
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    fail(std::string("protected TCP connect failed: ") + std::strerror(errno));
}

// 向保护流完整发送指定字节数，处理 TCP 短写，任何断链都视为生命周期测试失败。
void sendAll(int fd, size_t bytes) {
    std::string payload(bytes, 'p');
    size_t offset = 0;
    while (offset < payload.size()) {
        const ssize_t sent = send(fd, payload.data() + offset, payload.size() - offset, MSG_NOSIGNAL);
        if (sent <= 0) fail(std::string("protected TCP send failed: ") + std::strerror(errno));
        offset += static_cast<size_t>(sent);
    }
}

// 并发制造唯一 UDP 五元组：源端口 × 目的端口形成短流矩阵，用于把 LRU 推到容量压力。
uint64_t generateShortUdpFlows(const std::string& peerAddress,
                               int firstSource,
                               int sourceCount,
                               int destinationCount,
                               std::uint32_t senderThreads) {
    constexpr uint16_t kSourceBase = 20000;
    constexpr uint16_t kDestinationBase = 10000;
    const char payload = 'u';
    const sockaddr_in peerBase = endpoint(peerAddress, kDestinationBase);
    std::atomic<uint64_t> sentFlows{0};
    bench::StartGate gate(senderThreads);
    std::vector<std::thread> senders;
    senders.reserve(senderThreads);

    for (std::uint32_t threadIndex = 0; threadIndex < senderThreads; ++threadIndex) {
        senders.emplace_back([&, threadIndex] {
            // 每个线程负责互不重叠的源端口区间，避免 bind 冲突，也确保 flow 数可精确推导。
            const int first = firstSource + sourceCount * static_cast<int>(threadIndex) /
                                                static_cast<int>(senderThreads);
            const int last = firstSource + sourceCount * static_cast<int>(threadIndex + 1U) /
                                               static_cast<int>(senderThreads);
            // socket 循环前统一放行，测到的是 sender 并发强度，而不是线程创建抖动。
            gate.workerWait();
            for (int source = first; source < last; ++source) {
                const int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, IPPROTO_UDP);
                if (fd < 0) fail(std::string("UDP socket failed: ") + std::strerror(errno));
                sockaddr_in local{};
                local.sin_family = AF_INET;
                local.sin_addr.s_addr = htonl(INADDR_ANY);
                local.sin_port = htons(static_cast<uint16_t>(kSourceBase + source));
                if (bind(fd, reinterpret_cast<const sockaddr*>(&local), sizeof(local)) != 0) {
                    close(fd);
                    fail(std::string("UDP bind failed: ") + std::strerror(errno));
                }
                for (int destination = 0; destination < destinationCount; ++destination) {
                    sockaddr_in peer = peerBase;
                    peer.sin_port = htons(static_cast<uint16_t>(kDestinationBase + destination));
                    if (sendto(fd, &payload, sizeof(payload), 0,
                               reinterpret_cast<const sockaddr*>(&peer), sizeof(peer)) !=
                        sizeof(payload)) {
                        close(fd);
                        fail(std::string("UDP sendto failed: ") + std::strerror(errno));
                    }
                    sentFlows.fetch_add(1, std::memory_order_relaxed);
                }
                close(fd);
            }
        });
    }
    gate.waitUntilReady();
    gate.release();
    for (auto& sender : senders) sender.join();
    return sentFlows.load(std::memory_order_relaxed);
}

// 在 snapshot 事件列表中查找指定内核生命周期事件。
bool hasEvent(const TrafficSnapshotPtr& snapshot, uint32_t type) {
    for (const auto& event : snapshot->events) if (event.type == type) return true;
    return false;
}

// 内核集成测试的可选结果参数；不指定 output 时仍可作为纯 correctness gate 运行。
struct KernelBenchmarkOptions {
    std::string profile = "standard";
    std::string output;
};

// 前四个位置参数属于集成驱动，位置 5 之后只接受统一 profile/output 选项。
KernelBenchmarkOptions parseBenchmarkOptions(int argc, char** argv) {
    KernelBenchmarkOptions options;
    for (int index = 5; index < argc; ++index) {
        const std::string argument = argv[index];
        if (argument == "--profile" && index + 1 < argc) {
            options.profile = argv[++index];
            if (options.profile != "smoke" && options.profile != "standard" &&
                options.profile != "stress") {
                fail("unknown benchmark profile: " + options.profile);
            }
        } else if (argument == "--output" && index + 1 < argc) {
            options.output = argv[++index];
        } else {
            fail("usage: traffic_kernel_integration IFACE PEER_IPV4 PROTECTED_PORT BPF_OBJECT "
                 "[--profile smoke|standard|stress --output PATH]");
        }
    }
    return options;
}

// 一档内核负载由压力波数、每波 flow 矩阵以及 sender 并发数组成。
struct KernelLoadProfile {
    std::uint32_t waves;
    int sources_per_wave;
    int destinations_per_source;
    std::uint32_t sender_threads;
};

// 选择真实短流规模；stress 必须同时跨过 current LRU 和用户态 tombstone 总边界。
KernelLoadProfile kernelLoadProfile(const std::string& profile) {
    if (profile == "stress") {
        // 5 * 250 * 240 = 30 万条唯一 flow。每 6 万条 refresh 一次，使 everSeenFlows
        // 超过 266,240 的 tombstone 上界，从而真实覆盖淘汰与有界历史清理。
        return {5, 250, 240, 8};
    }
    if (profile == "standard") return {1, 300, 240, 4};  // 7.2 万条唯一流，4 个发送线程。
    return {1, 300, 240, 2};  // 供单独调用的 smoke；组合 smoke 不启动内核 namespace。
}

constexpr std::uint64_t kTombstoneGateEntries =
    FLOW_LRU_MAX_ENTRIES * 4ULL + FLOW_PROTECTED_MAX_ENTRIES;

// 把流量生成、每波 snapshot 刷新和保护流生命周期拆成三个 benchmark，并附进程资源指标。
std::string renderKernelBenchmark(const KernelBenchmarkOptions& options,
                                  const KernelLoadProfile& load,
                                  const std::string& startedAt,
                                  std::uint64_t totalDurationNs,
                                  std::uint64_t flowDurationNs,
                                  const std::vector<std::uint64_t>& snapshotDurationsNs,
                                  std::uint64_t lifecycleDurationNs,
                                  std::uint64_t shortFlows,
                                  const TrafficSnapshotPtr& pressure) {
    bench::BenchmarkResult generation;
    generation.name = "kernel_udp_flow_generation";
    generation.operations = shortFlows;
    generation.threads = load.sender_threads;
    generation.duration_ns = flowDurationNs;
    generation.latency_method = "aggregate_batch_ns_per_flow";
    generation.latency_samples.push_back(shortFlows == 0 ? 0 : flowDurationNs / shortFlows);
    generation.details_json =
        "{\"transport\":\"UDP\",\"distinct_five_tuples\":" +
        std::to_string(shortFlows) + ",\"payload_bytes_per_flow\":1,\"waves\":" +
        std::to_string(load.waves) + ",\"sources_per_wave\":" +
        std::to_string(load.sources_per_wave) + ",\"destinations_per_source\":" +
        std::to_string(load.destinations_per_source) + ",\"tombstone_gate_entries\":" +
        std::to_string(kTombstoneGateEntries) +
        ",\"generated_unique_keys_cross_tombstone_gate\":" +
        std::string(shortFlows > kTombstoneGateEntries ? "true" : "false") + "}";

    bench::BenchmarkResult refresh;
    refresh.name = "kernel_pressure_snapshot_refresh";
    refresh.operations = snapshotDurationsNs.size();
    refresh.threads = 1;
    refresh.duration_ns = 0;
    refresh.latency_method = "end_to_end_refresh_per_wave";
    for (const std::uint64_t duration : snapshotDurationsNs) {
        refresh.duration_ns += duration;
        refresh.latency_samples.push_back(duration);
    }
    refresh.details_json =
        "{\"map_read_complete\":" + std::string(pressure->mapReadComplete ? "true" : "false") +
        ",\"waves_sampled\":" + std::to_string(snapshotDurationsNs.size()) +
        ",\"lru_entries\":" + std::to_string(pressure->mapObservability.lruEntries) +
        ",\"protected_entries\":" +
        std::to_string(pressure->mapObservability.protectedEntries) + "}";

    bench::BenchmarkResult lifecycle;
    lifecycle.name = "kernel_protected_flow_lifecycle";
    lifecycle.operations = 3;  // 晋升、压力下存活、关闭后移除三个生命周期断言。
    lifecycle.threads = 1;
    lifecycle.duration_ns = lifecycleDurationNs;
    lifecycle.latency_method = "aggregate_lifecycle";
    lifecycle.latency_samples.push_back(lifecycleDurationNs / lifecycle.operations);
    lifecycle.details_json =
        "{\"promotion_checked\":true,\"pressure_survival_checked\":true,"
        "\"close_event_checked\":true}";

    struct rusage usage {};
    getrusage(RUSAGE_SELF, &usage);
    std::ostringstream output;
    output.imbue(std::locale::classic());
    output << '{'
           << "\"schema_version\":" << bench::jsonEscape(bench::kSchemaVersion) << ','
           << "\"component\":\"kernel_pressure_benchmark\","
           << "\"profile\":" << bench::jsonEscape(options.profile) << ','
           << "\"environment\":" << bench::environmentJson() << ','
           << "\"started_at\":" << bench::jsonEscape(startedAt) << ','
           << "\"duration_ms\":" << std::fixed << std::setprecision(3)
           << static_cast<double>(totalDurationNs) / 1000000.0 << ','
           << "\"benchmarks\":["
           << bench::benchmarkJson(generation) << ','
           << bench::benchmarkJson(refresh) << ','
           << bench::benchmarkJson(lifecycle)
           << "],\"summary\":{"
           << "\"status\":\"passed\","
           << "\"correctness_passed\":true,"
           << "\"benchmark_count\":3,"
           << "\"total_operations\":"
           << shortFlows + refresh.operations + lifecycle.operations << ','
           << "\"errors\":0,"
           << "\"short_flows\":" << shortFlows << ','
           << "\"sender_threads\":" << load.sender_threads << ','
           << "\"pressure_waves\":" << load.waves << ','
           << "\"tombstone_gate_entries\":" << kTombstoneGateEntries << ','
           << "\"generated_unique_keys_cross_tombstone_gate\":"
           << (shortFlows > kTombstoneGateEntries ? "true" : "false") << ','
           << "\"lru_entries\":" << pressure->mapObservability.lruEntries << ','
           << "\"protected_entries\":" << pressure->mapObservability.protectedEntries << ','
           << "\"max_rss_kb\":" << usage.ru_maxrss << ','
           << "\"minor_faults\":" << usage.ru_minflt << ','
           << "\"major_faults\":" << usage.ru_majflt << ','
           << "\"voluntary_context_switches\":" << usage.ru_nvcsw << ','
           << "\"involuntary_context_switches\":" << usage.ru_nivcsw
           << "}}";
    return output.str();
}

// TC ownership 的三个内核场景共用这个短生命周期探针：它只加载真实对象、执行一次
// initForInterface，并在需要时通过 ready/release 文件让外层脚本有机会检查进程存活期间的槽位。
int runTcOwnershipProbe(int argc, char** argv) {
    if (argc < 5) {
        fail("usage: traffic_kernel_integration --tc-ownership-probe IFACE BPF_OBJECT "
             "expect-tc READY RELEASE | expect-reject");
    }
    const std::string iface = argv[2];
    const std::string bpfObject = argv[3];
    const std::string expectation = argv[4];

    auto analyzer = NetTrafficAnalyzer::getInstance();
    analyzer->setBpfObjectPath(bpfObject);
    const bool initialized = analyzer->initForInterface(iface);
    // init 的失败原因先落在内部 support；主动发布一次快照后，探针才能给出精确拒绝原因。
    const auto snapshot = analyzer->refreshSnapshot();

    if (expectation == "expect-reject") {
        // foreign 槽位必须在任何 TC 写入前被拒绝；kprobe fallback 是否可用不影响本断言。
        if (snapshot->support.captureMode == "tc" ||
            snapshot->support.degradedReason.find("refusing unsafe replacement") ==
                std::string::npos) {
            fail("foreign TC slot was not rejected before mutation: " +
                 snapshot->support.degradedReason);
        }
        std::cout << "tc_ownership_probe: EXPECTED_REJECT reason="
                  << snapshot->support.degradedReason << '\n';
        return EXIT_SUCCESS;
    }

    if (expectation != "expect-tc" || argc != 7) {
        fail("expect-tc requires READY and RELEASE file paths");
    }
    if (!initialized || snapshot->support.captureMode != "tc" ||
        !snapshot->support.tcIngressAttached || !snapshot->support.tcEgressAttached) {
        fail("expected complete TC attachment: " + snapshot->support.degradedReason);
    }

    // close() 后才算 ready，避免 Shell 看见文件时用户态状态尚未完成提交。
    {
        std::ofstream ready(argv[5], std::ios::out | std::ios::trunc);
        if (!ready) fail("cannot create TC ownership ready file");
        ready << "ready\n";
        if (!ready) fail("cannot publish TC ownership ready state");
    }

    // 最多等待 15 秒，既给 Shell 足够时间做外部 replace，也避免失败场景留下悬挂进程。
    for (int attempt = 0; attempt < 300; ++attempt) {
        if (access(argv[6], F_OK) == 0) {
            std::cout << "tc_ownership_probe: READY_AND_RELEASED\n";
            return EXIT_SUCCESS;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    fail("timed out waiting for TC ownership release file");
}

}  // namespace

// 在已由 Shell 建好的隔离网络中附加真实 TC/eBPF，执行保护流与短流压力的完整生命周期。
int main(int argc, char** argv) {
    if (argc >= 2 && std::string(argv[1]) == "--tc-ownership-probe") {
        return runTcOwnershipProbe(argc, argv);
    }
    if (argc < 5) {
        fail("usage: traffic_kernel_integration IFACE PEER_IPV4 PROTECTED_PORT BPF_OBJECT "
             "[--profile smoke|standard|stress --output PATH]");
    }
    const KernelBenchmarkOptions benchmarkOptions = parseBenchmarkOptions(argc, argv);
    const KernelLoadProfile load = kernelLoadProfile(benchmarkOptions.profile);
    const std::string startedAt = bench::iso8601NowUtc();
    const auto suiteBegin = bench::SteadyClock::now();
    const std::string iface = argv[1];
    const std::string peerAddress = argv[2];
    const uint16_t protectedPort = static_cast<uint16_t>(std::strtoul(argv[3], nullptr, 10));

    auto analyzer = NetTrafficAnalyzer::getInstance();
    // 指向刚构建的真实 BPF object，并在 client veth 上同时初始化 TC ingress/egress。
    analyzer->setBpfObjectPath(argv[4]);
    if (!analyzer->initForInterface(iface)) {
        fail("full TC initialization failed: " + analyzer->getLatestSnapshot()->support.degradedReason);
    }

    // 先建立一条长寿命 TCP 作为保护对象，再用大量 UDP 短流挤压 LRU。
    const int protectedSocket = connectProtectedSocket(endpoint(peerAddress, protectedPort));
    const auto lifecycleBegin = bench::SteadyClock::now();
    const auto baseline = analyzer->refreshSnapshot();
    if (!baseline->support.captureComplete || baseline->support.captureCompleteness != "full") {
        fail("integration requires complete TC ingress+egress capture");
    }

    sendAll(protectedSocket, 1024);
    std::this_thread::sleep_for(std::chrono::seconds(1));
    const auto warm = analyzer->refreshSnapshot();
    if (!warm->mapReadComplete) fail("warm map sample was incomplete");
    if (warm->mapObservability.protectedEntries == 0) fail("protected TCP was not promoted");

    uint64_t shortFlows = 0;
    std::uint64_t flowDuration = 0;
    std::vector<std::uint64_t> snapshotRefreshDurations;
    snapshotRefreshDurations.reserve(load.waves);
    TrafficSnapshotPtr pressure;
    const std::uint64_t expectedPerWave =
        static_cast<std::uint64_t>(load.sources_per_wave) *
        static_cast<std::uint64_t>(load.destinations_per_source);
    // 分波制造压力并立即 refresh：既得到每波读取延迟，也能在过程中发现保护项提前消失。
    for (std::uint32_t wave = 0; wave < load.waves; ++wave) {
        const auto flowBegin = bench::SteadyClock::now();
        const std::uint64_t generated = generateShortUdpFlows(
            peerAddress, static_cast<int>(wave) * load.sources_per_wave,
            load.sources_per_wave, load.destinations_per_source, load.sender_threads);
        flowDuration += bench::elapsedNs(flowBegin, bench::SteadyClock::now());
        if (generated != expectedPerWave) fail("UDP pressure wave generated an unexpected flow count");
        shortFlows += generated;

        // 最后一轮在 refresh 前推动保护流 counter，最终 snapshot 必须同时证明压力存活和小增量。
        if (wave + 1U == load.waves) {
            sendAll(protectedSocket, 4096);
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
        const auto refreshBegin = bench::SteadyClock::now();
        pressure = analyzer->refreshSnapshot();
        snapshotRefreshDurations.push_back(
            bench::elapsedNs(refreshBegin, bench::SteadyClock::now()));
        if (!pressure->mapReadComplete) fail("pressure wave map sample was incomplete");
        if (pressure->mapObservability.protectedEntries == 0) {
            fail("protected entry disappeared during a pressure wave");
        }
    }
    // 数量门禁保证本次确实进入容量压力，而不是因生成器退化得到一个“空跑通过”。
    if (shortFlows <= FLOW_LRU_MAX_ENTRIES) fail("harness did not exceed LRU capacity");
    if (benchmarkOptions.profile == "stress" && shortFlows <= kTombstoneGateEntries) {
        fail("stress profile did not cross the bounded tombstone gate");
    }
    if (pressure->mapObservability.lruEntries < FLOW_LRU_MAX_ENTRIES - 1024) {
        fail("LRU map did not reach expected pressure");
    }

    // 高压后同时检查数值合理性和受保护 TCP 的小增量，防止无符号回退伪造超大速率。
    bool protectedRateObserved = false;
    for (const auto& flow : pressure->flows) {
        if (flow.bps > UINT64_C(1000000000000000)) fail("impossible rate suggests unsigned underflow");
        if (flow.protectedFlow && flow.proto == "TCP" && flow.dport == protectedPort && flow.bps > 0) {
            protectedRateObserved = true;
        }
    }
    if (!protectedRateObserved) fail("protected TCP delta was not observed after pressure");

    // 主动关闭保护 socket 后再次采样，要求 close event 出现且 protected map 条目被清除。
    shutdown(protectedSocket, SHUT_RDWR);
    close(protectedSocket);
    std::this_thread::sleep_for(std::chrono::seconds(2));
    const auto closed = analyzer->refreshSnapshot();
    if (!closed->mapReadComplete) fail("close lifecycle sample was incomplete");
    if (!hasEvent(closed, FLOW_EVENT_PROTECTED_CLOSED)) fail("protected close event was not emitted");
    if (closed->mapObservability.protectedEntries != 0) fail("protected map entry survived socket close");

    const std::uint64_t lifecycleDuration =
        bench::elapsedNs(lifecycleBegin, bench::SteadyClock::now());
    const std::uint64_t totalDuration =
        bench::elapsedNs(suiteBegin, bench::SteadyClock::now());
    if (!benchmarkOptions.output.empty()) {
        const std::string json = renderKernelBenchmark(
            benchmarkOptions, load, startedAt, totalDuration, flowDuration,
            snapshotRefreshDurations, lifecycleDuration, shortFlows, pressure);
        std::string outputError;
        if (!bench::writeJsonAtomically(benchmarkOptions.output, json, outputError)) {
            fail("cannot write benchmark JSON: " + outputError);
        }
    }

    std::cout << "traffic_kernel_integration: PASS short_flows=" << shortFlows
              << " sender_threads=" << load.sender_threads
              << " waves=" << load.waves
              << " lru_entries=" << pressure->mapObservability.lruEntries
              << " flow_duration_ms=" << std::fixed << std::setprecision(3)
              << static_cast<double>(flowDuration) / 1000000.0
              << " flows_per_second="
              << (flowDuration == 0 ? 0.0 :
                  static_cast<double>(shortFlows) * 1000000000.0 /
                      static_cast<double>(flowDuration));
    if (!benchmarkOptions.output.empty()) {
        std::cout << " output=" << benchmarkOptions.output;
    }
    std::cout << '\n';
    return EXIT_SUCCESS;
}
