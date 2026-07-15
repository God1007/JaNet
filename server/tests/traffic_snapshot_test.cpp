// 无 libbpf 快照测试：验证 generation、动态 ifindex 与所有查询均为非阻塞快照读取。

#include "net_traffic.h"

#include <chrono>
#include <cstdlib>
#include <iostream>
#include <net/if.h>
#include <string>

#define CHECK(condition) do { \
    if (!(condition)) { \
        std::cerr << "CHECK failed at " << __FILE__ << ':' << __LINE__ << ": " #condition "\n"; \
        return EXIT_FAILURE; \
    } \
} while (false)

// 驱动接口重绑和连续 refresh，验证 baseline、generation 与查询延迟契约。
int main() {
    auto analyzer = NetTrafficAnalyzer::getInstance();
    const auto initial = analyzer->getLatestSnapshot();
    CHECK(initial);
    CHECK(initial->generation == 0);

    const char* loopback = if_nametoindex("lo") != 0 ? "lo" : "lo0";
    const uint32_t loopbackIndex = if_nametoindex(loopback);
    CHECK(loopbackIndex != 0);
    (void)analyzer->updateInterface(loopback);  // 无 libbpf 时预期返回 false，但目标 ifindex 仍明确可见。

    const auto first = analyzer->refreshSnapshot();
    const auto second = analyzer->refreshSnapshot();
    CHECK(first->generation == 1);
    CHECK(second->generation == 2);
    CHECK(first->baselineOnly);
    CHECK(!second->baselineOnly);
    CHECK(!analyzer->isBaselinePending());
    CHECK(second->boundIfindex == loopbackIndex);
    CHECK(second->windowEnd >= second->windowStart);
    CHECK(!second->support.ipv6ExtensionHeadersSupported);
    CHECK(!second->support.coverageLimitations.empty());
    CHECK(second->mapObservability.lruCapacity == FLOW_LRU_MAX_ENTRIES);
    CHECK(second->mapObservability.protectedCapacity == FLOW_PROTECTED_MAX_ENTRIES);

    // 找到第二个真实接口后验证 A->B->A 每次都强制 baseline-only，同接口更新则不重置。
    std::string alternate;
    struct if_nameindex* interfaces = if_nameindex();
    if (interfaces) {
        for (struct if_nameindex* item = interfaces;
             item->if_index != 0 && item->if_name != nullptr; ++item) {
            if (item->if_index != loopbackIndex) {
                alternate = item->if_name;
                break;
            }
        }
        if_freenameindex(interfaces);
    }
    if (!alternate.empty()) {
        (void)analyzer->updateInterface(alternate);
        CHECK(analyzer->isBaselinePending());
        CHECK(analyzer->refreshSnapshot()->baselineOnly);
        CHECK(!analyzer->refreshSnapshot()->baselineOnly);
        (void)analyzer->updateInterface(loopback);
        CHECK(analyzer->isBaselinePending());
        CHECK(analyzer->refreshSnapshot()->baselineOnly);
        (void)analyzer->updateInterface(loopback);
        CHECK(!analyzer->isBaselinePending());
        CHECK(!analyzer->refreshSnapshot()->baselineOnly);
    }

    const auto start = std::chrono::steady_clock::now();
    (void)analyzer->sampleTopFlows(60, 10);
    (void)analyzer->detectAnomalies(60);
    (void)analyzer->getRealTimeStats();
    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start);
    CHECK(elapsed < std::chrono::milliseconds(250));

    // 显式 snapshot 查询必须返回已固化的异常，不受后续全局 history 清理影响。
    auto frozen = std::make_shared<TrafficSnapshot>();
    frozen->generation = 99;
    TrafficAnomaly frozenAnomaly;
    frozenAnomaly.flowKey = "frozen-flow";
    frozenAnomaly.anomalyType = "high_volume";
    frozenAnomaly.severity = 0.75;
    frozen->anomalies.push_back(frozenAnomaly);
    const TrafficSnapshotPtr frozenSnapshot = frozen;
    const auto beforeClear = analyzer->detectAnomalies(frozenSnapshot);
    analyzer->clearHistory();
    const auto afterClear = analyzer->detectAnomalies(frozenSnapshot);
    CHECK(beforeClear.size() == 1);
    CHECK(afterClear.size() == 1);
    CHECK(afterClear.front().flowKey == "frozen-flow");
    CHECK(afterClear.front().severity == 0.75);

    std::cout << "traffic_snapshot_test: all checks passed (query_ms=" << elapsed.count() << ")\n";
    return EXIT_SUCCESS;
}
