// 无权限纯函数测试：拓扑刷新必须保留同名接口指标，同时正确处理新增和删除。

#include "interface_snapshot_merge.hpp"

#include <cstdlib>
#include <iostream>

#define CHECK(condition) do { \
    if (!(condition)) { \
        std::cerr << "CHECK failed at " << __FILE__ << ':' << __LINE__ << ": " #condition "\n"; \
        return EXIT_FAILURE; \
    } \
} while (false)

// 构造保留、新增、删除三类接口，验证拓扑字段与监控指标按职责合并。
int main() {
    weaknet_grpc::NetInfo eth("eth0");
    eth.setType(weaknet_grpc::NetType::Ethernet);
    eth.setState(weaknet_grpc::NetState::Down);
    eth.setRttMs(37);
    eth.setPrevRttMs(41);
    eth.setQuality(weaknet_grpc::LinkQuality::Good);
    eth.setRssiDbm(-55);
    eth.setTcpLossRate(0.25);
    eth.setTcpLossLevel("good");
    eth.setTrafficStats(123456, 789, 12);

    weaknet_grpc::NetInfo removed("wlan9");
    removed.setRttMs(99);

    weaknet_grpc::NetInfo observedEth("eth0");
    observedEth.setType(weaknet_grpc::NetType::Unknown);
    observedEth.setState(weaknet_grpc::NetState::Up);
    observedEth.setDefaultRoute(true);
    observedEth.setUsingNow(true);

    weaknet_grpc::NetInfo added("usb0");
    added.setState(weaknet_grpc::NetState::Up);

    const auto merged = weaknet_grpc::mergeTopologyPreservingMetrics(
        {eth, removed}, {observedEth, added});
    CHECK(merged.size() == 2);

    const auto& kept = merged[0];
    CHECK(kept.ifName() == "eth0");
    CHECK(kept.isDefaultRoute());
    CHECK(kept.usingNow());
    CHECK(kept.state() == weaknet_grpc::NetState::Down);
    CHECK(kept.type() == weaknet_grpc::NetType::Ethernet);
    CHECK(kept.rttMs() == 37);
    CHECK(kept.prevRttMs() == 41);
    CHECK(kept.quality() == weaknet_grpc::LinkQuality::Good);
    CHECK(kept.rssiDbm() == -55);
    CHECK(kept.tcpLossRate() == 0.25);
    CHECK(kept.tcpLossLevel() == "good");
    CHECK(kept.trafficTotalBps() == 123456);
    CHECK(kept.trafficTotalPps() == 789);
    CHECK(kept.trafficActiveFlows() == 12);

    CHECK(merged[1].ifName() == "usb0");
    CHECK(merged[1].rttMs() == -1);
    CHECK(merged[1].trafficTotalBps() == 0);
    for (const auto& item : merged) CHECK(item.ifName() != "wlan9");

    std::cout << "interface_snapshot_merge_test: all checks passed\n";
    return EXIT_SUCCESS;
}
