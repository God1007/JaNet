// 综合质量评分回归：锁定分段线性锚点、连续性、缺失哨兵和 30/30/20/20 权重。
// 测试只构造 NetInfo，不访问真实网络、eBPF 或 gRPC，可在 macOS 与 Linux 上确定运行。

#include "net_info.hpp"
#include "network_quality_assessor.hpp"

#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <limits>
#include <string>

#include <glog/logging.h>

#define TEST_CHECK(condition) do { \
    if (!(condition)) { \
        std::cerr << "TEST_CHECK failed at " << __FILE__ << ':' << __LINE__ \
                  << ": " #condition "\n"; \
        return EXIT_FAILURE; \
    } \
} while (false)

namespace {

constexpr double kTolerance = 1e-9;

bool nearlyEqual(double lhs, double rhs) {
    return std::abs(lhs - rhs) <= kTolerance;
}

weaknet_grpc::NetInfo makePerfectInterface() {
    weaknet_grpc::NetInfo net("eth0");
    net.setUsingNow(true);
    net.setState(weaknet_grpc::NetState::Up);
    net.setQuality(weaknet_grpc::LinkQuality::Fair);
    net.setRttMs(0.0);
    net.setPrevRttMs(0.0);
    net.setTcpLossRate(0.0);
    net.setRssiDbm(-50);
    // 5 个流、平均包大小 1000B 对应新的 traffic 100 分锚点。
    net.setTrafficStats(5000, 5, 5);
    return net;
}

weaknet_grpc::NetworkQualityResult assess(const weaknet_grpc::NetInfo& net) {
    weaknet_grpc::NetworkQualityAssessor assessor;
    return assessor.assessInterfaceQuality(net);
}

// 其余三项保持 100 分，从加权总分反推出目标子分。
double rttSubscore(double value) {
    auto net = makePerfectInterface();
    net.setRttMs(value);
    return (assess(net).score - 70.0) / 0.3;
}

double tcpSubscore(double value) {
    auto net = makePerfectInterface();
    net.setTcpLossRate(value);
    return (assess(net).score - 70.0) / 0.3;
}

double rssiSubscore(int value) {
    auto net = makePerfectInterface();
    net.setRssiDbm(value);
    return (assess(net).score - 80.0) / 0.2;
}

double trafficSubscore(std::uint64_t bps, std::uint64_t pps, std::uint32_t flows) {
    auto net = makePerfectInterface();
    net.setTrafficStats(bps, pps, flows);
    return (assess(net).score - 80.0) / 0.2;
}

bool hasIssueContaining(const weaknet_grpc::NetworkQualityResult& result,
                        const std::string& token) {
    for (const auto& issue : result.issues) {
        if (issue.find(token) != std::string::npos) return true;
    }
    return false;
}

}  // namespace

int main(int argc, char* argv[]) {
    google::InitGoogleLogging(argc > 0 ? argv[0] : "network_quality_assessor_test");
    FLAGS_logtostderr = true;

    // 评分器与 typed Snapshot 共用同一组可用性谓词。
    TEST_CHECK(!weaknet_grpc::isRssiAvailable(-1000));
    TEST_CHECK(!weaknet_grpc::isRssiAvailable(0));
    TEST_CHECK(weaknet_grpc::isRssiAvailable(-65));
    TEST_CHECK(!weaknet_grpc::isTcpRetransmissionAvailable(-1.0));
    TEST_CHECK(!weaknet_grpc::isTcpRetransmissionAvailable(
        std::numeric_limits<double>::quiet_NaN()));
    TEST_CHECK(weaknet_grpc::isTcpRetransmissionAvailable(0.0));

    // RTT: 50/100/200ms 仍是 100/80/60 分锚点，区间中点必须精确线性。
    TEST_CHECK(nearlyEqual(rttSubscore(50.0), 100.0));
    TEST_CHECK(nearlyEqual(rttSubscore(75.0), 90.0));
    TEST_CHECK(nearlyEqual(rttSubscore(100.0), 80.0));
    TEST_CHECK(nearlyEqual(rttSubscore(150.0), 70.0));
    TEST_CHECK(nearlyEqual(rttSubscore(200.0), 60.0));
    TEST_CHECK(nearlyEqual(rttSubscore(240.0), 40.0));
    TEST_CHECK(nearlyEqual(rttSubscore(280.0), 20.0));

    // TCP 重传代理：每个旧阈值保留原分值，阈值之间不再发生整档跳变。
    TEST_CHECK(nearlyEqual(tcpSubscore(0.1), 100.0));
    TEST_CHECK(nearlyEqual(tcpSubscore(0.1 + 1e-6), 100.0 - 50.0e-6));
    TEST_CHECK(nearlyEqual(tcpSubscore(0.3), 90.0));
    TEST_CHECK(nearlyEqual(tcpSubscore(0.5), 80.0));
    TEST_CHECK(nearlyEqual(tcpSubscore(0.5 + 1e-6), 80.0 - (20.0 / 1.5) * 1e-6));
    TEST_CHECK(nearlyEqual(tcpSubscore(1.25), 70.0));
    TEST_CHECK(nearlyEqual(tcpSubscore(2.0), 60.0));
    TEST_CHECK(nearlyEqual(tcpSubscore(3.25), 35.0));
    TEST_CHECK(nearlyEqual(tcpSubscore(4.5), 10.0));

    // RSSI: 信号每下降 5dBm 都产生可解释的连续变化，-95dBm 后封底 10 分。
    TEST_CHECK(nearlyEqual(rssiSubscore(-50), 100.0));
    TEST_CHECK(nearlyEqual(rssiSubscore(-51), 98.0));
    TEST_CHECK(nearlyEqual(rssiSubscore(-55), 90.0));
    TEST_CHECK(nearlyEqual(rssiSubscore(-60), 80.0));
    TEST_CHECK(nearlyEqual(rssiSubscore(-61), 78.0));
    TEST_CHECK(nearlyEqual(rssiSubscore(-65), 70.0));
    TEST_CHECK(nearlyEqual(rssiSubscore(-70), 60.0));
    TEST_CHECK(nearlyEqual(rssiSubscore(-80), 40.0));
    TEST_CHECK(nearlyEqual(rssiSubscore(-95), 10.0));

    // Traffic 证据围绕 50 分双向变化；样本越多，正/负证据才越充分。
    TEST_CHECK(nearlyEqual(trafficSubscore(0, 0, 0), 50.0));
    TEST_CHECK(nearlyEqual(trafficSubscore(1000, 1, 1), 60.0));
    TEST_CHECK(nearlyEqual(trafficSubscore(1800, 3, 3), 50.0));
    TEST_CHECK(nearlyEqual(trafficSubscore(1000, 5, 5), 0.0));
    TEST_CHECK(nearlyEqual(trafficSubscore(3000, 5, 5), 50.0));
    TEST_CHECK(nearlyEqual(trafficSubscore(5000, 5, 5), 100.0));
    auto noTraffic = makePerfectInterface();
    noTraffic.setTrafficStats(0, 0, 0);
    auto smallPacketTraffic = makePerfectInterface();
    smallPacketTraffic.setTrafficStats(995, 5, 5);
    TEST_CHECK(assess(smallPacketTraffic).score < assess(noTraffic).score);
    TEST_CHECK(hasIssueContaining(assess(smallPacketTraffic), "Small packet size"));

    // -1000 是真实 RSSI 缺失哨兵，必须按中性未知处理，也不能产生虚假的弱信号告警。
    auto missingRssi = makePerfectInterface();
    missingRssi.setRssiDbm(-1000);
    const auto missingRssiResult = assess(missingRssi);
    TEST_CHECK(nearlyEqual(rssiSubscore(-1000), 50.0));
    TEST_CHECK(nearlyEqual(missingRssiResult.score, 90.0));
    TEST_CHECK(!hasIssueContaining(missingRssiResult, "Weak signal"));
    auto legacyMissingRssi = makePerfectInterface();
    legacyMissingRssi.setRssiDbm(0);
    TEST_CHECK(nearlyEqual(rssiSubscore(0), 50.0));
    TEST_CHECK(!hasIssueContaining(assess(legacyMissingRssi), "Weak signal"));

    // TCP 非有限值不能进入线性公式或生成非法 JSON token。
    auto invalidTcp = makePerfectInterface();
    invalidTcp.setTcpLossRate(std::numeric_limits<double>::quiet_NaN());
    const auto invalidTcpResult = assess(invalidTcp);
    TEST_CHECK(nearlyEqual(tcpSubscore(std::numeric_limits<double>::quiet_NaN()), 50.0));
    TEST_CHECK(invalidTcpResult.details.find("nan") == std::string::npos);
    TEST_CHECK(invalidTcpResult.details.find("\"tcp_loss_rate\":-1.00") != std::string::npos);
    TEST_CHECK(nearlyEqual(tcpSubscore(-1.0), 50.0));
    TEST_CHECK(nearlyEqual(tcpSubscore(std::numeric_limits<double>::infinity()), 50.0));

    // 用不同子分锁定 30/30/20/20 权重，并确保详情能说明当前评分模型。
    auto mixed = makePerfectInterface();
    mixed.setRttMs(75.0);       // 90
    mixed.setTcpLossRate(0.3);  // 90
    mixed.setRssiDbm(-65);      // 70
    mixed.setTrafficStats(3000, 5, 5); // 50
    const auto mixedResult = assess(mixed);
    TEST_CHECK(nearlyEqual(mixedResult.score, 78.0));
    TEST_CHECK(mixedResult.level == weaknet_grpc::NetworkQualityLevel::GOOD);
    TEST_CHECK(mixedResult.details.find("\"score_model\":\"piecewise_linear_v2\"") != std::string::npos);
    TEST_CHECK(mixedResult.details.find("\"metric_scores\"") != std::string::npos);
    // 旧字段仍输出 LinkQuality::Fair(2)，不得改成内部综合评级枚举。
    TEST_CHECK(mixedResult.details.find("\"quality_level\":2") != std::string::npos);

    google::ShutdownGoogleLogging();
    std::cout << "network_quality_assessor_test: all checks passed\n";
    return EXIT_SUCCESS;
}
