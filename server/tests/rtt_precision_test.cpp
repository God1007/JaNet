// RTT 精度与质量语义回归测试：确保亚毫秒值不会在领域对象或评分阶段退化成整数零。
// 本测试不发真实 ICMP 包，因而不依赖 root、网络状态或 Linux；它只验证确定性的业务语义。

#include "net_info.hpp"
#include "network_quality_assessor.hpp"
#include "rtt_utils.hpp"

#include <cmath>
#include <cstdlib>
#include <iostream>
#include <limits>
#include <type_traits>
#include <utility>

#include <glog/logging.h>

#define TEST_CHECK(condition) do { \
    if (!(condition)) { \
        std::cerr << "TEST_CHECK failed at " << __FILE__ << ':' << __LINE__ << ": " #condition "\n"; \
        return EXIT_FAILURE; \
    } \
} while (false)

namespace {

constexpr double kTolerance = 1e-12;
constexpr double kBoundaryEpsilon = 0.001;
constexpr double kControlledNonRttWeightedScore = 70.0;
constexpr double kRttWeight = 0.3;

// 固定非 RTT 指标为满分，使评估结果的差异只可能来自 RTT 可用性语义。
weaknet_grpc::NetInfo makeControlledInterface(double rttMs) {
    weaknet_grpc::NetInfo net("eth0");
    net.setUsingNow(true);
    net.setState(weaknet_grpc::NetState::Up);
    net.setRttMs(rttMs);
    net.setPrevRttMs(rttMs);
    net.setTcpLossRate(0.0);
    net.setRssiDbm(-50);
    // 5 个流、平均包长 1200 bytes，使 traffic 子分稳定为 100。
    net.setTrafficStats(6000, 5, 5);
    return net;
}

// 每个样本使用独立评估器，避免 lastResult_ 的变化计数影响测试阅读与失败定位。
weaknet_grpc::NetworkQualityResult assess(double rttMs) {
    weaknet_grpc::NetworkQualityAssessor assessor;
    return assessor.assessInterfaceQuality(makeControlledInterface(rttMs));
}

// 受控样本的 TCP/RSSI/traffic 均为 100 分，因此可从综合分精确反推出 RTT 子分。
double rttSubscore(double rttMs) {
    return (assess(rttMs).score - kControlledNonRttWeightedScore) / kRttWeight;
}

bool nearlyEqual(double lhs, double rhs) {
    return std::abs(lhs - rhs) <= kTolerance;
}

}  // namespace

int main(int argc, char* argv[]) {
    // 类型门禁比数值断言更早暴露回退：RTT getter 必须在整个领域模型中保持 double。
    static_assert(std::is_same_v<
        decltype(std::declval<const weaknet_grpc::NetInfo&>().rttMs()), double>);
    static_assert(std::is_same_v<
        decltype(std::declval<const weaknet_grpc::NetInfo&>().prevRttMs()), double>);

    google::InitGoogleLogging(argc > 0 ? argv[0] : "rtt_precision_test");
    FLAGS_logtostderr = true;

    // 0.134 ms 必须原样写入和读出；若存储层仍是 int，这里会被截断成 0。
    const auto subMillisecond = makeControlledInterface(0.134);
    TEST_CHECK(nearlyEqual(subMillisecond.rttMs(), 0.134));
    TEST_CHECK(nearlyEqual(subMillisecond.prevRttMs(), 0.134));

    // availability 只接受有限非负数；NaN/Infinity 也不能穿透成“有效 RTT”。
    TEST_CHECK(weaknet_grpc::isRttAvailable(0.134));
    TEST_CHECK(weaknet_grpc::isRttAvailable(0.0));
    TEST_CHECK(!weaknet_grpc::isRttAvailable(-1.0));
    TEST_CHECK(!weaknet_grpc::isRttAvailable(std::numeric_limits<double>::quiet_NaN()));
    TEST_CHECK(!weaknet_grpc::isRttAvailable(std::numeric_limits<double>::infinity()));

    // 旧 int32 协议继续兼容，但成功的亚毫秒样本至少写 1，不能退化成含糊的默认零。
    TEST_CHECK(weaknet_grpc::toLegacyRttMilliseconds(0.134) == 1);
    TEST_CHECK(weaknet_grpc::toLegacyRttMilliseconds(0.0) == 1);
    TEST_CHECK(weaknet_grpc::toLegacyRttMilliseconds(1.6) == 2);
    TEST_CHECK(weaknet_grpc::toLegacyRttMilliseconds(-1.0) == -1);
    TEST_CHECK(weaknet_grpc::toLegacyPingMilliseconds(-5.0) == -5);

    // 展示文本最多保留三位小数，同时去掉整数和有限小数末尾的冗余零。
    TEST_CHECK(weaknet_grpc::formatRttMilliseconds(0.134) == "0.134");
    TEST_CHECK(weaknet_grpc::formatRttMilliseconds(10.0) == "10");
    TEST_CHECK(weaknet_grpc::formatRttMilliseconds(10.5) == "10.5");

    // 0 ms 是成功测量的合法边界值；只有负值才表示失败或尚未采样。
    const auto subMillisecondResult = assess(0.134);
    const auto zeroResult = assess(0.0);
    const auto unavailableResult = assess(-1.0);
    TEST_CHECK(nearlyEqual(subMillisecondResult.score, 100.0));
    TEST_CHECK(nearlyEqual(zeroResult.score, subMillisecondResult.score));
    TEST_CHECK(nearlyEqual(unavailableResult.score, 85.0));
    TEST_CHECK(subMillisecondResult.score > unavailableResult.score);
    TEST_CHECK(zeroResult.score > unavailableResult.score);

    // 锁定三个分段阈值及其右侧极小增量；若中间任何一层退回 int，+epsilon 会落回左侧档位。
    TEST_CHECK(nearlyEqual(rttSubscore(50.0), 100.0));
    TEST_CHECK(nearlyEqual(rttSubscore(50.0 + kBoundaryEpsilon), 80.0));
    TEST_CHECK(nearlyEqual(rttSubscore(100.0), 80.0));
    TEST_CHECK(nearlyEqual(rttSubscore(100.0 + kBoundaryEpsilon), 60.0));
    TEST_CHECK(nearlyEqual(rttSubscore(200.0), 60.0));
    TEST_CHECK(nearlyEqual(
        rttSubscore(200.0 + kBoundaryEpsilon),
        60.0 - kBoundaryEpsilon * 0.5));

    // 质量详情也是对外数据面，不能被 score 的一位小数格式设置连带截断。
    TEST_CHECK(subMillisecondResult.details.find("\"rtt_ms\":0.134") != std::string::npos);

    google::ShutdownGoogleLogging();
    std::cout << "rtt_precision_test: all checks passed\n";
    return EXIT_SUCCESS;
}
