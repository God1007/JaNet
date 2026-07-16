// 综合网络质量评估器：把 RTT、TCP 重传率代理值、RSSI 和流量特征转换为统一分数与问题列表。
// 同时维护上一轮结果，用等级或显著分差识别质量变化。

#include "network_quality_assessor.hpp"
#include "logger.hpp"
#include "rtt_utils.hpp"
#include <sstream>
#include <algorithm>
#include <cmath>
#include <iomanip>

namespace weaknet_grpc {

namespace {

constexpr double kRttMinimumScore = 20.0;
constexpr double kTcpMinimumScore = 10.0;
constexpr double kRssiMinimumScore = 10.0;
constexpr double kUnavailableMetricScore = 50.0;

// 在两个业务锚点之间做有界线性插值；区间外夹紧到端点，避免异常值把总分推出 0..100。
double interpolateScore(double value,
                        double leftValue,
                        double leftScore,
                        double rightValue,
                        double rightScore) {
    if (!std::isfinite(value) || !std::isfinite(leftValue) || !std::isfinite(rightValue)
        || rightValue <= leftValue) {
        return leftScore;
    }
    const double ratio = std::clamp(
        (value - leftValue) / (rightValue - leftValue), 0.0, 1.0);
    return leftScore + (rightScore - leftScore) * ratio;
}

bool isTrafficMetricAvailable(const NetInfo& interface) {
    // 0 flow 既可能是真实空闲，也可能是采集链路暂无样本；两种情况都不能证明网络好坏。
    return interface.trafficActiveFlows() > 0
        && interface.trafficTotalBps() > 0
        && interface.trafficTotalPps() > 0;
}

NetworkQualityLevel levelForScore(double score) {
    if (score >= 90.0) return NetworkQualityLevel::EXCELLENT;
    if (score >= 75.0) return NetworkQualityLevel::GOOD;
    if (score >= 50.0) return NetworkQualityLevel::FAIR;
    return NetworkQualityLevel::POOR;
}

}  // namespace

// 初始化变化检测基线，首次有效评估会与 UNKNOWN 状态比较。
NetworkQualityAssessor::NetworkQualityAssessor()
    : qualityChangeCounter_(0) {
    lastResult_.level = NetworkQualityLevel::UNKNOWN;
    lastResult_.score = 0.0;
}

// 从接口快照选择当前活动接口并完成一次综合评估；空列表返回 UNKNOWN。
NetworkQualityResult NetworkQualityAssessor::assessQuality(const std::vector<NetInfo>& interfaces) {
    if (interfaces.empty()) {
        NetworkQualityResult result;
        result.level = NetworkQualityLevel::UNKNOWN;
        result.levelName = "UNKNOWN";
        result.score = 0.0;
        result.details = "{\"error\":\"No interfaces available\"}";
        result.issues.push_back("No network interfaces detected");
        return result;
    }

    // 查找当前正在使用的网络接口
    const NetInfo* activeInterface = nullptr;
    for (const auto& iface : interfaces) {
        if (iface.usingNow()) {
            activeInterface = &iface;
            break;
        }
    }

    // 如果没有找到活动接口，则回退到第一个接口
    if (!activeInterface) {
        activeInterface = &interfaces[0];
    }

    return assessInterfaceQuality(*activeInterface);
}

// 计算单接口各指标子分、加权总分、等级和诊断详情。
NetworkQualityResult NetworkQualityAssessor::assessInterfaceQuality(const NetInfo& interface) {
    NetworkQualityResult result;

    // 各项子分都是连续值；缺失项使用中性 50 分，并由 typed Snapshot 标记 degraded。
    const double rttScore = calculateRttScore(interface.rttMs());
    const double tcpLossScore = calculateTcpLossScore(interface.tcpLossRate());
    const double rssiScore = calculateRssiScore(interface.rssiDbm());
    const double trafficScore = calculateTrafficScore(interface);

    // 权重保持 30/30/20/20，避免模型升级同时改变历史业务口径。
    const double totalScore = rttScore * 0.3 + tcpLossScore * 0.3
        + rssiScore * 0.2 + trafficScore * 0.2;

    // 等级边界保持 90/75/50 不变；只把各指标子分从阶梯改成连续曲线。
    result.level = levelForScore(totalScore);

    result.levelName = getQualityLevelName(result.level);
    result.score = totalScore;

    // 检测具体的网络问题
    result.issues = detectNetworkIssues(interface, totalScore);

    // 生成详细的网络质量信息
    result.details = generateQualityDetails(interface, totalScore, result.issues);

    // 检查网络质量是否发生变化
    if (hasQualityChanged(result)) {
        qualityChangeCounter_++;
        LOG_INFO(LogModule::WEAK_MGR, "网络质量发生变化: " << result.levelName
            << " (分数: " << std::fixed << std::setprecision(1) << result.score
            << ", 接口: " << interface.ifName() << ")");
    }

    lastResult_ = result;
    return result;
}

// 将质量枚举转换为稳定的对外文本名称。
std::string NetworkQualityAssessor::getQualityLevelName(NetworkQualityLevel level) {
    switch (level) {
        case NetworkQualityLevel::EXCELLENT: return "EXCELLENT";
        case NetworkQualityLevel::GOOD: return "GOOD";
        case NetworkQualityLevel::FAIR: return "FAIR";
        case NetworkQualityLevel::POOR: return "POOR";
        case NetworkQualityLevel::UNKNOWN:
        default: return "UNKNOWN";
    }
}

// 统一通过 JSON 生成器输出质量详情，保持 RPC 与事件字段格式一致。
std::string NetworkQualityAssessor::generateQualityDetails(const NetInfo& interface, double score, const std::vector<std::string>& issues) {
    return generateMetricsJson(interface, score, issues);
}

// 等级变化或同等级分差超过 10 分时认定为有效变化，过滤轻微抖动。
bool NetworkQualityAssessor::hasQualityChanged(const NetworkQualityResult& current) {
    return (current.level != lastResult_.level) ||
           (std::abs(current.score - lastResult_.score) > 10.0);  // 分数变化超过 10 分时视为质量发生变化
}

// 整体替换一组评估阈值，避免逐字段更新造成配置含义不一致。
void NetworkQualityAssessor::updateThresholds(const QualityThresholds& newThresholds) {
    thresholds_ = newThresholds;
    LOG_INFO(LogModule::WEAK_MGR, "网络质量评估阈值已更新");
}

// RTT 使用保留原有业务锚点的分段线性映射，消除阈值右侧瞬间跳 20 分的问题。
double NetworkQualityAssessor::calculateRttScore(double rttMs) {
    // 0ms 和亚毫秒 RTT 都是有效且优秀的测量；只有负值/非有限值代表不可用。
    if (!isRttAvailable(rttMs)) return kUnavailableMetricScore;

    if (rttMs <= thresholds_.rtt_excellent) return 100.0;
    if (rttMs <= thresholds_.rtt_good) {
        return interpolateScore(rttMs, thresholds_.rtt_excellent, 100.0,
                                thresholds_.rtt_good, 80.0);
    }
    if (rttMs <= thresholds_.rtt_fair) {
        return interpolateScore(rttMs, thresholds_.rtt_good, 80.0,
                                thresholds_.rtt_fair, 60.0);
    }

    // 保留旧模型 0.5 分/ms 的尾段和 20 分下限，同时从 fair 锚点连续衔接。
    const double floorAtMs = thresholds_.rtt_fair + (60.0 - kRttMinimumScore) / 0.5;
    return interpolateScore(rttMs, thresholds_.rtt_fair, 60.0,
                            floorAtMs, kRttMinimumScore);
}

// TCP 重传代理值同样在三个业务阈值之间连续插值，并保留旧尾段斜率。
double NetworkQualityAssessor::calculateTcpLossScore(double lossRate) {
    if (!isTcpRetransmissionAvailable(lossRate)) return kUnavailableMetricScore;

    if (lossRate <= thresholds_.tcp_loss_excellent) return 100.0;
    if (lossRate <= thresholds_.tcp_loss_good) {
        return interpolateScore(lossRate, thresholds_.tcp_loss_excellent, 100.0,
                                thresholds_.tcp_loss_good, 80.0);
    }
    if (lossRate <= thresholds_.tcp_loss_fair) {
        return interpolateScore(lossRate, thresholds_.tcp_loss_good, 80.0,
                                thresholds_.tcp_loss_fair, 60.0);
    }

    const double floorAtRate = thresholds_.tcp_loss_fair
        + (60.0 - kTcpMinimumScore) / 20.0;
    return interpolateScore(lossRate, thresholds_.tcp_loss_fair, 60.0,
                            floorAtRate, kTcpMinimumScore);
}

// RSSI 越接近 0 越好；-50/-60/-70dBm 仍对应 100/80/60，但区间内不再整档跳变。
double NetworkQualityAssessor::calculateRssiScore(int rssiDbm) {
    if (!isRssiAvailable(rssiDbm)) return kUnavailableMetricScore;

    if (rssiDbm >= thresholds_.rssi_excellent) return 100.0;
    if (rssiDbm >= thresholds_.rssi_good) {
        return interpolateScore(rssiDbm, thresholds_.rssi_good, 80.0,
                                thresholds_.rssi_excellent, 100.0);
    }
    if (rssiDbm >= thresholds_.rssi_fair) {
        return interpolateScore(rssiDbm, thresholds_.rssi_fair, 60.0,
                                thresholds_.rssi_good, 80.0);
    }

    const double floorAtDbm = thresholds_.rssi_fair
        - (60.0 - kRssiMinimumScore) / 2.0;
    return interpolateScore(rssiDbm, floorAtDbm, kRssiMinimumScore,
                            thresholds_.rssi_fair, 60.0);
}

// 流量侧只作为弱证据：包大小贡献在 200..1000B 线性变化，样本量在 0..minFlows 平滑增信。
double NetworkQualityAssessor::calculateTrafficScore(const NetInfo& interface) {
    if (!isTrafficMetricAvailable(interface)) return kUnavailableMetricScore;

    const double activeFlows = static_cast<double>(interface.trafficActiveFlows());
    const double requiredFlows = std::max(1, thresholds_.min_flows_for_analysis);
    const double sampleConfidence = std::clamp(activeFlows / requiredFlows, 0.0, 1.0);
    const double bps = static_cast<double>(interface.trafficTotalBps());
    const double pps = static_cast<double>(interface.trafficTotalPps());
    const double averagePacketSize = bps / pps;
    const double packetEvidence = interpolateScore(
        averagePacketSize, 200.0, -50.0, 1000.0, 50.0);

    // 置信度越高，正/负证据才越远离中性 50 分；负证据不能反向变成奖励。
    return std::clamp(50.0 + sampleConfidence * packetEvidence, 0.0, 100.0);
}

// 根据原始指标阈值生成可读问题列表，便于上层直接展示或交给 AI 分析。
std::vector<std::string> NetworkQualityAssessor::detectNetworkIssues(const NetInfo& interface, double score) {
    std::vector<std::string> issues;

    // 检测 RTT 问题
    if (isRttAvailable(interface.rttMs()) && interface.rttMs() > thresholds_.rtt_fair) {
        issues.push_back("High latency: " + formatRttMilliseconds(interface.rttMs()) + "ms");
    }

    // 根据项目字段 tcp_loss_rate 检测 TCP 重传代理指标问题。
    if (isTcpRetransmissionAvailable(interface.tcpLossRate())
        && interface.tcpLossRate() > thresholds_.tcp_loss_fair) {
        issues.push_back("High TCP retransmission proxy: "
            + std::to_string(interface.tcpLossRate()) + "%");
    }

    // 检测 RSSI 问题
    if (isRssiAvailable(interface.rssiDbm())
        && interface.rssiDbm() < thresholds_.rssi_fair) {
        issues.push_back("Weak signal: " + std::to_string(interface.rssiDbm()) + "dBm");
    }

    // 检测流量问题
    if (interface.trafficActiveFlows() > 0) {
        double bps = interface.trafficTotalBps();
        double pps = interface.trafficTotalPps();
        if (bps > 0 && pps > 0) {
            double avgPacketSize = bps / pps;
            if (avgPacketSize < 200) {
                issues.push_back("Small packet size: " + std::to_string(avgPacketSize) + " bytes");
            }
        }
    }

    // 评估整体网络质量。
    if (score < 30) {
        issues.push_back("Poor overall network quality");
    } else if (score < 50) {
        issues.push_back("Below average network quality");
    }

    return issues;
}

// 按固定字段顺序生成紧凑 JSON，包含原始指标、总分、状态和问题数组。
std::string NetworkQualityAssessor::generateMetricsJson(const NetInfo& interface, double score, const std::vector<std::string>& issues) {
    std::ostringstream json;
    json << "{";
    json << "\"interface\":\"" << interface.ifName() << "\",";
    json << "\"quality_score\":" << std::fixed << std::setprecision(1) << score << ",";
    json << "\"score_model\":\"piecewise_linear_v2\",";
    json << "\"metric_scores\":{";
    json << "\"rtt\":" << std::fixed << std::setprecision(1) << calculateRttScore(interface.rttMs()) << ",";
    json << "\"tcp_retransmission\":" << calculateTcpLossScore(interface.tcpLossRate()) << ",";
    json << "\"rssi\":" << calculateRssiScore(interface.rssiDbm()) << ",";
    json << "\"traffic\":" << calculateTrafficScore(interface) << "},";
    // quality_score 已把流设为 1 位小数，这里必须显式恢复 3 位精度，否则 0.134 会再次变成 0.1。
    // 非有限值不能直接写入 JSON；统一退回与领域模型一致的 -1 不可用哨兵。
    const double serializableRtt = isRttAvailable(interface.rttMs()) ? interface.rttMs() : -1.0;
    json << "\"rtt_ms\":" << std::fixed << std::setprecision(3) << serializableRtt << ",";
    const double serializableTcp = isTcpRetransmissionAvailable(interface.tcpLossRate())
        ? interface.tcpLossRate() : -1.0;
    json << "\"tcp_loss_rate\":" << std::fixed << std::setprecision(2) << serializableTcp << ",";
    json << "\"rssi_dbm\":" << interface.rssiDbm() << ",";
    json << "\"traffic_bps\":" << interface.trafficTotalBps() << ",";
    json << "\"traffic_pps\":" << interface.trafficTotalPps() << ",";
    json << "\"active_flows\":" << interface.trafficActiveFlows() << ",";
    // 保留旧 JSON 字段语义：quality_level 始终是 RTT 派生的 LinkQuality 数值。
    json << "\"quality_level\":" << static_cast<int>(interface.quality()) << ",";
    json << "\"using_now\":" << (interface.usingNow() ? "true" : "false") << ",";
    json << "\"issues\":[";

    for (size_t i = 0; i < issues.size(); ++i) {
        if (i > 0) json << ",";
        json << "\"" << issues[i] << "\"";
    }

    json << "]}";
    return json.str();
}

} // namespace weaknet_grpc
