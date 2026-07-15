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

    // 计算各项网络指标得分
    double rttScore = calculateRttScore(interface.rttMs());
    double tcpLossScore = calculateTcpLossScore(interface.tcpLossRate());
    double rssiScore = calculateRssiScore(interface.rssiDbm());
    double trafficScore = calculateTrafficScore(interface);

    // 使用加权平均计算总分（权重可调整）
    double totalScore = (rttScore * 0.3 + tcpLossScore * 0.3 + rssiScore * 0.2 + trafficScore * 0.2);

    // 根据总分确定网络质量等级
    if (totalScore >= 90) {
        result.level = NetworkQualityLevel::EXCELLENT;
    } else if (totalScore >= 75) {
        result.level = NetworkQualityLevel::GOOD;
    } else if (totalScore >= 50) {
        result.level = NetworkQualityLevel::FAIR;
    } else {
        result.level = NetworkQualityLevel::POOR;
    }

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

// 按 RTT 分段评分，超过 fair 阈值后线性扣分并设置最低分。
double NetworkQualityAssessor::calculateRttScore(double rttMs) {
    // 0ms 和亚毫秒 RTT 都是有效且优秀的测量；只有负值/非有限值代表不可用。
    if (!isRttAvailable(rttMs)) return 50.0;

    if (rttMs <= thresholds_.rtt_excellent) return 100.0;
    if (rttMs <= thresholds_.rtt_good) return 80.0;
    if (rttMs <= thresholds_.rtt_fair) return 60.0;

    // 超过 fair 阈值后按比例递减
    double excess = rttMs - thresholds_.rtt_fair;
    double penalty = std::min(excess * 0.5, 40.0);  // 最多扣 40 分
    return std::max(20.0, 60.0 - penalty);
}

// 按 TCP 重传率分段评分，负值代表当前没有有效样本。
double NetworkQualityAssessor::calculateTcpLossScore(double lossRate) {
    if (lossRate < 0) return 50.0;  // 无法获得 TCP 重传代理值时给出中等分数

    if (lossRate <= thresholds_.tcp_loss_excellent) return 100.0;
    if (lossRate <= thresholds_.tcp_loss_good) return 80.0;
    if (lossRate <= thresholds_.tcp_loss_fair) return 60.0;

    // 超过 fair 阈值后按比例递减
    double excess = lossRate - thresholds_.tcp_loss_fair;
    double penalty = std::min(excess * 20.0, 50.0);  // 最多扣 50 分
    return std::max(10.0, 60.0 - penalty);
}

// 按 dBm 信号强度分段评分，越接近 0 表示信号越强。
double NetworkQualityAssessor::calculateRssiScore(int rssiDbm) {
    if (rssiDbm == 0) return 50.0;  // 无法测量 RSSI 时给出中等分数

    if (rssiDbm >= thresholds_.rssi_excellent) return 100.0;
    if (rssiDbm >= thresholds_.rssi_good) return 80.0;
    if (rssiDbm >= thresholds_.rssi_fair) return 60.0;

    // 低于 fair 阈值后按比例递减
    double deficit = thresholds_.rssi_fair - rssiDbm;
    double penalty = std::min(deficit * 2.0, 50.0);  // 最多扣 50 分
    return std::max(10.0, 60.0 - penalty);
}

// 用平均包大小和活跃流数量估算流量侧质量，并把结果限制在 0 到 100。
double NetworkQualityAssessor::calculateTrafficScore(const NetInfo& interface) {
    // 基于流量分析计算网络质量得分
    double score = 70.0;  // 基础分数

    // 检查流量特征是否异常
    if (interface.trafficActiveFlows() > 0) {
        // 存在活跃流量时，根据流量特征评分
        double bps = interface.trafficTotalBps();
        double pps = interface.trafficTotalPps();

        if (bps > 0 && pps > 0) {
            double avgPacketSize = bps / pps;
            if (avgPacketSize > 1000) {  // 平均包大小大于 1 KB，网络质量较好
                score += 20.0;
            } else if (avgPacketSize < 200) {  // 平均包较小，可能存在网络问题
                score -= 20.0;
            }
        }

        // 检查活跃流数量
        if (static_cast<int>(interface.trafficActiveFlows()) >= thresholds_.min_flows_for_analysis) {
            score += 10.0;  // 活跃流足够多，样本可用于质量分析
        }
    } else {
        score = 50.0;  // 没有活跃流量时给出中等分数
    }

    return std::max(0.0, std::min(100.0, score));
}

// 根据原始指标阈值生成可读问题列表，便于上层直接展示或交给 AI 分析。
std::vector<std::string> NetworkQualityAssessor::detectNetworkIssues(const NetInfo& interface, double score) {
    std::vector<std::string> issues;

    // 检测 RTT 问题
    if (isRttAvailable(interface.rttMs()) && interface.rttMs() > thresholds_.rtt_fair) {
        issues.push_back("High latency: " + formatRttMilliseconds(interface.rttMs()) + "ms");
    }

    // 根据项目字段 tcp_loss_rate 检测 TCP 重传代理指标问题。
    if (interface.tcpLossRate() > thresholds_.tcp_loss_fair) {
        issues.push_back("High packet loss: " + std::to_string(interface.tcpLossRate()) + "%");
    }

    // 检测 RSSI 问题
    if (interface.rssiDbm() != 0 && interface.rssiDbm() < thresholds_.rssi_fair) {
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

    // 评估整体网络质量
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
    // quality_score 已把流设为 1 位小数，这里必须显式恢复 3 位精度，否则 0.134 会再次变成 0.1。
    // 非有限值不能直接写入 JSON；统一退回与领域模型一致的 -1 不可用哨兵。
    const double serializableRtt = isRttAvailable(interface.rttMs()) ? interface.rttMs() : -1.0;
    json << "\"rtt_ms\":" << std::fixed << std::setprecision(3) << serializableRtt << ",";
    json << "\"tcp_loss_rate\":" << std::fixed << std::setprecision(2) << interface.tcpLossRate() << ",";
    json << "\"rssi_dbm\":" << interface.rssiDbm() << ",";
    json << "\"traffic_bps\":" << interface.trafficTotalBps() << ",";
    json << "\"traffic_pps\":" << interface.trafficTotalPps() << ",";
    json << "\"active_flows\":" << interface.trafficActiveFlows() << ",";
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
