// 高级流量模式检测器：维护流级时间序列，并识别持续外传、剧烈波动和时段异常。
// 结果同时给出置信度、严重度和可解释指标，供诊断层进一步分析。
#include "traffic_anomaly_detector.h"
#include <iostream>
#include <numeric>
#include <algorithm>
#include <cmath>
#include <sstream>

// 初始化三类检测的默认灵敏度参数。
TrafficAnomalyDetector::TrafficAnomalyDetector() 
    : burstThreshold_(2.5), volumeThreshold_(3.0), timeThreshold_(2.0) {
}

// 在锁内整体更新检测参数，避免分析线程读取到部分新配置。
void TrafficAnomalyDetector::setDetectionParams(double burstThreshold, double volumeThreshold, double timeThreshold) {
    std::lock_guard<std::mutex> lock(patternsMutex_);
    burstThreshold_ = burstThreshold;
    volumeThreshold_ = volumeThreshold;
    timeThreshold_ = timeThreshold;
}

// 将一个流量样本合并进对应五元组历史，并重新计算均值和标准差。
void TrafficAnomalyDetector::updateTrafficPattern(const FlowRate& flow) {
    std::string flowKey = flow.src + ":" + std::to_string(flow.sport) + "-" + 
                         flow.dst + ":" + std::to_string(flow.dport) + "/" + flow.proto;
    
    auto& pattern = trafficPatterns_[flowKey];
    pattern.flowKey = flowKey;
    
    auto now = std::chrono::system_clock::now();
    
    if (pattern.bpsHistory.empty()) {
        pattern.firstSeen = now;
    }
    pattern.lastSeen = now;
    
    pattern.bpsHistory.push_back(flow.bps);
    pattern.ppsHistory.push_back(flow.pps);
    pattern.totalBytes += flow.bps;
    pattern.totalPackets += flow.pps;
    
    // 每条流只保留最近 100 个样本，控制常驻内存并突出近期模式。
    const size_t MAX_HISTORY = 100;
    if (pattern.bpsHistory.size() > MAX_HISTORY) {
        pattern.bpsHistory.erase(pattern.bpsHistory.begin());
        pattern.ppsHistory.erase(pattern.ppsHistory.begin());
    }
    
    // 计算统计指标
    if (pattern.bpsHistory.size() > 1) {
        pattern.avgBps = std::accumulate(pattern.bpsHistory.begin(), pattern.bpsHistory.end(), 0.0) / pattern.bpsHistory.size();
        pattern.stdDevBps = calculateStandardDeviation(pattern.bpsHistory);
    }
}

// 计算总体标准差，用于衡量单条流速率的稳定程度。
double TrafficAnomalyDetector::calculateStandardDeviation(const std::vector<uint64_t>& values) {
    if (values.size() < 2) return 0.0;
    
    double mean = std::accumulate(values.begin(), values.end(), 0.0) / values.size();
    double variance = 0.0;
    
    for (uint64_t value : values) {
        variance += std::pow(value - mean, 2);
    }
    variance /= values.size();
    
    return std::sqrt(variance);
}

// 把样本转换为 Z-Score；零方差表示没有可比较波动。
double TrafficAnomalyDetector::calculateZScore(uint64_t value, double mean, double stdDev) {
    if (stdDev == 0.0) return 0.0;
    return (value - mean) / stdDev;
}

// 在排序副本上按最近下标法计算百分位，避免改变原始时间序列。
double TrafficAnomalyDetector::calculatePercentile(const std::vector<uint64_t>& values, double percentile) {
    if (values.empty()) return 0.0;
    
    std::vector<uint64_t> sortedValues = values;
    std::sort(sortedValues.begin(), sortedValues.end());
    
    size_t index = static_cast<size_t>((percentile / 100.0) * (sortedValues.size() - 1));
    return sortedValues[index];
}

// 样本数达到三次后应用 3-Sigma 规则判断离群点。
bool TrafficAnomalyDetector::isOutlier(uint64_t value, const std::vector<uint64_t>& values) {
    if (values.size() < 3) return false;
    
    double mean = std::accumulate(values.begin(), values.end(), 0.0) / values.size();
    double stdDev = calculateStandardDeviation(values);
    double zScore = calculateZScore(value, mean, stdDev);
    
    // 使用3-sigma规则检测异常值
    return std::abs(zScore) > 3.0;
}

// 在同一锁域更新历史并运行全部规则，返回本轮命中的高级异常。
std::vector<AdvancedAnomaly> TrafficAnomalyDetector::analyzeTrafficPatterns(const std::vector<FlowRate>& flows) {
    std::vector<AdvancedAnomaly> anomalies;
    
    // 更新与遍历共享同一容器，必须串行化以保持统计量和历史一致。
    std::lock_guard<std::mutex> lock(patternsMutex_);
    
    // 更新所有流量模式
    for (const auto& flow : flows) {
        updateTrafficPattern(flow);
    }
    
    // 分析每个模式
    for (auto& [flowKey, pattern] : trafficPatterns_) {
        // 检测数据泄露
        if (isDataExfiltrationPattern(pattern)) {
            AdvancedAnomaly anomaly;
            anomaly.flowKey = flowKey;
            anomaly.anomalyType = "data_exfiltration";
            anomaly.confidence = calculateAnomalyConfidence(pattern, "data_exfiltration");
            anomaly.severity = std::min(1.0, pattern.avgBps / (10 * 1024 * 1024)); // 相对于10MB/s的严重程度
            anomaly.description = "检测到可能的数据泄露行为";
            anomaly.timestamp = std::chrono::system_clock::now();
            anomaly.metrics["avg_bps"] = pattern.avgBps;
            anomaly.metrics["total_bytes"] = pattern.totalBytes;
            anomaly.metrics["duration_minutes"] = std::chrono::duration_cast<std::chrono::minutes>(
                pattern.lastSeen - pattern.firstSeen).count();
            anomalies.push_back(anomaly);
        }
        
        // 检测可疑连接
        if (isSuspiciousConnectionPattern(pattern)) {
            AdvancedAnomaly anomaly;
            anomaly.flowKey = flowKey;
            anomaly.anomalyType = "suspicious_connection";
            anomaly.confidence = calculateAnomalyConfidence(pattern, "suspicious_connection");
            anomaly.severity = std::min(1.0, pattern.stdDevBps / pattern.avgBps);
            anomaly.description = "检测到可疑连接模式";
            anomaly.timestamp = std::chrono::system_clock::now();
            anomaly.metrics["std_dev"] = pattern.stdDevBps;
            anomaly.metrics["coefficient_variation"] = pattern.stdDevBps / pattern.avgBps;
            anomalies.push_back(anomaly);
        }
        
        // 检测时间异常
        if (isTemporalAnomaly(pattern)) {
            AdvancedAnomaly anomaly;
            anomaly.flowKey = flowKey;
            anomaly.anomalyType = "temporal_anomaly";
            anomaly.confidence = calculateAnomalyConfidence(pattern, "temporal_anomaly");
            anomaly.severity = 0.7; // 时间异常通常中等严重程度
            anomaly.description = "检测到时间模式异常";
            anomaly.timestamp = std::chrono::system_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::minutes>(pattern.lastSeen - pattern.firstSeen);
            anomaly.metrics["duration_minutes"] = duration.count();
            anomalies.push_back(anomaly);
        }
    }
    
    return anomalies;
}

// 以“持续高吞吐且相对稳定”识别可能的数据外传模式。
bool TrafficAnomalyDetector::isDataExfiltrationPattern(const TrafficPattern& pattern) {
    if (pattern.bpsHistory.size() < 5) return false;
    
    // 检查持续高流量
    uint64_t highBpsCount = 0;
    uint64_t threshold = 5 * 1024 * 1024; // 5MB/s
    
    for (uint64_t bps : pattern.bpsHistory) {
        if (bps > threshold) {
            highBpsCount++;
        }
    }
    
    // 超过一半样本为高流量，才把偶发下载与持续传输区分开。
    double highBpsRatio = static_cast<double>(highBpsCount) / pattern.bpsHistory.size();
    
    // 检查流量稳定性（数据泄露通常比较稳定）
    double stability = 1.0 - (pattern.stdDevBps / pattern.avgBps);
    
    return highBpsRatio > 0.5 && stability > 0.3 && pattern.avgBps > threshold;
}

// 通过变异系数或 3-Sigma 离群点识别异常波动连接。
bool TrafficAnomalyDetector::isSuspiciousConnectionPattern(const TrafficPattern& pattern) {
    if (pattern.bpsHistory.size() < 3) return false;
    
    // 检查流量波动性
    double coefficientOfVariation = pattern.stdDevBps / pattern.avgBps;
    
    // 检查是否有异常峰值
    bool hasOutliers = false;
    for (uint64_t bps : pattern.bpsHistory) {
        if (isOutlier(bps, pattern.bpsHistory)) {
            hasOutliers = true;
            break;
        }
    }
    
    return coefficientOfVariation > 1.0 || hasOutliers;
}

// 检测工作时间之外仍保持高吞吐的流量模式。
bool TrafficAnomalyDetector::isTemporalAnomaly(const TrafficPattern& pattern) {
    auto now = std::chrono::system_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::minutes>(now - pattern.lastSeen);
    
    // 检查是否在非工作时间有大量流量
    auto time_t = std::chrono::system_clock::to_time_t(now);
    auto tm = *std::localtime(&time_t);
    int hour = tm.tm_hour;
    
    bool isOffHours = (hour < 8 || hour > 18); // 工作时间外
    bool hasHighVolume = pattern.avgBps > (2 * 1024 * 1024); // 2MB/s
    
    return isOffHours && hasHighVolume;
}

// 按异常类别将流量大小、稳定性或时段映射为 0 到 1 的置信度。
double TrafficAnomalyDetector::calculateAnomalyConfidence(const TrafficPattern& pattern, const std::string& anomalyType) {
    double confidence = 0.0;
    
    if (anomalyType == "data_exfiltration") {
        // 基于流量大小和稳定性计算置信度
        double volumeScore = std::min(1.0, pattern.avgBps / (20 * 1024 * 1024)); // 20MB/s为满分
        double stabilityScore = 1.0 - std::min(1.0, pattern.stdDevBps / pattern.avgBps);
        confidence = (volumeScore + stabilityScore) / 2.0;
    }
    else if (anomalyType == "suspicious_connection") {
        // 基于流量波动性计算置信度
        double variationScore = std::min(1.0, pattern.stdDevBps / pattern.avgBps);
        confidence = variationScore;
    }
    else if (anomalyType == "temporal_anomaly") {
        // 基于时间模式计算置信度
        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);
        auto tm = *std::localtime(&time_t);
        int hour = tm.tm_hour;
        
        double timeScore = 0.0;
        if (hour < 6 || hour > 22) timeScore = 1.0; // 深夜
        else if (hour < 8 || hour > 20) timeScore = 0.7; // 早晚
        else timeScore = 0.3; // 工作时间
        
        confidence = timeScore;
    }
    
    return std::min(1.0, std::max(0.0, confidence));
}

// 仅运行数据外传规则，适合调用方按场景选择检测成本。
std::vector<AdvancedAnomaly> TrafficAnomalyDetector::detectDataExfiltration(const std::vector<FlowRate>& flows) {
    std::vector<AdvancedAnomaly> anomalies;
    
    for (const auto& flow : flows) {
        // 检测大文件传输
        if (flow.bps > 10 * 1024 * 1024) { // 10MB/s
            AdvancedAnomaly anomaly;
            anomaly.flowKey = flow.src + ":" + std::to_string(flow.sport) + "-" + 
                             flow.dst + ":" + std::to_string(flow.dport) + "/" + flow.proto;
            anomaly.anomalyType = "data_exfiltration";
            anomaly.confidence = std::min(1.0, flow.bps / (50.0 * 1024 * 1024));
            anomaly.severity = std::min(1.0, flow.bps / (100.0 * 1024 * 1024));
            anomaly.description = "检测到高流量数据传输，可能存在数据泄露";
            anomaly.timestamp = std::chrono::system_clock::now();
            anomaly.metrics["current_bps"] = flow.bps;
            anomaly.metrics["pid"] = flow.pid;
            anomalies.push_back(anomaly);
        }
    }
    
    return anomalies;
}

// 仅运行可疑连接波动规则并返回命中项。
std::vector<AdvancedAnomaly> TrafficAnomalyDetector::detectSuspiciousConnections(const std::vector<FlowRate>& flows) {
    std::vector<AdvancedAnomaly> anomalies;
    
    // 统计每个进程的连接数
    std::map<uint32_t, int> pidConnectionCount;
    for (const auto& flow : flows) {
        if (flow.pid > 0) {
            pidConnectionCount[flow.pid]++;
        }
    }
    
    // 检测异常多连接的进程
    for (const auto& [pid, count] : pidConnectionCount) {
        if (count > 50) { // 超过50个连接
            AdvancedAnomaly anomaly;
            anomaly.flowKey = "PID:" + std::to_string(pid);
            anomaly.anomalyType = "suspicious_connection";
            anomaly.confidence = std::min(1.0, count / 200.0);
            anomaly.severity = std::min(1.0, count / 100.0);
            anomaly.description = "进程 " + std::to_string(pid) + " 有异常多的连接数: " + std::to_string(count);
            anomaly.timestamp = std::chrono::system_clock::now();
            anomaly.metrics["connection_count"] = count;
            anomaly.metrics["pid"] = pid;
            anomalies.push_back(anomaly);
        }
    }
    
    return anomalies;
}

// 仅运行非工作时段高流量规则并返回命中项。
std::vector<AdvancedAnomaly> TrafficAnomalyDetector::detectTemporalAnomalies(const std::vector<FlowRate>& flows) {
    std::vector<AdvancedAnomaly> anomalies;
    
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    auto tm = *std::localtime(&time_t);
    
    // 检查是否在非工作时间
    bool isOffHours = (tm.tm_hour < 8 || tm.tm_hour > 18);
    
    if (isOffHours) {
        uint64_t totalBps = 0;
        for (const auto& flow : flows) {
            totalBps += flow.bps;
        }
        
        if (totalBps > 5 * 1024 * 1024) { // 5MB/s
            AdvancedAnomaly anomaly;
            anomaly.flowKey = "temporal_anomaly";
            anomaly.anomalyType = "temporal_anomaly";
            anomaly.confidence = 0.8;
            anomaly.severity = std::min(1.0, totalBps / (20.0 * 1024 * 1024));
            anomaly.description = "在非工作时间检测到高流量活动";
            anomaly.timestamp = now;
            anomaly.metrics["total_bps"] = totalBps;
            anomaly.metrics["hour"] = tm.tm_hour;
            anomalies.push_back(anomaly);
        }
    }
    
    return anomalies;
}

// 在锁内复制全部流模式，避免暴露内部可变状态。
std::map<std::string, TrafficPattern> TrafficAnomalyDetector::getTrafficPatterns() {
    std::lock_guard<std::mutex> lock(patternsMutex_);
    return trafficPatterns_;
}

// 清空历史模式，使后续检测重新积累最小样本数。
void TrafficAnomalyDetector::clearHistory() {
    std::lock_guard<std::mutex> lock(patternsMutex_);
    trafficPatterns_.clear();
}
