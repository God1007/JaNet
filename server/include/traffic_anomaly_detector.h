// 基于流量历史的高级异常检测模型与分析器。
// 检测器实例持有跨采样历史，内部映射通过互斥量保护。

#pragma once

#include "net_traffic.h"
#include <vector>
#include <map>
#include <chrono>
#include <mutex>
#include <algorithm>
#include <cmath>

// 单条流在观察窗口内的统计特征和可疑状态。
struct TrafficPattern {
    std::string flowKey;                       // 稳定流标识
    std::vector<uint64_t> bpsHistory;          // 历史字节速率，单位 bytes/s
    std::vector<uint64_t> ppsHistory;          // 历史报文速率，单位 packets/s
    std::chrono::system_clock::time_point firstSeen; // 首次观察时间
    std::chrono::system_clock::time_point lastSeen;  // 最近观察时间
    uint64_t totalBytes = 0;                   // 观察期累计字节数
    uint64_t totalPackets = 0;                 // 观察期累计报文数
    double avgBps = 0.0;                       // 平均字节速率，单位 bytes/s
    double stdDevBps = 0.0;                    // 字节速率标准差
    bool isSuspicious = false;                 // 是否已被规则标记为可疑
};

// 一条高级异常检测结果及其判定依据。
struct AdvancedAnomaly {
    std::string flowKey; // 异常所属流标识
    std::string anomalyType; // 异常类别文本
    double confidence;  // 置信度 0.0-1.0
    double severity;    // 严重程度 0.0-1.0
    std::string description;
    std::map<std::string, double> metrics;  // 各种指标
    std::chrono::system_clock::time_point timestamp; // 判定时间
};

// 聚合流量历史并提供泄漏、连接和时间模式检测。
class TrafficAnomalyDetector {
public:
    // 创建空历史检测器。
    TrafficAnomalyDetector();
    // 析构仅释放本实例历史，不影响外部 FlowRate 数据。
    ~TrafficAnomalyDetector() = default;

    // 更新输入流的历史模式并返回综合异常结果。
    std::vector<AdvancedAnomaly> analyzeTrafficPatterns(const std::vector<FlowRate>& flows);

    // 返回满足数据外传特征的异常集合。
    std::vector<AdvancedAnomaly> detectDataExfiltration(const std::vector<FlowRate>& flows);

    // 返回满足可疑连接模式的异常集合。
    std::vector<AdvancedAnomaly> detectSuspiciousConnections(const std::vector<FlowRate>& flows);

    // 返回偏离既有时间分布的异常集合。
    std::vector<AdvancedAnomaly> detectTemporalAnomalies(const std::vector<FlowRate>& flows);

    // 返回当前模式映射的值拷贝，调用方不持有内部锁。
    std::map<std::string, TrafficPattern> getTrafficPatterns();

    // 更新三个无量纲检测阈值倍数，影响后续分析。
    void setDetectionParams(double burstThreshold, double volumeThreshold, double timeThreshold);

    // 在线程安全边界内清空全部模式历史。
    void clearHistory();

private:
    // 保护 trafficPatterns_ 及依赖它的跨线程读写。
    mutable std::mutex patternsMutex_;
    std::map<std::string, TrafficPattern> trafficPatterns_;
    
    // 三类异常判定使用的无量纲阈值倍数。
    double burstThreshold_;      // 突发阈值倍数
    double volumeThreshold_;    // 流量阈值倍数
    double timeThreshold_;      // 时间异常阈值
    
    // 将单条流并入对应的历史模式。
    void updateTrafficPattern(const FlowRate& flow);
    // 计算样本总体标准差，空输入返回实现定义的基础值。
    double calculateStandardDeviation(const std::vector<uint64_t>& values);
    // 判断单条模式是否命中数据外传规则。
    bool isDataExfiltrationPattern(const TrafficPattern& pattern);
    // 判断单条模式是否命中可疑连接规则。
    bool isSuspiciousConnectionPattern(const TrafficPattern& pattern);
    // 判断单条模式是否命中时间异常规则。
    bool isTemporalAnomaly(const TrafficPattern& pattern);
    // 将规则证据归一化为 0.0-1.0 的置信度。
    double calculateAnomalyConfidence(const TrafficPattern& pattern, const std::string& anomalyType);

    // 计算单值相对均值和标准差的 Z 分数。
    double calculateZScore(uint64_t value, double mean, double stdDev);
    // 计算给定分位点；percentile 为 0.0-1.0。
    double calculatePercentile(const std::vector<uint64_t>& values, double percentile);
    // 依据历史分布判断 value 是否为离群点。
    bool isOutlier(uint64_t value, const std::vector<uint64_t>& values);
};
