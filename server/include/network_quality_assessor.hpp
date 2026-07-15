// 多指标网络质量评估器：融合 RTT、TCP 重传率代理值、RSSI 和流量特征生成分数与问题列表。
// 每个实例保存上一次评估结果和变化计数，跨线程共享同一实例时需由调用方同步。

#ifndef NETWORK_QUALITY_ASSESSOR_HPP
#define NETWORK_QUALITY_ASSESSOR_HPP

#include <string>
#include <map>
#include <vector>
#include "net_info.hpp"

namespace weaknet_grpc {

// 综合网络质量等级，数值越大表示质量越好。
enum class NetworkQualityLevel {
    EXCELLENT = 4,  // 优秀
    GOOD = 3,       // 良好
    FAIR = 2,       // 一般
    POOR = 1,       // 较差
    UNKNOWN = 0     // 未知
};

// 一次质量评估的完整值结果。
struct NetworkQualityResult {
    NetworkQualityLevel level;       // 归纳后的质量等级
    std::string levelName;           // 等级的稳定可读名称
    std::string details;             // 指标详情，当前实现为 JSON 文本
    double score;                    // 综合分数，范围 0-100
    std::vector<std::string> issues; // 识别到的问题描述列表
};

// 对接口快照执行同步质量评估，并记录实例内的相邻结果变化。
class NetworkQualityAssessor {
private:
    // 各指标的分级阈值；RTT 单位毫秒，TCP 代理值单位百分比，RSSI 单位 dBm。
    struct QualityThresholds {
        // RTT 分级上界，单位毫秒。
        int rtt_excellent = 50;
        int rtt_good = 100;
        int rtt_fair = 200;
        
        // TCP 重传率代理值分级上界，单位百分比。
        double tcp_loss_excellent = 0.1;
        double tcp_loss_good = 0.5;
        double tcp_loss_fair = 2.0;
        
        // RSSI 分级下界，单位 dBm。
        int rssi_excellent = -50;
        int rssi_good = -60;
        int rssi_fair = -70;
        
        // 流量异常比例阈值和参与分析的最小活跃流数量。
        double traffic_anomaly_threshold = 0.8;
        int min_flows_for_analysis = 5;
    };

    QualityThresholds thresholds_;          // 当前实例使用的评估阈值
    NetworkQualityResult lastResult_;       // 上一次评估结果，用于变化判断
    int32_t qualityChangeCounter_;           // 本实例累计识别到的质量变化次数

public:
    // 创建使用默认阈值、上次等级为 UNKNOWN 的评估器。
    NetworkQualityAssessor();
    
    // 评估接口列表中的活动接口；无活动标记时回退到第一个接口。
    NetworkQualityResult assessQuality(const std::vector<NetInfo>& interfaces);
    
    // 评估单个接口并更新本实例的 lastResult_ 与变化计数。
    NetworkQualityResult assessInterfaceQuality(const NetInfo& interface);
    
    // 把质量枚举转换为稳定英文名称。
    static std::string getQualityLevelName(NetworkQualityLevel level);
    
    // 根据接口、综合分和问题列表生成详情 JSON。
    std::string generateQualityDetails(const NetInfo& interface, double score, const std::vector<std::string>& issues);
    
    // 比较 current 与 lastResult_，等级变化或分差超过阈值时返回 true。
    bool hasQualityChanged(const NetworkQualityResult& current);
    
    // 返回本实例生命周期内累计的质量变化次数。
    int32_t getQualityChangeCounter() const { return qualityChangeCounter_; }
    
    // 替换后续评估使用的全部阈值配置。
    void updateThresholds(const QualityThresholds& newThresholds);
    
private:
    // 将 RTT 毫秒值映射为 0-100 分。
    double calculateRttScore(double rttMs);
    
    // 将 TCP 重传百分比代理值映射为 0-100 分。
    double calculateTcpLossScore(double lossRate);
    
    // 将 RSSI dBm 值映射为 0-100 分。
    double calculateRssiScore(int rssiDbm);
    
    // 根据接口的活跃流和平均包大小计算 0-100 流量分。
    double calculateTrafficScore(const NetInfo& interface);
    
    // 根据阈值和综合分生成可读问题列表。
    std::vector<std::string> detectNetworkIssues(const NetInfo& interface, double score);
    
    // 将接口指标、综合分和问题列表编码为 JSON 文本。
    std::string generateMetricsJson(const NetInfo& interface, double score, const std::vector<std::string>& issues);
};

} // namespace weaknet_grpc

#endif // NETWORK_QUALITY_ASSESSOR_HPP
