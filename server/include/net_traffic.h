// eBPF 流量观测公开模型：中心采样器发布只读 TrafficSnapshot，查询方不再各自阻塞采样。
// Linux 缺权限或缺内核能力时仍发布 support/degraded_reason，避免把零值误当成真实无流量。

#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <deque>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "flow_abi.h"
#include "flow_observation_core.hpp"

// 一个采样窗口内的单条流速率、归属和连续性状态。
struct FlowRate {
    std::string src;
    std::string dst;
    int sport = 0;
    int dport = 0;
    std::string proto;
    std::string direction;
    uint8_t family = FLOW_AF_UNSPEC;
    uint32_t ifindex = 0;
    uint64_t socketCookie = 0;
    uint64_t bps = 0;
    uint64_t pps = 0;
    uint32_t tgid = 0;
    uint32_t pid = 0;
    uint64_t cgroupId = 0;
    std::string cgroupPath;
    std::string comm;
    bool protectedFlow = false;
    bool continuityLost = false;
    bool counterReset = false;
};

// 一条基础流量异常或可信度异常。
struct TrafficAnomaly {
    std::string flowKey;
    std::string anomalyType;
    uint64_t currentBps = 0;
    uint64_t thresholdBps = 0;
    double severity = 0.0;
    std::chrono::system_clock::time_point timestamp;
    std::string description;
};

// 单条流的有限窗口历史及累计量。
struct TrafficHistory {
    std::deque<uint64_t> bpsHistory;
    std::deque<uint64_t> ppsHistory;
    std::chrono::system_clock::time_point lastUpdate;
    uint64_t totalBytes = 0;
    uint64_t totalPackets = 0;
};

// 接口/协议/方向聚合直接来自独立的内核 per-CPU map，不依赖 TopN 明细是否截断。
struct InterfaceTrafficStats {
    uint32_t ifindex = 0;
    uint8_t family = FLOW_AF_UNSPEC;
    uint8_t protocol = 0;
    uint8_t direction = FLOW_DIR_UNKNOWN;
    uint64_t bps = 0;
    uint64_t pps = 0;
    bool continuityLost = false;
    bool counterReset = false;
};

// 低频状态事件来自内核 ring buffer 或用户态安全差分器。
struct TrafficObservationEvent {
    uint32_t type = FLOW_EVENT_UNSPEC;
    uint32_t reason = 0;
    uint64_t socketCookie = 0;
    std::string flowKey;
    std::string description;
    std::chrono::system_clock::time_point timestamp;
    // 事件归属的不可变快照代际；快照发布前由中心采样器统一填充。
    uint64_t generation = 0;
    // 仅 FLOW_EVENT_TRAFFIC_ANOMALY 使用；其他事件保持空字符串/0。
    std::string anomalyType;
    double severity = 0.0;
};

// 支持状态明确区分“无流量”和“采集不可用/部分降级”。
struct TrafficSupportStatus {
    bool libbpfAvailable = false;
    bool bpfLoaded = false;
    bool tcIngressAttached = false;
    bool tcEgressAttached = false;
    bool tcpKprobeAttached = false;
    bool udpKprobeAttached = false;
    bool sockDiagAvailable = false;
    bool sockDiagIpv4Available = false;
    bool sockDiagIpv6Available = false;
    bool procOwnerResolution = false;
    bool ipv4Supported = false;
    bool ipv6Supported = false;
    bool ipv6ExtensionHeadersSupported = false;
    bool bidirectional = false;
    bool udpInterfaceReliable = false;
    // full 仅表示 TC ingress+egress 都附加且接口过滤已生效；kprobe fallback 永远是 partial。
    bool captureComplete = false;
    std::string captureMode = "unavailable";
    std::string captureCompleteness = "unavailable";
    std::string sockDiagStatus = "not-attempted";
    std::string coverageLimitations;
    std::string degradedReason;
};

// map 容量、占用和本窗口连续性指标；kernelCounters 保留内核侧 attempt/failure/miss 明细。
struct TrafficMapObservability {
    uint64_t lruCapacity = FLOW_LRU_MAX_ENTRIES;
    uint64_t protectedCapacity = FLOW_PROTECTED_MAX_ENTRIES;
    uint64_t lruEntries = 0;
    uint64_t protectedEntries = 0;
    uint64_t disappearedThisWindow = 0;
    uint64_t continuityLostThisWindow = 0;
    uint64_t counterResetsThisWindow = 0;
    uint64_t policyUpdateAttempts = 0;
    uint64_t policyUpdateFailures = 0;
    bool mapReadComplete = false;
    uint64_t mapLookupMisses = 0;
    uint64_t mapDuplicateKeys = 0;
    int mapReadError = 0;
    uint64_t userEventsTruncated = 0;
    std::array<uint64_t, FLOW_STAT_MAX> kernelCounters{};
};

// 一次中心采样的完整不可变值对象。发布后只通过 shared_ptr<const TrafficSnapshot> 共享。
struct TrafficSnapshot {
    uint64_t generation = 0;
    bool baselineOnly = true;
    // false 时本轮 map 在高 churn/系统调用错误下只读到了部分结果，数值不可作为真实零。
    bool mapReadComplete = false;
    std::chrono::system_clock::time_point windowStart;
    std::chrono::system_clock::time_point windowEnd;
    uint32_t boundIfindex = 0;
    TrafficSupportStatus support;
    std::vector<FlowRate> flows;
    std::vector<InterfaceTrafficStats> interfaces;
    // 在本 generation 发布前由中心采样器固化，不再与后续可变 history 重算。
    std::vector<TrafficAnomaly> anomalies;
    std::array<uint64_t, FLOW_STAT_MAX> mapStats{};
    TrafficMapObservability mapObservability;
    std::vector<TrafficObservationEvent> events;
};

using TrafficSnapshotPtr = std::shared_ptr<const TrafficSnapshot>;

// 管理 eBPF 生命周期、sock_diag 校准、中心采样、历史和异常派生。
class NetTrafficAnalyzer {
public:
    // 仅供本翻译单元中的平台适配帮助函数使用；公开的是不完整类型，调用方不能访问其状态。
    struct Impl;

    static std::shared_ptr<NetTrafficAnalyzer> getInstance();
    ~NetTrafficAnalyzer();

    void setBpfObjectPath(const std::string& path);

    // 首次加载对象并附加目标接口；失败时保留可查询的明确降级状态。
    bool initForInterface(const std::string& ifaceName);

    // 动态修改运行时 ifindex；TC 已附加到不同设备时会安全重附加，失败则退回 kprobe。
    bool updateInterface(const std::string& ifaceName);

    // true 表示接口/捕获模式刚切换，下一轮只能建基线，旧实时统计必须立即失效。
    bool isBaselinePending() const;

    // 中心采样器唯一写入口：读取一次全部 map，与上次基线做非阻塞差分并发布新 generation。
    TrafficSnapshotPtr refreshSnapshot();

    // 返回最近一次已发布的只读快照；没有样本时也返回 generation=0 的状态对象。
    TrafficSnapshotPtr getLatestSnapshot() const;

    // 兼容旧 API：intervalSec 不再触发 sleep，仅从同一最新快照派生 TopN。
    std::vector<FlowRate> sampleTopFlows(int intervalSec, int topN);
    std::vector<FlowRate> sampleTopFlows(const TrafficSnapshotPtr& snapshot, int topN) const;

    // 兼容旧 API：从最新快照派生异常，不再执行第二次阻塞采样。
    std::vector<TrafficAnomaly> detectAnomalies(int intervalSec,
                                               uint64_t burstThresholdBps = 10 * 1024 * 1024,
                                               uint64_t suspiciousThresholdBps = 50 * 1024 * 1024,
                                               double burstMultiplier = 3.0);
    // 从调用方指定的 immutable generation 派生，阈值使用 setAnomalyDetectionParams 的当前配置。
    std::vector<TrafficAnomaly> detectAnomalies(const TrafficSnapshotPtr& snapshot) const;

    std::map<std::string, TrafficHistory> getTrafficHistory();
    void setAnomalyDetectionParams(uint64_t burstThreshold,
                                   uint64_t suspiciousThreshold,
                                   double burstMultiplier);
    void setLongFlowPolicy(const weaknet_grpc::traffic_core::LongFlowPolicy& policy);

    // 旧上层仍可消费的汇总包装，数据来源始终是最新中心快照。
    struct RealTimeStats {
        uint64_t totalBps = 0;
        uint64_t totalPps = 0;
        size_t activeFlows = 0;
        uint64_t generation = 0;
        uint32_t boundIfindex = 0;
        size_t continuityLostFlows = 0;
        size_t counterResetFlows = 0;
        bool valid = false;
        TrafficSupportStatus support;
        std::chrono::system_clock::time_point timestamp;
    };
    RealTimeStats getRealTimeStats() const;
    // 直接从调用方刚获得的不可变快照派生总量，避免再读 latest 导致代际被其他操作插入。
    RealTimeStats getRealTimeStats(const TrafficSnapshotPtr& snapshot) const;

    void clearHistory();

private:
    NetTrafficAnalyzer();
    NetTrafficAnalyzer(const NetTrafficAnalyzer&) = delete;
    NetTrafficAnalyzer& operator=(const NetTrafficAnalyzer&) = delete;

    std::unique_ptr<Impl> impl_;

    static std::once_flag s_onceFlag;
    static std::shared_ptr<NetTrafficAnalyzer> s_instance;
};
