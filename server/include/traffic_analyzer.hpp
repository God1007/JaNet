// 流量分析工作线程封装：周期驱动 NetTrafficAnalyzer 并缓存最近一次汇总统计。
// 实例拥有工作线程，析构前应通过 stop 或析构函数完成停止与回收。

#pragma once

#include <thread>
#include <atomic>
#include <string>
#include <memory>
#include "net_traffic.h"
#include "traffic_observation_state.hpp"

namespace weaknet_grpc {

// 管理指定接口的流量分析线程及线程安全统计快照。
class TrafficAnalyzer {
public:
    // 创建未运行的分析器。
    TrafficAnalyzer();
    // 停止并回收仍在运行的工作线程。
    ~TrafficAnalyzer();

    // 为 interface 启动分析线程；interval_seconds 是后台采样周期，单位秒。
    void start(const std::string& interface, int interval_seconds = 10);

    // 默认出口变化时动态重定向 TC/runtime ifindex，无需创建第二个采样线程。
    bool updateInterface(const std::string& interface);
    
    // 请求停止并等待工作线程结束；可重复调用。
    void stop();
    
    // 原子读取当前工作线程是否处于运行状态。
    bool isRunning() const { return running_.load(); }
    
    // 返回最近一次缓存的实时流量统计快照。
    NetTrafficAnalyzer::RealTimeStats getCurrentStats() const;
    
    // 从中心快照返回流量最高的 top_count 条流；sample_seconds 仅为旧 ABI 兼容参数。
    std::vector<FlowRate> getTopFlows(int sample_seconds = 5, int top_count = 10) const;
    std::vector<FlowRate> getTopFlows(const TrafficSnapshotPtr& snapshot,
                                      int top_count = 10) const;
    
    // 从中心快照及历史返回基础异常集合，不触发额外采样。
    std::vector<TrafficAnomaly> detectAnomalies(int detection_seconds = 5) const;
    std::vector<TrafficAnomaly> detectAnomalies(const TrafficSnapshotPtr& snapshot) const;

    // 返回最近一次由唯一采样线程发布的完整只读快照。
    TrafficSnapshotPtr getCurrentSnapshot() const;

    using ObservationState = TrafficObservationStateStore::State;
    // 在同一把锁下复制汇总与明细，保证 RPC 不会拼接两个 generation。
    ObservationState getCurrentObservationState() const;
    
    // 返回底层分析器当前流量历史的值拷贝。
    std::map<std::string, TrafficHistory> getTrafficHistory() const;

private:
    // 工作线程主循环，按 interval_seconds_ 成对发布 stats + immutable snapshot。
    void analyzeLoop();
    
    // 本实例独占的工作线程；空指针表示尚未启动或已释放。
    std::unique_ptr<std::thread> thread_;
    // 跨线程停止标志。
    std::atomic<bool> running_;
    // 当前分析的接口名。
    std::string interface_;
    // 保护动态接口名及底层 runtime ifindex 更新。
    mutable std::mutex interface_mutex_;
    // 每次真实 rebind 递增；采样发布前用它拒绝旧接口结果回写。
    uint64_t interface_epoch_ = 0;
    // 后台分析周期，单位秒。
    int interval_seconds_;
    
    // 进程级底层流量分析器的共享所有权。
    std::shared_ptr<NetTrafficAnalyzer> analyzer_;
    
    // 统计与明细的原子发布槽，读者不会观察到两个 generation。
    TrafficObservationStateStore observation_state_;
    // 已桥接到 EventManager 的最后 generation，保证低频事件只发布一次。
    uint64_t last_event_generation_ = 0;
};

} // namespace weaknet_grpc
