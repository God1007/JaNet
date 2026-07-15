// WeakNet 核心状态管理器：维护网络接口快照并协调 RTT、RSSI、TCP 重传代理值与流量指标更新。
// current_interfaces_ 由内部互斥量保护；带 Safe 后缀的方法提供跨监控线程的同步入口。
// 部分 Safe 更新会持有该互斥量完成 Ping、RSSI 等阻塞 I/O，因此同期快照读取也可能被阻塞。

#pragma once

#include <vector>
#include <string>
#include <memory>
#include <mutex>

#include "net_info.hpp"
#include "traffic_analyzer.hpp"

namespace weaknet_grpc {

// 汇聚底层网络采集器并向 RPC、评估器提供一致的接口状态快照。
class WeakNetMgr {
private:
    // 可选流量分析工作器，由 startTrafficAnalysis 延迟创建并共享持有。
    std::shared_ptr<TrafficAnalyzer> traffic_analyzer_;
    // C++17 shared_ptr 对象的普通读写不是原子操作；该锁保护创建与所有指针复制。
    mutable std::mutex traffic_analyzer_mutex_;
    // 保护 current_interfaces_ 及 Safe 更新方法的互斥量。
    mutable std::mutex iface_mutex_;
    // 当前管理器快照；拓扑刷新会整体替换它，不能假设其中始终保留此前采集的全部指标。
    std::vector<NetInfo> current_interfaces_;

public:
    // 创建空接口列表且尚未启动流量分析的管理器。
    WeakNetMgr() : iface_mutex_(), current_interfaces_() {}

    // 从系统重新采集具备上网能力的接口并返回值快照；本方法本身不写 current_interfaces_。
    std::vector<NetInfo> collectCurrentInterfaces();

    // 在 list 中按接口名查找；找到时可复制到 out 并返回 true。
    bool findByName(const std::vector<NetInfo>& list, const std::string& ifname, NetInfo* out) const;

    // 将 NetInfo 列表转换为保持原顺序的接口名数组，供 RPC 返回。
    static std::vector<std::string> namesOf(const std::vector<NetInfo>& list);

    // 根据默认路由更新 list 的 usingNow 标记；发生变化返回 true，可选输出接口名和协议位图。
    bool updateCurrentUsing(std::vector<NetInfo>& list,
                            bool printLog,
                            std::string* outIfName = nullptr,
                            uint32_t* outFlags = nullptr);

    // 逐接口执行 Ping 并更新 RTT、状态和质量；timeoutMs 单位毫秒，任一字段变化返回 true。
    bool updateRttAndState(std::vector<NetInfo>& list, const std::string& host, int timeoutMs = 800);

    // 更新 list 中 Wi-Fi 接口的 RSSI；RSSI 单位 dBm，任一值变化返回 true。
    bool updateWifiRssi(std::vector<NetInfo>& list, const std::string& ctrlDir = "");

    // 更新指定接口的 tcp_loss_rate 代理值和等级；找到且值变化时返回 true。
    bool updateTcpLossRate(std::vector<NetInfo>& list, 
                          const std::string& iface_name, 
                          double loss_rate, 
                          const std::string& loss_level);

    // 延迟创建并启动指定接口的流量分析线程；interval_seconds 单位秒。
    void startTrafficAnalysis(const std::string& interface, int interval_seconds = 10);
    
    // 停止并回收已创建的流量分析线程；未启动时为空操作。
    void stopTrafficAnalysis();
    
    // 把当前流量统计写入 list 的活动接口；成功更新时返回 true。
    bool updateTrafficAnalysis(std::vector<NetInfo>& list);
    
    // 返回流量分析器的共享所有权；尚未创建时返回空指针。
    std::shared_ptr<TrafficAnalyzer> getTrafficAnalyzer() const;

    // 在 iface_mutex_ 保护下返回当前接口列表的值拷贝。
    std::vector<NetInfo> getCurrentInterfaces() const;
    
    // 在 iface_mutex_ 保护下用 new_interfaces 整体替换当前快照。
    void updateInterfaces(const std::vector<NetInfo>& new_interfaces);

    // 在 iface_mutex_ 内合并拓扑并返回新快照，保留同名接口的诊断指标且移除消失接口。
    std::vector<NetInfo> mergeTopologySnapshot(const std::vector<NetInfo>& observed_topology);
    
    // 持有 iface_mutex_ 跨逐接口 Ping I/O 更新 RTT、状态和质量；期间其他快照读写会阻塞。
    bool updateRttAndStateSafe(const std::string& host, int timeoutMs = 800);
    
    // 持有 iface_mutex_ 跨 wpa_supplicant 控制 I/O 更新 Wi-Fi RSSI；任一值变化返回 true。
    bool updateWifiRssiSafe(const std::string& ctrlDir = "");
    
    // 持有 iface_mutex_ 更新指定接口的 tcp_loss_rate 代理值和等级。
    bool updateTcpLossRateSafe(const std::string& iface_name, double loss_rate, const std::string& loss_level);
    
    // 持有 iface_mutex_ 把流量分析结果更新到当前活动接口。
    bool updateTrafficAnalysisSafe();
    
    // 持有 iface_mutex_ 重新判定当前上网接口，标记变化时返回 true。
    bool updateCurrentUsingSafe();
};

}  // namespace weaknet_grpc
