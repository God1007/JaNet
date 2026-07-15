// 网络指标聚合器：维护 NetInfo 快照并接收 RTT、RSSI、TCP 重传和流量更新。
// Safe 后缀入口统一使用互斥锁，为各监控线程和 RPC 读线程提供一致状态。

#include "weak_netmgr.hpp"
#include "net_iface.h"
#include "using_iface.h"
#include "net_ping.h"
#include "net_wifiriss.h"
#include "traffic_analyzer.hpp"
#include "interface_snapshot_merge.hpp"
#include "logger.hpp"
#include "rtt_utils.hpp"
#include <algorithm>
#include <net/if.h>

namespace weaknet_grpc {

// 从内核接口管理器构造当前可上网接口快照，并标记默认出口。
std::vector<NetInfo> WeakNetMgr::collectCurrentInterfaces() {
    LOG_INFO(LogModule::WEAK_MGR, "collectCurrentInterfaces begin");
    std::vector<NetInfo> result;
    auto mgr = NetInterfaceManager::getInstance();
    auto names = mgr->getInternetInterfaces();
    result.reserve(names.size());
    for (const auto& n : names) {
        NetInfo info(n);
        // 当前底层只返回接口名；类型和更多链路属性保留默认值等待后续采集补全。
        info.setDefaultRoute(false);
        info.setType(NetType::Unknown);
        info.setState(NetState::Up);
        info.setRttMs(-1.0);
        result.push_back(info);
    }
    // 根据默认路由监听器标记当前真正承担上网流量的接口。
    auto usingMgr = UsingInterfaceManager::getInstance();
    usingMgr->start();
    std::string usingIf = usingMgr->getCurrentInterface();
    for (auto& x : result) {
        const bool isUsing = !usingIf.empty() && x.ifName() == usingIf;
        x.setUsingNow(isUsing);
        x.setDefaultRoute(isUsing);
    }
    LOG_INFO(LogModule::WEAK_MGR, "collectCurrentInterfaces end: " << result.size() << " ifaces, using=" << (usingIf.empty() ? "(none)" : usingIf));
    return result;
}
// 将 RTT 映射为离散链路等级，负值统一表示探测失败。
static LinkQuality classifyQualityFromRtt(double rttMs) {
    if (!isRttAvailable(rttMs)) return LinkQuality::Bad;
    // 阈值按交互体验划分，边界值归入更好的等级。
    if (rttMs <= 50) return LinkQuality::Good;
    if (rttMs <= 100) return LinkQuality::Fair;
    if (rttMs <= 200) return LinkQuality::Poor;
    return LinkQuality::Bad;
}

// 逐接口执行绑定网卡的 Ping，并同步 RTT、质量等级和 Up/Down 状态。
bool WeakNetMgr::updateRttAndState(std::vector<NetInfo>& list, const std::string& host, int timeoutMs) {
    LOG_INFO(LogModule::WEAK_MGR, "updateRttAndState: starting, host=" << host << ", timeout=" << timeoutMs << ", size=" << list.size());
    auto pinger = NetPing::getInstance();
    LOG_INFO(LogModule::WEAK_MGR, "updateRttAndState: got pinger instance");
    bool anyChanged = false;
    for (auto& x : list) {
        LOG_INFO(LogModule::WEAK_MGR, "updateRttAndState: processing interface " << x.ifName());
        const double prev = x.rttMs();
        LOG_INFO(LogModule::WEAK_MGR, "updateRttAndState: calling ping for " << x.ifName());
        const double r = pinger->ping(host, x.ifName(), timeoutMs);
        LOG_INFO(LogModule::WEAK_MGR, "updateRttAndState: ping returned " << r << " for " << x.ifName());
        x.setPrevRttMs(prev);
        x.setRttMs(r);
        LinkQuality q = classifyQualityFromRtt(r);
        if (x.quality() != q) { x.setQuality(q); anyChanged = true; }
        // 当前状态只依据 Ping 成败判断，后续可叠加路由和链路信号。
        NetState ns = isRttAvailable(r) ? NetState::Up : NetState::Down;
        if (x.state() != ns) { x.setState(ns); anyChanged = true; }
        LOG_INFO(LogModule::WEAK_MGR, "iface=" << x.ifName() << " rtt=" << r << "ms quality=" << static_cast<int>(x.quality()) << " state=" << static_cast<int>(x.state()));
    }
    LOG_INFO(LogModule::WEAK_MGR, "updateRttAndState: completed, anyChanged=" << anyChanged);
    return anyChanged;
}

// 只对 Wi-Fi 接口查询 wpa_supplicant RSSI，并检测值是否变化。
bool WeakNetMgr::updateWifiRssi(std::vector<NetInfo>& list, const std::string& ctrlDir) {
    LOG_INFO(LogModule::WEAK_MGR, "updateWifiRssi: starting, ctrlDir=" << ctrlDir << " size=" << list.size());
    auto client = WiFiRssiClient::getInstance();
    LOG_INFO(LogModule::WEAK_MGR, "updateWifiRssi: got client instance");
    bool anyChanged = false;
    for (auto& x : list) {
        LOG_INFO(LogModule::WEAK_MGR, "updateWifiRssi: processing interface " << x.ifName() << " type=" << static_cast<int>(x.type()));
        if (x.type() != NetType::WiFi) {
            LOG_INFO(LogModule::WEAK_MGR, "updateWifiRssi: skipping non-WiFi interface " << x.ifName());
            continue;
        }
        // 每轮先确保控制套接字可用，连接失败的接口跳过而不覆盖旧值。
        LOG_INFO(LogModule::WEAK_MGR, "updateWifiRssi: attempting to connect to " << x.ifName());
        if (!client->connect(x.ifName(), ctrlDir)) {
            LOG_INFO(LogModule::WEAK_MGR, "updateWifiRssi: failed to connect to " << x.ifName());
            continue;
        }
        LOG_INFO(LogModule::WEAK_MGR, "updateWifiRssi: connected to " << x.ifName() << ", getting RSSI");
        int rssi = client->getRssi();
        LOG_INFO(LogModule::WEAK_MGR, "updateWifiRssi: got RSSI " << rssi << " for " << x.ifName());
        if (x.rssiDbm() != rssi) {
            x.setRssiDbm(rssi);
            anyChanged = true;
            if (x.usingNow()) {
                LOG_INFO(LogModule::RSSI, "using iface " << x.ifName() << " RSSI=" << rssi << " dBm");
            }
            LOG_INFO(LogModule::WEAK_MGR, "iface=" << x.ifName() << " rssi=" << rssi);
        }
    }
    LOG_INFO(LogModule::WEAK_MGR, "updateWifiRssi: completed, anyChanged=" << anyChanged);
    return anyChanged;
}

// 把默认路由监听器结果投影到每个 NetInfo 的 usingNow 标志。
bool WeakNetMgr::updateCurrentUsing(std::vector<NetInfo>& list, bool printLog, std::string* outIfName, uint32_t* outFlags) {
    auto usingMgr = UsingInterfaceManager::getInstance();
    usingMgr->start();
    std::string usingIf = usingMgr->getCurrentInterface();
    uint32_t flags = usingMgr->getMethodFlags();

    bool changed = false;
    LOG_INFO(LogModule::WEAK_MGR, "updateCurrentUsing: current=" << (usingIf.empty() ? "(none)" : usingIf) << " flags=" << flags);
    for (auto& x : list) {
        bool should = (!usingIf.empty() && x.ifName() == usingIf);
        if (x.usingNow() != should) { x.setUsingNow(should); changed = true; }
    }
    if (outIfName) *outIfName = usingIf;
    if (outFlags) *outFlags = flags;
    if (printLog) {
        if (!usingIf.empty()) {
            LOG_INFO(LogModule::INTERFACE, "current=" << usingIf << " flags=" <<
                ((flags & UsingMethodFlag::IPv4Default) ? "IPv4" : "") <<
                (((flags & UsingMethodFlag::IPv4Default) && (flags & UsingMethodFlag::IPv6Default)) ? "+" :
                 ((flags & UsingMethodFlag::IPv6Default) ? "IPv6" : "")));
        } else {
            LOG_INFO(LogModule::INTERFACE, "current=(none)");
        }
    }
    return changed;
}

// 按接口名查找快照，并可选复制完整 NetInfo 给调用方。
bool WeakNetMgr::findByName(const std::vector<NetInfo>& list, const std::string& ifname, NetInfo* out) const {
    for (const auto& x : list) {
        if (x.ifName() == ifname) { if (out) *out = x; return true; }
    }
    return false;
}

// 提取接口名作为拓扑比较和 RPC 返回的稳定表示。
std::vector<std::string> WeakNetMgr::namesOf(const std::vector<NetInfo>& list) {
    std::vector<std::string> names;
    names.reserve(list.size());
    for (const auto& x : list) names.push_back(x.ifName());
    return names;
}

// 更新指定接口的 TCP 重传率与等级，仅在任一字段变化时返回 true。
bool WeakNetMgr::updateTcpLossRate(std::vector<NetInfo>& list,
                                  const std::string& iface_name,
                                  double loss_rate,
                                  const std::string& loss_level) {
    bool changed = false;
    LOG_INFO(LogModule::WEAK_MGR, "updateTcpLossRate: iface=" << iface_name << " rate=" << loss_rate << " level=" << loss_level);

    for (auto& x : list) {
        if (x.ifName() == iface_name) {
            bool rateChanged = false, levelChanged = false;
            if (x.tcpLossRate() != loss_rate) {
                x.setTcpLossRate(loss_rate);
                rateChanged = true;
            }
            if (x.tcpLossLevel() != loss_level) {
                x.setTcpLossLevel(loss_level);
                levelChanged = true;
            }
            if (rateChanged || levelChanged) {
                changed = true;
                if (x.usingNow()) {
                    LOG_INFO(LogModule::TCP_LOSS, "using iface " << iface_name << " TCP loss rate updated: " << loss_rate << "% (" << loss_level << ")");
                }
                LOG_INFO(LogModule::WEAK_MGR, "iface=" << x.ifName() << " tcp_loss_rate=" << x.tcpLossRate() << " tcp_loss_level=" << x.tcpLossLevel());
            }
            break;
        }
    }
    return changed;
}

// 创建或复用流量分析器，并为指定接口启动采样线程。
void WeakNetMgr::startTrafficAnalysis(const std::string& interface, int interval_seconds) {
    std::lock_guard<std::mutex> lock(traffic_analyzer_mutex_);
    if (!traffic_analyzer_) {
        traffic_analyzer_ = std::make_shared<TrafficAnalyzer>();
    }
    traffic_analyzer_->start(interface, interval_seconds);
    LOG_INFO(LogModule::WEAK_MGR, "Started traffic analysis for interface: " << interface);
}

// 停止已有流量分析线程；未创建分析器时为空操作。
void WeakNetMgr::stopTrafficAnalysis() {
    std::lock_guard<std::mutex> lock(traffic_analyzer_mutex_);
    if (traffic_analyzer_) {
        traffic_analyzer_->stop();
        LOG_INFO(LogModule::WEAK_MGR, "Stopped traffic analysis");
    }
}

// 获取聚合流量、Top Flow 和异常，并把总量写入当前出口接口。
bool WeakNetMgr::updateTrafficAnalysis(std::vector<NetInfo>& list) {
    const auto trafficAnalyzer = getTrafficAnalyzer();
    if (!trafficAnalyzer || !trafficAnalyzer->isRunning()) {
        return false;
    }

    bool changed = false;

    try {
        // 默认出口可能在运行期变化；按 usingNow 动态重写 BPF runtime ifindex，而不是长期绑定 eth0。
        std::string activeInterface;
        for (const auto& net : list) {
            if (net.usingNow()) {
                activeInterface = net.ifName();
                break;
            }
        }
        if (!activeInterface.empty()) {
            trafficAnalyzer->updateInterface(activeInterface);
        }

        // 实时总量来自 TrafficAnalyzer 的线程安全缓存。
        const auto observationState = trafficAnalyzer->getCurrentObservationState();
        const auto& stats = observationState.stats;

        // generation 1 只建立累计计数基线；采集降级也不能把零值伪装成真实无流量。
        if (!stats.valid) {
            LOG_INFO(LogModule::WEAK_MGR, "Traffic snapshot not ready: generation=" << stats.generation
                << " mode=" << stats.support.captureMode
                << " reason=" << stats.support.degradedReason);
            return false;
        }
        const uint32_t activeIfindex = activeInterface.empty()
            ? 0 : if_nametoindex(activeInterface.c_str());
        if (activeIfindex == 0 || stats.boundIfindex != activeIfindex) {
            LOG_INFO(LogModule::WEAK_MGR,
                     "Rejecting traffic stats from stale interface binding: active="
                     << activeInterface << " active_ifindex=" << activeIfindex
                     << " sampled_ifindex=" << stats.boundIfindex
                     << " generation=" << stats.generation);
            return false;
        }

        // 异常从同一 immutable generation 及历史派生，不再触发额外五秒采样。
        auto anomalies = trafficAnalyzer->detectAnomalies(observationState.snapshot);

        // 流量汇总只归属当前出口接口，其他接口保留原快照值。
        for (auto& net : list) {
            if (net.usingNow()) {
                // 一次性写入 Bps、Pps 和活跃流数，避免字段来源不同步。
                net.setTrafficStats(stats.totalBps, stats.totalPps, stats.activeFlows);

                // 异常只写日志，不改变 NetInfo 的基础流量指标。
                if (!anomalies.empty()) {
                    LOG_INFO(LogModule::WEAK_MGR, "Traffic anomalies detected on " << net.ifName()
                        << ": " << anomalies.size() << " anomalies");
                    for (const auto& anomaly : anomalies) {
                        LOG_INFO(LogModule::WEAK_MGR, "Anomaly: " << anomaly.anomalyType
                            << " severity: " << (anomaly.severity * 100) << "%");
                    }
                }

                LOG_INFO(LogModule::WEAK_MGR, "Updated traffic stats for " << net.ifName()
                    << ": " << (stats.totalBps / (1024*1024)) << " MB/s, "
                    << stats.activeFlows << " flows, " << stats.totalPps << " pps");

                changed = true;
                break;
            }
        }

    } catch (const std::exception& e) {
        LOG_ERROR(LogModule::WEAK_MGR, "Traffic analysis update error: " << e.what());
    }

    return changed;
}

// 返回共享分析器实例，允许只读诊断模块复用其查询接口。
std::shared_ptr<TrafficAnalyzer> WeakNetMgr::getTrafficAnalyzer() const {
    std::lock_guard<std::mutex> lock(traffic_analyzer_mutex_);
    return traffic_analyzer_;
}

// 在锁内复制当前接口列表，调用方获得独立且一致的快照。
std::vector<NetInfo> WeakNetMgr::getCurrentInterfaces() const {
    std::lock_guard<std::mutex> lock(iface_mutex_);
    return current_interfaces_;
}

// 在锁内整体替换接口列表，避免读线程观察到 vector 重建中间态。
void WeakNetMgr::updateInterfaces(const std::vector<NetInfo>& new_interfaces) {
    std::lock_guard<std::mutex> lock(iface_mutex_);
    current_interfaces_ = new_interfaces;
    LOG_INFO(LogModule::WEAK_MGR, "Updated interfaces list: " << current_interfaces_.size() << " interfaces");
}

// 合并和赋值在同一锁域，避免拓扑线程覆盖其他监控线程刚写入的指标。
std::vector<NetInfo> WeakNetMgr::mergeTopologySnapshot(
    const std::vector<NetInfo>& observed_topology) {
    std::lock_guard<std::mutex> lock(iface_mutex_);
    current_interfaces_ = mergeTopologyPreservingMetrics(current_interfaces_, observed_topology);
    return current_interfaces_;
}

// 串行化 RTT 与状态更新，保证多监控线程不同时修改 NetInfo。
bool WeakNetMgr::updateRttAndStateSafe(const std::string& host, int timeoutMs) {
    LOG_INFO(LogModule::WEAK_MGR, "updateRttAndStateSafe: acquiring lock");
    std::lock_guard<std::mutex> lock(iface_mutex_);
    LOG_INFO(LogModule::WEAK_MGR, "updateRttAndStateSafe: lock acquired, calling updateRttAndState");
    bool result = updateRttAndState(current_interfaces_, host, timeoutMs);
    LOG_INFO(LogModule::WEAK_MGR, "updateRttAndStateSafe: updateRttAndState completed, releasing lock");
    return result;
}

// 在共享接口锁内执行 RSSI 更新。
bool WeakNetMgr::updateWifiRssiSafe(const std::string& ctrlDir) {
    std::lock_guard<std::mutex> lock(iface_mutex_);
    return updateWifiRssi(current_interfaces_, ctrlDir);
}

// 在共享接口锁内更新指定接口 TCP 重传指标。
bool WeakNetMgr::updateTcpLossRateSafe(const std::string& iface_name, double loss_rate, const std::string& loss_level) {
    std::lock_guard<std::mutex> lock(iface_mutex_);
    return updateTcpLossRate(current_interfaces_, iface_name, loss_rate, loss_level);
}

// 在共享接口锁内把最新流量分析结果写回活动接口。
bool WeakNetMgr::updateTrafficAnalysisSafe() {
    std::lock_guard<std::mutex> lock(iface_mutex_);
    return updateTrafficAnalysis(current_interfaces_);
}

// 在共享接口锁内刷新当前默认出口标志。
bool WeakNetMgr::updateCurrentUsingSafe() {
    std::lock_guard<std::mutex> lock(iface_mutex_);
    return updateCurrentUsing(current_interfaces_, true);
}

}  // namespace weaknet_grpc
