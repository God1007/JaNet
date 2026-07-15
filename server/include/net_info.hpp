// 单个网络接口的状态与诊断指标值对象。
// NetInfo 不自行采集数据、不加锁，通常由 WeakNetMgr 在互斥区内更新并按值生成快照。

#pragma once

#include <cstdint>
#include <string>

namespace weaknet_grpc {

// 网络接口介质类型。
enum class NetType {
    Unknown = 0,
    Ethernet,
    WiFi,
    Cellular,
};

// 网络接口是否可用的二态状态。
enum class NetState {
    Down = 0,
    Up,
};

// 依据 RTT 等指标归纳的链路质量等级。
enum class LinkQuality {
    Unknown = 0,
    Good,
    Fair,
    Poor,
    Bad
};

// 聚合一个接口的身份、活动状态、质量指标和流量统计。
class NetInfo {
public:
    // 创建字段均为默认值的接口对象。
    NetInfo() = default;
    // 创建指定接口名的对象，其余字段仍使用默认值。
    explicit NetInfo(std::string name) : ifname_(std::move(name)) {}

    // 更新接口名。
    void setIfName(const std::string& n) { ifname_ = n; }
    // 返回接口名的只读引用，引用有效期与本对象一致。
    const std::string& ifName() const { return ifname_; }

    // 标记该接口是否承载默认路由。
    void setDefaultRoute(bool v) { is_default_ = v; }
    // 返回默认路由标记。
    bool isDefaultRoute() const { return is_default_; }

    // 更新接口介质类型。
    void setType(NetType t) { type_ = t; }
    // 返回接口介质类型。
    NetType type() const { return type_; }

    // 更新最新 RTT，单位毫秒；double 用于保留亚毫秒精度，负值表示失败或尚未测量。
    void setRttMs(double rtt) { rtt_ms_ = rtt; }
    // 返回最新 RTT，单位毫秒，可包含小数。
    double rttMs() const { return rtt_ms_; }

    // 保存上一次 RTT，单位毫秒，可包含小数。
    void setPrevRttMs(double rtt) { prev_rtt_ms_ = rtt; }
    // 返回上一次 RTT，单位毫秒，可包含小数。
    double prevRttMs() const { return prev_rtt_ms_; }

    // 更新接口连通状态。
    void setState(NetState s) { state_ = s; }
    // 返回接口连通状态。
    NetState state() const { return state_; }

    // 更新归纳后的链路质量等级。
    void setQuality(LinkQuality q) { quality_ = q; }
    // 返回链路质量等级。
    LinkQuality quality() const { return quality_; }

    // 更新 Wi-Fi 信号强度，单位 dBm；非 Wi-Fi 或未知时可保留哨兵值。
    void setRssiDbm(int rssi) { rssi_dbm_ = rssi; }
    // 返回 Wi-Fi 信号强度，单位 dBm。
    int rssiDbm() const { return rssi_dbm_; }

    // 标记该接口是否为当前实际使用的上网接口。
    void setUsingNow(bool v) { using_now_ = v; }
    // 返回当前上网接口标记。
    bool usingNow() const { return using_now_; }

    // 更新 tcp_loss_rate 字段；当前采集器写入的是 TCP 重传率代理值，单位百分比，负值表示未知。
    void setTcpLossRate(double rate) { tcp_loss_rate_ = rate; }
    // 返回 tcp_loss_rate 字段；当前语义为 TCP 重传率代理值，单位百分比。
    double tcpLossRate() const { return tcp_loss_rate_; }
    
    // 更新 TCP 代理指标的等级文本。
    void setTcpLossLevel(const std::string& level) { tcp_loss_level_ = level; }
    // 返回 TCP 代理指标等级文本的只读引用。
    const std::string& tcpLossLevel() const { return tcp_loss_level_; }
    
    // 原子语义地更新一次流量统计快照；速率单位分别为 bytes/s 和 packets/s。
    void setTrafficStats(uint64_t totalBps, uint64_t totalPps, uint32_t activeFlows) {
        traffic_total_bps_ = totalBps;
        traffic_total_pps_ = totalPps;
        traffic_active_flows_ = activeFlows;
    }
    
    // 返回总字节速率，单位 bytes/s。
    uint64_t trafficTotalBps() const { return traffic_total_bps_; }
    // 返回总报文速率，单位 packets/s。
    uint64_t trafficTotalPps() const { return traffic_total_pps_; }
    // 返回当前活跃流数量。
    uint32_t trafficActiveFlows() const { return traffic_active_flows_; }

    // 仅按接口名判断两个对象是否代表同一网卡。
    bool sameKey(const NetInfo& other) const { return ifname_ == other.ifname_; }

    // 比较接口身份、路由、类型、RTT 和状态等关键基础字段。
    bool equals(const NetInfo& other) const {
        return ifname_ == other.ifname_ && is_default_ == other.is_default_ && type_ == other.type_ && rtt_ms_ == other.rtt_ms_ && state_ == other.state_;
    }

private:
    std::string ifname_;                    // 系统接口名
    bool is_default_ = false;               // 是否承载默认路由
    NetType type_ = NetType::Unknown;       // 接口介质类型
    double rtt_ms_ = -1.0;                  // 最新 RTT，单位毫秒；double 保留亚毫秒，-1 表示未知
    double prev_rtt_ms_ = -1.0;             // 上一次 RTT，单位毫秒；double 保留亚毫秒，-1 表示未知
    NetState state_ = NetState::Down;       // 当前连通状态
    bool using_now_ = false;                // 是否为当前实际使用的上网接口
    LinkQuality quality_ = LinkQuality::Unknown; // 归纳后的链路质量
    int rssi_dbm_ = -1000;                  // Wi-Fi RSSI，单位 dBm；-1000 表示不可用
    double tcp_loss_rate_ = -1.0;           // 字段名沿用 loss，当前保存 TCP 重传率代理值；-1 表示未知
    std::string tcp_loss_level_;             // good/degraded/poor/insufficient 等分级文本
    
    uint64_t traffic_total_bps_ = 0;        // 总字节速率，单位 bytes/s
    uint64_t traffic_total_pps_ = 0;        // 总报文速率，单位 packets/s
    uint32_t traffic_active_flows_ = 0;      // 活跃流数量
};

}  // namespace weaknet_grpc
