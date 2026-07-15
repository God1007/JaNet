// Linux TCP 统计采样与重传率代理值计算接口。
// retransSegs 接近累计计数，但 sock_diag 主路径的 outSegs 是瞬时近似值；结果不等同于真实链路丢包率。

#pragma once

#include <cstdint>
#include <memory>
#include <mutex>
#include <string>

// 一次 TCP 统计快照；具体口径取决于 sock_diag 或链路层回退路径。
struct TcpStats {
    uint64_t inSegs = 0;      // 接收段近似值；当前 sock_diag 路径没有填充，通常为 0
    uint64_t outSegs = 0;     // 未确认/重传/SACK 之和，必要时回退为接口累计 tx_packets
    uint64_t retransSegs = 0; // 各 TCP socket 的 tcpi_total_retrans 之和
    bool valid = false;       // 是否成功获得可参与计算的快照
};

// 两次 TCP 快照之间的重传率评估结果。
struct TcpLossResult {
    double ratePercent = 0.0;   // 重传百分比：(deltaRetrans / deltaOut) * 100
    uint64_t sentDelta = 0;     // 两次 outSegs 的差值；主路径下只能视为近似分母
    uint64_t retransDelta = 0;  // 窗口内重传报文段数量
    std::string level;          // 分级文本：good/degraded/poor/insufficient
};

// 线程安全懒加载的 TCP 重传率代理值计算器。
class TcpLossMonitor {
public:
    // 返回进程级共享实例。
    static std::shared_ptr<TcpLossMonitor> getInstance();

    // 通过 sock_diag 聚合全系统 IPv4/IPv6 TCP socket，成功返回 true 并填充 outStats。
    bool sample(TcpStats& outStats);
    // 按接口聚合 tcp_info；发送近似值为 0 时回退到该接口的链路层累计 tx_packets。
    bool sampleForInterface(const std::string& ifaceName, TcpStats& outStats);

    // 对两次快照做差并计算代理值；minSent 是最小分母，两个阈值单位均为百分比。
    TcpLossResult compute(const TcpStats& prev,
                          const TcpStats& curr,
                          uint64_t minSent = 10,
                          double degradedThresholdPct = 1.0,
                          double poorThresholdPct = 5.0);

private:
    // 单例仅能通过 getInstance 创建。
    TcpLossMonitor() = default;
    // call_once 标记和对应的进程级共享实例。
    static std::once_flag s_onceFlag;
    static std::shared_ptr<TcpLossMonitor> s_instance;
};
