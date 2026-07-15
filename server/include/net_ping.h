// 指定网络接口的 IPv4 ICMP Echo 探测器。
// Linux RAW ICMP 需要 root 或 CAP_NET_RAW；每次 ping 创建独立套接字，但共享序列号未同步。

#pragma once

#include <string>
#include <cstdint>
#include <memory>
#include <mutex>

// 封装主机解析、ICMP 报文构造以及 RTT 计算。
class NetPing {
public:
    // 构造时不隐式执行探测，也不持有单次请求的套接字。
    NetPing();
    // 析构时无需回收单次 ping 的套接字，因为调用会同步关闭它。
    ~NetPing();

    // 返回线程安全懒加载的进程级共享实例。
    static std::shared_ptr<NetPing> getInstance();

    // 经 ifaceName 对 host 执行 ICMP Echo；timeoutMs 和成功返回值单位均为毫秒。
    // double 返回值保留亚毫秒精度，失败仍返回分阶段负错误码。
    // 每次调用持有独立套接字并使用原子序列号匹配回包，可由监控线程和 RPC 并发调用。
    double ping(const std::string& host, const std::string& ifaceName, int timeoutMs = 1000);

    // 预留的显式初始化钩子；当前实现不改变状态。
    void Init();
    // 预留的显式关闭钩子；当前实现不改变状态。
    void Shutdown();

private:
    // 计算 ICMP 校验和；len 为参与计算的字节数。
    static uint16_t checksum(uint16_t* addr, int len);
    // 将 IPv4 文本或主机名解析到 out，成功返回 true。
    static bool resolveHostIPv4(const std::string& host, struct sockaddr_in& out);
    // 写入一份 Echo Request 报文并返回报文长度，id/seq 用于匹配响应。
    static int packIcmp(struct icmp* icmp, uint16_t id, uint16_t seq);

    // call_once 标记和对应的进程级共享实例。
    static std::once_flag s_onceFlag;
    static std::shared_ptr<NetPing> s_instance;
};
