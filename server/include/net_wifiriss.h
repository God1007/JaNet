// wpa_supplicant 控制接口客户端：通过 UNIX DGRAM 查询指定 Wi-Fi 接口的 RSSI。
// 单例持有套接字和连接路径状态，调用方应在共享使用时遵守实现的串行访问约束。

#pragma once

#include <string>
#include <memory>
#include <mutex>

// 管理本地控制套接字生命周期并封装 SIGNAL_POLL 命令。
class WiFiRssiClient {
public:
    // 构造时尚未连接远端控制接口。
    WiFiRssiClient();
    // 析构时关闭套接字并清理本地临时路径。
    ~WiFiRssiClient();

    // 返回线程安全懒加载的进程级共享实例。
    static std::shared_ptr<WiFiRssiClient> getInstance();

    // 连接 ctrlDir 下 ifaceName 对应端点；非线程安全，重复调用会覆盖现有 fd，调用方需避免并发和资源覆盖。
    bool connect(const std::string& ifaceName, const std::string& ctrlDir = "/var/run/wpa_supplicant");

    // 发送 SIGNAL_POLL 并解析 RSSI；成功值单位 dBm，失败返回哨兵值 -1000。
    int getRssi();

private:
    // 当前 UNIX DGRAM 套接字描述符，-1 表示未连接。
    int sockfd_ = -1;
    // 当前目标接口、控制目录和本地临时套接字路径。
    std::string iface_;
    std::string ctrlDir_;
    std::string localSockPath_;

    // call_once 标记和对应的进程级共享实例。
    static std::once_flag s_onceFlag;
    static std::shared_ptr<WiFiRssiClient> s_instance;

    // 创建并绑定本地 UNIX 套接字地址，成功返回 true。
    bool bindLocal();
    // 将套接字连接到 wpa_supplicant 远端控制地址，成功返回 true。
    bool connectRemote();
    // 同步发送控制命令并返回原始响应文本，失败时返回空字符串。
    std::string sendCommand(const std::string& cmd);
};
