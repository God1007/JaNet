// Linux 网络接口发现器：根据接口状态和默认路由筛选具备上网能力的网卡。
// 实例采用进程级共享所有权，查询结果以值返回供调用方保存快照。

#pragma once

#include <string>
#include <vector>
#include <mutex>
#include <memory>

// 对底层接口枚举逻辑提供线程安全单例入口。
class NetInterfaceManager {
public:
    // 返回线程安全懒加载的进程级共享实例。
    static std::shared_ptr<NetInterfaceManager> getInstance();

    // 返回当前具备上网能力的网卡名快照，即接口为 UP 且存在 IPv4/IPv6 默认路由。
    std::vector<std::string> getInternetInterfaces();

    // 单例通常随进程结束释放，不管理调用方返回的快照。
    ~NetInterfaceManager() = default;

private:
    // 仅允许 getInstance 创建单例。
    NetInterfaceManager() = default;
    // 禁止复制构造，确保底层查询器只有一个共享实例。
    NetInterfaceManager(const NetInterfaceManager&) = delete;
    // 禁止复制赋值。
    NetInterfaceManager& operator=(const NetInterfaceManager&) = delete;

    // call_once 标记和对应的进程级共享实例。
    static std::once_flag s_onceFlag;
    static std::shared_ptr<NetInterfaceManager> s_instance;
};
