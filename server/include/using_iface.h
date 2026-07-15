// 当前上网接口判定器：综合 IPv4/IPv6 默认路由和接口状态维护进程内快照。
// 后台监听由单例拥有，查询方法返回加锁后的当前状态副本。

#pragma once

#include <string>
#include <memory>
#include <mutex>
#include <cstdint>

// 当前上网方式的位标志，可组合表示同时存在 IPv4 和 IPv6 默认路由。
namespace UsingMethodFlag {
    static constexpr uint32_t IPv4Default = 0x1; // 存在 IPv4 默认路由
    static constexpr uint32_t IPv6Default = 0x2; // 存在 IPv6 默认路由
}

// rtnetlink 发布的真实默认出口世代；首次有效出口只建基线，不伪造切换事件。
struct RouteTransitionState {
    std::string currentInterface;
    std::string previousInterface;
    uint64_t generation = 0;
    int64_t changedAtUnixMs = 0;
};

// 管理平台监听线程与当前活动接口状态的进程级单例。
class UsingInterfaceManager {
public:
    // 返回线程安全懒加载的共享实例。
    static std::shared_ptr<UsingInterfaceManager> getInstance();

    // 启动后台路由监听；可重复调用且应保持幂等。
    void start();

    // 请求后台监听退出、唤醒 netlink recv 并 join；可重复调用。
    void stop();

    // 返回默认路由且状态为 UP 的当前接口名快照；无可用接口时返回空字符串。
    std::string getCurrentInterface();

    // 返回当前默认路由协议位图，位定义见 UsingMethodFlag。
    uint32_t getMethodFlags();

    // 原子读取当前/上一个默认出口及最近真实切换的世代与时间。
    RouteTransitionState getRouteTransitionState();

    // 停止并回收平台监听实现及其资源。
    ~UsingInterfaceManager();

private:
    // 构造平台实现，单例仅能通过 getInstance 创建。
    UsingInterfaceManager();
    // 禁止复制构造，确保后台监听只有一个所有者。
    UsingInterfaceManager(const UsingInterfaceManager&) = delete;
    // 禁止复制赋值。
    UsingInterfaceManager& operator=(const UsingInterfaceManager&) = delete;

    // call_once 标记和对应的进程级共享实例。
    static std::once_flag s_onceFlag;
    static std::shared_ptr<UsingInterfaceManager> s_instance;

    // 保护 currentIfName_ 和 methodFlags_ 的跨线程访问。
    std::mutex stateMutex_;
    // 串行化 start/stop/析构，worker 不在持有该锁时回调 owner。
    std::mutex lifecycleMutex_;
    // 最近一次判定出的接口名和默认路由协议位图。
    std::string currentIfName_;
    uint32_t methodFlags_ = 0;
    bool routeStateInitialized_ = false;
    std::string previousIfName_;
    // 跨短暂/真实空路由状态保留最近非空出口，避免 DEL-old/ADD-new 分批时 previous 退化为空。
    std::string lastNonEmptyIfName_;
    uint64_t routeGeneration_ = 0;
    int64_t routeChangedAtUnixMs_ = 0;

    // 平台实现由本类独占，生命周期与单例一致。
    struct Impl;
    Impl* impl_ = nullptr;
};
