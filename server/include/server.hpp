// WeakNet 服务生命周期与共享运行上下文定义。
// ServerContext 由 start_server 在栈上创建，其有效期必须覆盖全部工作线程和 RPC。

#pragma once

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "net_info.hpp"
#include "process_resource_sampler.hpp"

namespace weaknet_grpc {

class EventPublisher;
class NetInfo;
class WeakNetMgr;

// 服务端各监控线程、接口快照和跨模块依赖的聚合上下文。
struct ServerContext {
    // 工作线程退出开关；跨线程读写，true 表示继续运行。
    std::atomic<bool> running{true};

    // Engine 进程资源差分采样器；与 ServerContext 同寿命，保证 CPU 基线不会随 RPC 重建。
    ProcessResourceSampler process_resource_sampler;

    // 由上下文保存的全部可 join 监控线程；关闭时 requestStop 后逐一回收。
    std::thread iface_thread;
    std::thread using_thread;
    std::thread rtt_thread;
    std::thread rssi_thread;
    std::thread tcp_loss_thread;
    std::thread traffic_analysis_thread;
    std::thread network_quality_thread;

    // 所有周期线程共用的可中断等待；requestStop 会立即唤醒，避免退出最多卡住 15 秒。
    std::mutex stop_mutex;
    std::condition_variable stop_cv;

    void requestStop() {
        running.store(false);
        stop_cv.notify_all();
    }

    template <typename Rep, typename Period>
    bool waitForStop(const std::chrono::duration<Rep, Period>& interval) {
        std::unique_lock<std::mutex> lock(stop_mutex);
        return stop_cv.wait_for(lock, interval, [this] { return !running.load(); });
    }

    // 保护兼容接口快照 iface_list 的互斥量。
    std::mutex iface_mutex;
    // 最近一次接口快照；访问时必须持有 iface_mutex。
    std::vector<NetInfo> iface_list;

    // 指向当前事件传输层，不拥有对象；其生命周期由 start_server 管理。
    EventPublisher* event_publisher = nullptr;
    // 非拥有指针；start_server 的 unique_ptr 在线程全部 join 后才释放对象。
    WeakNetMgr* weak_mgr = nullptr;
};

// 持久化并发布通用 Changed 事件；counter 是调用方提供的变化计数。
void publishChangedEvent(ServerContext* ctx, const std::string& message, int32_t counter = 0);
// 创建接口集合轮询线程并把线程句柄写入 ctx->iface_thread。
void start_iface_monitor_thread(ServerContext* ctx);

// 初始化后由 sigwait 驱动 SIGINT/SIGTERM 优雅退出，并回收所有线程与拥有对象。
int start_server();

}  // namespace weaknet_grpc
