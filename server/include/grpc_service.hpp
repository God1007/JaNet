// WeakNet gRPC 传输层：注册同步 RPC 服务并向流式订阅者分发网络事件。
// GrpcServer 由服务主流程创建并持有，生命周期覆盖全部 RPC 与订阅连接。

#pragma once

#include <condition_variable>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "event_manager.hpp"

namespace grpc {
class Server;
}  // namespace grpc

namespace weaknet_grpc {

class ServerContext;

// 同步 gRPC 服务封装，同时实现 EventPublisher 以接收监控线程产生的事件。
class GrpcServer final : public EventPublisher {
public:
    // 创建尚未监听端口的服务包装对象。
    GrpcServer();
    // 析构时尝试关闭底层 gRPC Server。
    ~GrpcServer() override;

    // 用 InsecureServerCredentials 监听 address；无 TLS/认证，非环回地址的暴露风险由调用方承担。
    // ctx 在服务停止前必须始终有效；启动成功返回 true。
    bool start(ServerContext* ctx, const std::string& address);
    // 阻塞当前线程直到底层 gRPC Server 完成关闭。
    void wait();
    // 幂等停止：先唤醒长流，再关闭底层 Server；可与 wait/destructor 并发。
    void shutdown();

    // 可由监控线程并发调用；按订阅过滤条件把事件加入各自的有界队列。
    void publish(const NetworkEvent& event) override;

private:
    // 单条流式连接的过滤条件、互斥量、条件变量与待发送队列。
    struct Subscriber;
    // weaknet.proto 生成的同步 Service 接口实现。
    class ServiceImpl;

    // 添加订阅者弱引用；调用方持有 Subscriber 的实际生命周期。
    void addSubscriber(const std::shared_ptr<Subscriber>& subscriber);
    // 移除目标订阅者以及已经失效的弱引用。
    void removeSubscriber(const std::shared_ptr<Subscriber>& subscriber);

    // 保护 subscribers_ 的跨 RPC、跨监控线程并发访问。
    std::mutex subscribers_mutex_;
    // 活跃订阅者弱引用集合，避免服务容器延长单条 RPC 的生命周期。
    std::vector<std::weak_ptr<Subscriber>> subscribers_;
    // Service 必须比已注册它的 grpc::Server 存活更久。
    std::unique_ptr<ServiceImpl> service_;
    // 保护 server_ 与 shutdown_started_；wait 只复制 shared_ptr 后释放锁再阻塞。
    std::mutex lifecycle_mutex_;
    std::condition_variable lifecycle_cv_;
    // shared ownership 防止 shutdown reset 时让并发 Wait 持有悬空 grpc::Server。
    std::shared_ptr<grpc::Server> server_;
    bool shutdown_started_ = false;
    bool shutdown_complete_ = false;
};

}  // namespace weaknet_grpc
