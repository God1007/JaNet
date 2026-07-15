// 网络事件管理器：把各监控模块产生的事件扇出给本地回调和 gRPC 传输层。
// 管理器为进程级单例，ServerContext 与 EventPublisher 均由服务主流程管理生命周期。

#pragma once

#include <chrono>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "net_info.hpp"
#include "net_traffic.h"

namespace weaknet_grpc {

// 服务内部使用的事件类别，与 weaknet.proto 的 EventType 一一对应。
enum class EventType {
    Changed,
    InterfaceChanged,
    ConnectionModeChanged,
    NetworkQualityChanged,
    TcpLossRateChanged,
    RttChanged,
    RssiChanged,
    TrafficObservation
};

// 一条内部事件值对象；字段可组装，发布时通常在线程间按值复制。
struct NetworkEvent {
    // 事件机器类型。
    EventType type;
    // 面向调用方的事件摘要。
    std::string message;
    // 事件创建时的系统时钟时间点。
    std::chrono::system_clock::time_point timestamp;
    // 生产模块或网络接口标识。
    std::string source;
    // 可选扩展详情，部分事件保存 JSON 文本。
    std::string details;
    // 事件优先级元数据；当前队列不按它调度或选择丢弃对象。
    int32_t priority = 0;
    // 诊断计数值，由生产者或事件管理器填充，不保证唯一或有序。
    int32_t counter = 0;
    // TrafficObservation 的机器可读载荷；details JSON 只用于旧客户端兼容。
    std::optional<TrafficObservationEvent> trafficObservation;

    // 默认构造供容器或后续逐字段填充使用。
    NetworkEvent() = default;
    // 创建事件并把 timestamp 初始化为当前系统时间。
    NetworkEvent(EventType t, const std::string& msg, const std::string& src = "", int32_t prio = 0)
        : type(t), message(msg), timestamp(std::chrono::system_clock::now()), source(src), priority(prio) {}
};

// 本地同步事件回调；在 emitEvent 的调用线程内执行。
using EventCallback = std::function<void(const NetworkEvent&)>;

// 事件传输抽象，由 gRPC 服务实现，调用方不转移 event 所有权。
class EventPublisher {
public:
    // 支持通过基类指针安全销毁具体 Publisher。
    virtual ~EventPublisher() = default;
    // 将事件发布到传输层；实现必须考虑多监控线程并发调用。
    virtual void publish(const NetworkEvent& event) = 0;
};

struct ServerContext;

// 进程内事件总线：负责回调注册、事件构造以及到 EventPublisher 的转发。
class NetworkEventManager {
public:
    // 创建尚未绑定 ServerContext 的管理器。
    NetworkEventManager();
    // 默认析构；不拥有 ServerContext 或 EventPublisher。
    ~NetworkEventManager() = default;

    // 除 Changed 外为 type 追加同步回调；容器无锁，注册不得与注销或事件分发并发执行。
    void registerCallback(EventType type, EventCallback callback);
    // 除 Changed 外清空 type 的全部回调；容器无锁，调用方必须与事件分发串行化。
    void unregisterCallback(EventType type);

    // 在当前线程执行本地回调并转发给已绑定的传输层。
    void emitEvent(const NetworkEvent& event);
    // 构造通用 Changed 事件后同步调用 emitEvent。
    void emitChanged(const std::string& message, int32_t counter = 0, const std::string& source = "");
    // 构造接口集合变化事件后同步调用 emitEvent。
    void emitInterfaceChanged(const std::string& message, const std::string& source = "");
    // 构造当前连接方式变化事件后同步调用 emitEvent。
    void emitConnectionModeChanged(const std::string& message, const std::string& source = "");
    // 构造综合质量变化事件，details 可携带 JSON 指标详情。
    void emitNetworkQualityChanged(const std::string& message, const std::string& details = "", const std::string& source = "");
    // 构造 TCP loss 命名的变化事件后同步调用 emitEvent；载荷当前是重传率代理值。
    void emitTcpLossRateChanged(const std::string& message, const std::string& source = "");
    // 构造 RTT 变化事件后同步调用 emitEvent。
    void emitRttChanged(const std::string& message, const std::string& source = "");
    // 构造 RSSI 变化事件后同步调用 emitEvent。
    void emitRssiChanged(const std::string& message, const std::string& source = "");
    // 构造 eBPF 低频生命周期/可信度事件；details 使用稳定 JSON。
    void emitTrafficObservation(const std::string& message,
                                const std::string& details,
                                const std::string& source = "traffic_observer");

    // 绑定服务上下文并注册默认日志回调；ctx 必须在监控停止前有效。
    void startEventMonitoring(ServerContext* ctx);
    // 标记停止并解绑非拥有 ServerContext，避免服务退出后留下悬空指针。
    void stopEventMonitoring();

private:
    // 按事件类型保存的同步回调列表。
    std::vector<EventCallback> interface_callbacks_;
    std::vector<EventCallback> connection_mode_callbacks_;
    std::vector<EventCallback> network_quality_callbacks_;
    std::vector<EventCallback> tcp_loss_callbacks_;
    std::vector<EventCallback> rtt_callbacks_;
    std::vector<EventCallback> rssi_callbacks_;
    std::vector<EventCallback> traffic_observation_callbacks_;

    // 非拥有型服务上下文指针，仅在服务生命周期内有效。
    ServerContext* server_ctx_ = nullptr;
    // 仅记录 start/stop 状态；emitEvent 当前不读取该标志。
    bool monitoring_active_ = false;

    // 根据事件类型同步遍历并调用对应回调列表。
    void invokeCallbacks(EventType type, const NetworkEvent& event);
    // 把内部事件类型映射为兼容的文本信号名。
    std::string getSignalName(EventType type) const;
};

// 返回进程级 NetworkEventManager 单例引用，引用有效至进程静态析构阶段。
NetworkEventManager& getEventManager();

}  // namespace weaknet_grpc
