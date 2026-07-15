// 网络事件总线：统一构造接口、连接方式、质量及指标变化事件并扇出。
// 本地回调同步执行，传输层发布器负责把事件交给 gRPC 订阅者。

#include "event_manager.hpp"

#include <atomic>
#include "server.hpp"
#include "common.hpp"
#include "logger.hpp"
#include <cstdio>
#include <chrono>
#include <thread>

using namespace std::chrono_literals;

namespace weaknet_grpc {

// 全局单例保证所有监控线程进入同一条事件分发链路。
static std::unique_ptr<NetworkEventManager> g_event_manager = std::make_unique<NetworkEventManager>();

// 返回进程级事件管理器引用，所有权仍由全局 unique_ptr 保持。
NetworkEventManager& getEventManager() {
    return *g_event_manager;
}

// 初始化为空上下文和停止状态，等待 ServerContext 注入后再向外发布。
NetworkEventManager::NetworkEventManager() 
    : server_ctx_(nullptr), monitoring_active_(false) {
    LOG_INFO(LogModule::EVENT_MGR, "NetworkEventManager initialized");
}

// 除 Changed 外按类型登记本地回调；同一类型按注册顺序执行，调用方负责避免并发修改。
void NetworkEventManager::registerCallback(EventType type, EventCallback callback) {
    switch (type) {
        case EventType::Changed:
            break;
        case EventType::InterfaceChanged:
            interface_callbacks_.push_back(callback);
            break;
        case EventType::ConnectionModeChanged:
            connection_mode_callbacks_.push_back(callback);
            break;
        case EventType::NetworkQualityChanged:
            network_quality_callbacks_.push_back(callback);
            break;
        case EventType::TcpLossRateChanged:
            tcp_loss_callbacks_.push_back(callback);
            break;
        case EventType::RttChanged:
            rtt_callbacks_.push_back(callback);
            break;
        case EventType::RssiChanged:
            rssi_callbacks_.push_back(callback);
            break;
        case EventType::TrafficObservation:
            traffic_observation_callbacks_.push_back(callback);
            break;
    }
    LOG_INFO(LogModule::EVENT_MGR, "registered callback for event type " << static_cast<int>(type));
}

// 除 Changed 外清空指定类型回调；调用方负责与 invokeCallbacks 串行化。
void NetworkEventManager::unregisterCallback(EventType type) {
    switch (type) {
        case EventType::Changed:
            break;
        case EventType::InterfaceChanged:
            interface_callbacks_.clear();
            break;
        case EventType::ConnectionModeChanged:
            connection_mode_callbacks_.clear();
            break;
        case EventType::NetworkQualityChanged:
            network_quality_callbacks_.clear();
            break;
        case EventType::TcpLossRateChanged:
            tcp_loss_callbacks_.clear();
            break;
        case EventType::RttChanged:
            rtt_callbacks_.clear();
            break;
        case EventType::RssiChanged:
            rssi_callbacks_.clear();
            break;
        case EventType::TrafficObservation:
            traffic_observation_callbacks_.clear();
            break;
    }
    LOG_INFO(LogModule::EVENT_MGR, "unregistered all callbacks for event type " << static_cast<int>(type));
}

// 将内部事件类型映射为兼容信号名称，未知专用类型回退到 Changed。
std::string NetworkEventManager::getSignalName(EventType type) const {
    switch (type) {
        case EventType::Changed:
            return kSignalChanged;
        case EventType::InterfaceChanged:
            return kSignalInterfaceChanged;
        case EventType::ConnectionModeChanged:
            return kSignalConnectionModeChanged;
        case EventType::NetworkQualityChanged:
            return kSignalNetworkQualityChanged;
        case EventType::TrafficObservation:
            return "TrafficObservation";
        default:
            return kSignalChanged; // 默认使用通用信号
    }
}

// 先同步通知本地观察者，再补全出站字段并交给传输层发布器。
// 多监控线程可同时进入此函数，但回调容器和下方静态计数器没有内部并发保护。
void NetworkEventManager::emitEvent(const NetworkEvent& event) {
    LOG_INFO(LogModule::EVENT_MGR, "emitting event: type=" << static_cast<int>(event.type) << ", message='" << event.message << "', source='" << event.source << "'");
    
    // 本地回调看到原始消息；source 前缀仅用于出站兼容文本。
    invokeCallbacks(event.type, event);
    
    if (server_ctx_ && server_ctx_->event_publisher) {
        // Changed 沿用调用方计数；其他类型使用非原子的进程内计数，只能当诊断元数据。
        static std::atomic<int32_t> eventCounter{0};
        NetworkEvent outbound = event;
        outbound.message = event.source.empty()
            ? event.message
            : "[" + event.source + "] " + event.message;
        outbound.counter = (event.type == EventType::Changed)
            ? event.counter : eventCounter.fetch_add(1, std::memory_order_relaxed);
        server_ctx_->event_publisher->publish(outbound);
    }
}

// 构造通用变化事件，并保留调用方提供的兼容计数器。
void NetworkEventManager::emitChanged(const std::string& message, int32_t counter, const std::string& source) {
    NetworkEvent event(EventType::Changed, message, source, 0);
    event.counter = counter;
    emitEvent(event);
}

// 构造高优先级接口拓扑变化事件。
void NetworkEventManager::emitInterfaceChanged(const std::string& message, const std::string& source) {
    emitEvent(NetworkEvent(EventType::InterfaceChanged, message, source, 8));
}

// 构造最高优先级的当前连接方式变化事件。
void NetworkEventManager::emitConnectionModeChanged(const std::string& message, const std::string& source) {
    emitEvent(NetworkEvent(EventType::ConnectionModeChanged, message, source, 9));
}

// 构造综合质量事件，并携带可机器解析的 details。
void NetworkEventManager::emitNetworkQualityChanged(const std::string& message, const std::string& details, const std::string& source) {
    NetworkEvent event(EventType::NetworkQualityChanged, message, source, 7);
    event.details = details;
    emitEvent(event);
}

// 构造 TCP 重传率变化事件。
void NetworkEventManager::emitTcpLossRateChanged(const std::string& message, const std::string& source) {
    emitEvent(NetworkEvent(EventType::TcpLossRateChanged, message, source, 6));
}

// 构造 RTT 变化事件。
void NetworkEventManager::emitRttChanged(const std::string& message, const std::string& source) {
    emitEvent(NetworkEvent(EventType::RttChanged, message, source, 5));
}

// 构造 Wi-Fi RSSI 变化事件。
void NetworkEventManager::emitRssiChanged(const std::string& message, const std::string& source) {
    emitEvent(NetworkEvent(EventType::RssiChanged, message, source, 4));
}

void NetworkEventManager::emitTrafficObservation(const std::string& message,
                                                 const std::string& details,
                                                 const std::string& source) {
    NetworkEvent event(EventType::TrafficObservation, message, source, 6);
    event.details = details;
    emitEvent(event);
}

// 绑定服务上下文并注册基础日志观察者，使后续事件可被传输层发布。
void NetworkEventManager::startEventMonitoring(struct ServerContext* ctx) {
    server_ctx_ = ctx;
    monitoring_active_ = true;
    
    LOG_INFO(LogModule::EVENT_MGR, "event monitoring started");
    
    // 默认回调只做审计日志，不改变事件内容或阻断传输层发布。
    registerCallback(EventType::InterfaceChanged, [](const NetworkEvent& event) {
        LOG_INFO(LogModule::EVENT_MGR, "Interface change event: " << event.message);
    });
    
    registerCallback(EventType::ConnectionModeChanged, [](const NetworkEvent& event) {
        LOG_INFO(LogModule::EVENT_MGR, "Connection mode change event: " << event.message);
    });
}

// 标记事件监控停止，供服务生命周期记录当前状态。
void NetworkEventManager::stopEventMonitoring() {
    monitoring_active_ = false;
    server_ctx_ = nullptr;
    LOG_INFO(LogModule::EVENT_MGR, "event monitoring stopped");
}

// 按事件类型顺序调用全部本地回调；Changed 当前没有本地回调容器。
void NetworkEventManager::invokeCallbacks(EventType type, const NetworkEvent& event) {
    switch (type) {
        case EventType::Changed:
            break;
        case EventType::InterfaceChanged:
            for (const auto& callback : interface_callbacks_) {
                callback(event);
            }
            break;
        case EventType::ConnectionModeChanged:
            for (const auto& callback : connection_mode_callbacks_) {
                callback(event);
            }
            break;
        case EventType::NetworkQualityChanged:
            for (const auto& callback : network_quality_callbacks_) {
                callback(event);
            }
            break;
        case EventType::TcpLossRateChanged:
            for (const auto& callback : tcp_loss_callbacks_) {
                callback(event);
            }
            break;
        case EventType::RttChanged:
            for (const auto& callback : rtt_callbacks_) {
                callback(event);
            }
            break;
        case EventType::RssiChanged:
            for (const auto& callback : rssi_callbacks_) {
                callback(event);
            }
            break;
        case EventType::TrafficObservation:
            for (const auto& callback : traffic_observation_callbacks_) {
                callback(event);
            }
            break;
    }
}

} // namespace weaknet_grpc
