// client.cpp
// WeakNet 客户端动态库实现：封装 gRPC unary/streaming 调用，并向外暴露稳定的 C ABI。

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <vector>

#include <grpcpp/grpcpp.h>

#include "common.hpp"
#include "logger.hpp"
#include "serializer.hpp"
#include "weaknet.grpc.pb.h"
#include "weaknet_client.h"

namespace weaknet_grpc {
namespace {

constexpr size_t kMaxQueuedEvents = 128;
constexpr int kConnectTimeoutMs = 5000;
constexpr int kUnaryTimeoutMs = 5000;
constexpr int kPingTimeoutMs = 15000;

// 只初始化一次客户端日志，避免宿主进程重复初始化 glog。
void initClientLogging() {
    static std::once_flag once;
    std::call_once(once, []() {
        if (!google::IsGoogleLoggingInitialized()) {
            FLAGS_logtostderr = false;
            FLAGS_alsologtostderr = false;
            FLAGS_minloglevel = static_cast<int>(google::GLOG_WARNING);
            google::InitGoogleLogging("weaknet-client");
        }
    });
}

// 优先读取环境变量，未配置时回退到本机默认 gRPC 地址。
std::string configuredGrpcAddress() {
    const char* configured = std::getenv("WEAKNET_GRPC_ADDRESS");
    if (configured && configured[0] != '\0') {
        return configured;
    }
    return kGrpcDefaultAddress;
}

// 将 proto 枚举统一转换为公共 C API 使用的事件名称。
std::string eventTypeName(weaknet::v1::EventType type, const std::string& fallback) {
    if (!fallback.empty()) {
        return fallback;
    }
    switch (type) {
        case weaknet::v1::EVENT_TYPE_CHANGED:
            return kSignalChanged;
        case weaknet::v1::EVENT_TYPE_INTERFACE_CHANGED:
            return kSignalInterfaceChanged;
        case weaknet::v1::EVENT_TYPE_CONNECTION_MODE_CHANGED:
            return kSignalConnectionModeChanged;
        case weaknet::v1::EVENT_TYPE_NETWORK_QUALITY_CHANGED:
            return kSignalNetworkQualityChanged;
        case weaknet::v1::EVENT_TYPE_TCP_LOSS_RATE_CHANGED:
            return "TcpLossRateChanged";
        case weaknet::v1::EVENT_TYPE_RTT_CHANGED:
            return "RttChanged";
        case weaknet::v1::EVENT_TYPE_RSSI_CHANGED:
            return "RssiChanged";
        default:
            return "Unknown";
    }
}

// 将事件压入有界队列；队列满时淘汰最旧事件，避免慢消费者导致内存无限增长。
template <typename T>
void pushBounded(std::deque<T>& queue, const T& event) {
    if (queue.size() >= kMaxQueuedEvents) {
        queue.pop_front();
    }
    queue.push_back(event);
}

// 安全地把 C++ 字符串复制到调用方提供的定长 C 缓冲区。
void writeCString(char* buffer, size_t size, const std::string& value) {
    if (!buffer || size == 0) {
        return;
    }
    std::snprintf(buffer, size, "%s", value.c_str());
}

// 为 unary RPC 设置统一 deadline，避免服务端异常时调用永久阻塞。
void setDeadline(grpc::ClientContext& context, int timeoutMs) {
    context.set_deadline(std::chrono::system_clock::now() + std::chrono::milliseconds(timeoutMs));
}

}  // namespace

// 管理 gRPC channel、stub、事件流线程以及回调和轮询共用的事件缓存。
class WeakNetClient {
public:
    // 默认构造时不连接，显式 connect 后才创建 gRPC 资源。
    WeakNetClient() = default;
    // 析构兜底关闭事件流和连接，避免调用方遗漏 cleanup 时泄漏线程。
    ~WeakNetClient() {
        disconnect();
    }

    // 建立 channel/stub，并在限定时间内等待服务端可达。
    bool connect() {
        std::lock_guard<std::mutex> lk(connectMutex_);
        if (connected_) {
            return true;
        }

        address_ = configuredGrpcAddress();
        channel_ = grpc::CreateChannel(address_, grpc::InsecureChannelCredentials());
        stub_ = weaknet::v1::WeakNet::NewStub(channel_);

        connected_ = channel_->WaitForConnected(std::chrono::system_clock::now() + std::chrono::milliseconds(kConnectTimeoutMs));
        if (!connected_) {
            LOG_ERROR(LogModule::CLIENT, "failed to connect to WeakNet gRPC server at " << address_);
            return false;
        }

        LOG_INFO(LogModule::CLIENT, "connected to WeakNet gRPC server at " << address_);
        return true;
    }

    // 先停止 streaming 线程，再释放 stub 和 channel，保证退出时不遗留后台访问。
    void disconnect() {
        stopEventStream();
        connected_ = false;
        stub_.reset();
        channel_.reset();
    }

    // 返回最近一次连接流程记录的连接状态。
    bool isConnected() const {
        return connected_;
    }

    // 调用 GetInterfaces，并把 repeated 字段转换为逗号分隔文本以兼容 C API。
    bool getInterfaces(std::string& result, std::string& errorMsg) {
        if (!ensureConnected(errorMsg)) {
            return false;
        }

        grpc::ClientContext context;
        setDeadline(context, kUnaryTimeoutMs);
        weaknet::v1::Empty request;
        weaknet::v1::GetInterfacesReply reply;
        grpc::Status status;
        {
            std::lock_guard<std::mutex> lk(rpcMutex_);
            status = stub_->GetInterfaces(&context, request, &reply);
        }
        if (!status.ok()) {
            errorMsg = "GetInterfaces failed: " + status.error_message();
            return false;
        }

        result.clear();
        for (int i = 0; i < reply.interfaces_size(); ++i) {
            if (!result.empty()) {
                result += ",";
            }
            result += reply.interfaces(i);
        }
        return true;
    }

    // 调用 HealthCheck，透传服务端 details 诊断结果。
    bool requestHealthCheck(std::string& result, std::string& errorMsg) {
        if (!ensureConnected(errorMsg)) {
            return false;
        }

        grpc::ClientContext context;
        setDeadline(context, kUnaryTimeoutMs);
        weaknet::v1::Empty request;
        weaknet::v1::HealthCheckReply reply;
        grpc::Status status;
        {
            std::lock_guard<std::mutex> lk(rpcMutex_);
            status = stub_->HealthCheck(&context, request, &reply);
        }
        if (!status.ok()) {
            errorMsg = "HealthCheck failed: " + status.error_message();
            return false;
        }

        result = reply.details();
        return true;
    }

    // 通过当前活动网卡执行服务端 Ping。返回值只表示 RPC 是否成功，探测失败信息仍放在 result 中。
    bool pingHost(const std::string& hostname, std::string& result, std::string& errorMsg) {
        if (!ensureConnected(errorMsg)) {
            return false;
        }
        if (hostname.empty()) {
            errorMsg = "hostname must not be empty";
            return false;
        }

        grpc::ClientContext context;
        setDeadline(context, kPingTimeoutMs);
        weaknet::v1::PingRequest request;
        request.set_hostname(hostname);
        weaknet::v1::PingReply reply;
        grpc::Status status;
        {
            std::lock_guard<std::mutex> lk(rpcMutex_);
            status = stub_->Ping(&context, request, &reply);
        }
        if (!status.ok()) {
            errorMsg = "Ping failed: " + status.error_message();
            return false;
        }

        result = reply.result();
        if (result.empty() && !reply.error().empty()) {
            result = reply.error();
        }
        return true;
    }

    // 离线读取服务端落盘的最新响应，兼容不经过实时 RPC 的旧调用方式。
    bool getLatestFromFile(std::string& result, std::string& errorMsg) {
        std::string fileErr;
        if (deserializeGetReplyFromFile(kGetReplySerializedFile, &result, &fileErr)) {
            return true;
        }

        ChangedPayload payload;
        if (deserializeChangedPayloadFromFile(kSignalSerializedFile, &payload, &fileErr)) {
            result = payload.message + " (counter=" + std::to_string(payload.counter) + ")";
            return true;
        }

        errorMsg = "failed to read serialized file: " + fileErr;
        return false;
    }

    // 非阻塞消费一条 Changed 事件；首次调用会按需启动共享事件流。
    bool checkForChanges(std::string& message, int32_t& counter) {
        startEventStream();
        std::lock_guard<std::mutex> lk(queueMutex_);
        if (changedQueue_.empty()) {
            return false;
        }
        auto event = changedQueue_.front();
        changedQueue_.pop_front();
        message = event.message;
        counter = event.counter;
        return true;
    }

    // 记录事件订阅和可选回调，并确保全局 gRPC streaming 已启动。
    bool subscribeToEvent(const std::string& eventType, weaknet_event_callback_t* callback) {
        if (!isConnected()) {
            return false;
        }
        {
            std::lock_guard<std::mutex> lk(callbackMutex_);
            subscribedEvents_.insert(eventType);
            if (callback) {
                eventCallbacks_[eventType] = callback;
            }
        }
        startEventStream();
        return true;
    }

    // 移除指定事件的过滤条件和回调，不影响其他订阅共享的事件流。
    bool unsubscribeEvent(const std::string& eventType) {
        std::lock_guard<std::mutex> lk(callbackMutex_);
        subscribedEvents_.erase(eventType);
        eventCallbacks_.erase(eventType);
        return true;
    }

    // 非阻塞消费一条通用事件，供轮询式 C API 使用。
    bool checkForEvents(std::string& eventType, std::string& message, int32_t& counter, std::string& source) {
        startEventStream();
        std::lock_guard<std::mutex> lk(queueMutex_);
        if (eventQueue_.empty()) {
            return false;
        }
        auto event = eventQueue_.front();
        eventQueue_.pop_front();
        eventType = event.eventType;
        message = event.message;
        counter = event.counter;
        source = event.source;
        return true;
    }

    // 注册网络质量专用回调，并复用同一条服务端事件流。
    bool subscribeToNetworkQuality(weaknet_network_quality_callback_t callback) {
        if (!isConnected()) {
            return false;
        }
        {
            std::lock_guard<std::mutex> lk(callbackMutex_);
            qualityCallback_ = callback;
        }
        startEventStream();
        return true;
    }

    // 非阻塞消费一条网络质量事件；无数据时通过 errorMsg 告知调用方。
    bool checkNetworkQuality(std::string& quality, std::string& details, int32_t& counter, std::string& errorMsg) {
        if (!ensureConnected(errorMsg)) {
            return false;
        }

        startEventStream();
        std::lock_guard<std::mutex> lk(queueMutex_);
        if (qualityQueue_.empty()) {
            errorMsg = "no network quality event available";
            return false;
        }
        auto event = qualityQueue_.front();
        qualityQueue_.pop_front();
        quality = event.quality;
        details = event.details;
        counter = event.counter;
        return true;
    }

private:
    // Changed 事件的最小缓存结构。
    struct ChangedEvent {
        std::string message;
        int32_t counter = 0;
    };

    // 通用事件缓存结构，保留类型、来源和计数器。
    struct GenericEvent {
        std::string eventType;
        std::string message;
        int32_t counter = 0;
        std::string source;
    };

    // 网络质量事件缓存结构，保留质量等级和结构化详情。
    struct NetworkQualityEvent {
        std::string quality;
        std::string details;
        int32_t counter = 0;
    };

    // 在发起 RPC 前统一检查 channel/stub 是否仍然有效。
    bool ensureConnected(std::string& errorMsg) const {
        if (!connected_ || !stub_) {
            errorMsg = "client is not connected";
            return false;
        }
        return true;
    }

    // 幂等启动 server-streaming 线程；断流后按一秒退避持续重连。
    void startEventStream() {
        bool expected = false;
        if (!streamRunning_.compare_exchange_strong(expected, true)) {
            return;
        }

        streamThread_ = std::thread([this]() {
            while (streamRunning_) {
                // 每轮重连都创建独立 ClientContext，供清理线程安全取消当前阻塞读取。
                grpc::ClientContext context;
                {
                    std::lock_guard<std::mutex> lk(streamContextMutex_);
                    activeStreamContext_ = &context;
                }

                // RPC 创建和其他 stub 调用串行化，随后在后台线程持续读取事件。
                weaknet::v1::EventRequest request;
                std::unique_ptr<grpc::ClientReader<weaknet::v1::NetworkEvent>> reader;
                {
                    std::lock_guard<std::mutex> lk(rpcMutex_);
                    if (!stub_) {
                        break;
                    }
                    reader = stub_->SubscribeEvents(&context, request);
                }

                // Read 阻塞到事件、断流或取消；退出后 Finish 获取最终 gRPC 状态。
                weaknet::v1::NetworkEvent event;
                while (streamRunning_ && reader->Read(&event)) {
                    handleEvent(event);
                }
                grpc::Status status = reader->Finish();

                {
                    std::lock_guard<std::mutex> lk(streamContextMutex_);
                    if (activeStreamContext_ == &context) {
                        activeStreamContext_ = nullptr;
                    }
                }

                // 仅当仍要求运行且异常断流时退避重连，主动清理不会重启流。
                if (streamRunning_ && !status.ok()) {
                    LOG_ERROR(LogModule::CLIENT, "event stream closed: " << status.error_message());
                    std::this_thread::sleep_for(std::chrono::seconds(1));
                }
            }
        });
    }

    // 原子关闭事件流，通过 TryCancel 唤醒阻塞 Read，并等待后台线程退出。
    void stopEventStream() {
        if (!streamRunning_.exchange(false)) {
            return;
        }

        {
            std::lock_guard<std::mutex> lk(streamContextMutex_);
            if (activeStreamContext_) {
                activeStreamContext_->TryCancel();
            }
        }

        if (streamThread_.joinable()) {
            streamThread_.join();
        }
    }

    // 将一条 proto 事件分发到有界队列和用户回调，回调始终在锁外执行。
    void handleEvent(const weaknet::v1::NetworkEvent& event) {
        const std::string eventName = eventTypeName(event.type(), event.event_type());
        const std::string message = event.message();
        const int32_t counter = event.counter();

        // 锁内只复制回调指针和订阅状态，避免用户代码在 callbackMutex_ 下运行。
        weaknet_event_callback_t* genericCallback = nullptr;
        weaknet_network_quality_callback_t qualityCallback = nullptr;
        bool genericCallbackAllowed = false;
        // 同一事件按语义进入 Changed、质量或通用轮询队列。
        {
            std::lock_guard<std::mutex> lk(callbackMutex_);
            auto callbackIt = eventCallbacks_.find(eventName);
            if (callbackIt != eventCallbacks_.end()) {
                genericCallback = callbackIt->second;
            }
            genericCallbackAllowed = subscribedEvents_.empty() || subscribedEvents_.count(eventName) > 0;
            qualityCallback = qualityCallback_;
        }

        {
            std::lock_guard<std::mutex> lk(queueMutex_);
            if (eventName == kSignalChanged) {
                pushBounded(changedQueue_, ChangedEvent{message, counter});
            } else if (eventName == kSignalNetworkQualityChanged) {
                pushBounded(qualityQueue_, NetworkQualityEvent{message, event.details(), counter});
            }

            if (eventName != kSignalChanged && genericCallbackAllowed) {
                pushBounded(eventQueue_, GenericEvent{eventName, message, counter, event.source()});
            }
        }

        // 回调在缓存更新完成且所有内部锁释放后执行，降低死锁和重入风险。
        if (genericCallback && genericCallbackAllowed) {
            genericCallback(eventName.c_str(), message.c_str(), counter, event.source().c_str());
        }

        if (eventName == kSignalNetworkQualityChanged && qualityCallback) {
            if (!qualityCallback(message.c_str(), event.details().c_str(), counter)) {
                std::lock_guard<std::mutex> lk(callbackMutex_);
                qualityCallback_ = nullptr;
            }
        }
    }

    std::string address_;
    std::shared_ptr<grpc::Channel> channel_;
    std::unique_ptr<weaknet::v1::WeakNet::Stub> stub_;
    std::atomic<bool> connected_{false};

    mutable std::mutex connectMutex_;
    std::mutex rpcMutex_;
    std::mutex queueMutex_;
    std::mutex callbackMutex_;
    std::mutex streamContextMutex_;
    grpc::ClientContext* activeStreamContext_ = nullptr;

    std::atomic<bool> streamRunning_{false};
    std::thread streamThread_;

    std::deque<ChangedEvent> changedQueue_;
    std::deque<GenericEvent> eventQueue_;
    std::deque<NetworkQualityEvent> qualityQueue_;
    std::set<std::string> subscribedEvents_;
    std::map<std::string, weaknet_event_callback_t*> eventCallbacks_;
    weaknet_network_quality_callback_t qualityCallback_ = nullptr;
};

// C ABI 保持单例语义，所有公开函数共享同一个 WeakNetClient 实例。
static WeakNetClient* g_client = nullptr;

}  // namespace weaknet_grpc

using weaknet_grpc::writeCString;

// 初始化全局客户端并建立 gRPC 连接；重复初始化直接复用现有实例。
extern "C" bool weaknet_init() {
    weaknet_grpc::initClientLogging();

    if (weaknet_grpc::g_client) {
        return weaknet_grpc::g_client->isConnected();
    }

    weaknet_grpc::g_client = new weaknet_grpc::WeakNetClient();
    if (!weaknet_grpc::g_client->connect()) {
        delete weaknet_grpc::g_client;
        weaknet_grpc::g_client = nullptr;
        return false;
    }
    return true;
}

// 停止后台事件流并销毁全局客户端，供宿主退出前显式释放资源。
extern "C" void weaknet_cleanup() {
    if (weaknet_grpc::g_client) {
        weaknet_grpc::g_client->disconnect();
        delete weaknet_grpc::g_client;
        weaknet_grpc::g_client = nullptr;
    }
}

// 查询全局客户端当前是否处于已连接状态。
extern "C" bool weaknet_is_connected() {
    return weaknet_grpc::g_client && weaknet_grpc::g_client->isConnected();
}

// 获取接口名称列表，并把 C++ 结果安全写入调用方缓冲区。
extern "C" bool weaknet_get_interfaces(char* buffer, size_t buffer_size, char* error_buffer, size_t error_size) {
    if (!weaknet_grpc::g_client || !weaknet_grpc::g_client->isConnected()) {
        writeCString(error_buffer, error_size, "client is not connected");
        return false;
    }

    std::string result;
    std::string errorMsg;
    if (!weaknet_grpc::g_client->getInterfaces(result, errorMsg)) {
        writeCString(error_buffer, error_size, errorMsg);
        return false;
    }
    writeCString(buffer, buffer_size, result);
    return true;
}

// 获取服务端健康诊断详情，并维持 C 风格结果/错误双缓冲区约定。
extern "C" bool weaknet_health_check(char* result_buffer, size_t result_size, char* error_buffer, size_t error_size) {
    if (!weaknet_grpc::g_client || !weaknet_grpc::g_client->isConnected()) {
        writeCString(error_buffer, error_size, "client is not connected");
        return false;
    }

    std::string result;
    std::string errorMsg;
    if (!weaknet_grpc::g_client->requestHealthCheck(result, errorMsg)) {
        writeCString(error_buffer, error_size, errorMsg);
        return false;
    }
    writeCString(result_buffer, result_size, result);
    return true;
}

// 从兼容序列化文件读取最新状态，不要求发起实时 RPC。
extern "C" bool weaknet_get_from_file(char* buffer, size_t buffer_size, char* error_buffer, size_t error_size) {
    if (!weaknet_grpc::g_client) {
        writeCString(error_buffer, error_size, "client is not connected");
        return false;
    }

    std::string result;
    std::string errorMsg;
    if (!weaknet_grpc::g_client->getLatestFromFile(result, errorMsg)) {
        writeCString(error_buffer, error_size, errorMsg);
        return false;
    }
    writeCString(buffer, buffer_size, result);
    return true;
}

// 校验主机参数后转发 Ping RPC，并返回可读结果。
extern "C" bool weaknet_ping_host(const char* hostname, char* result_buffer, size_t result_size, char* error_buffer, size_t error_size) {
    if (!weaknet_grpc::g_client || !weaknet_grpc::g_client->isConnected()) {
        writeCString(error_buffer, error_size, "client is not connected");
        return false;
    }
    if (!hostname || std::strlen(hostname) == 0) {
        writeCString(error_buffer, error_size, "hostname must not be empty");
        return false;
    }

    std::string result;
    std::string errorMsg;
    if (!weaknet_grpc::g_client->pingHost(hostname, result, errorMsg)) {
        writeCString(error_buffer, error_size, errorMsg);
        return false;
    }
    writeCString(result_buffer, result_size, result);
    return true;
}

// 非阻塞轮询一条 Changed 事件，无事件时返回 false 和说明信息。
extern "C" bool weaknet_check_changes(char* message_buffer, size_t message_size, int32_t* counter, char* error_buffer, size_t error_size) {
    if (!weaknet_grpc::g_client || !weaknet_grpc::g_client->isConnected()) {
        writeCString(error_buffer, error_size, "client is not connected");
        return false;
    }

    std::string message;
    int32_t localCounter = 0;
    if (!weaknet_grpc::g_client->checkForChanges(message, localCounter)) {
        writeCString(error_buffer, error_size, "no new state changes");
        return false;
    }
    writeCString(message_buffer, message_size, message);
    if (counter) {
        *counter = localCounter;
    }
    return true;
}

// 订阅指定事件，可选择同时注册立即回调。
extern "C" bool weaknet_subscribe_event(const char* event_type, weaknet_event_callback_t callback) {
    if (!weaknet_grpc::g_client || !weaknet_grpc::g_client->isConnected() || !event_type) {
        return false;
    }
    return weaknet_grpc::g_client->subscribeToEvent(event_type, callback);
}

// 取消指定事件订阅及其回调。
extern "C" bool weaknet_unsubscribe_event(const char* event_type) {
    if (!weaknet_grpc::g_client || !event_type) {
        return false;
    }
    return weaknet_grpc::g_client->unsubscribeEvent(event_type);
}

// 返回当前客户端支持的固定事件类型清单。
extern "C" bool weaknet_get_event_types(char* buffer, size_t buffer_size, char*, size_t) {
    writeCString(buffer, buffer_size,
                 "Changed,InterfaceChanged,ConnectionModeChanged,NetworkQualityChanged,TcpLossRateChanged,RttChanged,RssiChanged");
    return true;
}

// 非阻塞轮询一条通用事件，并分别写出类型、消息、计数器和来源。
extern "C" bool weaknet_check_events(char* event_type_buffer, size_t event_type_size,
                                     char* message_buffer, size_t message_size,
                                     int32_t* counter, char* source_buffer, size_t source_size,
                                     char* error_buffer, size_t error_size) {
    if (!weaknet_grpc::g_client || !weaknet_grpc::g_client->isConnected()) {
        writeCString(error_buffer, error_size, "client is not connected");
        return false;
    }

    std::string eventType;
    std::string message;
    std::string source;
    int32_t localCounter = 0;
    if (!weaknet_grpc::g_client->checkForEvents(eventType, message, localCounter, source)) {
        writeCString(error_buffer, error_size, "no event available");
        return false;
    }

    writeCString(event_type_buffer, event_type_size, eventType);
    writeCString(message_buffer, message_size, message);
    writeCString(source_buffer, source_size, source);
    if (counter) {
        *counter = localCounter;
    }
    return true;
}

// 注册网络质量事件专用回调。
extern "C" bool weaknet_subscribe_network_quality(weaknet_network_quality_callback_t callback) {
    if (!weaknet_grpc::g_client || !weaknet_grpc::g_client->isConnected()) {
        return false;
    }
    return weaknet_grpc::g_client->subscribeToNetworkQuality(callback);
}

// 非阻塞轮询一条网络质量事件及其详情。
extern "C" bool weaknet_check_network_quality(char* quality_buffer, size_t quality_size,
                                              char* details_buffer, size_t details_size,
                                              int32_t* counter, char* error_buffer, size_t error_size) {
    if (!weaknet_grpc::g_client || !weaknet_grpc::g_client->isConnected()) {
        writeCString(error_buffer, error_size, "client is not connected");
        return false;
    }

    std::string quality;
    std::string details;
    std::string errorMsg;
    int32_t localCounter = 0;
    if (!weaknet_grpc::g_client->checkNetworkQuality(quality, details, localCounter, errorMsg)) {
        writeCString(error_buffer, error_size, errorMsg);
        return false;
    }

    writeCString(quality_buffer, quality_size, quality);
    writeCString(details_buffer, details_size, details);
    if (counter) {
        *counter = localCounter;
    }
    return true;
}

// 返回对外稳定的客户端库版本字符串。
extern "C" bool weaknet_get_version(char* buffer, size_t buffer_size) {
    writeCString(buffer, buffer_size, "WeakNet Client Library v2.0.0");
    return true;
}

// 返回编译时间和关键构建能力，便于排查二进制版本。
extern "C" bool weaknet_get_build_info(char* buffer, size_t buffer_size) {
    std::string info = std::string("Built: ") + __DATE__ + " " + __TIME__ + " | gRPC-enabled | C++17";
    writeCString(buffer, buffer_size, info);
    return true;
}
