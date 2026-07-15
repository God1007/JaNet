// 真实事件链路压力驱动器：启动生产 GrpcServer，并把进程级 NetworkEventManager 绑定给它。
// benchmark 客户端通过仅监听本机的轻量控制协议注入可追踪事件，实际经过
// emitEvent -> EventPublisher::publish -> GrpcServer 有界订阅队列；无需污染生产 proto。

#include <arpa/inet.h>
#include <charconv>
#include <csignal>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <limits>
#include <poll.h>
#include <string>
#include <string_view>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

#include <atomic>
#include <chrono>
#include <thread>

#include "benchmark_support.hpp"
#include "event_manager.hpp"
#include "grpc_service.hpp"
#include "logger.hpp"
#include "server.hpp"

namespace {

using weaknet_benchmark::jsonEscape;
using weaknet_grpc::EventType;
using weaknet_grpc::GrpcServer;
using weaknet_grpc::Logger;
using weaknet_grpc::LogLevel;
using weaknet_grpc::NetworkEvent;
using weaknet_grpc::ServerContext;
using weaknet_grpc::getEventManager;

constexpr std::uint64_t kMaxEventsPerCommand = 100000;
constexpr std::uint64_t kMaxIntervalUs = 1000000;
constexpr std::uint64_t kMaxPayloadBytes = 65536;
constexpr std::size_t kMaxControlLineBytes = 4096;

// 信号处理与 SHUTDOWN 命令共享的退出标志；relaxed 足够表达单一布尔终止条件。
std::atomic<bool> g_running{true};

// 信号处理器只写原子变量，避免在异步信号上下文调用非 signal-safe 清理函数。
void handleSignal(int) {
    g_running.store(false, std::memory_order_relaxed);
}

// 驱动器同时监听生产 gRPC 地址和测试控制地址，默认都限制在 loopback。
struct Options {
    std::string grpc_address = "127.0.0.1:50051";
    std::string control_address = "127.0.0.1:50052";
    bool help = false;
};

// 输出控制驱动器的独立命令行格式。
const char* usage(const char* program) {
    static thread_local std::string text;
    text = std::string("usage: ") + program
        + " [--grpc-address IPv4:PORT] [--control-address IPv4:PORT]";
    return text.c_str();
}

// 解析两个监听地址；实际 IPv4/端口合法性在创建控制 socket 时继续严格验证。
bool parseOptions(int argc, char** argv, Options& options, std::string& error) {
    for (int index = 1; index < argc; ++index) {
        const std::string argument = argv[index];
        if (argument == "--help" || argument == "-h") {
            options.help = true;
            return true;
        }
        if (argument == "--grpc-address" || argument == "--control-address") {
            if (++index >= argc) {
                error = argument + " requires a value";
                return false;
            }
            if (argument == "--grpc-address") options.grpc_address = argv[index];
            else options.control_address = argv[index];
            continue;
        }
        error = "unknown argument: " + argument;
        return false;
    }
    return true;
}

// 把 IPv4:PORT 文本转换为 sockaddr_in；控制面故意不接受域名或隐式解析。
bool parseIpv4Address(const std::string& value,
                      sockaddr_in& address,
                      std::string& error) {
    const std::size_t separator = value.rfind(':');
    if (separator == std::string::npos || separator == 0 || separator + 1 >= value.size()) {
        error = "address must be IPv4:PORT: " + value;
        return false;
    }

    const std::string host = value.substr(0, separator);
    const std::string port_text = value.substr(separator + 1);
    unsigned int port = 0;
    const char* begin = port_text.data();
    const char* end = begin + port_text.size();
    const auto conversion = std::from_chars(begin, end, port);
    if (conversion.ec != std::errc() || conversion.ptr != end || port == 0 || port > 65535) {
        error = "invalid TCP port in address: " + value;
        return false;
    }

    std::memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_port = htons(static_cast<std::uint16_t>(port));
    if (inet_pton(AF_INET, host.c_str(), &address.sin_addr) != 1) {
        error = "control address host must be an IPv4 literal: " + host;
        return false;
    }
    return true;
}

// 创建单线程控制面的 TCP listener；SO_REUSEADDR 便于连续重复压测。
int createControlSocket(const std::string& value, std::string& error) {
    sockaddr_in address{};
    if (!parseIpv4Address(value, address, error)) return -1;

    const int descriptor = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (descriptor < 0) {
        error = "socket failed: " + std::string(std::strerror(errno));
        return -1;
    }

    const int enabled = 1;
    setsockopt(descriptor, SOL_SOCKET, SO_REUSEADDR, &enabled, sizeof(enabled));
    if (bind(descriptor, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) != 0) {
        error = "bind(" + value + ") failed: " + std::string(std::strerror(errno));
        close(descriptor);
        return -1;
    }
    if (listen(descriptor, 8) != 0) {
        error = "listen failed: " + std::string(std::strerror(errno));
        close(descriptor);
        return -1;
    }
    return descriptor;
}

// 完整写出一条响应，正确处理短写和 EINTR；连接关闭由调用方统一负责。
bool sendAll(int descriptor, const std::string& value) {
    std::size_t offset = 0;
    while (offset < value.size()) {
        const ssize_t written = send(descriptor,
                                     value.data() + offset,
                                     value.size() - offset,
                                     MSG_NOSIGNAL);
        if (written < 0 && errno == EINTR) continue;
        if (written <= 0) return false;
        offset += static_cast<std::size_t>(written);
    }
    return true;
}

// 每个连接只读取一条以换行结尾的命令，并设置超时/长度上限防止控制面被拖死。
bool receiveLine(int descriptor, std::string& line, std::string& error) {
    timeval timeout{};
    timeout.tv_sec = 5;
    setsockopt(descriptor, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    line.clear();
    char buffer[512];
    while (line.size() <= kMaxControlLineBytes) {
        const ssize_t received = recv(descriptor, buffer, sizeof(buffer), 0);
        if (received < 0 && errno == EINTR) continue;
        if (received < 0) {
            error = "recv failed: " + std::string(std::strerror(errno));
            return false;
        }
        if (received == 0) {
            error = "control connection closed before newline";
            return false;
        }
        const char* newline = static_cast<const char*>(
            std::memchr(buffer, '\n', static_cast<std::size_t>(received)));
        if (newline) {
            line.append(buffer, static_cast<std::size_t>(newline - buffer));
            return true;
        }
        line.append(buffer, static_cast<std::size_t>(received));
    }
    error = "control line exceeds " + std::to_string(kMaxControlLineBytes) + " bytes";
    return false;
}

// 控制协议使用 tab 分隔，避免 payload/标识中的普通空格造成歧义。
std::vector<std::string> splitTabs(const std::string& line) {
    std::vector<std::string> fields;
    std::size_t offset = 0;
    while (true) {
        const std::size_t separator = line.find('\t', offset);
        if (separator == std::string::npos) {
            fields.push_back(line.substr(offset));
            return fields;
        }
        fields.push_back(line.substr(offset, separator - offset));
        offset = separator + 1;
    }
}

// run_id/phase 仅允许安全 token，既便于日志关联，也避免控制字符进入 JSON 和日志。
bool validToken(std::string_view value) {
    if (value.empty() || value.size() > 120) return false;
    for (const unsigned char character : value) {
        if (!((character >= 'a' && character <= 'z')
              || (character >= 'A' && character <= 'Z')
              || (character >= '0' && character <= '9')
              || character == '.' || character == '_' || character == '-')) {
            return false;
        }
    }
    return true;
}

// 用 from_chars 做无 locale、无符号且有上界的数值解析。
bool parseBoundedUnsigned(const std::string& text,
                          std::uint64_t maximum,
                          std::uint64_t& value) {
    if (text.empty()) return false;
    const char* begin = text.data();
    const char* end = begin + text.size();
    const auto conversion = std::from_chars(begin, end, value);
    return conversion.ec == std::errc() && conversion.ptr == end && value <= maximum;
}

// 事件 details 中携带 wall-clock 纳秒，供进程外客户端估算注入到接收的端到端延迟。
std::uint64_t unixNanosecondsNow() {
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
}

// 统一控制协议错误响应，保证消息经过 JSON 转义且以换行结束。
std::string errorResponse(const std::string& message) {
    return "{\"ok\":false,\"error\":" + jsonEscape(message) + "}\n";
}

// 为普通注入生成单调递增 counter；固定 tuple 模式则让整批事件复用同一个 counter。
std::atomic<std::uint32_t> g_event_ordinal{1};

// 执行 INJECT/INJECT_FIXED_TUPLE：构造真实 NetworkEvent，注入后返回数量和时间边界。
std::string injectEvents(const std::vector<std::string>& fields, bool fixed_identity_tuple) {
    if (fields.size() != 6) {
        return errorResponse(
            "INJECT requires RUN_ID, PHASE, COUNT, INTERVAL_US and PAYLOAD_BYTES");
    }
    const std::string& run_id = fields[1];
    const std::string& phase = fields[2];
    if (!validToken(run_id) || !validToken(phase)) {
        return errorResponse("RUN_ID and PHASE must match [A-Za-z0-9._-]{1,120}");
    }

    std::uint64_t count = 0;
    std::uint64_t interval_us = 0;
    std::uint64_t payload_bytes = 0;
    if (!parseBoundedUnsigned(fields[3], kMaxEventsPerCommand, count) || count == 0) {
        return errorResponse("COUNT must be in [1,100000]");
    }
    if (!parseBoundedUnsigned(fields[4], kMaxIntervalUs, interval_us)) {
        return errorResponse("INTERVAL_US must be in [0,1000000]");
    }
    if (!parseBoundedUnsigned(fields[5], kMaxPayloadBytes, payload_bytes)) {
        return errorResponse("PAYLOAD_BYTES must be in [0,65536]");
    }

    const std::string payload(static_cast<std::size_t>(payload_bytes), 'x');
    const auto started = std::chrono::steady_clock::now();
    std::uint64_t first_injected_at = 0;
    std::uint64_t last_injected_at = 0;
    std::uint32_t first_ordinal = 0;
    std::uint32_t last_ordinal = 0;
    const std::uint32_t fixed_ordinal = fixed_identity_tuple
        ? g_event_ordinal.fetch_add(1, std::memory_order_relaxed) : 0;
    const auto fixed_timestamp = std::chrono::system_clock::now();

    // 协议字段：run_id + phase 标识一轮场景，sequence 标识该轮顺序，
    // injected_at_unix_ns 用于延迟关联，payload 用于施加可控消息体压力。
    for (std::uint64_t sequence = 0; sequence < count; ++sequence) {
        const std::uint64_t injected_at = unixNanosecondsNow();
        const std::uint32_t ordinal = fixed_identity_tuple
            ? fixed_ordinal : g_event_ordinal.fetch_add(1, std::memory_order_relaxed);
        if (sequence == 0) {
            first_injected_at = injected_at;
            first_ordinal = ordinal;
        }
        last_injected_at = injected_at;
        last_ordinal = ordinal;

        NetworkEvent event(
            EventType::Changed,
            "weaknet-event-benchmark:" + run_id + ':' + phase + ':' + std::to_string(sequence),
            "event_pipeline_driver",
            0);
        // 固定 tuple 模式刻意保持 Dashboard normalizeEvent 使用的
        // (timestamp,counter,type) 完全相同，而 sequence/message 继续变化；这样可在不改
        // 生产代码和 protobuf 的前提下复现 Dashboard ID 碰撞。这里的“ID 碰撞”不是哈希桶冲突。
        if (fixed_identity_tuple) event.timestamp = fixed_timestamp;
        event.counter = static_cast<std::int32_t>(ordinal & 0x7fffffffU);
        event.details = std::string("{\"benchmark\":\"weaknet.event.pipeline.v1\",")
            + "\"run_id\":" + jsonEscape(run_id) + ','
            + "\"phase\":" + jsonEscape(phase) + ','
            + "\"sequence\":" + std::to_string(sequence) + ','
            + "\"injected_at_unix_ns\":" + jsonEscape(std::to_string(injected_at)) + ','
            + "\"payload\":" + jsonEscape(payload) + '}';
        getEventManager().emitEvent(event);
        if (interval_us > 0 && sequence + 1 < count) {
            std::this_thread::sleep_for(std::chrono::microseconds(interval_us));
        }
    }

    const auto duration_us = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::steady_clock::now() - started).count();
    return "{\"ok\":true,\"command\":"
        + jsonEscape(fixed_identity_tuple ? "INJECT_FIXED_TUPLE" : "INJECT")
        + ",\"run_id\":"
        + jsonEscape(run_id)
        + ",\"phase\":" + jsonEscape(phase)
        + ",\"injected\":" + std::to_string(count)
        + ",\"interval_us\":" + std::to_string(interval_us)
        + ",\"payload_bytes\":" + std::to_string(payload_bytes)
        + ",\"first_injected_at_unix_ns\":" + jsonEscape(std::to_string(first_injected_at))
        + ",\"last_injected_at_unix_ns\":" + jsonEscape(std::to_string(last_injected_at))
        + ",\"first_counter\":" + std::to_string(first_ordinal)
        + ",\"last_counter\":" + std::to_string(last_ordinal)
        + ",\"duration_ms\":" + std::to_string(static_cast<double>(duration_us) / 1000.0)
        + "}\n";
}

// 控制协议路由：PING 做就绪探测，INJECT 注入事件，SHUTDOWN 请求有序退出。
std::string handleCommand(const std::string& line) {
    const std::vector<std::string> fields = splitTabs(line);
    if (fields.empty()) return errorResponse("empty command");
    if (fields[0] == "PING" && fields.size() == 1) {
        return "{\"ok\":true,\"command\":\"PING\","
               "\"pipeline\":\"NetworkEventManager->EventPublisher->GrpcServer\","
               "\"server_unix_ns\":" + jsonEscape(std::to_string(unixNanosecondsNow()))
               + "}\n";
    }
    if (fields[0] == "INJECT") return injectEvents(fields, false);
    if (fields[0] == "INJECT_FIXED_TUPLE") return injectEvents(fields, true);
    if (fields[0] == "SHUTDOWN" && fields.size() == 1) {
        g_running.store(false, std::memory_order_relaxed);
        return "{\"ok\":true,\"command\":\"SHUTDOWN\"}\n";
    }
    return errorResponse("unknown control command");
}

}  // namespace

// 启动真实事件发布链路与本机控制循环，并按 monitoring -> publisher -> gRPC 顺序清理。
int main(int argc, char** argv) {
    Options options;
    std::string error;
    if (!parseOptions(argc, argv, options, error)) {
        std::cerr << error << '\n' << usage(argv[0]) << '\n';
        return 2;
    }
    if (options.help) {
        std::cout << usage(argv[0]) << '\n';
        std::cout << "control protocol: PING | INJECT or INJECT_FIXED_TUPLE followed by RUN_ID, PHASE, COUNT, INTERVAL_US, PAYLOAD_BYTES (tab-separated) | SHUTDOWN\n";
        return 0;
    }

    std::signal(SIGINT, handleSignal);
    std::signal(SIGTERM, handleSignal);
    if (!Logger::init("event_pipeline_driver", "/tmp/weaknet-event-pipeline-logs",
                      LogLevel::WARNING, true)) {
        std::cerr << "failed to initialize logger\n";
        return 1;
    }

    ServerContext context;
    GrpcServer grpc_server;
    // 让真实 EventManager 最终调用 GrpcServer::publish，而非测试替身。
    context.event_publisher = &grpc_server;
    if (!grpc_server.start(&context, options.grpc_address)) {
        Logger::shutdown();
        return 1;
    }
    getEventManager().startEventMonitoring(&context);

    const int control_socket = createControlSocket(options.control_address, error);
    if (control_socket < 0) {
        std::cerr << error << '\n';
        getEventManager().stopEventMonitoring();
        context.event_publisher = nullptr;
        grpc_server.shutdown();
        Logger::shutdown();
        return 1;
    }

    std::cout << "{\"ready\":true,\"grpc_address\":" << jsonEscape(options.grpc_address)
              << ",\"control_address\":" << jsonEscape(options.control_address)
              << ",\"pid\":" << getpid() << "}" << std::endl;

    // 控制面一次处理一个短连接，避免它自身的并发成为事件队列压测中的额外变量。
    while (g_running.load(std::memory_order_relaxed)) {
        pollfd descriptor{};
        descriptor.fd = control_socket;
        descriptor.events = POLLIN;
        const int ready = poll(&descriptor, 1, 250);
        if (ready < 0 && errno == EINTR) continue;
        if (ready < 0) {
            std::cerr << "control poll failed: " << std::strerror(errno) << '\n';
            break;
        }
        if (ready == 0 || !(descriptor.revents & POLLIN)) continue;

        const int client = accept4(control_socket, nullptr, nullptr, SOCK_CLOEXEC);
        if (client < 0 && errno == EINTR) continue;
        if (client < 0) {
            std::cerr << "control accept failed: " << std::strerror(errno) << '\n';
            break;
        }
        std::string line;
        std::string receive_error;
        const std::string response = receiveLine(client, line, receive_error)
            ? handleCommand(line)
            : errorResponse(receive_error);
        sendAll(client, response);
        shutdown(client, SHUT_RDWR);
        close(client);
    }

    // 先停止事件生产，再断开 publisher，最后关闭 gRPC，避免清理阶段向悬空对象发布。
    close(control_socket);
    getEventManager().stopEventMonitoring();
    context.event_publisher = nullptr;
    grpc_server.shutdown();
    Logger::shutdown();
    return 0;
}
