// WeakNet 统一日志接口：封装 Google glog 初始化、级别配置和模块化日志宏。
// Logger 管理进程级日志状态，调用方应在业务线程启动前初始化、全部线程退出后关闭。

#pragma once

#include <glog/logging.h>
#include <string>
#include <memory>

namespace weaknet_grpc {

// 对外暴露的最小日志级别，与 glog 严重级别顺序一致。
enum class LogLevel {
    INFO = 0,
    WARNING = 1,
    ERROR = 2,
    FATAL = 3
};

// 稳定的日志模块标签，用于按子系统检索和聚合日志。
namespace LogModule {
    constexpr const char* SERVER = "server";
    constexpr const char* CLIENT = "client";
    constexpr const char* RPC = "rpc";
    constexpr const char* WEAK_MGR = "weak_mgr";
    constexpr const char* TCP_LOSS = "tcp_loss";
    constexpr const char* RTT = "rtt";
    constexpr const char* RSSI = "rssi";
    constexpr const char* NETWORK = "network";
    constexpr const char* EVENT_MGR = "event_mgr";
    constexpr const char* PING = "ping";
    constexpr const char* INTERFACE = "interface";
}

// 管理进程级 glog 生命周期和全局配置。
class Logger {
public:
    // 初始化 glog；log_dir 为输出目录，成功返回 true，重复初始化由实现统一处理。
    static bool init(const std::string& program_name, 
                    const std::string& log_dir = "./logs/server",
                    LogLevel min_level = LogLevel::INFO,
                    bool log_to_stderr = true);
    
    // 刷新并关闭进程级日志系统，全部日志线程停止后调用。
    static void shutdown();
    
    // 动态更新最小输出级别，影响后续日志。
    static void setLogLevel(LogLevel level);
    
    // 更新日志输出目录，dir 的生命周期无需超过本次调用。
    static void setLogDir(const std::string& dir);
    
    // 返回当前进程是否已成功初始化日志系统。
    static bool isInitialized() { return initialized_; }

private:
    // 进程级初始化状态和当前日志目录。
    static bool initialized_;
    static std::string current_log_dir_;
};

// 基础模块日志宏：自动在正文前添加模块标签。
#define LOG_INFO(module, msg) LOG(INFO) << "[" << module << "] " << msg
#define LOG_WARNING(module, msg) LOG(WARNING) << "[" << module << "] " << msg
#define LOG_ERROR(module, msg) LOG(ERROR) << "[" << module << "] " << msg
#define LOG_FATAL(module, msg) LOG(FATAL) << "[" << module << "] " << msg

// 兼容可变参数调用形式的日志宏。
#define LOG_INFO_F(module, fmt, ...) \
    LOG(INFO) << "[" << module << "] " << std::string().append(fmt).c_str() << __VA_ARGS__

#define LOG_ERROR_F(module, fmt, ...) \
    LOG(ERROR) << "[" << module << "] " << std::string().append(fmt).c_str() << __VA_ARGS__

// 仅在 condition 为 true 时输出对应级别日志。
#define LOG_IF_INFO(condition, module, msg) \
    LOG_IF(INFO, condition) << "[" << module << "] " << msg

#define LOG_IF_ERROR(condition, module, msg) \
    LOG_IF(ERROR, condition) << "[" << module << "] " << msg

// 调试日志仅在 DEBUG 编译条件下生效。
#ifdef DEBUG
#define LOG_DEBUG(module, msg) LOG(INFO) << "[DEBUG][" << module << "] " << msg
#else
#define LOG_DEBUG(module, msg) do {} while(0)
#endif

// 记录操作耗时；duration_ms 单位为毫秒。
#define LOG_PERF(module, operation, duration_ms) \
    LOG(INFO) << "[" << module << "] PERF: " << operation << " took " << duration_ms << "ms"

// 记录网络接口及其状态文本。
#define LOG_NETWORK_STATE(module, interface, state) \
    LOG(INFO) << "[" << module << "] Network interface " << interface << " state: " << state

// 记录事件类型和事件摘要。
#define LOG_EVENT(module, event_type, message) \
    LOG(INFO) << "[" << module << "] EVENT: " << event_type << " - " << message

// 记录操作名称及数值错误码。
#define LOG_ERROR_WITH_CODE(module, operation, error_code) \
    LOG(ERROR) << "[" << module << "] " << operation << " failed with error code: " << error_code

} // namespace weaknet_grpc


