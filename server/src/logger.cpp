// 统一日志适配层：负责 glog 的目录、级别、输出目标和生命周期配置。

#include "logger.hpp"
#include <iostream>
#include <filesystem>

namespace weaknet_grpc {

// 静态成员初始化
bool Logger::initialized_ = false;
std::string Logger::current_log_dir_ = "";

// 幂等初始化 glog；先创建目录，再设置全局 FLAGS，避免日志落盘失败。
bool Logger::init(const std::string& program_name, 
                 const std::string& log_dir, 
                 LogLevel min_level,
                 bool log_to_stderr) {
    if (initialized_) {
        return true;
    }

    try {
        // 日志目录必须在初始化 glog 前存在，否则文件后端无法创建目标文件。
        std::filesystem::create_directories(log_dir);
        
        // 设置日志目录
        FLAGS_log_dir = log_dir;
        FLAGS_max_log_size = 10; // 10MB
        FLAGS_minloglevel = static_cast<int>(min_level);
        FLAGS_logtostderr = log_to_stderr;
        FLAGS_alsologtostderr = true;
        FLAGS_colorlogtostderr = true;
        
        // glog 使用进程级全局状态，异常时不标记 initialized_，允许调用方感知失败。
        try {
            google::InitGoogleLogging(program_name.c_str());
        } catch (const std::exception& e) {
            std::cerr << "[logger] Failed to initialize glog: " << e.what() << std::endl;
            return false;
        } catch (...) {
            std::cerr << "[logger] Failed to initialize glog: unknown error" << std::endl;
            return false;
        }
        
        current_log_dir_ = log_dir;
        initialized_ = true;
        
        LOG(INFO) << "[logger] Logger initialized successfully";
        LOG(INFO) << "[logger] Log directory: " << log_dir;
        LOG(INFO) << "[logger] Min log level: " << static_cast<int>(min_level);
        LOG(INFO) << "[logger] Log to stderr: " << (log_to_stderr ? "true" : "false");
        
        return true;
    } catch (const std::exception& e) {
        std::cerr << "[logger] Failed to initialize logger: " << e.what() << std::endl;
        return false;
    }
}

// 仅在已初始化时关闭 glog，避免重复释放全局日志资源。
void Logger::shutdown() {
    if (initialized_) {
        LOG(INFO) << "[logger] Shutting down logger";
        google::ShutdownGoogleLogging();
        initialized_ = false;
    }
}

// 动态调整最小日志级别；未初始化时保持配置不变。
void Logger::setLogLevel(LogLevel level) {
    if (initialized_) {
        FLAGS_minloglevel = static_cast<int>(level);
        LOG(INFO) << "[logger] Log level changed to: " << static_cast<int>(level);
    }
}

// 运行时切换日志目录，并在更新 FLAGS 前确保目录可用。
void Logger::setLogDir(const std::string& dir) {
    if (initialized_) {
        try {
            std::filesystem::create_directories(dir);
            FLAGS_log_dir = dir;
            current_log_dir_ = dir;
            LOG(INFO) << "[logger] Log directory changed to: " << dir;
        } catch (const std::exception& e) {
            LOG(ERROR) << "[logger] Failed to change log directory: " << e.what();
        }
    }
}

} // namespace weaknet_grpc
