// Linux Engine 进程资源采样：组合 getrusage 与 /proc，输出可跨 gRPC 传输的有界即时快照。
// 采样器由 ServerContext 单例持有；内部锁保证并发 GetNetworkSnapshot 不会破坏 CPU 差分基线。

#pragma once

#include <chrono>
#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace weaknet_grpc {

// /proc/self/status 中与进程资源相关的字段；optional 区分真实零与字段缺失/解析失败。
struct LinuxProcStatus {
    std::optional<std::uint64_t> rssBytes;
    std::optional<std::uint64_t> peakRssBytes;
    std::optional<std::uint64_t> virtualMemoryBytes;
    std::optional<std::uint32_t> threadCount;
};

// 纯文本解析入口独立于 Linux 文件系统，便于在 macOS 等构建机上验证格式和单位换算。
LinuxProcStatus parseLinuxProcStatus(std::string_view contents);

// CPU 百分比以一个逻辑 CPU 满载为 100%；elapsedNanos 为 0 时无法建立速率。
std::optional<double> calculateSingleCoreCpuPercent(std::uint64_t cpuDeltaMicros,
                                                    std::uint64_t elapsedNanos);

// 进程资源的进程内表示；unavailableMetrics 中出现的数值字段不得被解释成真实零。
struct ProcessResourceSample {
    std::int64_t sampledAtUnixMs = 0;
    std::uint64_t sampleWindowMs = 0;
    double cpuPercent = 0.0;
    std::uint64_t userCpuTimeMicros = 0;
    std::uint64_t systemCpuTimeMicros = 0;
    std::uint64_t rssBytes = 0;
    std::uint64_t peakRssBytes = 0;
    std::uint64_t virtualMemoryBytes = 0;
    std::uint32_t threadCount = 0;
    std::uint32_t openFdCount = 0;
    double uptimeSeconds = 0.0;
    std::uint64_t voluntaryContextSwitches = 0;
    std::uint64_t involuntaryContextSwitches = 0;
    std::uint32_t logicalCpuCount = 1;
    std::vector<std::string> unavailableMetrics;
};

// 按请求低频采样并缓存过近请求；不创建额外线程，也不改变现有监控调度周期。
class ProcessResourceSampler {
public:
    ProcessResourceSampler();

    // 返回当前或最近一次资源快照。相邻调用不足最小窗口时复用缓存，避免极短窗口放大 CPU 抖动。
    ProcessResourceSample sample();

private:
    std::mutex mutex_;
    std::chrono::steady_clock::time_point startedAt_;
    std::chrono::steady_clock::time_point lastSampleAt_;
    std::chrono::steady_clock::time_point previousCpuAt_;
    std::uint64_t previousUserCpuMicros_ = 0;
    std::uint64_t previousSystemCpuMicros_ = 0;
    bool hasPreviousCpu_ = false;
    bool hasCachedSample_ = false;
    ProcessResourceSample cachedSample_;
};

}  // namespace weaknet_grpc
