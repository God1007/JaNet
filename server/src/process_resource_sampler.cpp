// ProcessResourceSampler 实现：getrusage 提供调度/累计 CPU，Linux /proc 提供当前内存、线程与 FD。

#include "process_resource_sampler.hpp"

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <fstream>
#include <limits>
#include <sstream>
#include <sys/resource.h>
#include <thread>
#include <unistd.h>

#if defined(__linux__)
#include <dirent.h>
#endif

namespace weaknet_grpc {
namespace {

constexpr auto kMinimumCpuWindow = std::chrono::milliseconds(100);
constexpr std::uint64_t kMicrosPerSecond = 1000ULL * 1000ULL;
constexpr std::uint64_t kBytesPerKilobyte = 1024ULL;

std::string_view trim(std::string_view value) {
    while (!value.empty() && std::isspace(static_cast<unsigned char>(value.front()))) {
        value.remove_prefix(1);
    }
    while (!value.empty() && std::isspace(static_cast<unsigned char>(value.back()))) {
        value.remove_suffix(1);
    }
    return value;
}

std::optional<std::uint64_t> parseUnsigned(std::string_view token) {
    token = trim(token);
    if (token.empty()) return std::nullopt;

    std::uint64_t value = 0;
    for (const char character : token) {
        if (character < '0' || character > '9') return std::nullopt;
        const std::uint64_t digit = static_cast<std::uint64_t>(character - '0');
        if (value > (std::numeric_limits<std::uint64_t>::max() - digit) / 10ULL) {
            return std::nullopt;
        }
        value = value * 10ULL + digit;
    }
    return value;
}

std::optional<std::uint64_t> parseKilobytes(std::string_view value) {
    value = trim(value);
    const std::size_t separator = value.find_first_of(" \t");
    const std::string_view number = separator == std::string_view::npos
        ? value
        : value.substr(0, separator);
    const std::string_view unit = separator == std::string_view::npos
        ? std::string_view{}
        : trim(value.substr(separator));
    const auto kilobytes = parseUnsigned(number);
    if (!kilobytes || unit != "kB"
        || *kilobytes > std::numeric_limits<std::uint64_t>::max() / kBytesPerKilobyte) {
        return std::nullopt;
    }
    return *kilobytes * kBytesPerKilobyte;
}

std::uint64_t timevalToMicros(const timeval& value) {
    const auto seconds = value.tv_sec < 0 ? 0ULL : static_cast<std::uint64_t>(value.tv_sec);
    const auto micros = value.tv_usec < 0 ? 0ULL : static_cast<std::uint64_t>(value.tv_usec);
    if (seconds > (std::numeric_limits<std::uint64_t>::max() - micros) / kMicrosPerSecond) {
        return std::numeric_limits<std::uint64_t>::max();
    }
    return seconds * kMicrosPerSecond + micros;
}

std::optional<std::uint64_t> peakRssBytes(const rusage& usage) {
    if (usage.ru_maxrss < 0) return std::nullopt;
    const std::uint64_t raw = static_cast<std::uint64_t>(usage.ru_maxrss);
#if defined(__APPLE__)
    // Darwin 的 ru_maxrss 单位是 byte；Linux/BSD 常见实现则以 KiB 返回。
    return raw;
#else
    if (raw > std::numeric_limits<std::uint64_t>::max() / kBytesPerKilobyte) {
        return std::nullopt;
    }
    return raw * kBytesPerKilobyte;
#endif
}

#if defined(__linux__)
std::optional<std::string> readTextFile(const char* path) {
    std::ifstream input(path);
    if (!input) return std::nullopt;
    std::ostringstream contents;
    contents << input.rdbuf();
    if (input.bad()) return std::nullopt;
    return contents.str();
}

std::optional<std::uint32_t> countOpenFileDescriptors() {
    DIR* directory = opendir("/proc/self/fd");
    if (!directory) return std::nullopt;

    const int enumerationFd = dirfd(directory);
    std::uint64_t count = 0;
    errno = 0;
    while (dirent* entry = readdir(directory)) {
        const std::string_view name(entry->d_name);
        const auto parsed = parseUnsigned(name);
        if (!parsed || *parsed == static_cast<std::uint64_t>(enumerationFd)) continue;
        ++count;
    }
    const int readError = errno;
    closedir(directory);
    if (readError != 0 || count > std::numeric_limits<std::uint32_t>::max()) {
        return std::nullopt;
    }
    return static_cast<std::uint32_t>(count);
}
#endif

std::uint32_t onlineLogicalCpuCount(bool* discovered) {
    const long configured = sysconf(_SC_NPROCESSORS_ONLN);
    if (configured > 0 && static_cast<unsigned long>(configured)
        <= std::numeric_limits<std::uint32_t>::max()) {
        *discovered = true;
        return static_cast<std::uint32_t>(configured);
    }

    const unsigned int fallback = std::thread::hardware_concurrency();
    if (fallback > 0) {
        *discovered = true;
        return fallback;
    }
    *discovered = false;
    return 1;
}

void addUnavailable(ProcessResourceSample* sample, const char* metric) {
    sample->unavailableMetrics.emplace_back(metric);
}

#if defined(__linux__)
void markAvailable(ProcessResourceSample* sample, const char* metric) {
    sample->unavailableMetrics.erase(
        std::remove(sample->unavailableMetrics.begin(), sample->unavailableMetrics.end(), metric),
        sample->unavailableMetrics.end());
}
#endif

}  // namespace

LinuxProcStatus parseLinuxProcStatus(std::string_view contents) {
    LinuxProcStatus result;
    while (!contents.empty()) {
        const std::size_t newline = contents.find('\n');
        const std::string_view line = newline == std::string_view::npos
            ? contents
            : contents.substr(0, newline);
        contents = newline == std::string_view::npos
            ? std::string_view{}
            : contents.substr(newline + 1);

        const std::size_t colon = line.find(':');
        if (colon == std::string_view::npos) continue;
        const std::string_view key = trim(line.substr(0, colon));
        const std::string_view value = trim(line.substr(colon + 1));
        if (key == "VmRSS") {
            if (const auto parsed = parseKilobytes(value)) result.rssBytes = *parsed;
        } else if (key == "VmHWM") {
            if (const auto parsed = parseKilobytes(value)) result.peakRssBytes = *parsed;
        } else if (key == "VmSize") {
            if (const auto parsed = parseKilobytes(value)) result.virtualMemoryBytes = *parsed;
        } else if (key == "Threads") {
            const auto parsed = parseUnsigned(value);
            if (parsed && *parsed <= std::numeric_limits<std::uint32_t>::max()) {
                result.threadCount = static_cast<std::uint32_t>(*parsed);
            }
        }
    }
    return result;
}

std::optional<double> calculateSingleCoreCpuPercent(std::uint64_t cpuDeltaMicros,
                                                    std::uint64_t elapsedNanos) {
    if (elapsedNanos == 0) return std::nullopt;
    // CPU(us) / wall(ns) * 100，换算后一个逻辑 CPU 持续忙碌正好等于 100%。
    const long double cpuNanos = static_cast<long double>(cpuDeltaMicros) * 1000.0L;
    const long double percent = cpuNanos * 100.0L / static_cast<long double>(elapsedNanos);
    if (percent < 0.0L || percent > static_cast<long double>(std::numeric_limits<double>::max())) {
        return std::nullopt;
    }
    return static_cast<double>(percent);
}

ProcessResourceSampler::ProcessResourceSampler()
    : startedAt_(std::chrono::steady_clock::now()),
      lastSampleAt_(startedAt_),
      previousCpuAt_(startedAt_) {
    rusage usage{};
    if (getrusage(RUSAGE_SELF, &usage) == 0) {
        previousUserCpuMicros_ = timevalToMicros(usage.ru_utime);
        previousSystemCpuMicros_ = timevalToMicros(usage.ru_stime);
        hasPreviousCpu_ = true;
    }
}

ProcessResourceSample ProcessResourceSampler::sample() {
    std::lock_guard<std::mutex> lock(mutex_);
    const auto steadyNow = std::chrono::steady_clock::now();
    if (hasCachedSample_ && steadyNow - lastSampleAt_ < kMinimumCpuWindow) {
        return cachedSample_;
    }

    ProcessResourceSample result;
    result.sampledAtUnixMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    result.uptimeSeconds = std::chrono::duration<double>(steadyNow - startedAt_).count();

    bool logicalCpuDiscovered = false;
    result.logicalCpuCount = onlineLogicalCpuCount(&logicalCpuDiscovered);
    if (!logicalCpuDiscovered) addUnavailable(&result, "logical_cpu_count");

    rusage usage{};
    if (getrusage(RUSAGE_SELF, &usage) == 0) {
        result.userCpuTimeMicros = timevalToMicros(usage.ru_utime);
        result.systemCpuTimeMicros = timevalToMicros(usage.ru_stime);
        result.voluntaryContextSwitches = usage.ru_nvcsw < 0
            ? 0ULL
            : static_cast<std::uint64_t>(usage.ru_nvcsw);
        result.involuntaryContextSwitches = usage.ru_nivcsw < 0
            ? 0ULL
            : static_cast<std::uint64_t>(usage.ru_nivcsw);
        if (usage.ru_nvcsw < 0) addUnavailable(&result, "voluntary_context_switches");
        if (usage.ru_nivcsw < 0) addUnavailable(&result, "involuntary_context_switches");

        if (const auto peak = peakRssBytes(usage)) {
            result.peakRssBytes = *peak;
        } else {
            addUnavailable(&result, "peak_rss_bytes");
        }

        const auto cpuWindow = steadyNow - previousCpuAt_;
        const auto elapsedNanosSigned = std::chrono::duration_cast<std::chrono::nanoseconds>(
            cpuWindow).count();
        if (hasPreviousCpu_ && cpuWindow >= kMinimumCpuWindow
            && elapsedNanosSigned > 0
            && result.userCpuTimeMicros >= previousUserCpuMicros_
            && result.systemCpuTimeMicros >= previousSystemCpuMicros_) {
            const std::uint64_t userDelta = result.userCpuTimeMicros - previousUserCpuMicros_;
            const std::uint64_t systemDelta = result.systemCpuTimeMicros - previousSystemCpuMicros_;
            if (userDelta <= std::numeric_limits<std::uint64_t>::max() - systemDelta) {
                const auto cpu = calculateSingleCoreCpuPercent(
                    userDelta + systemDelta,
                    static_cast<std::uint64_t>(elapsedNanosSigned));
                if (cpu) {
                    result.cpuPercent = *cpu;
                    result.sampleWindowMs = static_cast<std::uint64_t>(
                        std::chrono::duration_cast<std::chrono::milliseconds>(cpuWindow).count());
                } else {
                    addUnavailable(&result, "cpu_percent");
                }
            } else {
                addUnavailable(&result, "cpu_percent");
            }
        } else {
            addUnavailable(&result, "cpu_percent");
        }
        previousUserCpuMicros_ = result.userCpuTimeMicros;
        previousSystemCpuMicros_ = result.systemCpuTimeMicros;
        previousCpuAt_ = steadyNow;
        hasPreviousCpu_ = true;
    } else {
        addUnavailable(&result, "cpu_percent");
        addUnavailable(&result, "user_cpu_time_micros");
        addUnavailable(&result, "system_cpu_time_micros");
        addUnavailable(&result, "peak_rss_bytes");
        addUnavailable(&result, "voluntary_context_switches");
        addUnavailable(&result, "involuntary_context_switches");
    }

#if defined(__linux__)
    if (const auto statusText = readTextFile("/proc/self/status")) {
        const LinuxProcStatus status = parseLinuxProcStatus(*statusText);
        if (status.rssBytes) result.rssBytes = *status.rssBytes;
        else addUnavailable(&result, "rss_bytes");
        // /proc 的 VmHWM 与 VmRSS 来自同一次文本快照，避免 getrusage 与
        // 随后读取 /proc 之间的新分配造成短暂的 peak < current 矛盾。
        if (status.peakRssBytes || status.rssBytes) {
            const std::uint64_t procPeak = std::max(
                status.peakRssBytes.value_or(0), status.rssBytes.value_or(0));
            result.peakRssBytes = std::max(result.peakRssBytes, procPeak);
            markAvailable(&result, "peak_rss_bytes");
        }
        if (status.virtualMemoryBytes) result.virtualMemoryBytes = *status.virtualMemoryBytes;
        else addUnavailable(&result, "virtual_memory_bytes");
        if (status.threadCount) result.threadCount = *status.threadCount;
        else addUnavailable(&result, "thread_count");
    } else {
        addUnavailable(&result, "rss_bytes");
        addUnavailable(&result, "virtual_memory_bytes");
        addUnavailable(&result, "thread_count");
    }

    if (const auto descriptors = countOpenFileDescriptors()) {
        result.openFdCount = *descriptors;
    } else {
        addUnavailable(&result, "open_fd_count");
    }
#else
    addUnavailable(&result, "rss_bytes");
    addUnavailable(&result, "virtual_memory_bytes");
    addUnavailable(&result, "thread_count");
    addUnavailable(&result, "open_fd_count");
#endif

    lastSampleAt_ = steadyNow;
    cachedSample_ = result;
    hasCachedSample_ = true;
    return result;
}

}  // namespace weaknet_grpc
