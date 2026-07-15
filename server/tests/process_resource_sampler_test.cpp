// 进程资源采样单测：纯 parser/rate 契约跨平台运行，Linux 额外读取真实 /proc/self。

#include "process_resource_sampler.hpp"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdlib>
#include <iostream>
#include <string>
#include <thread>

#define CHECK(condition) do { \
    if (!(condition)) { \
        std::cerr << "CHECK failed at " << __FILE__ << ':' << __LINE__ << ": " #condition "\n"; \
        return EXIT_FAILURE; \
    } \
} while (false)

namespace {

bool unavailable(const weaknet_grpc::ProcessResourceSample& sample, const std::string& metric) {
    return std::find(sample.unavailableMetrics.begin(), sample.unavailableMetrics.end(), metric)
        != sample.unavailableMetrics.end();
}

bool near(double left, double right) {
    return std::fabs(left - right) < 0.000001;
}

}  // namespace

int main() {
    // 字段顺序、额外空白和无关行不影响解析；内核 kB 统一转换为 byte。
    const auto parsed = weaknet_grpc::parseLinuxProcStatus(
        "Name:\tweaknet\n"
        "  Threads:   23  \n"
        "VmRSS:\t1536 kB\n"
        "VmHWM:\t2048 kB\n"
        "State:\tS (sleeping)\n"
        "VmSize:  4096 kB\n");
    CHECK(parsed.rssBytes.has_value());
    CHECK(*parsed.rssBytes == 1536ULL * 1024ULL);
    CHECK(parsed.peakRssBytes.has_value());
    CHECK(*parsed.peakRssBytes == 2048ULL * 1024ULL);
    CHECK(parsed.virtualMemoryBytes.has_value());
    CHECK(*parsed.virtualMemoryBytes == 4096ULL * 1024ULL);
    CHECK(parsed.threadCount.has_value());
    CHECK(*parsed.threadCount == 23U);

    // 非数字、负数、错误单位和 kB->byte 溢出必须保持 unavailable，不能制造零值。
    const auto malformed = weaknet_grpc::parseLinuxProcStatus(
        "VmRSS: -1 kB\n"
        "VmSize: 18446744073709551615 kB\n"
        "Threads: many\n");
    CHECK(!malformed.rssBytes.has_value());
    CHECK(!malformed.virtualMemoryBytes.has_value());
    CHECK(!malformed.threadCount.has_value());

    // 1 秒墙钟窗口内使用 1 秒 CPU 等于单核 100%，多线程并行允许超过 100%。
    const auto halfCore = weaknet_grpc::calculateSingleCoreCpuPercent(500000ULL, 1000000000ULL);
    const auto oneCore = weaknet_grpc::calculateSingleCoreCpuPercent(1000000ULL, 1000000000ULL);
    const auto twoCores = weaknet_grpc::calculateSingleCoreCpuPercent(2000000ULL, 1000000000ULL);
    CHECK(halfCore.has_value() && near(*halfCore, 50.0));
    CHECK(oneCore.has_value() && near(*oneCore, 100.0));
    CHECK(twoCores.has_value() && near(*twoCores, 200.0));
    CHECK(!weaknet_grpc::calculateSingleCoreCpuPercent(1, 0).has_value());

    weaknet_grpc::ProcessResourceSampler sampler;
    const auto first = sampler.sample();
    const auto cached = sampler.sample();
    CHECK(cached.sampledAtUnixMs == first.sampledAtUnixMs);
    std::this_thread::sleep_for(std::chrono::milliseconds(120));
    const auto second = sampler.sample();
    CHECK(second.sampledAtUnixMs >= first.sampledAtUnixMs);
    CHECK(second.uptimeSeconds >= first.uptimeSeconds);
    CHECK(second.logicalCpuCount >= 1U);
    CHECK(second.sampleWindowMs >= 100U);
    CHECK(!unavailable(second, "cpu_percent"));
    CHECK(second.cpuPercent >= 0.0);

#if defined(__linux__)
    // 生产 Linux 路径必须能读取自身 /proc；真实零仍通过 unavailableMetrics 与失败区分。
    CHECK(!unavailable(second, "rss_bytes"));
    CHECK(!unavailable(second, "virtual_memory_bytes"));
    CHECK(!unavailable(second, "thread_count"));
    CHECK(!unavailable(second, "open_fd_count"));
    CHECK(second.rssBytes > 0);
    CHECK(!unavailable(second, "peak_rss_bytes"));
    CHECK(second.peakRssBytes >= second.rssBytes);
    CHECK(second.virtualMemoryBytes >= second.rssBytes);
    CHECK(second.threadCount >= 1U);
    CHECK(second.openFdCount >= 3U);
#else
    // 非 Linux 构建仍验证 getrusage/CPU，/proc 专属字段则必须显式不可用。
    CHECK(unavailable(second, "rss_bytes"));
    CHECK(unavailable(second, "virtual_memory_bytes"));
    CHECK(unavailable(second, "thread_count"));
    CHECK(unavailable(second, "open_fd_count"));
#endif

    std::cout << "process_resource_sampler_test: all checks passed"
              << " (cpu_percent=" << second.cpuPercent
              << ", rss_bytes=" << second.rssBytes
              << ", threads=" << second.threadCount
              << ", fds=" << second.openFdCount << ")\n";
    return EXIT_SUCCESS;
}
