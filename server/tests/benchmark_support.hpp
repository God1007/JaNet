// 性能基准公共设施：统一 CLI、延迟分位数、JSON 序列化和原子结果落盘。
// 仅供 server/tests 下的独立 benchmark 使用，不进入生产服务二进制。

#pragma once

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <iterator>
#include <limits>
#include <locale>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include <sys/utsname.h>
#include <unistd.h>

namespace weaknet_benchmark {

using SteadyClock = std::chrono::steady_clock;

// 所有压测组件共用同一份版本标识；总编排器会做精确匹配，拒绝旧格式结果。
inline constexpr const char* kSchemaVersion = "weaknet.benchmark.v1";

// 三档固定压力规模；组件自行把 profile 映射成操作数，但结果中始终保留同名档位。
enum class Profile {
    Smoke,
    Standard,
    Stress,
};

// benchmark 的通用命令行配置。profile 决定负载规模，output_path 是可审计结果的唯一落点。
struct Options {
    Profile profile = Profile::Smoke;
    std::string profile_name = "smoke";
    std::string output_path;
    bool help = false;
};

// 返回统一帮助文本；thread_local 避免并发调用时共享临时字符串产生数据竞争。
inline const char* usage(const char* program) {
    static thread_local std::string value;
    value = std::string("usage: ") + program +
            " --profile smoke|standard|stress --output <path>";
    return value.c_str();
}

// 严格解析公共参数：未知参数、未知 profile 或缺少输出路径都直接拒绝，避免“假跑成功”。
inline bool parseOptions(int argc, char** argv, Options& options, std::string& error) {
    for (int index = 1; index < argc; ++index) {
        const std::string argument = argv[index];
        if (argument == "--help" || argument == "-h") {
            options.help = true;
            return true;
        }
        if (argument == "--profile") {
            if (++index >= argc) {
                error = "--profile requires a value";
                return false;
            }
            options.profile_name = argv[index];
            if (options.profile_name == "smoke") options.profile = Profile::Smoke;
            else if (options.profile_name == "standard") options.profile = Profile::Standard;
            else if (options.profile_name == "stress") options.profile = Profile::Stress;
            else {
                error = "unknown profile: " + options.profile_name;
                return false;
            }
            continue;
        }
        if (argument == "--output") {
            if (++index >= argc) {
                error = "--output requires a path";
                return false;
            }
            options.output_path = argv[index];
            continue;
        }
        error = "unknown argument: " + argument;
        return false;
    }
    if (options.output_path.empty()) {
        error = "--output is required so the result is a durable JSON artifact";
        return false;
    }
    return true;
}

// 将任意字符串编码成合法 JSON string，尤其处理控制字符，防止详情字段破坏结果文档。
inline std::string jsonEscape(const std::string& input) {
    std::ostringstream output;
    output << '"';
    for (const unsigned char character : input) {
        switch (character) {
            case '"': output << "\\\""; break;
            case '\\': output << "\\\\"; break;
            case '\b': output << "\\b"; break;
            case '\f': output << "\\f"; break;
            case '\n': output << "\\n"; break;
            case '\r': output << "\\r"; break;
            case '\t': output << "\\t"; break;
            default:
                if (character < 0x20) {
                    output << "\\u00" << std::hex << std::setw(2) << std::setfill('0')
                           << static_cast<unsigned int>(character) << std::dec;
                } else {
                    output << static_cast<char>(character);
                }
        }
    }
    output << '"';
    return output.str();
}

// 生成 UTC wall-clock 时间，只用于结果溯源；性能耗时统一由单调时钟 SteadyClock 计算。
inline std::string iso8601NowUtc() {
    const std::time_t now = std::time(nullptr);
    std::tm brokenDown{};
    gmtime_r(&now, &brokenDown);
    std::ostringstream output;
    output << std::put_time(&brokenDown, "%Y-%m-%dT%H:%M:%SZ");
    return output.str();
}

// 采集影响性能结果解释的最小环境指纹，不把易变的整份系统信息塞入结果。
inline std::string environmentJson() {
    struct utsname information {};
    const bool unameSucceeded = uname(&information) == 0;
    std::ostringstream output;
    output << '{'
           << "\"os\":" << jsonEscape(unameSucceeded ? information.sysname : "unknown") << ','
           << "\"kernel_release\":"
           << jsonEscape(unameSucceeded ? information.release : "unknown") << ','
           << "\"architecture\":"
           << jsonEscape(unameSucceeded ? information.machine : "unknown") << ','
           << "\"hardware_concurrency\":" << std::thread::hardware_concurrency() << ','
           << "\"pid\":" << static_cast<unsigned long long>(getpid()) << ','
           << "\"uid\":" << static_cast<unsigned long long>(getuid()) << ','
           << "\"euid\":" << static_cast<unsigned long long>(geteuid())
           << '}';
    return output.str();
}

// 单项 benchmark 的 nearest-rank 延迟摘要，单位始终为纳秒。
struct LatencySummary {
    std::uint64_t p50_ns = 0;
    std::uint64_t p95_ns = 0;
    std::uint64_t p99_ns = 0;
    std::uint64_t max_ns = 0;
};

// 已排序样本上的 nearest-rank 分位数：例如 p99 取 ceil(0.99*N) 对应的观测值。
inline std::uint64_t nearestRank(const std::vector<std::uint64_t>& sorted, double percentile) {
    if (sorted.empty()) return 0;
    const double rank = std::ceil(percentile * static_cast<double>(sorted.size()));
    const std::size_t index = static_cast<std::size_t>(std::max(1.0, rank)) - 1;
    return sorted[std::min(index, sorted.size() - 1)];
}

// 在副本上排序并计算 p50/p95/p99/max，保留调用方原始采样顺序。
inline LatencySummary summarizeLatencies(std::vector<std::uint64_t> samples) {
    if (samples.empty()) return {};
    std::sort(samples.begin(), samples.end());
    return {
        nearestRank(samples, 0.50),
        nearestRank(samples, 0.95),
        nearestRank(samples, 0.99),
        samples.back(),
    };
}

// 单个压测项的中间结果；details_json 由各组件补充业务正确性与测试口径。
struct BenchmarkResult {
    std::string name;
    std::uint64_t operations = 0;
    std::uint32_t threads = 0;
    std::uint64_t duration_ns = 0;
    std::uint64_t latency_sample_stride = 1;
    std::string latency_method = "sampled_single_operation";
    std::vector<std::uint64_t> latency_samples;
    std::uint64_t errors = 0;
    std::string details_json = "{}";
};

// 根据实际完成操作数和端到端计时计算吞吐；零时长显式返回 0，避免除零。
inline double operationsPerSecond(const BenchmarkResult& result) {
    if (result.duration_ns == 0) return 0.0;
    return static_cast<double>(result.operations) * 1000000000.0 /
           static_cast<double>(result.duration_ns);
}

// 把单项结果序列化成 schema 中的 benchmark 对象，并在此处统一延迟分位数口径。
inline std::string benchmarkJson(const BenchmarkResult& result) {
    const LatencySummary latency = summarizeLatencies(result.latency_samples);
    std::ostringstream output;
    output.imbue(std::locale::classic());
    output << '{'
           << "\"name\":" << jsonEscape(result.name) << ','
           << "\"status\":" << jsonEscape(result.errors == 0 ? "ok" : "failed") << ','
           << "\"operations\":" << result.operations << ','
           << "\"threads\":" << result.threads << ','
           << "\"duration_ms\":" << std::fixed << std::setprecision(3)
           << static_cast<double>(result.duration_ns) / 1000000.0 << ','
           << "\"ops_per_second\":" << std::fixed << std::setprecision(3)
           << operationsPerSecond(result) << ','
           << "\"latency_method\":" << jsonEscape(result.latency_method) << ','
           << "\"latency_sample_stride\":" << result.latency_sample_stride << ','
           << "\"latency_samples\":" << result.latency_samples.size() << ','
           << "\"latency_ns\":{"
           << "\"p50\":" << latency.p50_ns << ','
           << "\"p95\":" << latency.p95_ns << ','
           << "\"p99\":" << latency.p99_ns << ','
           << "\"max\":" << latency.max_ns << "},"
           << "\"errors\":" << result.errors << ','
           << "\"details\":" << result.details_json
           << '}';
    return output.str();
}

// 汇总线程私有采样。线程运行期间不共享 vector，join 后再搬移可避免锁和采样干扰。
inline void appendSamples(std::vector<std::uint64_t>& destination,
                          std::vector<std::uint64_t>&& source) {
    destination.insert(destination.end(),
                       std::make_move_iterator(source.begin()),
                       std::make_move_iterator(source.end()));
}

// 将单调时钟时间点差转换为纳秒；不受系统时间校准或 NTP 回拨影响。
inline std::uint64_t elapsedNs(SteadyClock::time_point begin, SteadyClock::time_point end) {
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(end - begin).count());
}

// 所有 worker 都 ready 后再同时放行，避免把线程创建时间计入并发吞吐。
class StartGate {
public:
    // participants 必须等于即将调用 workerWait() 的 worker 数量，否则主线程会永久等待。
    explicit StartGate(std::uint32_t participants) : participants_(participants) {}

    // worker 先发布 ready，再等待 release acquire；线程创建/初始化成本不会进入吞吐窗口。
    void workerWait() {
        ready_.fetch_add(1, std::memory_order_acq_rel);
        while (!start_.load(std::memory_order_acquire)) std::this_thread::yield();
    }

    // 主线程等待全部 worker 到达 barrier，保证高并发档位尽量同时起跑。
    void waitUntilReady() const {
        while (ready_.load(std::memory_order_acquire) != participants_) {
            std::this_thread::yield();
        }
    }

    // release-store 与 worker acquire-load 建立同步关系，然后主线程才开始等待 join。
    void release() {
        start_.store(true, std::memory_order_release);
    }

private:
    const std::uint32_t participants_;
    std::atomic<std::uint32_t> ready_{0};
    std::atomic<bool> start_{false};
};

// 先写同目录临时文件再 rename，避免中断时留下看似完整、实际被截断的 JSON。
inline bool writeJsonAtomically(const std::string& path,
                                const std::string& json,
                                std::string& error) {
    const std::string temporary = path + ".tmp." + std::to_string(getpid());
    {
        std::ofstream output(temporary, std::ios::binary | std::ios::trunc);
        if (!output) {
            error = "cannot open temporary output " + temporary;
            return false;
        }
        output << json << '\n';
        output.flush();
        if (!output) {
            error = "cannot write JSON output " + temporary;
            std::remove(temporary.c_str());
            return false;
        }
    }
    if (std::rename(temporary.c_str(), path.c_str()) != 0) {
        error = "cannot rename benchmark output: " + std::string(std::strerror(errno));
        std::remove(temporary.c_str());
        return false;
    }
    return true;
}

}  // namespace weaknet_benchmark
