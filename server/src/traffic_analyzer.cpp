// 流量分析线程封装：负责定位并初始化 eBPF 对象、周期采样和缓存实时统计。
// eBPF 不可用时保留线程运行，以降级模式向上层暴露空统计。

#include "traffic_analyzer.hpp"
#include "event_manager.hpp"
#include "flow_observation_core.hpp"
#include "logger.hpp"
#include <chrono>
#include <cstdlib>
#include <fstream>
#include <net/if.h>
#include <sstream>
#include <thread>

namespace weaknet_grpc {
namespace {

// 按“环境变量优先、常见构建目录回退”的顺序定位 eBPF 对象文件。
std::string resolveBpfObjectPath() {
    const char* configured = std::getenv("WEAKNET_BPF_OBJECT");
    if (configured && configured[0] != '\0') {
        return configured;
    }

    const char* candidates[] = {
        "server/build/flow_rate.bpf.o",
        "./server/build/flow_rate.bpf.o",
        "build/flow_rate.bpf.o",
        "../build/flow_rate.bpf.o",
    };

    for (const char* candidate : candidates) {
        std::ifstream file(candidate);
        if (file.good()) {
            return candidate;
        }
    }

    return "server/build/flow_rate.bpf.o";
}

std::string jsonEscape(const std::string& value) {
    std::ostringstream output;
    for (const unsigned char character : value) {
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
                    const char hex[] = "0123456789abcdef";
                    output << "\\u00" << hex[(character >> 4) & 0xf] << hex[character & 0xf];
                } else {
                    output << static_cast<char>(character);
                }
        }
    }
    return output.str();
}

const char* trafficEventName(uint32_t type) {
    switch (type) {
        case FLOW_EVENT_PROTECTED_PROMOTED: return "protected_promoted";
        case FLOW_EVENT_MAP_INSERT_FAILURE: return "map_insert_failure";
        case FLOW_EVENT_CONTINUITY_LOST: return "continuity_lost";
        case FLOW_EVENT_COUNTER_RESET: return "counter_reset";
        case FLOW_EVENT_SOCK_DIAG_DEGRADED: return "sock_diag_degraded";
        case FLOW_EVENT_PROTECTED_DEMOTED: return "protected_demoted";
        case FLOW_EVENT_PROTECTED_CLOSED: return "protected_closed";
        case FLOW_EVENT_TRAFFIC_ANOMALY: return "traffic_anomaly";
        default: return "unspecified";
    }
}

std::string trafficEventDetails(uint64_t generation, const TrafficObservationEvent& event) {
    std::ostringstream output;
    output << "{\"generation\":" << generation
           << ",\"event_type\":\"" << trafficEventName(event.type) << '"'
           << ",\"event_type_id\":" << event.type
           << ",\"reason\":" << event.reason
           << ",\"socket_cookie\":\"" << event.socketCookie << '"'
           << ",\"flow_key\":\"" << jsonEscape(event.flowKey) << '"'
           << ",\"description\":\"" << jsonEscape(event.description) << '"'
           << ",\"anomaly_type\":\"" << jsonEscape(event.anomalyType) << '"'
           << ",\"severity\":" << event.severity << '}';
    return output.str();
}

}  // namespace


// 获取底层单例并建立未运行的初始状态。
TrafficAnalyzer::TrafficAnalyzer() 
    : running_(false), interval_seconds_(10) {
    analyzer_ = NetTrafficAnalyzer::getInstance();
}

// 析构前停止并等待分析线程，避免对象释放后线程继续访问成员。
TrafficAnalyzer::~TrafficAnalyzer() {
    stop();
}

// 配置目标接口和异常阈值，尝试加载 eBPF 后启动周期分析线程。
void TrafficAnalyzer::start(const std::string& interface, int interval_seconds) {
    if (running_.load()) {
        const bool updated = updateInterface(interface);
        LOG_INFO(LogModule::WEAK_MGR, "Traffic analyzer already running; interface update "
            << (updated ? "succeeded" : "degraded") << ": " << interface);
        return;
    }

    {
        std::lock_guard<std::mutex> lock(interface_mutex_);
        interface_ = interface;
        ++interface_epoch_;
    }
    interval_seconds_ = interval_seconds;
    observation_state_.reset();
    last_event_generation_ = 0;
    
    // 对象路径允许部署环境覆盖，默认路径则兼容从仓库或 server 目录启动。
    analyzer_->setBpfObjectPath(resolveBpfObjectPath());
    
    // 设置流量异常检测阈值，统一由底层分析器保存。
    analyzer_->setAnomalyDetectionParams(
        5 * 1024 * 1024,    // 突发阈值：5 MB/s
        20 * 1024 * 1024,   // 可疑阈值：20 MB/s
        2.5                 // 突发倍数：历史均值的 2.5 倍
    );
    
    // 初始化接口过滤和内核探针；失败时仍允许上层获得明确的降级状态。
    if (!analyzer_->initForInterface(interface)) {
        LOG_ERROR(LogModule::WEAK_MGR, "Failed to initialize traffic analyzer for interface: " << interface);
        LOG_INFO(LogModule::WEAK_MGR, "Traffic analyzer will run in degraded mode (no eBPF monitoring)");
        // 不提前返回，线程继续运行但跳过依赖 eBPF 数据的能力。
    }
    
    running_.store(true);
    thread_ = std::make_unique<std::thread>(&TrafficAnalyzer::analyzeLoop, this);
    
    LOG_INFO(LogModule::WEAK_MGR, "Traffic analyzer started for interface: " << interface << " (interval=" << interval_seconds << "s)");
}

// 更新用户态目标接口，并让底层分析器重写 runtime_config/必要时重附加 TC。
bool TrafficAnalyzer::updateInterface(const std::string& interface) {
    std::lock_guard<std::mutex> lock(interface_mutex_);
    const bool bindingChanged = interface != interface_;
    const auto snapshot = analyzer_->getLatestSnapshot();
    const bool updated = snapshot && snapshot->support.libbpfAvailable && !snapshot->support.bpfLoaded
        ? analyzer_->initForInterface(interface)
        : analyzer_->updateInterface(interface);
    interface_ = interface;
    if (bindingChanged) ++interface_epoch_;
    if (analyzer_->isBaselinePending()) {
        observation_state_.invalidateForRebind(if_nametoindex(interface.c_str()));
    }
    return updated;
}

// 发出停止信号并 join 工作线程，之后清理跨轮次的流量历史。
void TrafficAnalyzer::stop() {
    if (!running_.load()) {
        return;
    }
    
    running_.store(false);
    
    if (thread_ && thread_->joinable()) {
        thread_->join();
    }
    
    // 停止后清空历史，防止下次启动沿用上一会话基线。
    analyzer_->clearHistory();
    observation_state_.reset();
    last_event_generation_ = 0;
    
    LOG_INFO(LogModule::WEAK_MGR, "Traffic analyzer stopped");
}

// 每轮只调用一次 refreshSnapshot；总量、异常和 Top Flow 都从同一 generation 派生。
void TrafficAnalyzer::analyzeLoop() {
    LOG_INFO(LogModule::WEAK_MGR, "Traffic analysis loop started");
    
    while (running_.load()) {
        try {
            NetTrafficAnalyzer::RealTimeStats stats;
            TrafficSnapshotPtr snapshot;
            try {
                weaknet_grpc::traffic_core::InterfaceBindingEpoch sampledBinding;
                {
                    std::lock_guard<std::mutex> interfaceLock(interface_mutex_);
                    sampledBinding.epoch = interface_epoch_;
                    sampledBinding.ifindex = if_nametoindex(interface_.c_str());
                }
                snapshot = analyzer_->refreshSnapshot();
                // 直接从刚 refresh 的快照派生 stats，不再二次读 latest。
                stats = analyzer_->getRealTimeStats(snapshot);
                std::vector<TrafficObservationEvent> eventsToPublish;
                {
                    // 持有 interface 锁直到成对发布完成；rebind 只能发生在发布前或发布后，
                    // 不能夹在 epoch 校验与 cache 写入之间。
                    std::lock_guard<std::mutex> interfaceLock(interface_mutex_);
                    const weaknet_grpc::traffic_core::InterfaceBindingEpoch currentBinding{
                        interface_epoch_, if_nametoindex(interface_.c_str())
                    };
                    if (!snapshot || !weaknet_grpc::traffic_core::sampleMatchesBinding(
                            sampledBinding, currentBinding, snapshot->boundIfindex)) {
                        LOG_INFO(LogModule::WEAK_MGR,
                                 "discarding stale traffic snapshot after interface rebind: generation="
                                 << (snapshot ? snapshot->generation : 0));
                        snapshot.reset();
                        stats = NetTrafficAnalyzer::RealTimeStats{};
                    } else if (!observation_state_.publish(stats, snapshot)) {
                        LOG_ERROR(LogModule::WEAK_MGR,
                                  "refusing mismatched traffic stats/snapshot generation");
                        snapshot.reset();
                        stats = NetTrafficAnalyzer::RealTimeStats{};
                    } else if (snapshot->generation > last_event_generation_) {
                        eventsToPublish = snapshot->events;
                        last_event_generation_ = snapshot->generation;
                    }
                }
                // 每个不可变 generation 最多桥接一次；这里发布的是状态事件，不是逐包数据。
                for (const auto& observation : eventsToPublish) {
                    NetworkEvent event(EventType::TrafficObservation,
                        observation.description.empty() ? trafficEventName(observation.type)
                                                        : observation.description,
                        "traffic_observer", 6);
                    event.timestamp = observation.timestamp;
                    event.details = trafficEventDetails(snapshot->generation, observation);
                    event.trafficObservation = observation;
                    getEventManager().emitEvent(event);
                }
            } catch (const std::exception& e) {
                LOG_INFO(LogModule::WEAK_MGR, "Traffic stats unavailable (eBPF not working): " << e.what());
            }
            
            // 所有派生查询均复用 snapshot generation，不会再 sleep 或重新遍历内核 map。
            if (snapshot && stats.valid) {
                try {
                    auto anomalies = analyzer_->detectAnomalies(snapshot);
                    if (!anomalies.empty()) {
                        LOG_INFO(LogModule::WEAK_MGR, "Detected " << anomalies.size() << " traffic anomalies");
                        for (const auto& anomaly : anomalies) {
                            LOG_INFO(LogModule::WEAK_MGR, "Anomaly: " << anomaly.anomalyType 
                                << " on " << anomaly.flowKey 
                                << " (severity: " << (anomaly.severity * 100) << "%)");
                        }
                    }
                } catch (const std::exception& e) {
                    LOG_INFO(LogModule::WEAK_MGR, "Anomaly detection unavailable: " << e.what());
                }
            }
            
            // 输出聚合统计，便于从日志核对采样窗口和接口。
            if (snapshot && stats.valid) {
                std::string currentInterface;
                {
                    std::lock_guard<std::mutex> lock(interface_mutex_);
                    currentInterface = interface_;
                }
                LOG_INFO(LogModule::WEAK_MGR, "TRAFFIC_MONITOR: Total=" << (stats.totalBps / (1024*1024)) 
                    << "MB/s, Flows=" << stats.activeFlows 
                    << ", PPS=" << stats.totalPps
                    << ", Interface=" << currentInterface
                    << ", Generation=" << stats.generation
                    << ", ContinuityLost=" << stats.continuityLostFlows);
                    
                // Top Flow 采样可能独立失败，不影响已经取得的总量统计。
                try {
                    auto topFlows = analyzer_->sampleTopFlows(snapshot, 5);
                    if (!topFlows.empty()) {
                        LOG_INFO(LogModule::WEAK_MGR, "TOP_FLOWS: ");
                        for (size_t i = 0; i < std::min(topFlows.size(), size_t(3)); ++i) {
                            const auto& flow = topFlows[i];
                            LOG_INFO(LogModule::WEAK_MGR, "  " << (i+1) << ". " << flow.proto 
                                << " " << flow.src << ":" << flow.sport 
                                << " -> " << flow.dst << ":" << flow.dport 
                                << " | " << (flow.bps / 1024) << "KB/s, " << flow.pps << "pps");
                        }
                    }
                } catch (const std::exception& e) {
                    LOG_INFO(LogModule::WEAK_MGR, "Top flows unavailable: " << e.what());
                }
            } else {
                const std::string reason = snapshot ? snapshot->support.degradedReason : "snapshot unavailable";
                LOG_INFO(LogModule::WEAK_MGR, "TRAFFIC_MONITOR: warming/degraded mode: " << reason);
            }
            
        } catch (const std::exception& e) {
            LOG_ERROR(LogModule::WEAK_MGR, "Traffic analysis error: " << e.what());
        }
        
        // 拆成一秒粒度等待，使 stop 最多等待约一秒即可被工作线程观察到。
        for (int i = 0; i < interval_seconds_ && running_.load(); ++i) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }
    
    LOG_INFO(LogModule::WEAK_MGR, "Traffic analysis loop stopped");
}

// 返回缓存快照；复制期间持锁，调用方不会观察到部分更新。
NetTrafficAnalyzer::RealTimeStats TrafficAnalyzer::getCurrentStats() const {
    return observation_state_.load().stats;
}

// 透传指定窗口的 Top Flow 采样请求。
std::vector<FlowRate> TrafficAnalyzer::getTopFlows(int sample_seconds, int top_count) const {
    (void)sample_seconds;
    return getTopFlows(observation_state_.load().snapshot, top_count);
}

std::vector<FlowRate> TrafficAnalyzer::getTopFlows(
    const TrafficSnapshotPtr& snapshot, int top_count) const {
    return analyzer_->sampleTopFlows(snapshot, top_count);
}

// 透传指定窗口的流量异常检测请求。
std::vector<TrafficAnomaly> TrafficAnalyzer::detectAnomalies(int detection_seconds) const {
    (void)detection_seconds;
    return detectAnomalies(observation_state_.load().snapshot);
}

std::vector<TrafficAnomaly> TrafficAnalyzer::detectAnomalies(
    const TrafficSnapshotPtr& snapshot) const {
    return analyzer_->detectAnomalies(snapshot);
}

// 共享不可变快照，调用方只读且不会延长采样临界区。
TrafficSnapshotPtr TrafficAnalyzer::getCurrentSnapshot() const {
    return observation_state_.load().snapshot;
}

TrafficAnalyzer::ObservationState TrafficAnalyzer::getCurrentObservationState() const {
    return observation_state_.load();
}

// 返回底层分析器维护的流级历史快照。
std::map<std::string, TrafficHistory> TrafficAnalyzer::getTrafficHistory() const {
    return analyzer_->getTrafficHistory();
}

} // namespace weaknet_grpc
