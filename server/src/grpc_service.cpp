// gRPC 传输层：实现查询、健康检查、主动 Ping 与事件流订阅接口。
// 事件按订阅者独立排队并限制队列长度，避免慢客户端无限占用内存。

#include "grpc_service.hpp"

#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <cstdlib>
#include <deque>
#include <net/if.h>
#include <set>
#include <thread>

#include <grpcpp/grpcpp.h>

#include "common.hpp"
#include "logger.hpp"
#include "net_info.hpp"
#include "net_ping.h"
#include "network_quality_assessor.hpp"
#include "rtt_utils.hpp"
#include "server.hpp"
#include "using_iface.h"
#include "weak_netmgr.hpp"
#include "weaknet.grpc.pb.h"

namespace weaknet_grpc {
namespace {

constexpr size_t kMaxQueuedEvents = 128;
constexpr int64_t kRouteTransitionEvidenceWindowMs = 60 * 1000;

// 下面两个 helper 是协议滚动升级期间唯一允许触碰 deprecated RTT 字段的位置。
// 精确值仍写入新的 optional double 字段，旧字段仅服务尚未升级的客户端。
#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#elif defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif
void setLegacyInterfaceRttFields(weaknet::v1::InterfaceSnapshot* snapshot,
                                 double rttMs,
                                 double previousRttMs) {
    snapshot->set_rtt_ms(toLegacyRttMilliseconds(rttMs));
    snapshot->set_previous_rtt_ms(toLegacyRttMilliseconds(previousRttMs));
}

void setLegacyPingLatency(weaknet::v1::PingReply* reply, int32_t latencyMs) {
    reply->set_latency_ms(latencyMs);
}
#if defined(__clang__)
#pragma clang diagnostic pop
#elif defined(__GNUC__)
#pragma GCC diagnostic pop
#endif

// 将内部事件枚举映射为稳定的文本名称，供协议兼容字段使用。
const char* eventTypeName(EventType type) {
    switch (type) {
        case EventType::Changed:
            return kSignalChanged;
        case EventType::InterfaceChanged:
            return kSignalInterfaceChanged;
        case EventType::ConnectionModeChanged:
            return kSignalConnectionModeChanged;
        case EventType::NetworkQualityChanged:
            return kSignalNetworkQualityChanged;
        case EventType::TcpLossRateChanged:
            return "TcpLossRateChanged";
        case EventType::RttChanged:
            return "RttChanged";
        case EventType::RssiChanged:
            return "RssiChanged";
        case EventType::TrafficObservation:
            return "TrafficObservation";
    }
    return "Unknown";
}

// 将内部事件类型转换为 protobuf 枚举。
weaknet::v1::EventType toProtoEventType(EventType type) {
    switch (type) {
        case EventType::Changed:
            return weaknet::v1::EVENT_TYPE_CHANGED;
        case EventType::InterfaceChanged:
            return weaknet::v1::EVENT_TYPE_INTERFACE_CHANGED;
        case EventType::ConnectionModeChanged:
            return weaknet::v1::EVENT_TYPE_CONNECTION_MODE_CHANGED;
        case EventType::NetworkQualityChanged:
            return weaknet::v1::EVENT_TYPE_NETWORK_QUALITY_CHANGED;
        case EventType::TcpLossRateChanged:
            return weaknet::v1::EVENT_TYPE_TCP_LOSS_RATE_CHANGED;
        case EventType::RttChanged:
            return weaknet::v1::EVENT_TYPE_RTT_CHANGED;
        case EventType::RssiChanged:
            return weaknet::v1::EVENT_TYPE_RSSI_CHANGED;
        case EventType::TrafficObservation:
            return weaknet::v1::EVENT_TYPE_TRAFFIC_OBSERVATION;
    }
    return weaknet::v1::EVENT_TYPE_UNSPECIFIED;
}

// 将进程内接口介质类型映射为跨语言协议枚举。
weaknet::v1::InterfaceType toProtoInterfaceType(NetType type) {
    switch (type) {
        case NetType::Ethernet:
            return weaknet::v1::INTERFACE_TYPE_ETHERNET;
        case NetType::WiFi:
            return weaknet::v1::INTERFACE_TYPE_WIFI;
        case NetType::Cellular:
            return weaknet::v1::INTERFACE_TYPE_CELLULAR;
        case NetType::Unknown:
        default:
            return weaknet::v1::INTERFACE_TYPE_UNSPECIFIED;
    }
}

// 将二态接口状态映射为协议枚举；NetInfo 当前没有独立的 unknown 状态。
weaknet::v1::InterfaceState toProtoInterfaceState(NetState state) {
    return state == NetState::Up ? weaknet::v1::INTERFACE_STATE_UP : weaknet::v1::INTERFACE_STATE_DOWN;
}

// 将 RTT 派生的链路质量映射为协议枚举。
weaknet::v1::LinkQuality toProtoLinkQuality(LinkQuality quality) {
    switch (quality) {
        case LinkQuality::Good:
            return weaknet::v1::LINK_QUALITY_GOOD;
        case LinkQuality::Fair:
            return weaknet::v1::LINK_QUALITY_FAIR;
        case LinkQuality::Poor:
            return weaknet::v1::LINK_QUALITY_POOR;
        case LinkQuality::Bad:
            return weaknet::v1::LINK_QUALITY_BAD;
        case LinkQuality::Unknown:
        default:
            return weaknet::v1::LINK_QUALITY_UNSPECIFIED;
    }
}

// 将综合质量等级映射为协议枚举，避免 Dashboard 再解析 JSON 文本。
weaknet::v1::NetworkQualityLevel toProtoNetworkQualityLevel(NetworkQualityLevel level) {
    switch (level) {
        case NetworkQualityLevel::EXCELLENT:
            return weaknet::v1::NETWORK_QUALITY_LEVEL_EXCELLENT;
        case NetworkQualityLevel::GOOD:
            return weaknet::v1::NETWORK_QUALITY_LEVEL_GOOD;
        case NetworkQualityLevel::FAIR:
            return weaknet::v1::NETWORK_QUALITY_LEVEL_FAIR;
        case NetworkQualityLevel::POOR:
            return weaknet::v1::NETWORK_QUALITY_LEVEL_POOR;
        case NetworkQualityLevel::UNKNOWN:
        default:
            return weaknet::v1::NETWORK_QUALITY_LEVEL_UNSPECIFIED;
    }
}

// proto3 数值默认值不能表达“未采样”，因此每个指标同时携带可用性枚举。
weaknet::v1::MetricAvailability metricAvailability(bool available) {
    return available ? weaknet::v1::METRIC_AVAILABILITY_AVAILABLE
                     : weaknet::v1::METRIC_AVAILABILITY_UNAVAILABLE;
}

// 解析客户端过滤条件；未知枚举返回 false 并由调用方忽略。
bool fromProtoEventType(weaknet::v1::EventType protoType, EventType* out) {
    switch (protoType) {
        case weaknet::v1::EVENT_TYPE_CHANGED:
            *out = EventType::Changed;
            return true;
        case weaknet::v1::EVENT_TYPE_INTERFACE_CHANGED:
            *out = EventType::InterfaceChanged;
            return true;
        case weaknet::v1::EVENT_TYPE_CONNECTION_MODE_CHANGED:
            *out = EventType::ConnectionModeChanged;
            return true;
        case weaknet::v1::EVENT_TYPE_NETWORK_QUALITY_CHANGED:
            *out = EventType::NetworkQualityChanged;
            return true;
        case weaknet::v1::EVENT_TYPE_TCP_LOSS_RATE_CHANGED:
            *out = EventType::TcpLossRateChanged;
            return true;
        case weaknet::v1::EVENT_TYPE_RTT_CHANGED:
            *out = EventType::RttChanged;
            return true;
        case weaknet::v1::EVENT_TYPE_RSSI_CHANGED:
            *out = EventType::RssiChanged;
            return true;
        case weaknet::v1::EVENT_TYPE_TRAFFIC_OBSERVATION:
            *out = EventType::TrafficObservation;
            return true;
        default:
            return false;
    }
}

// 把进程内时间点转换为跨语言协议使用的 Unix 毫秒时间戳。
int64_t toUnixMillis(const std::chrono::system_clock::time_point& tp) {
    return std::chrono::duration_cast<std::chrono::milliseconds>(tp.time_since_epoch()).count();
}

// 把进程内资源样本复制到协议；unavailable_metrics 保留真实零与采集失败的区别。
void fillProtoProcessResourceSnapshot(const ProcessResourceSample& sample,
                                      weaknet::v1::ProcessResourceSnapshot* out) {
    out->set_sampled_at_unix_ms(sample.sampledAtUnixMs);
    out->set_sample_window_ms(sample.sampleWindowMs);
    out->set_cpu_percent(sample.cpuPercent);
    out->set_user_cpu_time_micros(sample.userCpuTimeMicros);
    out->set_system_cpu_time_micros(sample.systemCpuTimeMicros);
    out->set_rss_bytes(sample.rssBytes);
    out->set_peak_rss_bytes(sample.peakRssBytes);
    out->set_virtual_memory_bytes(sample.virtualMemoryBytes);
    out->set_thread_count(sample.threadCount);
    out->set_open_fd_count(sample.openFdCount);
    out->set_uptime_seconds(sample.uptimeSeconds);
    out->set_voluntary_context_switches(sample.voluntaryContextSwitches);
    out->set_involuntary_context_switches(sample.involuntaryContextSwitches);
    out->set_logical_cpu_count(sample.logicalCpuCount);
    for (const auto& metric : sample.unavailableMetrics) {
        out->add_unavailable_metrics(metric);
    }
}

weaknet::v1::TrafficObservationEventType toProtoTrafficObservationEventType(uint32_t type) {
    const int value = static_cast<int>(type);
    if (!weaknet::v1::TrafficObservationEventType_IsValid(value)) {
        return weaknet::v1::TRAFFIC_OBSERVATION_EVENT_UNSPECIFIED;
    }
    return static_cast<weaknet::v1::TrafficObservationEventType>(value);
}

// Snapshot 和实时事件共用一个 typed 转换，避免两条对外链路字段漂移。
void fillProtoTrafficObservationEvent(const TrafficObservationEvent& event,
                                      weaknet::v1::TrafficObservationEvent* out) {
    out->set_type(toProtoTrafficObservationEventType(event.type));
    out->set_reason(event.reason);
    out->set_socket_cookie(event.socketCookie);
    out->set_flow_key(event.flowKey);
    out->set_description(event.description);
    out->set_timestamp_unix_ms(toUnixMillis(event.timestamp));
    out->set_generation(event.generation);
    out->set_anomaly_type(event.anomalyType);
    out->set_severity(event.severity);
}

// 完整复制内部事件字段到 protobuf，保留类型文本用于旧客户端兼容。
weaknet::v1::NetworkEvent toProtoEvent(const NetworkEvent& event) {
    weaknet::v1::NetworkEvent out;
    out.set_type(toProtoEventType(event.type));
    out.set_event_type(eventTypeName(event.type));
    out.set_message(event.message);
    out.set_source(event.source);
    out.set_details(event.details);
    out.set_counter(event.counter);
    out.set_priority(event.priority);
    out.set_timestamp_unix_ms(toUnixMillis(event.timestamp));
    if (event.trafficObservation.has_value()) {
        fillProtoTrafficObservationEvent(*event.trafficObservation,
                                         out.mutable_traffic_observation());
    }
    return out;
}

}  // namespace

struct GrpcServer::Subscriber {
    std::mutex mutex;
    std::condition_variable cv;
    std::deque<NetworkEvent> queue;
    std::set<EventType> filters;
    bool active = true;

    // 空过滤集合表示订阅全部事件，否则只接受显式选择的类型。
    bool accepts(EventType type) const {
        return filters.empty() || filters.count(type) > 0;
    }
};

class GrpcServer::ServiceImpl final : public weaknet::v1::WeakNet::Service {
public:
    // 保存非拥有型 ctx 与 owner 指针；调用方必须保证二者覆盖全部 RPC 生命周期。
    ServiceImpl(ServerContext* ctx, GrpcServer* owner) : ctx_(ctx), owner_(owner) {}

    // 返回基础连通性消息，供最小客户端验证 RPC 链路。
    grpc::Status Get(grpc::ServerContext*, const weaknet::v1::Empty*, weaknet::v1::GetReply* reply) override {
        reply->set_message("Hello from WeakNet Server");
        return grpc::Status::OK;
    }

    // 返回当前接口名快照；优先读取集中管理器，缺失时回退到上下文镜像。
    grpc::Status GetInterfaces(grpc::ServerContext*, const weaknet::v1::Empty*, weaknet::v1::GetInterfacesReply* reply) override {
        std::vector<NetInfo> interfaces;
        if (ctx_->weak_mgr) {
            interfaces = ctx_->weak_mgr->getCurrentInterfaces();
        } else {
            std::lock_guard<std::mutex> lk(ctx_->iface_mutex);
            interfaces = ctx_->iface_list;
        }
        std::vector<std::string> snapshot = WeakNetMgr::namesOf(interfaces);
        for (const auto& iface : snapshot) {
            reply->add_interfaces(iface);
        }
        return grpc::Status::OK;
    }

    // 从 WeakNetMgr 只复制一次状态，生成无需日志正则或 JSON 二次解析的 typed snapshot。
    grpc::Status GetNetworkSnapshot(grpc::ServerContext*,
                                    const weaknet::v1::Empty*,
                                    weaknet::v1::NetworkSnapshot* reply) override {
        std::vector<NetInfo> snapshot;
        if (ctx_->weak_mgr) {
            snapshot = ctx_->weak_mgr->getCurrentInterfaces();
        } else {
            std::lock_guard<std::mutex> lk(ctx_->iface_mutex);
            snapshot = ctx_->iface_list;
        }

        const int64_t observedAtUnixMs = toUnixMillis(std::chrono::system_clock::now());
        reply->set_observed_at_unix_ms(observedAtUnixMs);
        // 资源采样与本轮 typed snapshot 同步返回；采样器内部处理并发 RPC 和极短差分窗口。
        fillProtoProcessResourceSnapshot(
            ctx_->process_resource_sampler.sample(), reply->mutable_engine_resources());

        const auto trafficAnalyzer = ctx_->weak_mgr ? ctx_->weak_mgr->getTrafficAnalyzer() : nullptr;
        TrafficAnalyzer::ObservationState trafficObservationState;
        if (trafficAnalyzer) {
            // 单次加锁复制 stats+snapshot，禁止采样线程在两次 getter 间发布 N+1。
            trafficObservationState = trafficAnalyzer->getCurrentObservationState();
        }
        const auto& trafficStats = trafficObservationState.stats;
        const TrafficSnapshotPtr& trafficSnapshot = trafficObservationState.snapshot;
        const bool trafficGenerationAligned = trafficSnapshot &&
            trafficStats.generation == trafficSnapshot->generation &&
            trafficStats.boundIfindex == trafficSnapshot->boundIfindex;
        const bool trafficObservationValid = trafficAnalyzer && trafficAnalyzer->isRunning() &&
            trafficGenerationAligned && trafficStats.valid;
        auto* trafficStatus = reply->mutable_traffic_observation();
        trafficStatus->set_availability(metricAvailability(trafficObservationValid));
        trafficStatus->set_valid(trafficObservationValid);
        trafficStatus->set_generation(trafficStats.generation);
        trafficStatus->set_sampled_at_unix_ms(toUnixMillis(trafficStats.timestamp));
        trafficStatus->set_bound_ifindex(trafficStats.boundIfindex);
        trafficStatus->set_capture_mode(trafficStats.support.captureMode);
        std::string trafficDegradedReason = trafficStats.support.degradedReason;
        if (trafficDegradedReason.empty() && !trafficObservationValid) {
            if (!trafficAnalyzer) {
                trafficDegradedReason = "traffic analyzer is not initialized";
            } else if (!trafficAnalyzer->isRunning()) {
                trafficDegradedReason = "traffic analyzer is not running";
            } else {
                trafficDegradedReason = "traffic observation is warming up or unavailable";
            }
        }
        trafficStatus->set_degraded_reason(trafficDegradedReason);
        trafficStatus->set_libbpf_available(trafficStats.support.libbpfAvailable);
        trafficStatus->set_bpf_loaded(trafficStats.support.bpfLoaded);
        trafficStatus->set_tc_ingress_attached(trafficStats.support.tcIngressAttached);
        trafficStatus->set_tc_egress_attached(trafficStats.support.tcEgressAttached);
        trafficStatus->set_tcp_kprobe_attached(trafficStats.support.tcpKprobeAttached);
        trafficStatus->set_udp_kprobe_attached(trafficStats.support.udpKprobeAttached);
        trafficStatus->set_sock_diag_available(trafficStats.support.sockDiagAvailable);
        trafficStatus->set_sock_diag_ipv4_available(trafficStats.support.sockDiagIpv4Available);
        trafficStatus->set_sock_diag_ipv6_available(trafficStats.support.sockDiagIpv6Available);
        trafficStatus->set_proc_owner_resolution(trafficStats.support.procOwnerResolution);
        trafficStatus->set_ipv4_supported(trafficStats.support.ipv4Supported);
        trafficStatus->set_ipv6_supported(trafficStats.support.ipv6Supported);
        trafficStatus->set_ipv6_extension_headers_supported(trafficStats.support.ipv6ExtensionHeadersSupported);
        trafficStatus->set_bidirectional(trafficStats.support.bidirectional);
        trafficStatus->set_udp_interface_reliable(trafficStats.support.udpInterfaceReliable);
        trafficStatus->set_sock_diag_status(trafficStats.support.sockDiagStatus);
        trafficStatus->set_coverage_limitations(trafficStats.support.coverageLimitations);
        trafficStatus->set_capture_complete(trafficStats.support.captureComplete);
        trafficStatus->set_capture_completeness(trafficStats.support.captureCompleteness);
        trafficStatus->set_map_read_complete(
            trafficGenerationAligned && trafficSnapshot->mapReadComplete);
        trafficStatus->set_baseline_only(
            !trafficGenerationAligned || trafficSnapshot->baselineOnly);

        if (trafficGenerationAligned) {
            const auto& observability = trafficSnapshot->mapObservability;
            auto* map = trafficStatus->mutable_map_observability();
            map->set_lru_capacity(observability.lruCapacity);
            map->set_protected_capacity(observability.protectedCapacity);
            map->set_lru_entries(observability.lruEntries);
            map->set_protected_entries(observability.protectedEntries);
            map->set_disappeared_this_window(observability.disappearedThisWindow);
            map->set_continuity_lost_this_window(observability.continuityLostThisWindow);
            map->set_counter_resets_this_window(observability.counterResetsThisWindow);
            map->set_policy_update_attempts(observability.policyUpdateAttempts);
            map->set_policy_update_failures(observability.policyUpdateFailures);
            map->set_read_complete(observability.mapReadComplete);
            map->set_lookup_misses(observability.mapLookupMisses);
            map->set_duplicate_keys(observability.mapDuplicateKeys);
            map->set_read_error(observability.mapReadError);
            const auto& counters = observability.kernelCounters;
            map->set_lru_insert_failures(counters[FLOW_STAT_LRU_INSERT_FAILURE]);
            map->set_protected_insert_failures(counters[FLOW_STAT_PROTECTED_INSERT_FAILURE]);
            map->set_interface_insert_failures(counters[FLOW_STAT_IFACE_INSERT_FAILURE]);
            map->set_event_drops(counters[FLOW_STAT_EVENT_DROPPED]);
            map->set_packets_seen(counters[FLOW_STAT_PACKETS_SEEN]);
            map->set_interface_rejected(counters[FLOW_STAT_IFACE_REJECTED]);
            map->set_parse_failures(counters[FLOW_STAT_PARSE_FAILURE]);
            map->set_lru_lookup_misses(counters[FLOW_STAT_LRU_LOOKUP_MISS]);
            map->set_lru_insert_attempts(counters[FLOW_STAT_LRU_INSERT_ATTEMPT]);
            map->set_lru_insert_successes(counters[FLOW_STAT_LRU_INSERT_SUCCESS]);
            map->set_protected_hits(counters[FLOW_STAT_PROTECTED_HIT]);
            map->set_protected_insert_attempts(counters[FLOW_STAT_PROTECTED_INSERT_ATTEMPT]);
            map->set_protected_insert_successes(counters[FLOW_STAT_PROTECTED_INSERT_SUCCESS]);
            map->set_interface_insert_attempts(counters[FLOW_STAT_IFACE_INSERT_ATTEMPT]);
            map->set_events_emitted(counters[FLOW_STAT_EVENT_EMITTED]);
            map->set_user_events_truncated(observability.userEventsTruncated);
            for (uint64_t counter : counters) map->add_kernel_counters(counter);

            for (const auto& event : trafficSnapshot->events) {
                fillProtoTrafficObservationEvent(event, trafficStatus->add_recent_events());
            }
        }
        const NetInfo* assessedInterface = snapshot.empty() ? nullptr : &snapshot.front();

        for (const auto& net : snapshot) {
            auto* item = reply->add_interfaces();
            item->set_interface_name(net.ifName());
            item->set_is_default_route(net.isDefaultRoute());
            item->set_interface_type(toProtoInterfaceType(net.type()));
            item->set_state(toProtoInterfaceState(net.state()));
            item->set_using_now(net.usingNow());
            // 新字段保留 double 精度；旧 int32 字段继续填充，供滚动升级中的旧客户端使用。
            setLegacyInterfaceRttFields(item, net.rttMs(), net.prevRttMs());
            if (isRttAvailable(net.rttMs())) item->set_rtt_ms_precise(net.rttMs());
            if (isRttAvailable(net.prevRttMs())) item->set_previous_rtt_ms_precise(net.prevRttMs());
            item->set_rtt_availability(metricAvailability(isRttAvailable(net.rttMs())));
            item->set_link_quality(toProtoLinkQuality(net.quality()));
            item->set_rssi_dbm(net.rssiDbm());
            item->set_rssi_availability(metricAvailability(isRssiAvailable(net.rssiDbm())));
            item->set_tcp_retransmission_rate_percent(net.tcpLossRate());
            item->set_tcp_retransmission_level(net.tcpLossLevel());
            item->set_tcp_retransmission_availability(
                metricAvailability(isTcpRetransmissionAvailable(net.tcpLossRate())));
            const uint32_t interfaceIndex = if_nametoindex(net.ifName().c_str());
            const bool trafficBoundToInterface = trafficStats.boundIfindex != 0
                && interfaceIndex == trafficStats.boundIfindex;
            const bool interfaceTrafficValid = trafficObservationValid
                && net.usingNow() && trafficBoundToInterface;
            // 数值、valid、generation 均来自同一份 RealTimeStats，禁止 N 状态搭配 N-1 数值。
            if (interfaceTrafficValid) {
                item->set_traffic_bytes_per_second(trafficStats.totalBps);
                item->set_traffic_packets_per_second(trafficStats.totalPps);
                item->set_active_flows(static_cast<uint32_t>(trafficStats.activeFlows));
            }
            item->set_traffic_availability(
                metricAvailability(interfaceTrafficValid));

            if (net.usingNow()) {
                reply->set_has_active_interface(true);
                reply->set_active_interface(net.ifName());
                assessedInterface = &net;
            }
        }

        // 路由世代来自 rtnetlink 发布点，而非“上一次 RPC 看到了什么”，避免轮询漏报/误报。
        const RouteTransitionState routeState =
            UsingInterfaceManager::getInstance()->getRouteTransitionState();
        const bool changedRecently = routeState.changedAtUnixMs > 0
            && observedAtUnixMs >= routeState.changedAtUnixMs
            && observedAtUnixMs - routeState.changedAtUnixMs <= kRouteTransitionEvidenceWindowMs;
        reply->set_previous_active_interface(routeState.previousInterface);
        reply->set_default_route_changed(changedRecently);
        reply->set_route_generation(routeState.generation);
        reply->set_route_changed_at_unix_ms(routeState.changedAtUnixMs);
        reply->set_current_default_route_interface(routeState.currentInterface);

        NetworkQualityAssessor assessor;
        const NetworkQualityResult quality = assessor.assessQuality(snapshot);
        auto* qualitySummary = reply->mutable_quality();
        qualitySummary->set_level(toProtoNetworkQualityLevel(quality.level));
        qualitySummary->set_score(quality.score);
        for (const auto& issue : quality.issues) {
            qualitySummary->add_issues(issue);
        }

        if (!reply->has_active_interface()) {
            qualitySummary->add_missing_metrics("active_interface");
        }
        if (!assessedInterface) {
            qualitySummary->add_missing_metrics("interfaces");
        } else {
            if (!isRttAvailable(assessedInterface->rttMs())) {
                qualitySummary->add_missing_metrics("rtt_ms");
            }
            if (!isRssiAvailable(assessedInterface->rssiDbm())) {
                qualitySummary->add_missing_metrics("rssi_dbm");
            }
            if (!isTcpRetransmissionAvailable(assessedInterface->tcpLossRate())) {
                qualitySummary->add_missing_metrics("tcp_retransmission_rate_percent");
            }
            const uint32_t assessedIfindex = if_nametoindex(assessedInterface->ifName().c_str());
            if (!trafficObservationValid || !assessedInterface->usingNow()
                || assessedIfindex == 0 || assessedIfindex != trafficStats.boundIfindex) {
                qualitySummary->add_missing_metrics("traffic");
            }
        }
        qualitySummary->set_degraded(qualitySummary->missing_metrics_size() > 0);
        return grpc::Status::OK;
    }

    // 对当前接口快照即时执行综合质量评估，并返回 JSON 详情。
    grpc::Status HealthCheck(grpc::ServerContext*, const weaknet::v1::Empty*, weaknet::v1::HealthCheckReply* reply) override {
        std::vector<NetInfo> snapshot;
        if (ctx_->weak_mgr) {
            snapshot = ctx_->weak_mgr->getCurrentInterfaces();
        } else {
            std::lock_guard<std::mutex> lk(ctx_->iface_mutex);
            snapshot = ctx_->iface_list;
        }

        NetworkQualityAssessor assessor;
        NetworkQualityResult result = assessor.assessQuality(snapshot);
        reply->set_details(result.details);
        return grpc::Status::OK;
    }

    // 经当前活动接口对指定主机执行一次 ICMP Ping，并区分参数与前置状态错误。
    grpc::Status Ping(grpc::ServerContext*, const weaknet::v1::PingRequest* request, weaknet::v1::PingReply* reply) override {
        const std::string hostname = request->hostname();
        if (hostname.empty()) {
            return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "hostname must not be empty");
        }

        std::string currentIface;
        std::vector<NetInfo> interfaces;
        if (ctx_->weak_mgr) {
            interfaces = ctx_->weak_mgr->getCurrentInterfaces();
        } else {
            std::lock_guard<std::mutex> lk(ctx_->iface_mutex);
            interfaces = ctx_->iface_list;
        }
        for (const auto& net : interfaces) {
            if (net.usingNow()) {
                currentIface = net.ifName();
                break;
            }
        }

        if (currentIface.empty()) {
            return grpc::Status(grpc::StatusCode::FAILED_PRECONDITION, "no active network interface");
        }

        auto pingInstance = NetPing::getInstance();
        const double pingResult = pingInstance->ping(hostname, currentIface, 3000);

        const int32_t legacyPingResult = toLegacyPingMilliseconds(pingResult);
        reply->set_interface_name(currentIface);
        setLegacyPingLatency(reply, legacyPingResult);
        if (isRttAvailable(pingResult)) {
            // optional precise 字段只在成功时出现，调用方可用 presence 区分有效 0 与字段缺失。
            reply->set_latency_ms_precise(pingResult);
            reply->set_success(true);
            reply->set_result("PING " + hostname + " via " + currentIface + ": "
                + formatRttMilliseconds(pingResult) + "ms");
        } else {
            reply->set_success(false);
            // 失败码沿用历史整数文本，避免 double 迁移把 -5 变成不兼容的 -5.000000。
            reply->set_error("ping failed with error code " + std::to_string(legacyPingResult));
            reply->set_result("PING " + hostname + " via " + currentIface
                + ": FAILED (error code: " + std::to_string(legacyPingResult) + ")");
        }

        return grpc::Status::OK;
    }

    // 建立服务端流：按请求过滤事件，阻塞等待队列并感知客户端取消。
    grpc::Status SubscribeEvents(grpc::ServerContext* context,
                                 const weaknet::v1::EventRequest* request,
                                 grpc::ServerWriter<weaknet::v1::NetworkEvent>* writer) override {
        auto subscriber = std::make_shared<Subscriber>();
        for (const auto protoType : request->types()) {
            EventType type;
            if (fromProtoEventType(static_cast<weaknet::v1::EventType>(protoType), &type)) {
                subscriber->filters.insert(type);
            }
        }

        owner_->addSubscriber(subscriber);
        LOG_INFO(LogModule::EVENT_MGR, "gRPC event subscriber connected");

        while (!context->IsCancelled()) {
            NetworkEvent event;
            {
                std::unique_lock<std::mutex> lk(subscriber->mutex);
                // 定时唤醒用于复查 gRPC 取消状态，避免无事件时永久阻塞。
                subscriber->cv.wait_for(lk, std::chrono::seconds(1), [&]() {
                    return !subscriber->queue.empty() || !subscriber->active || context->IsCancelled();
                });

                if (!subscriber->active || context->IsCancelled()) {
                    break;
                }
                if (subscriber->queue.empty()) {
                    continue;
                }

                event = subscriber->queue.front();
                subscriber->queue.pop_front();
            }

            weaknet::v1::NetworkEvent protoEvent = toProtoEvent(event);
            if (!writer->Write(protoEvent)) {
                break;
            }
        }

        {
            std::lock_guard<std::mutex> lk(subscriber->mutex);
            subscriber->active = false;
        }
        owner_->removeSubscriber(subscriber);
        LOG_INFO(LogModule::EVENT_MGR, "gRPC event subscriber disconnected");
        return grpc::Status::OK;
    }

private:
    ServerContext* ctx_;
    GrpcServer* owner_;
};

// 默认构造时暂不占用端口，实际资源在 start 中创建。
GrpcServer::GrpcServer() = default;
// 析构复用 shutdown；调用方仍应先结束长连接，避免底层 Shutdown 卡住。
GrpcServer::~GrpcServer() {
    shutdown();
}

// 注册服务实现并在指定地址启动不加密的本地 gRPC Server。
bool GrpcServer::start(ServerContext* ctx, const std::string& address) {
    service_ = std::make_unique<ServiceImpl>(ctx, this);

    grpc::ServerBuilder builder;
    builder.AddListeningPort(address, grpc::InsecureServerCredentials());
    builder.RegisterService(service_.get());
    std::shared_ptr<grpc::Server> startedServer = builder.BuildAndStart();
    if (!startedServer) {
        LOG_ERROR(LogModule::SERVER, "failed to start gRPC server on " << address);
        return false;
    }
    {
        std::lock_guard<std::mutex> lock(lifecycle_mutex_);
        server_ = std::move(startedServer);
        shutdown_started_ = false;
        shutdown_complete_ = false;
    }

    LOG_INFO(LogModule::SERVER, "gRPC server listening on " << address);
    return true;
}

// 阻塞主线程直到 gRPC Server 被关闭。
void GrpcServer::wait() {
    std::shared_ptr<grpc::Server> server;
    {
        std::lock_guard<std::mutex> lock(lifecycle_mutex_);
        server = server_;
    }
    if (server) {
        server->Wait();
    }
}

// 先停用订阅者并 notify，确保同步流离开，再 Shutdown；shared_ptr 保护并发 Wait 的对象寿命。
void GrpcServer::shutdown() {
    std::shared_ptr<grpc::Server> server;
    {
        std::unique_lock<std::mutex> lock(lifecycle_mutex_);
        if (shutdown_started_) {
            lifecycle_cv_.wait(lock, [this]() { return shutdown_complete_; });
            return;
        }
        shutdown_started_ = true;
        server = server_;
    }

    std::vector<std::shared_ptr<Subscriber>> subscribers;
    {
        std::lock_guard<std::mutex> lk(subscribers_mutex_);
        for (auto it = subscribers_.begin(); it != subscribers_.end();) {
            if (auto subscriber = it->lock()) {
                subscribers.push_back(subscriber);
                ++it;
            } else {
                it = subscribers_.erase(it);
            }
        }
    }

    for (const auto& subscriber : subscribers) {
        {
            std::lock_guard<std::mutex> lk(subscriber->mutex);
            subscriber->active = false;
        }
        subscriber->cv.notify_all();
    }

    if (server) {
        server->Shutdown();
    }
    {
        std::lock_guard<std::mutex> lock(lifecycle_mutex_);
        if (server_ == server) {
            server_.reset();
        }
        shutdown_complete_ = true;
    }
    lifecycle_cv_.notify_all();
}

// 把事件扇出到所有匹配订阅者；队列满时丢弃最旧项保持内存有界。
void GrpcServer::publish(const NetworkEvent& event) {
    std::vector<std::shared_ptr<Subscriber>> subscribers;
    // 先在全局锁下提升 weak_ptr，再逐订阅者加锁，避免长时间占用订阅表锁。
    {
        std::lock_guard<std::mutex> lk(subscribers_mutex_);
        for (auto it = subscribers_.begin(); it != subscribers_.end();) {
            if (auto subscriber = it->lock()) {
                subscribers.push_back(subscriber);
                ++it;
            } else {
                it = subscribers_.erase(it);
            }
        }
    }

    for (const auto& subscriber : subscribers) {
        {
            std::lock_guard<std::mutex> lk(subscriber->mutex);
            if (!subscriber->active || !subscriber->accepts(event.type)) {
                continue;
            }
            // 慢消费者只保留最近事件，防止生产线程被无界积压拖垮。
            if (subscriber->queue.size() >= kMaxQueuedEvents) {
                subscriber->queue.pop_front();
            }
            subscriber->queue.push_back(event);
        }
        subscriber->cv.notify_one();
    }
}

// 在全局订阅表中登记弱引用，实际生命周期仍由流处理调用持有。
void GrpcServer::addSubscriber(const std::shared_ptr<Subscriber>& subscriber) {
    std::lock_guard<std::mutex> lk(subscribers_mutex_);
    subscribers_.push_back(subscriber);
}

// 移除目标或已过期订阅者，防止订阅表积累失效 weak_ptr。
void GrpcServer::removeSubscriber(const std::shared_ptr<Subscriber>& subscriber) {
    std::lock_guard<std::mutex> lk(subscribers_mutex_);
    subscribers_.erase(
        std::remove_if(subscribers_.begin(), subscribers_.end(), [&](const std::weak_ptr<Subscriber>& item) {
            auto locked = item.lock();
            return !locked || locked == subscriber;
        }),
        subscribers_.end());
}

}  // namespace weaknet_grpc
