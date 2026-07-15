// 与内核权限无关的流量观测核心：安全计数器差分、速率换算和长连接保护策略。
// 该文件保持 header-only，使 macOS/CI 无 libbpf 时仍可执行确定性的单元测试。

#pragma once

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

#include "flow_abi.h"

namespace weaknet_grpc::traffic_core {

// 用户态 flow 历史只服务于短窗口异常判定，不能随着短连接 churn 永久保留。
// 默认值覆盖 60 个 10 秒样本后的短暂空闲期；硬上限拒绝把配置误设成“近似无限”。
inline constexpr std::uint64_t kDefaultFlowHistoryTtlSeconds = 30 * 60;
inline constexpr std::uint64_t kMinFlowHistoryTtlSeconds = 60;
inline constexpr std::uint64_t kMaxFlowHistoryTtlSeconds = 24 * 60 * 60;
inline constexpr std::size_t kDefaultFlowHistoryMaxEntries = 4096;
inline constexpr std::size_t kMinFlowHistoryMaxEntries = 128;
inline constexpr std::size_t kMaxFlowHistoryMaxEntries =
    FLOW_LRU_MAX_ENTRIES + FLOW_PROTECTED_MAX_ENTRIES;

struct FlowHistoryRetentionPolicy {
    std::chrono::seconds ttl{kDefaultFlowHistoryTtlSeconds};
    std::size_t max_entries = kDefaultFlowHistoryMaxEntries;
};

// 环境变量先由调用方解析成无符号整数，再在这里统一夹紧到可运维的安全区间。
inline FlowHistoryRetentionPolicy normalizeFlowHistoryRetentionPolicy(
    std::uint64_t ttl_seconds,
    std::uint64_t max_entries) noexcept {
    FlowHistoryRetentionPolicy policy;
    policy.ttl = std::chrono::seconds(std::clamp(
        ttl_seconds, kMinFlowHistoryTtlSeconds, kMaxFlowHistoryTtlSeconds));
    policy.max_entries = static_cast<std::size_t>(std::clamp<std::uint64_t>(
        max_entries, kMinFlowHistoryMaxEntries, kMaxFlowHistoryMaxEntries));
    return policy;
}

struct FlowHistoryPruneResult {
    std::size_t ttl_evictions = 0;
    std::size_t capacity_evictions = 0;
};

// 使用 TrafficHistory::lastUpdate 做 TTL 与最老优先淘汰。
// protected_keys 是调用方选出的本轮有界活跃集合；helper 宁可暂时超额，也不删除刚形成的基线。
// TTL 扫描为 O(n)；仅超容量时才做 O(n) 选择和 O(k log n) 删除，避免维护侵入式 LRU 索引。
template <typename HistoryMap, typename ProtectedKeys>
inline FlowHistoryPruneResult pruneFlowHistory(
    HistoryMap& history,
    std::chrono::system_clock::time_point now,
    const FlowHistoryRetentionPolicy& policy,
    const ProtectedKeys& protected_keys) {
    FlowHistoryPruneResult result;
    const auto isProtected = [&](const auto& key) {
        return protected_keys.find(key) != protected_keys.end();
    };

    for (auto it = history.begin(); it != history.end();) {
        const auto lastUpdate = it->second.lastUpdate;
        const bool timestampMissing = lastUpdate.time_since_epoch().count() == 0;
        const bool expired = timestampMissing ||
            (now > lastUpdate && now - lastUpdate > policy.ttl);
        if (!isProtected(it->first) && expired) {
            it = history.erase(it);
            ++result.ttl_evictions;
        } else {
            ++it;
        }
    }

    if (history.size() <= policy.max_entries) return result;

    using Candidate = std::pair<std::chrono::system_clock::time_point, std::string>;
    std::vector<Candidate> candidates;
    candidates.reserve(history.size());
    for (const auto& [key, value] : history) {
        if (!isProtected(key)) candidates.emplace_back(value.lastUpdate, key);
    }

    const std::size_t requested = history.size() - policy.max_entries;
    const std::size_t evictCount = std::min(requested, candidates.size());
    const auto olderFirst = [](const Candidate& left, const Candidate& right) {
        if (left.first != right.first) return left.first < right.first;
        return left.second < right.second;
    };
    if (evictCount < candidates.size()) {
        std::nth_element(candidates.begin(), candidates.begin() + evictCount,
                         candidates.end(), olderFirst);
    }
    for (std::size_t index = 0; index < evictCount; ++index) {
        result.capacity_evictions += history.erase(candidates[index].second);
    }
    return result;
}

// 某个 map 条目在一次采样边界上的累计计数和身份代次，用于与上一轮安全求差。
struct CounterSample {
    std::uint64_t bytes = 0;
    std::uint64_t packets = 0;
    std::uint64_t first_seen_ns = 0;
    std::uint32_t generation = 0;
};

// 两轮累计值的窗口增量；continuity_lost/counter_reset 让上层区分正常差分与保守重建值。
struct CounterDelta {
    std::uint64_t bytes = 0;
    std::uint64_t packets = 0;
    bool continuity_lost = false;
    bool counter_reset = false;
};

// 一轮采样在 refresh 前记住绑定 epoch/ifindex，发布前必须与当前绑定完全一致。
// 这会拒绝“old-if refresh 完成后才发生 rebind”的旧快照回写竞态。
struct InterfaceBindingEpoch {
    std::uint64_t epoch = 0;
    std::uint32_t ifindex = 0;
};

// 确认采样前后的绑定 epoch/ifindex 未变化，并且待发布快照确实属于当前接口。
inline bool sampleMatchesBinding(const InterfaceBindingEpoch& sampled,
                                 const InterfaceBindingEpoch& current,
                                 std::uint32_t snapshot_ifindex) noexcept {
    return sampled.epoch == current.epoch &&
           sampled.ifindex == current.ifindex &&
           snapshot_ifindex == current.ifindex;
}

// policy TTL 必须始终覆盖至少两个 sock_diag 周期并留出查询预算，
// 否则用户将 interval 配大后，保护 map 会在两轮校准之间自然过期。
inline std::uint64_t protectionTtlSeconds(std::uint64_t sock_diag_interval_seconds) noexcept {
    constexpr std::uint64_t kMinimumTtlSeconds = 75;
    constexpr std::uint64_t kQueryBudgetSeconds = 5;
    constexpr std::uint64_t kMultiplier = 3;
    constexpr std::uint64_t kMaxChronoSeconds =
        static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max());
    if (sock_diag_interval_seconds >
        (kMaxChronoSeconds - kQueryBudgetSeconds) / kMultiplier) {
        return kMaxChronoSeconds;
    }
    return std::max(kMinimumTtlSeconds,
                    sock_diag_interval_seconds * kMultiplier + kQueryBudgetSeconds);
}

// 对“边解析边写候选状态”的 dump 实施事务化重试：每轮必须先 reset，
// 所以失败轮已经 dispatch 的 partial/stale 对象不会泄漏到下一轮。
template <typename Reset, typename Attempt>
inline bool retryTransactionalSnapshot(std::size_t max_attempts,
                                       Reset&& reset,
                                       Attempt&& attempt) {
    for (std::size_t index = 0; index < max_attempts; ++index) {
        reset();
        if (attempt(index)) return true;
    }
    return false;
}

// 对累计计数器做饱和安全差分。重建项使用“当前累计值”作为保守窗口增量，
// 同时显式标记连续性丢失，绝不允许 unsigned underflow 伪造超大流量。
inline CounterDelta calculateCounterDelta(const CounterSample& current,
                                          const CounterSample* previous,
                                          bool seen_before_window) noexcept {
    if (previous == nullptr) {
        return {current.bytes, current.packets, seen_before_window, seen_before_window};
    }

    const bool generation_changed =
        current.generation != previous->generation ||
        (current.first_seen_ns != 0 && previous->first_seen_ns != 0 &&
         current.first_seen_ns != previous->first_seen_ns);
    const bool decreased = current.bytes < previous->bytes || current.packets < previous->packets;
    if (generation_changed || decreased) {
        return {current.bytes, current.packets, true, true};
    }

    return {current.bytes - previous->bytes, current.packets - previous->packets, false, false};
}

// 以纳秒窗口换算每秒速率；零窗口返回 0，并对极端值做饱和处理。
inline std::uint64_t perSecond(std::uint64_t delta, std::uint64_t elapsed_ns) noexcept {
    if (elapsed_ns == 0 || delta == 0) return 0;
    constexpr long double kNanosPerSecond = 1000000000.0L;
    const long double rate = static_cast<long double>(delta) * kNanosPerSecond /
                             static_cast<long double>(elapsed_ns);
    if (rate >= static_cast<long double>(std::numeric_limits<std::uint64_t>::max())) {
        return std::numeric_limits<std::uint64_t>::max();
    }
    return static_cast<std::uint64_t>(rate);
}

// map 的多个 key 不是原子读取；用“开始/结束时刻的中点”近似本轮 counter 快照边界。
// sock_diag 与 /proc 校准必须发生在 read_begin 之前，因此它们的耗时不会被误算进采样窗口。
inline std::uint64_t mapReadBoundaryNs(std::uint64_t read_begin_ns,
                                      std::uint64_t read_end_ns) noexcept {
    if (read_end_ns <= read_begin_ns) return read_begin_ns;
    return read_begin_ns + (read_end_ns - read_begin_ns) / 2;
}

// 统计上一轮存在、当前完整样本中消失的 key；仅能对已确认完整的当前 dump 使用。
template <typename PreviousMap, typename CurrentMap>
inline std::uint64_t countDisappeared(const PreviousMap& previous, const CurrentMap& current) {
    std::uint64_t count = 0;
    for (const auto& entry : previous) {
        if (current.find(entry.first) == current.end()) ++count;
    }
    return count;
}

// 长流保护的可配置门槛与信号集合；端口、进程、cgroup、超长低速均是独立保护理由。
struct LongFlowPolicy {
    std::uint64_t min_observed_seconds = 300;
    std::uint64_t extended_low_rate_seconds = 900;
    std::uint64_t low_rate_bps = 64 * 1024;
    std::vector<std::uint16_t> protected_ports{22};
    std::vector<std::string> protected_processes{"ssh", "sshd", "mosh", "git"};
    std::vector<std::string> protected_cgroup_fragments;
};

// 从 sock_diag/cgroup 等观测拼出的单条长流候选，不直接携带最终保护状态。
struct LongFlowCandidate {
    std::uint64_t observed_seconds = 0;
    std::uint64_t recent_bps = 0;
    std::uint16_t sport = 0;
    std::uint16_t dport = 0;
    std::string comm;
    std::string cgroup;
};

// 策略评估结果；reason_flags 可同时记录多个命中理由，protect 表示是否至少命中一个。
struct PolicyDecision {
    bool protect = false;
    std::uint32_t reason_flags = 0;
};

// 已安装策略与本轮期望状态对账后，对 BPF map 应采取的生命周期动作。
enum class ProtectionReconciliationAction {
    None,
    InstallOrRefresh,
    DemoteAndDelete,
};

// sock_diag 是按地址族独立查询的。查询失败的族不能用“空 desired 集合”做负向推断，
// 否则 IPv4 成功/IPv6 失败会把仍然存活的 IPv6 保护策略误判为 closed。
// 某一地址族独立对账的结果：next 是下一轮基线，removals 是可确认已消失的策略。
template <typename Set>
struct FamilyPolicyReconciliationPlan {
    Set next;
    std::vector<typename Set::value_type> removals;
};

// 仅当该地址族查询完整成功时才做删除；查询失败时原样保留已安装集合。
template <typename Set>
inline FamilyPolicyReconciliationPlan<Set> planFamilyPolicyReconciliation(
    const Set& installed,
    const Set& desired,
    bool family_query_succeeded) {
    FamilyPolicyReconciliationPlan<Set> plan;
    if (!family_query_succeeded) {
        plan.next = installed;
        return plan;
    }
    plan.next = desired;
    for (const auto& value : installed) {
        if (desired.find(value) == desired.end()) plan.removals.push_back(value);
    }
    return plan;
}

// 把策略状态转换成明确的 map 生命周期动作；Demote 必须同时删除 policy 与 protected flow。
inline ProtectionReconciliationAction protectionReconciliationAction(bool was_installed,
                                                                      bool desired_now) noexcept {
    if (desired_now) return ProtectionReconciliationAction::InstallOrRefresh;
    if (was_installed) return ProtectionReconciliationAction::DemoteAndDelete;
    return ProtectionReconciliationAction::None;
}

// 判断本轮快照是否足以对外声明有效：基线模式、BPF/捕获/map 任一不完整都不可用。
inline bool snapshotUsable(bool baseline_only,
                           bool bpf_loaded,
                           bool capture_complete,
                           bool map_sample_complete) noexcept {
    return !baseline_only && bpf_loaded && capture_complete && map_sample_complete;
}

// capture 与 sock_diag 分开保存，每轮由当前状态重算，避免 partial/unavailable 恢复后残留旧文案。
inline std::string composeDegradedReason(const std::string& capture_reason,
                                         const std::string& sock_diag_status) {
    std::string result = capture_reason;
    std::string sockReason;
    if (sock_diag_status == "partial") sockReason = "sock_diag has partial IPv4/IPv6 coverage";
    else if (sock_diag_status == "unavailable") sockReason = "sock_diag is unavailable";
    if (!sockReason.empty()) {
        if (!result.empty()) result += "; ";
        result += sockReason;
    }
    return result;
}

// 判断文本是否包含任一非空 token，用于进程名与 cgroup 片段的策略匹配。
inline bool containsToken(const std::string& value, const std::vector<std::string>& tokens) {
    return std::any_of(tokens.begin(), tokens.end(), [&](const std::string& token) {
        return !token.empty() && value.find(token) != std::string::npos;
    });
}

// 保护判定始终要求“持续时间”成立；端口只是多种信号之一，进程、cgroup 和
// 超长低频连接均可独立命中，避免把 SSH 保护错误简化为固定 22 端口白名单。
inline PolicyDecision evaluateLongFlowPolicy(const LongFlowPolicy& policy,
                                             const LongFlowCandidate& candidate) {
    PolicyDecision result;
    if (candidate.observed_seconds < policy.min_observed_seconds) return result;

    // 先过统一持续时间门槛，再累加各独立理由；不能让单一端口绕过长流定义。
    const auto port_matches = [&](std::uint16_t port) {
        return std::find(policy.protected_ports.begin(), policy.protected_ports.end(), port) !=
               policy.protected_ports.end();
    };
    if (port_matches(candidate.sport) || port_matches(candidate.dport)) {
        result.reason_flags |= FLOW_POLICY_PORT;
    }
    if (containsToken(candidate.comm, policy.protected_processes)) {
        result.reason_flags |= FLOW_POLICY_PROCESS;
    }
    if (containsToken(candidate.cgroup, policy.protected_cgroup_fragments)) {
        result.reason_flags |= FLOW_POLICY_CGROUP;
    }
    if (candidate.observed_seconds >= policy.extended_low_rate_seconds &&
        candidate.recent_bps <= policy.low_rate_bps) {
        result.reason_flags |= FLOW_POLICY_LONG_LOW_RATE;
    }
    result.protect = result.reason_flags != 0;
    return result;
}

}  // namespace weaknet_grpc::traffic_core
