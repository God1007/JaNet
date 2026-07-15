// 无内核权限单元测试：锁定共享 ABI、计数器重建语义和多信号长连接保护策略。

#include "flow_abi.h"
#include "flow_observation_core.hpp"
#include "net_traffic.h"

#include <cstdlib>
#include <deque>
#include <iostream>
#include <type_traits>
#include <unordered_map>
#include <unordered_set>

namespace core = weaknet_grpc::traffic_core;

#define CHECK(condition) do { \
    if (!(condition)) { \
        std::cerr << "CHECK failed at " << __FILE__ << ':' << __LINE__ << ": " #condition "\n"; \
        return EXIT_FAILURE; \
    } \
} while (false)

static_assert(sizeof(flow_key) == 56);
static_assert(offsetof(flow_key, sport_be) == 8);
static_assert(offsetof(flow_key, dport_be) == 10);
static_assert(sizeof(flow_key::sport_be) == 2);
static_assert(FLOW_PORT_BYTE_ORDER_NETWORK == 1U);
static_assert(sizeof(flow_value) == 72);
static_assert(sizeof(flow_protected_record) == 128);
static_assert(offsetof(flow_protected_record, value) == 56);
static_assert(sizeof(flow_protection_policy) == 48);
static_assert(offsetof(flow_protection_policy, comm) == 32);
static_assert(sizeof(flow_runtime_config) == 16);
static_assert(offsetof(flow_runtime_config, capture_mode) == 8);
static_assert(sizeof(flow_iface_key) == 8);
static_assert(offsetof(flow_iface_key, direction) == 6);
static_assert(sizeof(flow_iface_counters) == 16);
static_assert(sizeof(flow_event) == 104);
static_assert(offsetof(flow_event, key) == 48);
static_assert(std::is_const_v<std::remove_reference_t<decltype(*std::declval<TrafficSnapshotPtr>())>>,
              "published TrafficSnapshot must be const");

// 按独立场景验证 ABI、计数器连续性、策略协调、快照可用性和长流保护判定。
int main() {
    {
        const core::CounterSample previous{1000, 100, 10, 0};
        const core::CounterSample current{1250, 125, 10, 0};
        const auto delta = core::calculateCounterDelta(current, &previous, true);
        CHECK(delta.bytes == 250);
        CHECK(delta.packets == 25);
        CHECK(!delta.continuity_lost);
        CHECK(!delta.counter_reset);
    }

    {
        // LRU 淘汰后同 key 重建，当前值小于旧值；不能发生 uint64 underflow。
        const core::CounterSample previous{UINT64_C(9000), UINT64_C(90), 10, 0};
        const core::CounterSample rebuilt{UINT64_C(12), UINT64_C(2), 20, 0};
        const auto delta = core::calculateCounterDelta(rebuilt, &previous, true);
        CHECK(delta.bytes == 12);
        CHECK(delta.packets == 2);
        CHECK(delta.continuity_lost);
        CHECK(delta.counter_reset);
    }

    {
        // 即便累计值更大，first_seen 变化仍代表新 generation，不能跨代相减。
        const core::CounterSample previous{100, 10, 10, 0};
        const core::CounterSample rebuilt{500, 50, 20, 0};
        const auto delta = core::calculateCounterDelta(rebuilt, &previous, true);
        CHECK(delta.bytes == 500);
        CHECK(delta.counter_reset);
    }

    {
        const core::CounterSample firstAppearance{320, 4, 10, 0};
        const auto newFlow = core::calculateCounterDelta(firstAppearance, nullptr, false);
        CHECK(newFlow.bytes == 320);
        CHECK(!newFlow.continuity_lost);

        const auto reappeared = core::calculateCounterDelta(firstAppearance, nullptr, true);
        CHECK(reappeared.bytes == 320);
        CHECK(reappeared.continuity_lost);
        CHECK(reappeared.counter_reset);
    }

    CHECK(core::perSecond(500, 500000000ULL) == 1000);
    CHECK(core::protectionTtlSeconds(1) == 75);
    CHECK(core::protectionTtlSeconds(30) == 95);
    CHECK(core::protectionTtlSeconds(120) == 365);
    CHECK(core::protectionTtlSeconds(120) > 120 * 2);
    {
        std::vector<int> candidate;
        const bool complete = core::retryTransactionalSnapshot(
            3,
            // 每轮尝试前清空候选，模拟丢弃不完整 netlink/sock_diag dump。
            [&] { candidate.clear(); },
            // 第一轮故意失败并写入 111；第二轮成功，最终只能提交 222。
            [&](size_t attempt) {
                candidate.push_back(attempt == 0 ? 111 : 222);
                return attempt == 1;
            });
        CHECK(complete);
        CHECK(candidate.size() == 1);
        CHECK(candidate.front() == 222);  // 失败轮的 partial 111 已回滚。
    }
    CHECK(core::perSecond(500, 0) == 0);
    {
        // 20 秒校准扫描发生在 readBegin 之前，不应进入边界；只取真实 map read [100, 120] 的中点。
        CHECK(core::mapReadBoundaryNs(100, 120) == 110);
        CHECK(core::mapReadBoundaryNs(120, 100) == 120);
    }
    {
        const core::InterfaceBindingEpoch oldBinding{7, 2};
        const core::InterfaceBindingEpoch sameBinding{7, 2};
        const core::InterfaceBindingEpoch rebound{8, 3};
        CHECK(core::sampleMatchesBinding(oldBinding, sameBinding, 2));
        CHECK(!core::sampleMatchesBinding(oldBinding, rebound, 2));
        CHECK(!core::sampleMatchesBinding(oldBinding, sameBinding, 3));
    }
    {
        const std::unordered_map<int, int> previous{{1, 10}, {2, 20}, {3, 30}};
        const std::unordered_map<int, int> current{{2, 25}, {3, 35}, {4, 40}};
        CHECK(core::countDisappeared(previous, current) == 1);
    }
    CHECK(core::protectionReconciliationAction(false, false) ==
          core::ProtectionReconciliationAction::None);
    CHECK(core::protectionReconciliationAction(false, true) ==
          core::ProtectionReconciliationAction::InstallOrRefresh);
    CHECK(core::protectionReconciliationAction(true, false) ==
          core::ProtectionReconciliationAction::DemoteAndDelete);
    CHECK(core::snapshotUsable(false, true, true, true));
    CHECK(!core::snapshotUsable(true, true, true, true));
    CHECK(!core::snapshotUsable(false, true, false, true));
    CHECK(!core::snapshotUsable(false, true, true, false));

    {
        // IPv4 成功可更新/删除 IPv4；IPv6 查询失败必须原样保留 IPv6，且 removals 为空。
        const std::unordered_set<uint64_t> installedV4{4, 40};
        const std::unordered_set<uint64_t> desiredV4{40, 44};
        const std::unordered_set<uint64_t> installedV6{6, 66};
        const std::unordered_set<uint64_t> emptyDesiredV6;
        const auto v4Plan = core::planFamilyPolicyReconciliation(installedV4, desiredV4, true);
        const auto v6Plan = core::planFamilyPolicyReconciliation(installedV6, emptyDesiredV6, false);
        CHECK(v4Plan.next == desiredV4);
        CHECK(v4Plan.removals.size() == 1 && v4Plan.removals.front() == 4);
        CHECK(v6Plan.next == installedV6);
        CHECK(v6Plan.removals.empty());
    }
    const std::string partialReason = core::composeDegradedReason("", "partial");
    CHECK(partialReason.find("partial") != std::string::npos);
    CHECK(core::composeDegradedReason("", "full").empty());
    CHECK(core::composeDegradedReason("TC attach failed", "full") == "TC attach failed");

    core::LongFlowPolicy policy;
    policy.min_observed_seconds = 300;
    policy.extended_low_rate_seconds = 900;
    policy.low_rate_bps = 64 * 1024;
    policy.protected_ports = {22, 2022};
    policy.protected_processes = {"ssh", "build-tunnel"};
    policy.protected_cgroup_fragments = {"critical-build"};

    {
        core::LongFlowCandidate tooYoung;
        tooYoung.observed_seconds = 10;
        tooYoung.dport = 22;
        CHECK(!core::evaluateLongFlowPolicy(policy, tooYoung).protect);
    }
    {
        core::LongFlowCandidate byPort;
        byPort.observed_seconds = 301;
        byPort.dport = 22;
        const auto decision = core::evaluateLongFlowPolicy(policy, byPort);
        CHECK(decision.protect);
        CHECK((decision.reason_flags & FLOW_POLICY_PORT) != 0);
    }
    {
        // 非 22 端口仍可由进程策略命中，证明保护不依赖单一端口猜测。
        core::LongFlowCandidate byProcess;
        byProcess.observed_seconds = 301;
        byProcess.dport = 443;
        byProcess.comm = "build-tunnel-agent";
        const auto decision = core::evaluateLongFlowPolicy(policy, byProcess);
        CHECK(decision.protect);
        CHECK((decision.reason_flags & FLOW_POLICY_PROCESS) != 0);
    }
    {
        core::LongFlowCandidate byCgroup;
        byCgroup.observed_seconds = 301;
        byCgroup.dport = 8443;
        byCgroup.cgroup = "/jobs/critical-build/runner-3";
        const auto decision = core::evaluateLongFlowPolicy(policy, byCgroup);
        CHECK(decision.protect);
        CHECK((decision.reason_flags & FLOW_POLICY_CGROUP) != 0);
    }
    {
        core::LongFlowCandidate lowRateLongFlow;
        lowRateLongFlow.observed_seconds = 901;
        lowRateLongFlow.dport = 12345;
        lowRateLongFlow.recent_bps = 1024;
        const auto decision = core::evaluateLongFlowPolicy(policy, lowRateLongFlow);
        CHECK(decision.protect);
        CHECK((decision.reason_flags & FLOW_POLICY_LONG_LOW_RATE) != 0);
    }
    {
        core::LongFlowCandidate unrelated;
        unrelated.observed_seconds = 500;
        unrelated.dport = 443;
        unrelated.comm = "browser";
        unrelated.recent_bps = 10 * 1024 * 1024;
        CHECK(!core::evaluateLongFlowPolicy(policy, unrelated).protect);
    }

    {
        // 纯模型压力：普通 LRU 容量被超过后发生淘汰，独立 non-LRU protected map 不受冲刷。
        // 真正内核 map 压测由 test-traffic-kernel 在 Linux 权限环境执行，此处保证架构不回退为同一 LRU。
        std::deque<uint64_t> lruOrder;
        std::unordered_set<uint64_t> lruEntries;
        std::unordered_map<uint64_t, uint64_t> protectedEntries;
        constexpr uint64_t protectedCookie = UINT64_C(0x1122334455667788);
        protectedEntries[protectedCookie] = 1;
        for (uint64_t flow = 0; flow < FLOW_LRU_MAX_ENTRIES + 4096ULL; ++flow) {
            if (lruEntries.size() == FLOW_LRU_MAX_ENTRIES) {
                lruEntries.erase(lruOrder.front());
                lruOrder.pop_front();
            }
            lruEntries.insert(flow);
            lruOrder.push_back(flow);
            ++protectedEntries[protectedCookie];
        }
        CHECK(lruEntries.size() == FLOW_LRU_MAX_ENTRIES);
        CHECK(lruEntries.find(0) == lruEntries.end());
        CHECK(protectedEntries.at(protectedCookie) == FLOW_LRU_MAX_ENTRIES + 4097ULL);

        // 被保护长流仍按自身单调 counter 做小增量，70k 短流不会制造 unsigned 假峰值。
        const core::CounterSample protectedBefore{10000, 100, 1234, 0};
        const core::CounterSample protectedAfter{10512, 104, 1234, 0};
        const auto protectedDelta = core::calculateCounterDelta(
            protectedAfter, &protectedBefore, true);
        CHECK(protectedDelta.bytes == 512);
        CHECK(protectedDelta.packets == 4);
        CHECK(core::perSecond(protectedDelta.bytes, 1000000000ULL) == 512);
        CHECK(!protectedDelta.continuity_lost);
        CHECK(!protectedDelta.counter_reset);

        // 普通 LRU 项即便被淘汰重建，也只报告保守当前值与 reset，不会膨胀到 UINT64_MAX。
        const core::CounterSample evictedBefore{500000, 500, 100, 0};
        const core::CounterSample recreatedAfter{7, 1, 200, 0};
        const auto recreatedDelta = core::calculateCounterDelta(
            recreatedAfter, &evictedBefore, true);
        CHECK(recreatedDelta.bytes == 7);
        CHECK(core::perSecond(recreatedDelta.bytes, 1000000000ULL) == 7);
        CHECK(recreatedDelta.continuity_lost);
        CHECK(recreatedDelta.counter_reset);

        CHECK(core::protectionReconciliationAction(true, false) ==
              core::ProtectionReconciliationAction::DemoteAndDelete);
        CHECK(core::protectionReconciliationAction(false, true) ==
              core::ProtectionReconciliationAction::InstallOrRefresh);
        CHECK(FLOW_EVENT_PROTECTED_PROMOTED != FLOW_EVENT_PROTECTED_DEMOTED);
        CHECK(FLOW_EVENT_PROTECTED_DEMOTED != FLOW_EVENT_PROTECTED_CLOSED);

        // Promotion 删除旧 LRU，demotion 删除 protected；下一包以干净 generation 重建普通 LRU。
        const core::CounterSample protectedAtDemotion{10512, 104, 200, 0};
        const core::CounterSample cleanLruAfterDemotion{9, 1, 300, 0};
        const auto demotionDelta = core::calculateCounterDelta(
            cleanLruAfterDemotion, &protectedAtDemotion, true);
        CHECK(demotionDelta.bytes == 9);
        CHECK(core::perSecond(demotionDelta.bytes, 1000000000ULL) == 9);
        CHECK(demotionDelta.continuity_lost);
        CHECK(demotionDelta.counter_reset);
    }

    std::cout << "traffic_core_test: all checks passed\n";
    return EXIT_SUCCESS;
}
