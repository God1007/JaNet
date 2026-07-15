// 默认路由纯状态机：按完整 route identity 幂等维护候选、稳定选择 metric，并抑制 DEL/ADD 间瞬时空出口。

#pragma once

#include <algorithm>
#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <tuple>
#include <vector>

namespace weaknet_grpc::route_selection {

// 与 Linux route/netlink 值解耦的内部常量，便于在无 netlink 的单元测试中驱动状态机。
constexpr std::uint8_t kFamilyIpv4 = 4;
constexpr std::uint8_t kFamilyIpv6 = 6;
constexpr std::uint32_t kTableDefault = 253;
constexpr std::uint32_t kTableMain = 254;
constexpr std::uint8_t kNextHopDead = 1U;
constexpr std::uint8_t kNextHopLinkDown = 16U;

// 一条默认路由的完整身份；同接口不同 metric/gateway/nexthop 必须作为独立候选保存。
struct RouteIdentity {
    std::uint8_t family = 0;
    std::uint32_t table = 0;
    std::uint32_t metric = 0;
    int ifindex = -1;
    std::uint8_t hops = 0;
    std::uint8_t flags = 0;
    std::string gateway;
    std::uint8_t protocol = 0;
    std::uint8_t scope = 0;
    std::uint8_t type = 0;

    // 为 std::set 提供确定的全字段严格弱序，也使重复 NEWROUTE 插入天然幂等。
    bool operator<(const RouteIdentity& other) const {
        return std::tie(family, table, metric, ifindex, hops, flags, gateway,
                        protocol, scope, type) <
               std::tie(other.family, other.table, other.metric, other.ifindex,
                        other.hops, other.flags, other.gateway, other.protocol,
                        other.scope, other.type);
    }
};

// 对外发布的单一绑定接口，以及该接口当前可用的 IPv4/IPv6 route 能力。
struct Selection {
    int ifindex = -1;
    bool ipv4 = false;
    bool ipv6 = false;

    // 判断发布值是否真正改变，避免重复拓扑通知触发无意义重绑。
    bool operator==(const Selection& other) const {
        return ifindex == other.ifindex && ipv4 == other.ipv4 && ipv6 == other.ipv6;
    }
    // 与 operator== 保持互补，供状态机直接表达“选择发生变化”。
    bool operator!=(const Selection& other) const { return !(*this == other); }
};

// 幂等维护默认路由候选，并按稳定 tie-break 选出唯一绑定接口。
class DefaultRouteTable {
public:
    // NEWROUTE 通知可能重复，完整 identity 插入保持幂等；同一接口的不同 metric/gateway 不会互相覆盖。
    void add(const RouteIdentity& route) { routes_.insert(route); }
    // 优先按完整 identity 删除；对字段不全的 DELROUTE 只做受约束回退匹配。
    void remove(const RouteIdentity& route) {
        if (routes_.erase(route) != 0) return;
        // 某些 DELROUTE 通知省略 gateway/nexthop flags；只回退到同族/表/metric/oif/protocol，绝不按 ifindex 全删。
        for (auto iterator = routes_.begin(); iterator != routes_.end(); ++iterator) {
            if (iterator->family != route.family || iterator->table != route.table ||
                iterator->metric != route.metric || iterator->ifindex != route.ifindex ||
                iterator->protocol != route.protocol) continue;
            if (!route.gateway.empty() && iterator->gateway != route.gateway) continue;
            routes_.erase(iterator);
            return;
        }
    }

    // 链路删除时清除该接口的全部 route identity，不影响其他接口候选。
    void removeInterface(int ifindex) {
        for (auto iterator = routes_.begin(); iterator != routes_.end();) {
            if (iterator->ifindex == ifindex) iterator = routes_.erase(iterator);
            else ++iterator;
        }
    }

    // 分别寻找 v4/v6 最优候选；tie-break 依次为表优先级、metric、ifindex、gateway、hops。
    // 最终单一 boundIfindex 优先采用 v4，随后只汇总该接口自身的协议能力。
    Selection select(const std::set<int>& upIfaces) const {
        const RouteIdentity* bestV4 = nullptr;
        const RouteIdentity* bestV6 = nullptr;
        for (const auto& route : routes_) {
            if (route.ifindex <= 0 || upIfaces.find(route.ifindex) == upIfaces.end()) continue;
            if ((route.flags & (kNextHopDead | kNextHopLinkDown)) != 0) continue;
            // 显式排序键让同一候选集合的结果与 netlink 消息到达顺序无关。
            const auto better = [](const RouteIdentity& candidate, const RouteIdentity* current) {
                const auto tableRank = [](std::uint32_t table) {
                    if (table == kTableMain) return 0;
                    if (table == kTableDefault) return 1;
                    return 2;
                };
                return current == nullptr ||
                       std::make_tuple(tableRank(candidate.table), candidate.metric, candidate.ifindex,
                                candidate.gateway, candidate.hops) <
                       std::make_tuple(tableRank(current->table), current->metric, current->ifindex,
                                current->gateway, current->hops);
            };
            if (route.family == kFamilyIpv4 && better(route, bestV4)) bestV4 = &route;
            if (route.family == kFamilyIpv6 && better(route, bestV6)) bestV6 = &route;
        }

        // 单一 boundIfindex 不能同时代表分属不同接口的 v4/v6；保持 v4 优先且 flags 只描述被选接口。
        Selection result;
        if (bestV4) result.ifindex = bestV4->ifindex;
        else if (bestV6) result.ifindex = bestV6->ifindex;
        if (result.ifindex < 0) return result;
        for (const auto& route : routes_) {
            if (route.ifindex != result.ifindex || upIfaces.find(route.ifindex) == upIfaces.end()) continue;
            if ((route.flags & (kNextHopDead | kNextHopLinkDown)) != 0) continue;
            if (route.family == kFamilyIpv4) result.ipv4 = true;
            if (route.family == kFamilyIpv6) result.ipv6 = true;
        }
        return result;
    }

    // 返回至少有一条非 dead/link-down route 的 up 接口，用于拓扑 using 状态推导。
    std::set<int> activeInterfaces(const std::set<int>& upIfaces) const {
        std::set<int> result;
        for (const auto& route : routes_) {
            if (route.ifindex <= 0 || upIfaces.find(route.ifindex) == upIfaces.end()) continue;
            if ((route.flags & (kNextHopDead | kNextHopLinkDown)) != 0) continue;
            result.insert(route.ifindex);
        }
        return result;
    }

    // 返回当前保存的完整 route identity 数量，而不是去重后的接口数量。
    std::size_t size() const { return routes_.size(); }

private:
    std::set<RouteIdentity> routes_;
};

// 一次 debounce 观察的输出：publish 表示是否通知消费者，value 是当前稳定发布值。
struct PublicationDecision {
    bool publish = false;
    Selection value;
};

// 抑制 DELROUTE/NEWROUTE 重排之间的短暂空窗，同时让真实持续断网在 grace 后正常发布。
class EmptyTransitionDebouncer {
public:
    // graceMs 只延迟“已有非空 -> 空”的转换；新的非空选择始终立即生效。
    explicit EmptyTransitionDebouncer(std::uint64_t graceMs = 300) : graceMs_(graceMs) {}

    // 输入必须使用单调时钟毫秒；时钟回退时按 0 elapsed 处理，避免提前发布空选择。
    PublicationDecision observe(const Selection& observed, std::uint64_t monotonicMs) {
        if (observed.ifindex >= 0) {
            emptySinceMs_ = 0;
            const bool changed = !hasPublished_ || observed != published_;
            if (changed) {
                published_ = observed;
                hasPublished_ = true;
            }
            return {changed, published_};
        }

        // 第一次空观察只记起点并继续返回旧值；空窗超过 grace 才提交真实无出口状态。
        if (hasPublished_ && published_.ifindex >= 0) {
            if (emptySinceMs_ == 0) emptySinceMs_ = monotonicMs == 0 ? 1 : monotonicMs;
            const std::uint64_t elapsed = monotonicMs >= emptySinceMs_
                ? monotonicMs - emptySinceMs_ : 0;
            if (elapsed < graceMs_) return {false, published_};
        }

        emptySinceMs_ = 0;
        const bool changed = !hasPublished_ || observed != published_;
        if (changed) {
            published_ = observed;
            hasPublished_ = true;
        }
        return {changed, published_};
    }

private:
    std::uint64_t graceMs_;
    std::uint64_t emptySinceMs_ = 0;
    bool hasPublished_ = false;
    Selection published_;
};

// 当前接口名短暂为空时保留最近的非空值，用于跨 DEL/ADD 空窗维持诊断归属。
inline std::string previousNonEmptyInterface(const std::string& current,
                                             const std::string& lastNonEmpty) {
    return current.empty() ? lastNonEmpty : current;
}

}  // namespace weaknet_grpc::route_selection
