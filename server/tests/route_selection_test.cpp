// 默认路由纯测试：覆盖 metric、稳定 tie-break、direct route identity、多路径和 DEL/ADD 空窗抑制。

#include "route_selection.hpp"

#include <cstdlib>
#include <iostream>
#include <set>

namespace route = weaknet_grpc::route_selection;

#define CHECK(condition) do { \
    if (!(condition)) { \
        std::cerr << "CHECK failed at " << __FILE__ << ':' << __LINE__ << ": " #condition "\n"; \
        return EXIT_FAILURE; \
    } \
} while (false)

// 覆盖默认路由选择、幂等增删、多路径 identity 和空路由防抖的全部不变量。
int main() {
    route::DefaultRouteTable table;
    const route::RouteIdentity highMetric{route::kFamilyIpv4, 254, 500, 9, 0, 0, "gateway-a"};
    const route::RouteIdentity lowMetric{route::kFamilyIpv4, 254, 10, 7, 0, 0, ""}; // direct default dev
    const route::RouteIdentity tiedHigherIfindex{route::kFamilyIpv4, 254, 10, 8, 0, 0, "gateway-b"};
    const route::RouteIdentity v6OtherInterface{route::kFamilyIpv6, 254, 1, 11, 0, 0, "gateway-v6"};
    table.add(highMetric);
    table.add(lowMetric);
    table.add(tiedHigherIfindex);
    table.add(v6OtherInterface);
    table.add(lowMetric);  // duplicate NEW is idempotent
    CHECK(table.size() == 4);

    const std::set<int> up{7, 8, 9, 11};
    auto selected = table.select(up);
    CHECK(selected.ifindex == 7);
    CHECK(selected.ipv4);
    CHECK(!selected.ipv6);  // v6 在别的接口，不能宣称 bound ifindex 是双栈完整覆盖。

    // Linux policy rule 先查 main 再查 default，metric 不能跨表让 RT_TABLE_DEFAULT 抢占 main。
    route::DefaultRouteTable tablePolicy;
    tablePolicy.add({route::kFamilyIpv4, route::kTableMain, 100, 30, 0, 0, "main"});
    tablePolicy.add({route::kFamilyIpv4, route::kTableDefault, 0, 31, 0, 0, "default"});
    CHECK(tablePolicy.select({30, 31}).ifindex == 30);
    tablePolicy.add({route::kFamilyIpv4, route::kTableMain, 1, 29, 0,
                     route::kNextHopLinkDown, "down"});
    CHECK(tablePolicy.select({29, 30, 31}).ifindex == 30);

    table.remove(lowMetric);
    selected = table.select(up);
    CHECK(selected.ifindex == 8);  // 同 metric 时稳定选择较小 ifindex。
    table.removeInterface(8);
    CHECK(table.select(up).ifindex == 9);

    // multipath 的每个 nexthop 是独立 identity；删除一个不会误删另一个。
    route::DefaultRouteTable multipath;
    const route::RouteIdentity nextHopA{route::kFamilyIpv4, 254, 20, 20, 1, 0, "a"};
    const route::RouteIdentity nextHopB{route::kFamilyIpv4, 254, 20, 21, 1, 0, "b"};
    multipath.add(nextHopA);
    multipath.add(nextHopB);
    multipath.remove(nextHopA);
    CHECK(multipath.size() == 1);
    CHECK(multipath.select({20, 21}).ifindex == 21);

    // DEL old 与 ADD new 分批到达：短暂空状态不得覆盖最后一个非空出口。
    route::EmptyTransitionDebouncer debouncer(300);
    route::Selection oldRoute{7, true, false};
    route::Selection noRoute;
    route::Selection newRoute{21, true, false};
    CHECK(debouncer.observe(oldRoute, 1000).publish);
    const auto held = debouncer.observe(noRoute, 1100);
    CHECK(!held.publish && held.value.ifindex == 7);
    const auto switched = debouncer.observe(newRoute, 1150);
    CHECK(switched.publish && switched.value.ifindex == 21);
    CHECK(route::previousNonEmptyInterface("", "old0") == "old0");
    CHECK(route::previousNonEmptyInterface("current0", "old0") == "current0");

    CHECK(!debouncer.observe(noRoute, 2000).publish);
    const auto expired = debouncer.observe(noRoute, 2401);
    CHECK(expired.publish && expired.value.ifindex == -1);

    std::cout << "route_selection_test: all checks passed\n";
    return EXIT_SUCCESS;
}
