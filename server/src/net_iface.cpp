// 网络接口发现器：通过 rtnetlink 汇总链路状态和 IPv4/IPv6 默认路由。
// 只返回“接口已启用且承载默认路由”的非回环接口，非 Linux 平台返回空集合。
#if defined(__linux__)
#include "net_iface.h"
#include "flow_observation_core.hpp"
#include "route_selection.hpp"
#include "netlink_dump.hpp"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if_link.h>
#include <net/if.h>
#include <stdexcept>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <cstdint>
#include <string>
#include <set>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#ifndef IFF_LOWER_UP
#define IFF_LOWER_UP 0x10000
#endif
#ifndef IFF_DORMANT
#define IFF_DORMANT 0x20000
#endif

namespace {

// 将 netlink 套接字设为非阻塞，避免异常内核响应永久卡住监控线程
void setNonBlocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) {
        throw std::runtime_error("fcntl(F_GETFL) failed");
    }
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
        throw std::runtime_error("fcntl(F_SETFL) failed");
    }
}

// 将变长 rtattr 链按类型索引，越界属性直接忽略。
template <typename T, size_t N>
void parseRtAttributes(struct rtattr* rta, int len, T (&attrs)[N]) {
    std::fill(std::begin(attrs), std::end(attrs), nullptr);
    while (RTA_OK(rta, len)) {
        if (rta->rta_type < N) {
            attrs[rta->rta_type] = rta;
        }
        rta = RTA_NEXT(rta, len);
    }
}

// 把链路 flags 转成可读文本，供诊断日志按需使用。
[[maybe_unused]]
std::string ifFlagsToString(unsigned int flags) {
    std::vector<std::string> names;
    if (flags & IFF_UP) names.emplace_back("UP");
    if (flags & IFF_BROADCAST) names.emplace_back("BROADCAST");
    if (flags & IFF_DEBUG) names.emplace_back("DEBUG");
    if (flags & IFF_LOOPBACK) names.emplace_back("LOOPBACK");
    if (flags & IFF_POINTOPOINT) names.emplace_back("P2P");
    if (flags & IFF_RUNNING) names.emplace_back("RUNNING");
    if (flags & IFF_NOARP) names.emplace_back("NOARP");
    if (flags & IFF_PROMISC) names.emplace_back("PROMISC");
    if (flags & IFF_ALLMULTI) names.emplace_back("ALLMULTI");
    if (flags & IFF_MULTICAST) names.emplace_back("MULTICAST");
    if (flags & IFF_LOWER_UP) names.emplace_back("LOWER_UP");
    if (flags & IFF_DORMANT) names.emplace_back("DORMANT");
    std::string out;
    for (size_t i = 0; i < names.size(); ++i) {
        out += names[i];
        if (i + 1 < names.size()) out += '|';
    }
    return out;
}

class SnapshotCollector {
public:
    ~SnapshotCollector() {
        if (nlSocket_ >= 0) ::close(nlSocket_);
    }

    // 顺序拉取链路、IPv4 路由和 IPv6 路由，再计算一次完整接口快照。
    std::vector<std::string> collect() {
        openSocket();
        std::string lastError;
        const bool complete = weaknet_grpc::traffic_core::retryTransactionalSnapshot(
            3,
            [&] {
                // 失败轮可能已 dispatch 部分链路/路由；下轮必须从空状态开始，禁止 stale 残留。
                ifindexToName_.clear();
                upInterfaces_.clear();
                defaultRoutes_ = weaknet_grpc::route_selection::DefaultRouteTable{};
                managedIfaces_.clear();
            },
            [&](size_t) {
                return requestCompleteDump(RTM_GETLINK, AF_PACKET, lastError) &&
                       requestCompleteDump(RTM_GETROUTE, AF_INET, lastError) &&
                       requestCompleteDump(RTM_GETROUTE, AF_INET6, lastError);
            });
        if (!complete) throw std::runtime_error("不完整的 rtnetlink dump: " + lastError);
        recomputeManagedInterfaces(false);
        ::close(nlSocket_);
        nlSocket_ = -1;
        return namesOfManaged();
    }

private:
    int nlSocket_ = -1;
    uint32_t nextSequence_ = 0;

    std::unordered_map<int, std::string> ifindexToName_;
    std::set<int> upInterfaces_;
    weaknet_grpc::route_selection::DefaultRouteTable defaultRoutes_;
    std::unordered_set<int> managedIfaces_; // up ∩ (v4默认网关 ∪ v6默认网关)

    // 创建并绑定 rtnetlink 套接字，同时订阅后续链路和路由变化组。
    void openSocket() {
        nlSocket_ = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
        if (nlSocket_ < 0) {
            throw std::runtime_error("socket(AF_NETLINK) 失败");
        }

        sockaddr_nl addr{};
        addr.nl_family = AF_NETLINK;
        addr.nl_groups = RTMGRP_LINK | RTMGRP_IPV4_ROUTE | RTMGRP_IPV6_ROUTE;

        if (bind(nlSocket_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
            throw std::runtime_error("bind(AF_NETLINK) 失败");
        }

        setNonBlocking(nlSocket_);
    }


    // 发送指定 family 的 dump 请求，序列号用于标识本轮内核响应。
    uint32_t sendNetlinkRequest(uint16_t nlmsgType, uint16_t flags, uint8_t family) {
        struct {
            nlmsghdr nlh;
            rtgenmsg gen;
        } req{};

        req.nlh.nlmsg_len = sizeof(req);
        req.nlh.nlmsg_type = nlmsgType;
        req.nlh.nlmsg_flags = flags | NLM_F_REQUEST;
        if (++nextSequence_ == 0) ++nextSequence_;
        req.nlh.nlmsg_seq = nextSequence_;
        req.nlh.nlmsg_pid = 0;
        req.gen.rtgen_family = family;

        sockaddr_nl nladdr{};
        nladdr.nl_family = AF_NETLINK;

        struct iovec iov{ &req, sizeof(req) };
        struct msghdr msg{};
        msg.msg_name = &nladdr;
        msg.msg_namelen = sizeof(nladdr);
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;

        if (sendmsg(nlSocket_, &msg, 0) < 0) {
            throw std::runtime_error("sendmsg 失败");
        }
        return nextSequence_;
    }

    // 重试仅用于截断/中断/超时的部分 dump；只有完整 DONE 才允许继续构建快照。
    bool requestCompleteDump(uint16_t type, uint8_t family, std::string& error) {
        const uint32_t sequence = sendNetlinkRequest(type, NLM_F_DUMP, family);
        return weaknet_grpc::netlink_dump::receiveCompleteDump(
            nlSocket_, sequence,
            [this](nlmsghdr* header) { dispatchNetlinkMessage(header); }, error);
    }

    // 按消息类型分派链路或路由载荷，忽略本模块不关心的 netlink 消息。
    void dispatchNetlinkMessage(struct nlmsghdr* hdr) {
        switch (hdr->nlmsg_type) {
            case RTM_NEWLINK:
            case RTM_DELLINK:
                if (hdr->nlmsg_len < NLMSG_LENGTH(sizeof(ifinfomsg))) return;
                handleLink(reinterpret_cast<ifinfomsg*>(NLMSG_DATA(hdr)),
                           IFLA_RTA(reinterpret_cast<ifinfomsg*>(NLMSG_DATA(hdr))),
                           IFLA_PAYLOAD(hdr), hdr->nlmsg_type == RTM_DELLINK);
                break;
            case RTM_NEWROUTE:
            case RTM_DELROUTE:
                if (hdr->nlmsg_len < NLMSG_LENGTH(sizeof(rtmsg))) return;
                handleRoute(reinterpret_cast<rtmsg*>(NLMSG_DATA(hdr)), RTM_RTA(reinterpret_cast<rtmsg*>(NLMSG_DATA(hdr))), RTM_PAYLOAD(hdr), hdr->nlmsg_type);
                break;
            default:
                break;
        }
    }

    // 更新 ifindex 到名称映射和 UP 集合，并清理由删除链路遗留的路由状态。
    void handleLink(ifinfomsg* info, void* attrHead, int attrLen, bool deleted) {
        struct rtattr* attrs[IFLA_MAX + 1];
        parseRtAttributes(reinterpret_cast<struct rtattr*>(attrHead), attrLen, attrs);

        int ifindex = info->ifi_index;
        std::string ifname;
        if (attrs[IFLA_IFNAME]) {
            char name[IFNAMSIZ]{};
            std::snprintf(name, sizeof(name), "%s", reinterpret_cast<char*>(RTA_DATA(attrs[IFLA_IFNAME])));
            ifname = name;
            ifindexToName_[ifindex] = ifname;
        } else {
            auto it = ifindexToName_.find(ifindex);
            if (it != ifindexToName_.end()) ifname = it->second; // best effort
        }

        bool isLoopback = (info->ifi_flags & IFF_LOOPBACK) != 0;
        bool isUp = (info->ifi_flags & IFF_UP) != 0;

        if (isUp && !isLoopback) {
            upInterfaces_.insert(ifindex);
        } else {
            upInterfaces_.erase(ifindex);
        }

        if (deleted) {
            upInterfaces_.erase(ifindex);
            ifindexToName_.erase(ifindex);
            defaultRoutes_.removeInterface(ifindex);
        }

        (void)ifname; // 保留局部变量以兼容日志需求，但不输出
    }

    // 仅接受目标前缀长度为 0 且属于主/默认路由表的全局默认路由。
    static bool isDefaultRoute(const rtmsg* rtm, uint32_t table) {
        return rtm->rtm_dst_len == 0 &&
               (table == RT_TABLE_MAIN || table == RT_TABLE_DEFAULT) &&
               rtm->rtm_type == RTN_UNICAST &&
               (rtm->rtm_scope == RT_SCOPE_UNIVERSE || rtm->rtm_scope == RT_SCOPE_NOWHERE ||
                rtm->rtm_scope == RT_SCOPE_SITE);
    }

    static uint32_t readU32(const rtattr* attribute, uint32_t fallback = 0) {
        if (!attribute || RTA_PAYLOAD(attribute) < sizeof(uint32_t)) return fallback;
        uint32_t value = fallback;
        std::memcpy(&value, RTA_DATA(attribute), sizeof(value));
        return value;
    }

    static std::string attributeIdentity(const rtattr* attribute) {
        if (!attribute) return {};
        const auto* begin = static_cast<const char*>(RTA_DATA(attribute));
        return std::string(begin, begin + RTA_PAYLOAD(attribute));
    }

    void updateRouteIdentity(const weaknet_grpc::route_selection::RouteIdentity& route,
                             int nlmsgType) {
        if (route.ifindex <= 0) return;
        if (nlmsgType == RTM_NEWROUTE) defaultRoutes_.add(route);
        else defaultRoutes_.remove(route);
    }

    // 与 UsingInterfaceManager 使用同一 route identity：支持 direct default、metric/table 和 multipath。
    void handleRoute(rtmsg* rtm, void* attrHead, int attrLen, int nlmsgType) {
        struct rtattr* attrs[RTA_MAX + 1];
        parseRtAttributes(reinterpret_cast<struct rtattr*>(attrHead), attrLen, attrs);
        const uint32_t table = attrs[RTA_TABLE]
            ? readU32(attrs[RTA_TABLE], rtm->rtm_table) : rtm->rtm_table;
        if (!isDefaultRoute(rtm, table)) return;
        if (rtm->rtm_family != AF_INET && rtm->rtm_family != AF_INET6) return;
        const uint8_t family = rtm->rtm_family == AF_INET
            ? weaknet_grpc::route_selection::kFamilyIpv4
            : weaknet_grpc::route_selection::kFamilyIpv6;
        const uint32_t metric = readU32(attrs[RTA_PRIORITY], 0);
        const std::string routeGateway = attributeIdentity(attrs[RTA_GATEWAY]);

        const auto fillCommon = [&](weaknet_grpc::route_selection::RouteIdentity& route) {
            route.family = family;
            route.table = table;
            route.metric = metric;
            route.protocol = rtm->rtm_protocol;
            route.scope = rtm->rtm_scope;
            route.type = rtm->rtm_type;
        };
        if (attrs[RTA_MULTIPATH]) {
            int remaining = RTA_PAYLOAD(attrs[RTA_MULTIPATH]);
            auto* hop = reinterpret_cast<rtnexthop*>(RTA_DATA(attrs[RTA_MULTIPATH]));
            while (RTNH_OK(hop, remaining)) {
                struct rtattr* hopAttrs[RTA_MAX + 1];
                const int hopAttrLength = static_cast<int>(hop->rtnh_len) -
                                          static_cast<int>(sizeof(*hop));
                parseRtAttributes(reinterpret_cast<rtattr*>(RTNH_DATA(hop)), hopAttrLength, hopAttrs);
                weaknet_grpc::route_selection::RouteIdentity route;
                fillCommon(route);
                route.ifindex = hop->rtnh_ifindex;
                route.hops = hop->rtnh_hops;
                route.flags = hop->rtnh_flags;
                route.gateway = hopAttrs[RTA_GATEWAY]
                    ? attributeIdentity(hopAttrs[RTA_GATEWAY]) : routeGateway;
                updateRouteIdentity(route, nlmsgType);
                const int step = RTNH_ALIGN(hop->rtnh_len);
                remaining -= step;
                hop = reinterpret_cast<rtnexthop*>(reinterpret_cast<char*>(hop) + step);
            }
            return;
        }

        weaknet_grpc::route_selection::RouteIdentity route;
        fillCommon(route);
        route.ifindex = static_cast<int>(readU32(attrs[RTA_OIF], 0));
        route.gateway = routeGateway;
        updateRouteIdentity(route, nlmsgType);
    }

    // 取“UP 接口”与“任一地址族默认路由出口”的交集作为可上网接口。
    void recomputeManagedInterfaces(bool announceChanges) {
        (void)announceChanges;
        std::unordered_set<int> newManaged;
        const auto active = defaultRoutes_.activeInterfaces(upInterfaces_);
        newManaged.insert(active.begin(), active.end());
        managedIfaces_.swap(newManaged);
    }

    // 把受管 ifindex 转回名称并排序，保证跨轮次比较结果稳定。
    std::vector<std::string> namesOfManaged() const {
        std::vector<std::string> names;
        names.reserve(managedIfaces_.size());
        for (int idx : managedIfaces_) {
            auto it = ifindexToName_.find(idx);
            if (it != ifindexToName_.end()) names.push_back(it->second);
        }
        std::sort(names.begin(), names.end());
        return names;
    }
};

} // namespace

// 单例状态由 once_flag 保护，首次请求时才创建实例。
std::once_flag NetInterfaceManager::s_onceFlag;
std::shared_ptr<NetInterfaceManager> NetInterfaceManager::s_instance;

// 线程安全地获取 Linux 接口管理器单例。
std::shared_ptr<NetInterfaceManager> NetInterfaceManager::getInstance() {
    std::call_once(s_onceFlag, [](){ s_instance = std::shared_ptr<NetInterfaceManager>(new NetInterfaceManager()); });
    return s_instance;
}

// 创建短生命周期采集器并返回当前默认路由接口快照。
std::vector<std::string> NetInterfaceManager::getInternetInterfaces() {
    SnapshotCollector collector;
    return collector.collect();
}

#else

#include "net_iface.h"
#include <string>
#include <vector>

// 非 Linux 分支沿用相同的线程安全懒加载语义。
std::once_flag NetInterfaceManager::s_onceFlag;
std::shared_ptr<NetInterfaceManager> NetInterfaceManager::s_instance;

// 线程安全地获取非 Linux 兼容管理器单例。
std::shared_ptr<NetInterfaceManager> NetInterfaceManager::getInstance() {
    std::call_once(s_onceFlag, [](){ s_instance = std::shared_ptr<NetInterfaceManager>(new NetInterfaceManager()); });
    return s_instance;
}

// 非 Linux 尚无采集实现，返回空集合表达能力不可用。
std::vector<std::string> NetInterfaceManager::getInternetInterfaces() {
    return {};
}

#endif // defined(__linux__)
