// 当前上网接口追踪器：持续监听 rtnetlink 链路与默认路由变化并发布出口快照。
// 对外状态由互斥锁保护，监控线程只写接口名和 IPv4/IPv6 来源标志。
#include "using_iface.h"
#include "flow_observation_core.hpp"
#include "route_selection.hpp"
#include "netlink_dump.hpp"

#include <atomic>
#include <chrono>
#include <set>
#include <chrono>
#include <thread>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <algorithm>
#include <cstring>
#include <iostream>

#if defined(__linux__)
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
#endif

std::once_flag UsingInterfaceManager::s_onceFlag;
std::shared_ptr<UsingInterfaceManager> UsingInterfaceManager::s_instance;

// 通过 call_once 构造进程级路由监听器，供多个监控模块共享。
std::shared_ptr<UsingInterfaceManager> UsingInterfaceManager::getInstance() {
    std::call_once(s_onceFlag, [](){ s_instance = std::shared_ptr<UsingInterfaceManager>(new UsingInterfaceManager()); });
    return s_instance;
}

// 延迟创建平台实现，只有 start 时才占用 netlink 资源。
UsingInterfaceManager::UsingInterfaceManager() = default;

struct UsingInterfaceManager::Impl {
#if defined(__linux__)
    std::atomic<int> nlSocket{-1};
    std::thread worker;
    std::atomic<bool> running{false};
    std::unordered_map<int, std::string> ifindexToName;
    std::set<int> upIfaces;
    weaknet_grpc::route_selection::DefaultRouteTable defaultRoutes;
    weaknet_grpc::route_selection::EmptyTransitionDebouncer routeDebouncer{300};
    uint32_t nextSequence = 0;

    // 将监听套接字设为非阻塞，事件循环可周期检查停止标志。
    static void setNonBlocking(int fd) {
        int flags = fcntl(fd, F_GETFL, 0);
        if (flags == -1) throw std::runtime_error("fcntl(F_GETFL) failed");
        if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) throw std::runtime_error("fcntl(F_SETFL) failed");
    }

    // 创建并绑定 rtnetlink 套接字，订阅链路及两类默认路由事件。
    void openSocket() {
        const int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
        if (fd < 0) throw std::runtime_error("socket(AF_NETLINK) failed");
        sockaddr_nl addr{};
        addr.nl_family = AF_NETLINK;
        addr.nl_groups = RTMGRP_LINK | RTMGRP_IPV4_ROUTE | RTMGRP_IPV6_ROUTE;
        if (bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
            close(fd);
            throw std::runtime_error("bind(AF_NETLINK) failed");
        }
        try {
            setNonBlocking(fd);
        } catch (...) {
            close(fd);
            throw;
        }
        nlSocket.store(fd);
    }

    // 发送链路或路由 dump 请求，建立事件监听前的完整状态基线。
    uint32_t sendReq(uint16_t type, uint16_t flags, uint8_t family) {
        struct { nlmsghdr nlh; rtgenmsg gen; } req{};
        req.nlh.nlmsg_len = sizeof(req);
        req.nlh.nlmsg_type = type;
        req.nlh.nlmsg_flags = flags | NLM_F_REQUEST;
        if (++nextSequence == 0) ++nextSequence;
        req.nlh.nlmsg_seq = nextSequence;
        req.nlh.nlmsg_pid = 0;
        req.gen.rtgen_family = family;
        sockaddr_nl nladdr{}; nladdr.nl_family = AF_NETLINK;
        struct iovec iov{ &req, sizeof(req) };
        struct msghdr msg{}; msg.msg_name = &nladdr; msg.msg_namelen = sizeof(nladdr); msg.msg_iov = &iov; msg.msg_iovlen = 1;
        if (sendmsg(nlSocket.load(), &msg, 0) < 0) throw std::runtime_error("sendmsg failed");
        return nextSequence;
    }

    bool requestCompleteDump(uint16_t type, uint8_t family, std::string& error) {
        const uint32_t sequence = sendReq(type, NLM_F_DUMP, family);
        return weaknet_grpc::netlink_dump::receiveCompleteDump(
            nlSocket.load(), sequence,
            [this](nlmsghdr* header) { dispatch(header); }, error);
    }

    // 每次启动先清空上一个 socket 的镜像，再依次拉取三个完整 dump。
    // 任何一个 dump 未收到匹配 NLMSG_DONE 都不会发布初始出口。
    void dumpInitial() {
        std::string lastError;
        const bool complete = weaknet_grpc::traffic_core::retryTransactionalSnapshot(
            3,
            [&] {
                // 每轮都从空镜像开始：上轮在 DUMP_INTR/MSG_TRUNC 前分发的 partial 消息
                // 必须整体丢弃，不能与下一轮成功 dump 混合。
                ifindexToName.clear();
                upIfaces.clear();
                defaultRoutes = weaknet_grpc::route_selection::DefaultRouteTable{};
                routeDebouncer = weaknet_grpc::route_selection::EmptyTransitionDebouncer{300};
            },
            [&](size_t) {
                return requestCompleteDump(RTM_GETLINK, AF_PACKET, lastError) &&
                       requestCompleteDump(RTM_GETROUTE, AF_INET, lastError) &&
                       requestCompleteDump(RTM_GETROUTE, AF_INET6, lastError);
            });
        if (complete) return;
        throw std::runtime_error("incomplete initial rtnetlink dump: " + lastError);
    }

    // 将变长 rtattr 链按类型索引，未知或越界属性直接忽略。
    template <typename T, size_t N>
    static void parseAttrs(struct rtattr* rta, int len, T (&attrs)[N]) {
        std::fill(std::begin(attrs), std::end(attrs), nullptr);
        while (RTA_OK(rta, len)) {
            if (rta->rta_type < N) attrs[rta->rta_type] = rta;
            rta = RTA_NEXT(rta, len);
        }
    }

    // 更新 ifindex 名称与 UP 状态，并清理由删除链路遗留的默认路由记录。
    void handleLink(ifinfomsg* info, void* attrHead, int attrLen, bool deleted) {
        struct rtattr* attrs[IFLA_MAX + 1];
        parseAttrs(reinterpret_cast<struct rtattr*>(attrHead), attrLen, attrs);
        int ifindex = info->ifi_index;
        if (attrs[IFLA_IFNAME]) {
            char name[IFNAMSIZ]{};
            std::snprintf(name, sizeof(name), "%s", reinterpret_cast<char*>(RTA_DATA(attrs[IFLA_IFNAME])));
            ifindexToName[ifindex] = name;
        }
        bool isLoopback = (info->ifi_flags & IFF_LOOPBACK) != 0;
        bool isUp = (info->ifi_flags & IFF_UP) != 0;
        if (isUp && !isLoopback) upIfaces.insert(ifindex); else upIfaces.erase(ifindex);
        if (deleted) {
            upIfaces.erase(ifindex);
            ifindexToName.erase(ifindex);
            defaultRoutes.removeInterface(ifindex);
        }
    }

    // 只接受目标前缀为 0、位于常用路由表且作用域合理的默认路由。
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
        if (nlmsgType == RTM_NEWROUTE) defaultRoutes.add(route);
        else defaultRoutes.remove(route);
    }

    // 按完整 identity 维护单路径/多路径候选；无 gateway 的 default dev 也是合法出口。
    void handleRoute(rtmsg* rtm, void* attrHead, int attrLen, int nlmsgType) {
        struct rtattr* attrs[RTA_MAX + 1];
        parseAttrs(reinterpret_cast<struct rtattr*>(attrHead), attrLen, attrs);
        const uint32_t table = attrs[RTA_TABLE]
            ? readU32(attrs[RTA_TABLE], rtm->rtm_table) : rtm->rtm_table;
        if (!isDefaultRoute(rtm, table)) return;
        if (rtm->rtm_family != AF_INET && rtm->rtm_family != AF_INET6) return;

        const uint8_t family = rtm->rtm_family == AF_INET
            ? weaknet_grpc::route_selection::kFamilyIpv4
            : weaknet_grpc::route_selection::kFamilyIpv6;
        const uint32_t metric = readU32(attrs[RTA_PRIORITY], 0);
        const std::string routeGateway = attributeIdentity(attrs[RTA_GATEWAY]);
        if (attrs[RTA_MULTIPATH]) {
            int remaining = RTA_PAYLOAD(attrs[RTA_MULTIPATH]);
            auto* hop = reinterpret_cast<rtnexthop*>(RTA_DATA(attrs[RTA_MULTIPATH]));
            while (RTNH_OK(hop, remaining)) {
                struct rtattr* hopAttrs[RTA_MAX + 1];
                const int hopAttrLength = static_cast<int>(hop->rtnh_len) -
                                          static_cast<int>(sizeof(*hop));
                parseAttrs(reinterpret_cast<rtattr*>(RTNH_DATA(hop)), hopAttrLength, hopAttrs);
                weaknet_grpc::route_selection::RouteIdentity route;
                route.family = family;
                route.table = table;
                route.metric = metric;
                route.ifindex = hop->rtnh_ifindex;
                route.hops = hop->rtnh_hops;
                route.flags = hop->rtnh_flags;
                route.gateway = hopAttrs[RTA_GATEWAY]
                    ? attributeIdentity(hopAttrs[RTA_GATEWAY]) : routeGateway;
                route.protocol = rtm->rtm_protocol;
                route.scope = rtm->rtm_scope;
                route.type = rtm->rtm_type;
                updateRouteIdentity(route, nlmsgType);

                const int step = RTNH_ALIGN(hop->rtnh_len);
                remaining -= step;
                hop = reinterpret_cast<rtnexthop*>(reinterpret_cast<char*>(hop) + step);
            }
            return;
        }

        weaknet_grpc::route_selection::RouteIdentity route;
        route.family = family;
        route.table = table;
        route.metric = metric;
        route.ifindex = static_cast<int>(readU32(attrs[RTA_OIF], 0));
        route.gateway = routeGateway;
        route.protocol = rtm->rtm_protocol;
        route.scope = rtm->rtm_scope;
        route.type = rtm->rtm_type;
        updateRouteIdentity(route, nlmsgType);
    }

    // 把 netlink 消息分派给链路或路由处理器，其余类型不影响出口判断。
    void dispatch(nlmsghdr* hdr) {
        switch (hdr->nlmsg_type) {
            case RTM_NEWLINK:
            case RTM_DELLINK: {
                if (hdr->nlmsg_len < NLMSG_LENGTH(sizeof(ifinfomsg))) return;
                auto* msg = reinterpret_cast<ifinfomsg*>(NLMSG_DATA(hdr));
                void* attrsHead = IFLA_RTA(msg);
                int attrsLen = IFLA_PAYLOAD(hdr);
                handleLink(msg, attrsHead, attrsLen, hdr->nlmsg_type == RTM_DELLINK);
                break;
            }
            case RTM_NEWROUTE:
            case RTM_DELROUTE: {
                if (hdr->nlmsg_len < NLMSG_LENGTH(sizeof(rtmsg))) return;
                auto* msg = reinterpret_cast<rtmsg*>(NLMSG_DATA(hdr));
                void* attrsHead = RTM_RTA(msg);
                int attrsLen = RTM_PAYLOAD(hdr);
                handleRoute(msg, attrsHead, attrsLen, hdr->nlmsg_type);
                break;
            }
            default:
                break;
        }
    }

    // 从已启用的默认路由中选出当前出口，并在锁内一次性发布名称和来源标志。
    void publishState(UsingInterfaceManager* owner, bool printLog) {
        const auto observed = defaultRoutes.select(upIfaces);
        const auto nowMs = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
        const auto decision = routeDebouncer.observe(observed, nowMs);
        if (!decision.publish) return;

        const int chosen = decision.value.ifindex;
        uint32_t methodFlags = 0;
        if (decision.value.ipv4) methodFlags |= UsingMethodFlag::IPv4Default;
        if (decision.value.ipv6) methodFlags |= UsingMethodFlag::IPv6Default;
        std::string ifname;
        if (chosen != -1) {
            auto it = ifindexToName.find(chosen);
            if (it != ifindexToName.end()) ifname = it->second; else ifname = std::string("ifindex=") + std::to_string(chosen);
        }
        // 读线程通过同一把锁获取两个字段，避免看到名称与 flags 不匹配的快照。
        {
            std::lock_guard<std::mutex> lk(owner->stateMutex_);
            if (!owner->routeStateInitialized_) {
                // 启动空窗不计事件；首次有效默认出口只建立 generation=1 基线。
                if (!ifname.empty()) {
                    owner->routeStateInitialized_ = true;
                    owner->routeGeneration_ = 1;
                    owner->lastNonEmptyIfName_ = ifname;
                }
            } else if (ifname != owner->currentIfName_) {
                owner->previousIfName_ = weaknet_grpc::route_selection::previousNonEmptyInterface(
                    owner->currentIfName_, owner->lastNonEmptyIfName_);
                ++owner->routeGeneration_;
                owner->routeChangedAtUnixMs_ = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count();
            }
            if (!ifname.empty()) owner->lastNonEmptyIfName_ = ifname;
            owner->currentIfName_ = ifname;
            owner->methodFlags_ = methodFlags;
        }
        if (printLog) {
            if (!ifname.empty()) {
                std::cout << "[net] 当前上网网卡: " << ifname
                          << " flags=" << ((methodFlags & UsingMethodFlag::IPv4Default) ? "IPv4" : "")
                          << (((methodFlags & UsingMethodFlag::IPv4Default) && (methodFlags & UsingMethodFlag::IPv6Default)) ? "+" : "")
                          << ((methodFlags & UsingMethodFlag::IPv6Default) ? "IPv6" : "")
                          << std::endl;
            } else {
                std::cout << "[net] 当前上网网卡: (none)" << std::endl;
            }
        }
    }

    // 建立初始快照后持续消费内核事件，每批消息完成后重新发布出口状态。
    void eventLoop(UsingInterfaceManager* owner) {
        try {
            openSocket();
            dumpInitial();
            // 发布一次初始状态，避免刚启动阶段为空
            publishState(owner, /*printLog=*/true);
            std::vector<char> buf(64 * 1024);
            while (running.load()) {
                sockaddr_nl nladdr{};
                struct iovec iov{ buf.data(), buf.size() };
                struct msghdr msg{}; msg.msg_name = &nladdr; msg.msg_namelen = sizeof(nladdr); msg.msg_iov = &iov; msg.msg_iovlen = 1;
                ssize_t len = recvmsg(nlSocket.load(), &msg, 0);
                if (len < 0) {
                    if (errno == EINTR) continue;
                    if (errno == ENOBUFS) {
                        std::cerr << "[net] rtnetlink receive overrun; rebuilding full route snapshot" << std::endl;
                        dumpInitial();
                        publishState(owner, /*printLog=*/true);
                        continue;
                    }
                    // 暂无事件时短暂退避，避免非阻塞轮询占满 CPU。
                    if (errno == EAGAIN || errno == EWOULDBLOCK) {
                        // 轮询 debouncer，使真正断网在 grace 到期后发布；DEL/ADD 切换空窗则被抑制。
                        publishState(owner, /*printLog=*/false);
                        usleep(1000 * 50);
                        continue;
                    }
                    throw std::runtime_error("recvmsg failed");
                }
                if (len == 0) continue;
                if (nladdr.nl_pid != 0) continue;
                if ((msg.msg_flags & MSG_TRUNC) != 0) {
                    std::cerr << "[net] truncated rtnetlink event; rebuilding full route snapshot" << std::endl;
                    dumpInitial();
                    publishState(owner, /*printLog=*/true);
                    continue;
                }
                bool seenDone = false;
                bool needsResync = false;
                int remainingBytes = static_cast<int>(len);
                for (nlmsghdr* hdr = reinterpret_cast<nlmsghdr*>(buf.data());
                     NLMSG_OK(hdr, remainingBytes);
                     hdr = NLMSG_NEXT(hdr, remainingBytes)) {
                    if (hdr->nlmsg_type == NLMSG_DONE) { seenDone = true; break; }
                    if (hdr->nlmsg_type == NLMSG_OVERRUN ||
                        (hdr->nlmsg_flags & NLM_F_DUMP_INTR) != 0) {
                        needsResync = true;
                        break;
                    }
                    if (hdr->nlmsg_type == NLMSG_ERROR) {
                        if (hdr->nlmsg_len < NLMSG_LENGTH(sizeof(nlmsgerr)) ||
                            reinterpret_cast<nlmsgerr*>(NLMSG_DATA(hdr))->error != 0) {
                            needsResync = true;
                            break;
                        }
                        continue;
                    }
                    dispatch(hdr);
                }
                if (remainingBytes != 0 && !seenDone) needsResync = true;
                if (needsResync) {
                    std::cerr << "[net] rtnetlink overrun/interruption; rebuilding full route snapshot" << std::endl;
                    dumpInitial();
                    publishState(owner, /*printLog=*/true);
                    continue;
                }
                if (seenDone) continue;
                // 每批处理后发布最新状态
                publishState(owner, /*printLog=*/true);
            }
        } catch (const std::exception& ex) {
            std::cerr << "[net] loop error: " << ex.what() << std::endl;
        }
        const int fd = nlSocket.exchange(-1);
        if (fd >= 0) close(fd);
        running.store(false);
    }
#else
    // 非 Linux 平台没有 rtnetlink，保留空事件循环满足统一接口。
    void eventLoop(UsingInterfaceManager*) {}
#endif
};

// 幂等启动后台监听线程；平台实现延迟分配并在运行时复用。
void UsingInterfaceManager::start() {
#if defined(__linux__)
    std::lock_guard<std::mutex> lifecycleLock(lifecycleMutex_);
    if (impl_ == nullptr) impl_ = new Impl();
    bool expected = false;
    if (!impl_->running.compare_exchange_strong(expected, true)) return;
    // 上一次启动可能在 open/bind 失败后自行退出；先回收旧句柄再创建唯一 worker。
    if (impl_->worker.joinable()) impl_->worker.join();
    try {
        impl_->worker = std::thread([this]{ impl_->eventLoop(this); });
    } catch (...) {
        impl_->running.store(false);
        throw;
    }
#else
    (void)stateMutex_;
#endif
}

void UsingInterfaceManager::stop() {
#if defined(__linux__)
    std::lock_guard<std::mutex> lifecycleLock(lifecycleMutex_);
    if (!impl_) return;
    impl_->running.store(false);
    const int fd = impl_->nlSocket.load();
    if (fd >= 0) shutdown(fd, SHUT_RDWR);
    if (impl_->worker.joinable()) impl_->worker.join();
#endif
}

UsingInterfaceManager::~UsingInterfaceManager() {
    stop();
    std::lock_guard<std::mutex> lifecycleLock(lifecycleMutex_);
    delete impl_;
    impl_ = nullptr;
}

// 在锁内复制当前出口名，调用方不持有内部字符串引用。
std::string UsingInterfaceManager::getCurrentInterface() {
    std::lock_guard<std::mutex> lk(stateMutex_);
    return currentIfName_;
}

// 在锁内读取 IPv4/IPv6 默认路由来源标志。
uint32_t UsingInterfaceManager::getMethodFlags() {
    std::lock_guard<std::mutex> lk(stateMutex_);
    return methodFlags_;
}

RouteTransitionState UsingInterfaceManager::getRouteTransitionState() {
    std::lock_guard<std::mutex> lk(stateMutex_);
    return RouteTransitionState{
        currentIfName_, previousIfName_, routeGeneration_, routeChangedAtUnixMs_
    };
}
