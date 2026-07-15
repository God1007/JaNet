// 中心流量采样器：加载共享 ABI 的 eBPF maps，单次读取后发布不可变快照，并周期执行 sock_diag 校准。
// 非 Linux、缺少 libbpf 或权限不足时同样可编译运行，但快照会携带明确的 support 降级原因。
#include "net_traffic.h"
#include "netlink_dump.hpp"

#include <algorithm>
#include <arpa/inet.h>
#include <array>
#include <cerrno>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <fstream>
#include <iomanip>
#include <iterator>
#include <limits>
#include <net/if.h>
#include <numeric>
#include <set>
#include <sstream>
#include <unordered_map>
#include <unordered_set>
#include <utility>

#if defined(__linux__)
#include <dirent.h>
#include <fcntl.h>
#include <linux/inet_diag.h>
#include <linux/netlink.h>
#include <linux/pkt_sched.h>
#include <linux/rtnetlink.h>
#include <linux/sock_diag.h>
#include <linux/tcp.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#endif

#if defined(__linux__) && defined(__has_include)
#  if __has_include(<linux/bpf.h>) && __has_include(<bpf/libbpf.h>) && __has_include(<bpf/bpf.h>)
#    define WEAKNET_HAVE_LIBBPF 1
extern "C" {
#include <linux/bpf.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
}
#  else
#    define WEAKNET_HAVE_LIBBPF 0
#  endif
#else
#  define WEAKNET_HAVE_LIBBPF 0
#endif

namespace {

using weaknet_grpc::traffic_core::CounterSample;
using weaknet_grpc::traffic_core::calculateCounterDelta;
using weaknet_grpc::traffic_core::perSecond;

uint64_t parseUnsignedEnv(const char* name, uint64_t fallback);

#if WEAKNET_HAVE_LIBBPF
std::chrono::seconds sockDiagInterval() {
    // 生产默认 30 秒；特权集成测试可缩短周期以验证 close/demotion 生命周期。
    static const auto value = std::chrono::seconds(std::max<uint64_t>(
        1, parseUnsignedEnv("WEAKNET_SOCK_DIAG_INTERVAL_SEC", 30)));
    return value;
}

std::chrono::seconds protectionTtl() {
    return std::chrono::seconds(weaknet_grpc::traffic_core::protectionTtlSeconds(
        static_cast<uint64_t>(sockDiagInterval().count())));
}

std::string binaryKey(const flow_key& key) {
    return std::string(reinterpret_cast<const char*>(&key), sizeof(key));
}

std::string ifaceBinaryKey(const flow_iface_key& key) {
    return std::string(reinterpret_cast<const char*>(&key), sizeof(key));
}

std::string addressToString(const flow_key& key, bool source) {
    char buffer[INET6_ADDRSTRLEN] = {};
    const void* address = source ? static_cast<const void*>(key.saddr)
                                 : static_cast<const void*>(key.daddr);
    const int family = key.family == FLOW_AF_INET6 ? AF_INET6 : AF_INET;
    if (inet_ntop(family, address, buffer, sizeof(buffer)) == nullptr) return "?";
    return buffer;
}

std::string directionToString(uint8_t direction) {
    if (direction == FLOW_DIR_INGRESS) return "ingress";
    if (direction == FLOW_DIR_EGRESS) return "egress";
    return "unknown";
}

std::string protocolToString(uint8_t protocol) {
    if (protocol == IPPROTO_TCP) return "TCP";
    if (protocol == IPPROTO_UDP) return "UDP";
    return std::to_string(protocol);
}

std::string flowKeyToString(const flow_key& key) {
    std::ostringstream out;
    out << addressToString(key, true) << ':' << ntohs(key.sport_be)
        << '-' << addressToString(key, false) << ':' << ntohs(key.dport_be)
        << '/' << protocolToString(key.protocol) << '/' << directionToString(key.direction)
        << "@if" << key.ifindex;
    if (key.socket_cookie != 0) out << "#" << key.socket_cookie;
    return out.str();
}

std::string fixedCommToString(const char comm[FLOW_COMM_LEN]) {
    const auto length = strnlen(comm, FLOW_COMM_LEN);
    return std::string(comm, length);
}
#endif

std::string flowHistoryKey(const FlowRate& flow) {
    std::ostringstream out;
    out << flow.src << ':' << flow.sport << '-' << flow.dst << ':' << flow.dport
        << '/' << flow.proto << '/' << flow.direction << "@if" << flow.ifindex;
    return out.str();
}

template <typename Clock>
typename Clock::time_point mapReadBoundary(typename Clock::time_point begin,
                                           typename Clock::time_point end) {
    const auto beginNs = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
        begin.time_since_epoch()).count());
    const auto endNs = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
        end.time_since_epoch()).count());
    const auto boundaryNs = weaknet_grpc::traffic_core::mapReadBoundaryNs(beginNs, endNs);
    return typename Clock::time_point(std::chrono::duration_cast<typename Clock::duration>(
        std::chrono::nanoseconds(boundaryNs)));
}

std::vector<std::string> splitTokens(const char* raw) {
    std::vector<std::string> result;
    if (!raw) return result;
    std::stringstream input(raw);
    std::string token;
    while (std::getline(input, token, ',')) {
        if (!token.empty()) result.push_back(token);
    }
    return result;
}

uint64_t parseUnsignedEnv(const char* name, uint64_t fallback) {
    const char* raw = std::getenv(name);
    if (!raw || raw[0] == '\0') return fallback;
    char* end = nullptr;
    errno = 0;
    const auto value = std::strtoull(raw, &end, 10);
    return errno == 0 && end && *end == '\0' ? value : fallback;
}

weaknet_grpc::traffic_core::LongFlowPolicy policyFromEnvironment() {
    weaknet_grpc::traffic_core::LongFlowPolicy policy;
    policy.min_observed_seconds = parseUnsignedEnv("WEAKNET_LONG_FLOW_MIN_SEC", policy.min_observed_seconds);
    policy.extended_low_rate_seconds =
        parseUnsignedEnv("WEAKNET_LONG_FLOW_LOW_RATE_MIN_SEC", policy.extended_low_rate_seconds);
    policy.low_rate_bps = parseUnsignedEnv("WEAKNET_LONG_FLOW_LOW_RATE_BPS", policy.low_rate_bps);

    if (const char* raw_ports = std::getenv("WEAKNET_PROTECTED_PORTS")) {
        policy.protected_ports.clear();
        for (const auto& token : splitTokens(raw_ports)) {
            char* end = nullptr;
            const long value = std::strtol(token.c_str(), &end, 10);
            if (end && *end == '\0' && value > 0 && value <= 65535) {
                policy.protected_ports.push_back(static_cast<uint16_t>(value));
            }
        }
    }
    if (const char* raw_processes = std::getenv("WEAKNET_PROTECTED_COMMS")) {
        policy.protected_processes = splitTokens(raw_processes);
    }
    if (const char* raw_cgroups = std::getenv("WEAKNET_PROTECTED_CGROUPS")) {
        policy.protected_cgroup_fragments = splitTokens(raw_cgroups);
    }
    return policy;
}

#if WEAKNET_HAVE_LIBBPF
uint64_t monotonicNowNs() {
#if defined(__linux__)
    timespec value{};
    if (clock_gettime(CLOCK_MONOTONIC, &value) == 0) {
        return static_cast<uint64_t>(value.tv_sec) * 1000000000ULL +
               static_cast<uint64_t>(value.tv_nsec);
    }
#endif
    return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count());
}
#endif

}  // namespace

struct NetTrafficAnalyzer::Impl {
    struct RawFlow {
        flow_key key{};
        flow_value value{};
    };

    struct SocketOwner {
        uint32_t tgid = 0;
        std::string comm;
        std::string cgroup;
    };

    struct DiagSocket {
        uint64_t cookie = 0;
        uint64_t inode = 0;
        uint8_t family = FLOW_AF_UNSPEC;
        uint32_t ifindex = 0;
        uint16_t sport = 0;
        uint16_t dport = 0;
    };

    mutable std::mutex configMutex;
    mutable std::mutex samplerMutex;
    mutable std::mutex snapshotMutex;
    mutable std::mutex historyMutex;

    std::string bpfObjPath = "build/flow_rate.bpf.o";
    std::string boundIface;
    uint32_t boundIfindex = 0;
    bool attached = false;

    void* bpfObject = nullptr;
    void* tcpLink = nullptr;
    void* udpLink = nullptr;
    void* ringBuffer = nullptr;
    int mapCurrentFd = -1;
    int mapProtectedPolicyFd = -1;
    int mapProtectedFlowsFd = -1;
    int mapRuntimeConfigFd = -1;
    int mapStatsFd = -1;
    int mapIfaceTotalsFd = -1;
    int mapEventsFd = -1;
    uint32_t tcIfindex = 0;
    bool tcIngressAttached = false;
    bool tcEgressAttached = false;
    uint32_t tcIngressProgId = 0;
    uint32_t tcEgressProgId = 0;
    int tcLockFd = -1;
    uint32_t tcLockIfindex = 0;

    TrafficSupportStatus support;
    std::string captureDegradedReason;
    TrafficSnapshotPtr latestSnapshot;
    uint64_t generation = 0;
    std::chrono::steady_clock::time_point previousSampleSteady{};
    std::chrono::system_clock::time_point previousSampleWall{};
    std::unordered_map<std::string, flow_value> previousFlows;
    // 有界 tombstone，用于识别沉默多轮后的同 key 重现；仅在容量压力下淘汰，不按短 generation TTL 过期。
    std::unordered_map<std::string, uint64_t> everSeenFlows;
    std::unordered_map<std::string, flow_iface_counters> previousInterfaces;
    std::vector<flow_event> pendingKernelEvents;

    std::map<std::string, TrafficHistory> trafficHistory;
    uint64_t burstThresholdBps = 10 * 1024 * 1024;
    uint64_t suspiciousThresholdBps = 50 * 1024 * 1024;
    double burstMultiplier = 3.0;
    static constexpr size_t kMaxHistorySize = 60;

    weaknet_grpc::traffic_core::LongFlowPolicy longFlowPolicy = policyFromEnvironment();
    std::chrono::steady_clock::time_point lastSockDiag{};
    std::unordered_map<uint64_t, std::chrono::steady_clock::time_point> diagFirstSeen;
    std::unordered_map<uint64_t, uint8_t> diagFamilies;
    std::unordered_map<uint64_t, SocketOwner> socketOwners;
    // IPv4/IPv6 独立维护：某一族 sock_diag 失败时必须保留该族上一轮策略。
    std::array<std::unordered_set<uint64_t>, 2> installedPoliciesByFamily;
    uint64_t policyUpdateAttempts = 0;
    uint64_t policyUpdateFailures = 0;

    Impl() {
        support.libbpfAvailable = WEAKNET_HAVE_LIBBPF != 0;
        support.ipv6ExtensionHeadersSupported = false;
        support.coverageLimitations =
            "IPv6 extension headers are not parsed; TC ingress may not expose a socket cookie before socket lookup";
        captureDegradedReason = support.libbpfAvailable
            ? "eBPF object has not been initialized"
            : "libbpf is unavailable on this build/operating system";
        support.degradedReason = weaknet_grpc::traffic_core::composeDegradedReason(
            captureDegradedReason, support.sockDiagStatus);
        auto initial = std::make_shared<TrafficSnapshot>();
        initial->support = support;
        latestSnapshot = initial;
    }
};

namespace {

void recomputeDegradedReason(NetTrafficAnalyzer::Impl& state) {
    state.support.degradedReason = weaknet_grpc::traffic_core::composeDegradedReason(
        state.captureDegradedReason, state.support.sockDiagStatus);
}

std::vector<TrafficAnomaly> deriveTrafficAnomalies(
    const TrafficSnapshotPtr& snapshot,
    const std::map<std::string, TrafficHistory>& historyByFlow,
    uint64_t burstThresholdBps,
    uint64_t suspiciousThresholdBps,
    double burstMultiplier) {
    if (!snapshot) return {};
    std::vector<TrafficAnomaly> anomalies;
    for (const auto& flow : snapshot->flows) {
        const std::string key = flowHistoryKey(flow);
        const auto history = historyByFlow.find(key);
        uint64_t average = 0;
        if (history != historyByFlow.end() && history->second.bpsHistory.size() >= 3) {
            average = std::accumulate(history->second.bpsHistory.begin(),
                                      history->second.bpsHistory.end(), uint64_t{0}) /
                      history->second.bpsHistory.size();
        }
        const bool burst = average > 0 && flow.bps > burstThresholdBps &&
                           static_cast<long double>(flow.bps) >
                               static_cast<long double>(average) * burstMultiplier;
        const bool suspicious = flow.bps > suspiciousThresholdBps;
        if (burst || suspicious || flow.continuityLost) {
            TrafficAnomaly anomaly;
            anomaly.flowKey = key;
            anomaly.anomalyType = flow.continuityLost ? "continuity_lost" : (burst ? "burst" : "high_volume");
            anomaly.currentBps = flow.bps;
            anomaly.thresholdBps = flow.continuityLost ? 0 :
                (burst ? burstThresholdBps : suspiciousThresholdBps);
            anomaly.severity = flow.continuityLost ? 1.0 : std::min(1.0,
                static_cast<double>(flow.bps - anomaly.thresholdBps) /
                static_cast<double>(std::max<uint64_t>(1, anomaly.thresholdBps)));
            anomaly.timestamp = snapshot->windowEnd;
            anomaly.description = flow.continuityLost
                ? "counter continuity lost; this rate is conservative and must not be treated as an exact uninterrupted series"
                : (burst ? "traffic burst exceeds historical baseline" : "traffic exceeds the configured volume threshold");
            anomalies.push_back(std::move(anomaly));
        }
    }
    return anomalies;
}

}  // namespace

std::once_flag NetTrafficAnalyzer::s_onceFlag;
std::shared_ptr<NetTrafficAnalyzer> NetTrafficAnalyzer::s_instance;

NetTrafficAnalyzer::NetTrafficAnalyzer() : impl_(std::make_unique<Impl>()) {}

std::shared_ptr<NetTrafficAnalyzer> NetTrafficAnalyzer::getInstance() {
    std::call_once(s_onceFlag, [] {
        s_instance = std::shared_ptr<NetTrafficAnalyzer>(new NetTrafficAnalyzer());
    });
    return s_instance;
}

#if WEAKNET_HAVE_LIBBPF
namespace {

bool mapAbiMatches(int fd, uint32_t keySize, uint32_t valueSize, uint32_t maxEntries,
                   const char* name, std::string& error) {
    bpf_map_info info{};
    uint32_t infoLength = sizeof(info);
    if (bpf_obj_get_info_by_fd(fd, &info, &infoLength) != 0) {
        error = std::string("cannot query map ABI for ") + name + ": " + std::strerror(errno);
        return false;
    }
    if (info.key_size != keySize || info.value_size != valueSize || info.max_entries != maxEntries) {
        std::ostringstream message;
        message << "map ABI mismatch for " << name << " (key=" << info.key_size
                << "/" << keySize << ", value=" << info.value_size << "/" << valueSize
                << ", max_entries=" << info.max_entries << "/" << maxEntries << ')';
        error = message.str();
        return false;
    }
    return true;
}

void destroyLink(void*& rawLink) {
    if (!rawLink) return;
    bpf_link__destroy(static_cast<bpf_link*>(rawLink));
    rawLink = nullptr;
}

constexpr uint32_t kWeakNetTcHandle = 1;
constexpr uint32_t kWeakNetTcPriority = 1;

struct TcSlotPlan {
    bpf_program* program = nullptr;
    enum bpf_tc_attach_point point = BPF_TC_INGRESS;
    bpf_prog_info currentInfo{};
    uint32_t previousProgId = 0;
    int previousProgFd = -1;
    bool applied = false;
};

// 把 libbpf 的负 errno 转成稳定诊断文本，避免只暴露难以定位的数字返回值。
std::string tcErrorText(int error) {
    const int code = error < 0 ? -error : error;
    return std::string(std::strerror(code)) + " (" + std::to_string(error) + ")";
}

// 读取已加载程序的内核身份；name/tag 用于确认固定 TC 槽位确实属于本轮 JaNet。
bool readBpfProgramInfo(int programFd, bpf_prog_info& info, std::string& error) {
    info = {};
    uint32_t infoLength = sizeof(info);
    if (bpf_obj_get_info_by_fd(programFd, &info, &infoLength) == 0) return true;
    error = std::string("cannot inspect BPF program: ") + std::strerror(errno);
    return false;
}

std::string bpfProgramName(const bpf_prog_info& info) {
    return std::string(info.name, strnlen(info.name, sizeof(info.name)));
}

std::string bpfProgramTag(const bpf_prog_info& info) {
    std::ostringstream output;
    output << std::hex << std::setfill('0');
    for (uint8_t byte : info.tag) output << std::setw(2) << static_cast<unsigned int>(byte);
    return output.str();
}

// Classic TC filter 会在进程崩溃后留在内核。只有类型、内核截断名和指令 tag
// 都与本轮待附加程序一致时才视为 JaNet 遗留；否则拒绝替换，避免误伤其他 TC 用户。
bool tcSlotOwnedByCurrentProgram(bpf_program* currentProgram,
                                 const bpf_prog_info& currentInfo,
                                 const bpf_prog_info& existingInfo,
                                 uint32_t existingProgramId,
                                 enum bpf_tc_attach_point point,
                                 std::string& error) {
    const char* expectedName = point == BPF_TC_INGRESS
        ? "weaknet_tc_ingress" : "weaknet_tc_egress";
    const char* currentName = bpf_program__name(currentProgram);
    if (!currentName || std::string(currentName) != expectedName) {
        error = std::string("unexpected JaNet TC program name: ") +
            (currentName ? currentName : "(null)");
        return false;
    }

    const bool sameIdentity =
        currentInfo.type == BPF_PROG_TYPE_SCHED_CLS &&
        existingInfo.type == currentInfo.type &&
        bpfProgramName(existingInfo) == bpfProgramName(currentInfo) &&
        std::memcmp(existingInfo.tag, currentInfo.tag, sizeof(currentInfo.tag)) == 0;
    if (sameIdentity) return true;

    error = std::string("TC ") + (point == BPF_TC_INGRESS ? "ingress" : "egress") +
        " slot pref=1 handle=1 is owned by a different program (id=" +
        std::to_string(existingProgramId) + ", name=" + bpfProgramName(existingInfo) +
        ", tag=" + bpfProgramTag(existingInfo) + "); refusing unsafe replacement";
    return false;
}

// 查询固定槽位。每次都使用全新的 opts；libbpf 会把 prog_id 写回该结构，不能复用。
int queryTcSlot(uint32_t ifindex,
                enum bpf_tc_attach_point point,
                uint32_t& programId) {
    bpf_tc_hook hook{};
    hook.sz = sizeof(hook);
    hook.ifindex = static_cast<int>(ifindex);
    hook.attach_point = point;
    bpf_tc_opts query{};
    query.sz = sizeof(query);
    query.handle = kWeakNetTcHandle;
    query.priority = kWeakNetTcPriority;
    const int queryResult = bpf_tc_query(&hook, &query);
    programId = queryResult == 0 ? query.prog_id : 0;
    return queryResult;
}

// 先从 rtnetlink 判断 clsact 是否存在，避免对已存在的 qdisc 调用 EXCL create，
// 从源头消除 libbpf 的 “Exclusivity flag on” 启动噪声。
bool clsactHookExists(uint32_t ifindex, bool& exists, std::string& error) {
    exists = false;
    const int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (fd < 0) {
        error = std::string("cannot open qdisc netlink socket: ") + std::strerror(errno);
        return false;
    }
    sockaddr_nl local{};
    local.nl_family = AF_NETLINK;
    if (bind(fd, reinterpret_cast<sockaddr*>(&local), sizeof(local)) != 0) {
        error = std::string("cannot bind qdisc netlink socket: ") + std::strerror(errno);
        close(fd);
        return false;
    }

    struct {
        nlmsghdr header;
        tcmsg message;
    } request{};
    request.header.nlmsg_len = NLMSG_LENGTH(sizeof(tcmsg));
    request.header.nlmsg_type = RTM_GETQDISC;
    request.header.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    request.header.nlmsg_seq = 1;
    request.message.tcm_family = AF_UNSPEC;
    request.message.tcm_ifindex = static_cast<int>(ifindex);

    sockaddr_nl kernel{};
    kernel.nl_family = AF_NETLINK;
    if (sendto(fd, &request, request.header.nlmsg_len, 0,
               reinterpret_cast<sockaddr*>(&kernel), sizeof(kernel)) < 0) {
        error = std::string("cannot request qdisc dump: ") + std::strerror(errno);
        close(fd);
        return false;
    }

    const bool complete = weaknet_grpc::netlink_dump::receiveCompleteDump(
        fd, request.header.nlmsg_seq,
        [&](const nlmsghdr* header) {
            if (header->nlmsg_type != RTM_NEWQDISC ||
                header->nlmsg_len < NLMSG_LENGTH(sizeof(tcmsg))) return;
            const auto* message = static_cast<const tcmsg*>(NLMSG_DATA(header));
            if (message->tcm_ifindex != static_cast<int>(ifindex)) return;
            int attributesLength = static_cast<int>(header->nlmsg_len) -
                                   static_cast<int>(NLMSG_LENGTH(sizeof(tcmsg)));
            for (const rtattr* attribute = TCA_RTA(message);
                 RTA_OK(attribute, attributesLength);
                 attribute = RTA_NEXT(attribute, attributesLength)) {
                if (attribute->rta_type != TCA_KIND || RTA_PAYLOAD(attribute) == 0) continue;
                const char* kind = static_cast<const char*>(RTA_DATA(attribute));
                const size_t length = strnlen(kind, RTA_PAYLOAD(attribute));
                if (std::string(kind, length) == "clsact") exists = true;
            }
        }, error);
    close(fd);
    return complete;
}

struct TcFilterSlotPresence {
    bool exists = false;
    bool isBpf = false;
};

// bpf_tc_query 在“clsact 存在但该方向尚无 chain”时会返回 EINVAL，并让 libbpf
// 打印 Cannot find specified filter chain。先用 RTM_GETTFILTER 的空 dump 判空，
// 只有确认目标槽位存在且确实是 BPF classifier 后才进入 libbpf 身份查询。
bool inspectTcFilterSlot(uint32_t ifindex,
                         enum bpf_tc_attach_point point,
                         TcFilterSlotPresence& result,
                         std::string& error) {
    result = {};
    const int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (fd < 0) {
        error = std::string("cannot open TC filter netlink socket: ") + std::strerror(errno);
        return false;
    }
    sockaddr_nl local{};
    local.nl_family = AF_NETLINK;
    if (bind(fd, reinterpret_cast<sockaddr*>(&local), sizeof(local)) != 0) {
        error = std::string("cannot bind TC filter netlink socket: ") + std::strerror(errno);
        close(fd);
        return false;
    }

    const uint32_t parent = TC_H_MAKE(
        TC_H_CLSACT, point == BPF_TC_INGRESS ? TC_H_MIN_INGRESS : TC_H_MIN_EGRESS);
    struct {
        nlmsghdr header;
        tcmsg message;
    } request{};
    request.header.nlmsg_len = NLMSG_LENGTH(sizeof(tcmsg));
    request.header.nlmsg_type = RTM_GETTFILTER;
    request.header.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    request.header.nlmsg_seq = 2;
    request.message.tcm_family = AF_UNSPEC;
    request.message.tcm_ifindex = static_cast<int>(ifindex);
    request.message.tcm_parent = parent;

    sockaddr_nl kernel{};
    kernel.nl_family = AF_NETLINK;
    if (sendto(fd, &request, request.header.nlmsg_len, 0,
               reinterpret_cast<sockaddr*>(&kernel), sizeof(kernel)) < 0) {
        error = std::string("cannot request TC filter dump: ") + std::strerror(errno);
        close(fd);
        return false;
    }

    const bool complete = weaknet_grpc::netlink_dump::receiveCompleteDump(
        fd, request.header.nlmsg_seq,
        [&](const nlmsghdr* header) {
            if (header->nlmsg_type != RTM_NEWTFILTER ||
                header->nlmsg_len < NLMSG_LENGTH(sizeof(tcmsg))) return;
            const auto* message = static_cast<const tcmsg*>(NLMSG_DATA(header));
            const uint32_t priority = message->tcm_info >> 16U;
            if (message->tcm_ifindex != static_cast<int>(ifindex) ||
                message->tcm_parent != parent ||
                message->tcm_handle != kWeakNetTcHandle ||
                priority != kWeakNetTcPriority) return;

            uint32_t chain = 0;
            std::string kind;
            int attributesLength = static_cast<int>(header->nlmsg_len) -
                                   static_cast<int>(NLMSG_LENGTH(sizeof(tcmsg)));
            for (const rtattr* attribute = TCA_RTA(message);
                 RTA_OK(attribute, attributesLength);
                 attribute = RTA_NEXT(attribute, attributesLength)) {
                if (attribute->rta_type == TCA_CHAIN &&
                    RTA_PAYLOAD(attribute) >= sizeof(chain)) {
                    std::memcpy(&chain, RTA_DATA(attribute), sizeof(chain));
                } else if (attribute->rta_type == TCA_KIND && RTA_PAYLOAD(attribute) > 0) {
                    const char* rawKind = static_cast<const char*>(RTA_DATA(attribute));
                    kind.assign(rawKind, strnlen(rawKind, RTA_PAYLOAD(attribute)));
                }
            }
            if (chain == 0) {
                result.exists = true;
                result.isBpf = kind == "bpf";
            }
        }, error);
    close(fd);
    return complete;
}

uint64_t currentNetworkNamespaceId() {
    struct stat info{};
    return stat("/proc/self/ns/net", &info) == 0 ? static_cast<uint64_t>(info.st_ino) : 0;
}

// Classic TC 没有 compare-and-swap。进程生命周期文件锁用于阻止两个活着的 JaNet
// 实例把相同 name/tag 误判成“崩溃遗留”后互相 REPLACE；进程退出时内核自动释放锁。
bool acquireTcLock(NetTrafficAnalyzer::Impl& state, uint32_t ifindex, std::string& error) {
    if (state.tcLockFd >= 0 && state.tcLockIfindex == ifindex) return true;
    if (state.tcLockFd >= 0) {
        close(state.tcLockFd);
        state.tcLockFd = -1;
        state.tcLockIfindex = 0;
    }
    const std::string path = "/run/weaknet-tc-" +
        std::to_string(currentNetworkNamespaceId()) + "-if" + std::to_string(ifindex) + ".lock";
    const int fd = open(path.c_str(), O_CREAT | O_CLOEXEC | O_RDWR, 0600);
    if (fd < 0) {
        error = "cannot open TC ownership lock " + path + ": " + std::strerror(errno);
        return false;
    }
    if (flock(fd, LOCK_EX | LOCK_NB) != 0) {
        error = "another live JaNet instance owns TC on this interface";
        close(fd);
        return false;
    }
    state.tcLockFd = fd;
    state.tcLockIfindex = ifindex;
    return true;
}

void releaseTcLock(NetTrafficAnalyzer::Impl& state) {
    if (state.tcLockFd >= 0) close(state.tcLockFd);
    state.tcLockFd = -1;
    state.tcLockIfindex = 0;
}

void closeTcSlotPlan(TcSlotPlan& plan) {
    if (plan.previousProgFd >= 0) close(plan.previousProgFd);
    plan.previousProgFd = -1;
}

// 两个方向都先执行 prepare；遇到 foreign filter 时 attachTc 尚未修改任何槽位。
bool prepareTcSlot(TcSlotPlan& plan,
                   uint32_t ifindex,
                   bool hookExists,
                   std::string& error) {
    if (!readBpfProgramInfo(bpf_program__fd(plan.program), plan.currentInfo, error)) return false;
    if (plan.currentInfo.id == 0 || plan.currentInfo.type != BPF_PROG_TYPE_SCHED_CLS) {
        error = "current JaNet TC program has an invalid kernel identity";
        return false;
    }

    if (!hookExists) return true;
    TcFilterSlotPresence slot;
    if (!inspectTcFilterSlot(ifindex, plan.point, slot, error)) return false;
    if (!slot.exists) return true;
    if (!slot.isBpf) {
        error = std::string("TC ") +
            (plan.point == BPF_TC_INGRESS ? "ingress" : "egress") +
            " slot pref=1 handle=1 is not a BPF classifier; refusing unsafe replacement";
        return false;
    }

    uint32_t existingProgramId = 0;
    const int queryResult = queryTcSlot(ifindex, plan.point, existingProgramId);
    if (queryResult == -ENOENT) return true;
    if (queryResult != 0) {
        error = "cannot query TC slot ownership: " + tcErrorText(queryResult);
        return false;
    }
    if (existingProgramId == 0) {
        error = "TC slot query returned no program identity";
        return false;
    }

    plan.previousProgFd = bpf_prog_get_fd_by_id(existingProgramId);
    if (plan.previousProgFd < 0) {
        error = "TC slot changed while checking ownership; retry on the next sampling cycle";
        return false;
    }
    bpf_prog_info existingInfo{};
    if (!readBpfProgramInfo(plan.previousProgFd, existingInfo, error) ||
        !tcSlotOwnedByCurrentProgram(plan.program, plan.currentInfo, existingInfo,
                                     existingProgramId, plan.point, error)) {
        return false;
    }
    plan.previousProgId = existingProgramId;
    return true;
}

bool tcSlotMatches(uint32_t ifindex,
                   enum bpf_tc_attach_point point,
                   uint32_t expectedProgramId) {
    TcFilterSlotPresence slot;
    std::string ignoredError;
    if (!inspectTcFilterSlot(ifindex, point, slot, ignoredError) ||
        !slot.exists || !slot.isBpf) return false;
    uint32_t actualProgramId = 0;
    return queryTcSlot(ifindex, point, actualProgramId) == 0 &&
           actualProgramId == expectedProgramId;
}

bool applyTcSlot(TcSlotPlan& plan, uint32_t ifindex, std::string& error) {
    bpf_tc_hook hook{};
    hook.sz = sizeof(hook);
    hook.ifindex = static_cast<int>(ifindex);
    hook.attach_point = plan.point;

    bpf_tc_opts options{};
    options.sz = sizeof(options);
    options.prog_fd = bpf_program__fd(plan.program);
    options.handle = kWeakNetTcHandle;
    options.priority = kWeakNetTcPriority;
    options.flags = plan.previousProgFd >= 0 ? BPF_TC_F_REPLACE : 0;
    const int attachResult = bpf_tc_attach(&hook, &options);
    if (attachResult != 0) {
        error = std::string(plan.previousProgFd >= 0 ? "cannot replace owned stale TC filter: "
                                                     : "cannot attach TC filter: ") +
            tcErrorText(attachResult);
        return false;
    }
    plan.applied = true;
    if (tcSlotMatches(ifindex, plan.point, plan.currentInfo.id)) return true;
    error = "TC slot changed during attach; refusing to claim ownership";
    return false;
}

// apply 第二步失败时逆序恢复：原来为空则只删除仍指向本轮 prog_id 的槽；
// 原来是 JaNet 遗留则使用保留的旧 FD 原位 REPLACE。任何外部抢占都保持不动。
void rollbackTcSlot(TcSlotPlan& plan, uint32_t ifindex) {
    if (!plan.applied || !tcSlotMatches(ifindex, plan.point, plan.currentInfo.id)) return;
    bpf_tc_hook hook{};
    hook.sz = sizeof(hook);
    hook.ifindex = static_cast<int>(ifindex);
    hook.attach_point = plan.point;
    bpf_tc_opts options{};
    options.sz = sizeof(options);
    options.handle = kWeakNetTcHandle;
    options.priority = kWeakNetTcPriority;
    if (plan.previousProgFd >= 0) {
        options.prog_fd = plan.previousProgFd;
        options.flags = BPF_TC_F_REPLACE;
        bpf_tc_attach(&hook, &options);
    } else {
        bpf_tc_detach(&hook, &options);
    }
}

// 清理也必须按本轮记录的 prog_id 二次确认，禁止仅凭固定 handle/pref 盲删。
void detachOwnedTcSlot(uint32_t ifindex,
                       enum bpf_tc_attach_point point,
                       uint32_t ownedProgramId) {
    if (ownedProgramId == 0 || !tcSlotMatches(ifindex, point, ownedProgramId)) return;
    bpf_tc_hook hook{};
    hook.sz = sizeof(hook);
    hook.ifindex = static_cast<int>(ifindex);
    hook.attach_point = point;
    bpf_tc_opts options{};
    options.sz = sizeof(options);
    options.handle = kWeakNetTcHandle;
    options.priority = kWeakNetTcPriority;
    bpf_tc_detach(&hook, &options);
}

void detachTc(NetTrafficAnalyzer::Impl& state) {
    if (state.tcIfindex != 0) {
        if (state.tcIngressAttached) {
            detachOwnedTcSlot(state.tcIfindex, BPF_TC_INGRESS, state.tcIngressProgId);
        }
        if (state.tcEgressAttached) {
            detachOwnedTcSlot(state.tcIfindex, BPF_TC_EGRESS, state.tcEgressProgId);
        }
    }
    state.tcIngressAttached = false;
    state.tcEgressAttached = false;
    state.tcIngressProgId = 0;
    state.tcEgressProgId = 0;
    state.tcIfindex = 0;
    releaseTcLock(state);
}

bool tcAttachmentMatchesState(const NetTrafficAnalyzer::Impl& state) {
    return state.tcIfindex != 0 && state.tcIngressAttached && state.tcEgressAttached &&
           tcSlotMatches(state.tcIfindex, BPF_TC_INGRESS, state.tcIngressProgId) &&
           tcSlotMatches(state.tcIfindex, BPF_TC_EGRESS, state.tcEgressProgId);
}

bool attachTc(NetTrafficAnalyzer::Impl& state, uint32_t ifindex, std::string& error) {
    if (!state.bpfObject || ifindex == 0) {
        error = "TC attach requires a loaded BPF object and a valid interface";
        return false;
    }
    auto* object = static_cast<bpf_object*>(state.bpfObject);
    bpf_program* ingress = bpf_object__find_program_by_name(object, "weaknet_tc_ingress");
    bpf_program* egress = bpf_object__find_program_by_name(object, "weaknet_tc_egress");
    if (!ingress || !egress) {
        error = "eBPF object is missing the TC ingress or egress program";
        return false;
    }

    if (!acquireTcLock(state, ifindex, error)) return false;
    TcSlotPlan ingressPlan{ingress, BPF_TC_INGRESS};
    TcSlotPlan egressPlan{egress, BPF_TC_EGRESS};
    bool hookExists = false;
    if (!clsactHookExists(ifindex, hookExists, error)) {
        closeTcSlotPlan(ingressPlan);
        closeTcSlotPlan(egressPlan);
        releaseTcLock(state);
        return false;
    }
    // prepare 是只读阶段；两个槽位都确认后才允许第一次 attach/replace。
    const bool prepared = prepareTcSlot(ingressPlan, ifindex, hookExists, error) &&
                          prepareTcSlot(egressPlan, ifindex, hookExists, error);
    if (!prepared) {
        closeTcSlotPlan(ingressPlan);
        closeTcSlotPlan(egressPlan);
        releaseTcLock(state);
        return false;
    }

    if (!hookExists) {
        bpf_tc_hook hook{};
        hook.sz = sizeof(hook);
        hook.ifindex = static_cast<int>(ifindex);
        hook.attach_point = static_cast<enum bpf_tc_attach_point>(
            BPF_TC_INGRESS | BPF_TC_EGRESS);
        const int createResult = bpf_tc_hook_create(&hook);
        if (createResult != 0) {
            error = "cannot create clsact hook: " + tcErrorText(createResult);
            closeTcSlotPlan(ingressPlan);
            closeTcSlotPlan(egressPlan);
            releaseTcLock(state);
            return false;
        }
    }

    const bool ingressApplied = applyTcSlot(ingressPlan, ifindex, error);
    const bool egressApplied = ingressApplied && applyTcSlot(egressPlan, ifindex, error);
    if (!egressApplied) {
        rollbackTcSlot(egressPlan, ifindex);
        rollbackTcSlot(ingressPlan, ifindex);
        closeTcSlotPlan(ingressPlan);
        closeTcSlotPlan(egressPlan);
        releaseTcLock(state);
        return false;
    }

    state.tcIfindex = ifindex;
    state.tcIngressAttached = true;
    state.tcEgressAttached = true;
    state.tcIngressProgId = ingressPlan.currentInfo.id;
    state.tcEgressProgId = egressPlan.currentInfo.id;
    closeTcSlotPlan(ingressPlan);
    closeTcSlotPlan(egressPlan);
    return true;
}

bool attachKprobeFallback(NetTrafficAnalyzer::Impl& state) {
    if (!state.bpfObject) return false;
    auto* object = static_cast<bpf_object*>(state.bpfObject);
    if (!state.tcpLink) {
        if (bpf_program* tcp = bpf_object__find_program_by_name(object, "tcp_transmit_entry")) {
            bpf_link* link = bpf_program__attach(tcp);
            const long error = libbpf_get_error(link);
            if (error == 0) state.tcpLink = link;
            // attach 失败返回 ERR_PTR，不是可 destroy 的 bpf_link。
        }
    }
    if (!state.udpLink) {
        if (bpf_program* udp = bpf_object__find_program_by_name(object, "udp_send_entry")) {
            bpf_link* link = bpf_program__attach(udp);
            const long error = libbpf_get_error(link);
            if (error == 0) state.udpLink = link;
        }
    }
    return state.tcpLink || state.udpLink;
}

bool writeRuntimeConfig(NetTrafficAnalyzer::Impl& state, uint32_t ifindex, uint32_t captureMode) {
    if (state.mapRuntimeConfigFd < 0) return false;
    const uint32_t zero = 0;
    flow_runtime_config config{};
    config.abi_version = FLOW_ABI_VERSION;
    config.ifindex = ifindex;
    config.capture_mode = captureMode;
    return bpf_map_update_elem(state.mapRuntimeConfigFd, &zero, &config, BPF_ANY) == 0;
}

int onRingBufferEvent(void* context, void* data, size_t size) {
    auto* state = static_cast<NetTrafficAnalyzer::Impl*>(context);
    if (!state || size != sizeof(flow_event)) return 0;
    flow_event event{};
    std::memcpy(&event, data, sizeof(event));
    if (event.abi_version == FLOW_ABI_VERSION) state->pendingKernelEvents.push_back(event);
    return 0;
}

struct MapReadHealth {
    bool complete = false;
    uint64_t lookupMisses = 0;
    uint64_t duplicateKeys = 0;
    int error = 0;
};

void mergeMapReadHealth(MapReadHealth& target, const MapReadHealth& source) {
    target.complete = target.complete && source.complete;
    target.lookupMisses += source.lookupMisses;
    target.duplicateKeys += source.duplicateKeys;
    if (target.error == 0) target.error = source.error;
}

template <typename Key>
struct MapKeyReadResult {
    std::vector<Key> keys;
    MapReadHealth health;
};

template <typename Key>
MapKeyReadResult<Key> enumerateMapKeys(int fd, size_t declaredCapacity) {
    MapKeyReadResult<Key> result;
    if (fd < 0) {
        result.health.error = EBADF;
        return result;
    }

    // LRU 高 churn 时 current key 可能在 get_next_key 前被淘汰，内核会从首 key 重启。
    // 对 key 去重并限制 syscall 次数，保证采样不会无限循环；出现重启即把本轮标为不完整。
    const size_t stepBudget = declaredCapacity * 2 + 64;
    std::unordered_set<std::string> seen;
    seen.reserve(declaredCapacity);
    Key current{};
    Key next{};
    bool haveCurrent = false;
    for (size_t step = 0; step < stepBudget; ++step) {
        errno = 0;
        const int status = bpf_map_get_next_key(fd, haveCurrent ? &current : nullptr, &next);
        if (status != 0) {
            const int readError = errno;
            if (readError == ENOENT) {
                result.health.complete = result.health.lookupMisses == 0 &&
                                         result.health.duplicateKeys == 0;
            } else {
                result.health.error = readError == 0 ? EIO : readError;
            }
            return result;
        }

        current = next;
        haveCurrent = true;
        const std::string id(reinterpret_cast<const char*>(&next), sizeof(next));
        if (!seen.insert(id).second) {
            ++result.health.duplicateKeys;
            continue;
        }
        result.keys.push_back(next);
        if (result.keys.size() > declaredCapacity) {
            result.health.error = EOVERFLOW;
            return result;
        }
    }

    result.health.error = EAGAIN;
    return result;
}

template <typename Key, typename Value>
struct MapReadResult {
    std::vector<std::pair<Key, Value>> entries;
    MapReadHealth health;
};

template <typename Key, typename Value>
MapReadResult<Key, Value> readMap(int fd, size_t declaredCapacity) {
    MapReadResult<Key, Value> result;
    auto keys = enumerateMapKeys<Key>(fd, declaredCapacity);
    result.health = keys.health;
    result.entries.reserve(keys.keys.size());
    for (const auto& key : keys.keys) {
        Value value{};
        errno = 0;
        if (bpf_map_lookup_elem(fd, &key, &value) == 0) {
            result.entries.emplace_back(key, value);
            continue;
        }
        ++result.health.lookupMisses;
        if (errno != ENOENT && result.health.error == 0) {
            result.health.error = errno == 0 ? EIO : errno;
        }
    }
    if (result.health.lookupMisses != 0 || result.health.error != 0) {
        result.health.complete = false;
    }
    return result;
}

template <typename Key>
bool clearMap(int fd, size_t declaredCapacity) {
    // 调用方必须先停掉所有写入 hook。重复读取是为了确认 map 已真正为空，而不是只删一次快照。
    for (int pass = 0; pass < 3; ++pass) {
        auto keys = enumerateMapKeys<Key>(fd, declaredCapacity);
        for (const auto& key : keys.keys) bpf_map_delete_elem(fd, &key);
        if (keys.health.error != 0 && keys.health.error != EAGAIN) return false;
        if (keys.keys.empty() && keys.health.complete) return true;
    }
    return false;
}

struct PerCpuStatsReadResult {
    std::array<uint64_t, FLOW_STAT_MAX> totals{};
    MapReadHealth health;
};

PerCpuStatsReadResult readPerCpuStats(int fd) {
    PerCpuStatsReadResult result;
    const int cpuCount = libbpf_num_possible_cpus();
    if (fd < 0 || cpuCount <= 0) {
        result.health.error = fd < 0 ? EBADF : EINVAL;
        return result;
    }
    result.health.complete = true;
    std::vector<uint64_t> perCpu(static_cast<size_t>(cpuCount));
    for (uint32_t id = 0; id < FLOW_STAT_MAX; ++id) {
        std::fill(perCpu.begin(), perCpu.end(), 0);
        errno = 0;
        if (bpf_map_lookup_elem(fd, &id, perCpu.data()) == 0) {
            result.totals[id] = std::accumulate(perCpu.begin(), perCpu.end(), uint64_t{0});
        } else {
            result.health.complete = false;
            ++result.health.lookupMisses;
            if (result.health.error == 0) result.health.error = errno == 0 ? EIO : errno;
        }
    }
    return result;
}

MapReadResult<flow_iface_key, flow_iface_counters> readPerCpuInterfaces(int fd) {
    MapReadResult<flow_iface_key, flow_iface_counters> result;
    const int cpuCount = libbpf_num_possible_cpus();
    if (fd < 0 || cpuCount <= 0) {
        result.health.error = fd < 0 ? EBADF : EINVAL;
        return result;
    }

    auto keys = enumerateMapKeys<flow_iface_key>(fd, FLOW_IFACE_MAX_ENTRIES);
    result.health = keys.health;
    std::vector<flow_iface_counters> perCpu(static_cast<size_t>(cpuCount));
    result.entries.reserve(keys.keys.size());
    for (const auto& key : keys.keys) {
        std::fill(perCpu.begin(), perCpu.end(), flow_iface_counters{});
        errno = 0;
        if (bpf_map_lookup_elem(fd, &key, perCpu.data()) == 0) {
            flow_iface_counters total{};
            for (const auto& value : perCpu) {
                total.bytes += value.bytes;
                total.packets += value.packets;
            }
            result.entries.emplace_back(key, total);
        } else {
            ++result.health.lookupMisses;
            if (errno != ENOENT && result.health.error == 0) {
                result.health.error = errno == 0 ? EIO : errno;
            }
        }
    }
    if (result.health.lookupMisses != 0 || result.health.error != 0) {
        result.health.complete = false;
    }
    return result;
}

#if defined(__linux__)
// inet_diag idiag_state follows the kernel TCP state ABI; ESTABLISHED is value 1.
// linux/tcp.h does not expose TCP_ESTABLISHED on all distributions, and mixing
// netinet/tcp.h with linux/tcp.h causes duplicate TCP struct definitions.
constexpr uint8_t kInetDiagTcpEstablished = 1;

bool querySockDiagFamily(int family, std::vector<NetTrafficAnalyzer::Impl::DiagSocket>& sockets,
                         std::string& error) {
    const int fd = socket(AF_NETLINK, SOCK_DGRAM | SOCK_CLOEXEC, NETLINK_SOCK_DIAG);
    if (fd < 0) {
        error = std::string("NETLINK_SOCK_DIAG socket failed: ") + std::strerror(errno);
        return false;
    }
    timeval timeout{1, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    struct Request {
        nlmsghdr header;
        inet_diag_req_v2 request;
    } request{};
    request.header.nlmsg_len = sizeof(request);
    request.header.nlmsg_type = SOCK_DIAG_BY_FAMILY;
    request.header.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    request.request.sdiag_family = static_cast<uint8_t>(family);
    request.request.sdiag_protocol = IPPROTO_TCP;
    request.request.idiag_states = UINT32_MAX;

    sockaddr_nl destination{};
    destination.nl_family = AF_NETLINK;
    std::string lastError;
    for (uint32_t attempt = 1; attempt <= 3; ++attempt) {
        request.header.nlmsg_seq = attempt;
        if (sendto(fd, &request, sizeof(request), 0,
                   reinterpret_cast<sockaddr*>(&destination), sizeof(destination)) < 0) {
            lastError = std::string("NETLINK_SOCK_DIAG send failed: ") + std::strerror(errno);
            continue;
        }

        bool payloadValid = true;
        std::vector<NetTrafficAnalyzer::Impl::DiagSocket> completeBatch;
        std::string dumpError;
        const bool complete = weaknet_grpc::netlink_dump::receiveCompleteDump(
            fd, attempt,
            [&](nlmsghdr* header) {
                if (header->nlmsg_type != SOCK_DIAG_BY_FAMILY) return;
                if (header->nlmsg_len < NLMSG_LENGTH(sizeof(inet_diag_msg))) {
                    payloadValid = false;
                    return;
                }
                const auto* message = reinterpret_cast<const inet_diag_msg*>(NLMSG_DATA(header));
                if (message->idiag_state != kInetDiagTcpEstablished) return;
                if (message->id.idiag_cookie[0] == INET_DIAG_NOCOOKIE &&
                    message->id.idiag_cookie[1] == INET_DIAG_NOCOOKIE) return;

                NetTrafficAnalyzer::Impl::DiagSocket socketInfo;
                socketInfo.cookie = static_cast<uint64_t>(message->id.idiag_cookie[0]) |
                                    (static_cast<uint64_t>(message->id.idiag_cookie[1]) << 32U);
                socketInfo.inode = message->idiag_inode;
                socketInfo.family = family == AF_INET6 ? FLOW_AF_INET6 : FLOW_AF_INET4;
                socketInfo.ifindex = message->id.idiag_if;
                socketInfo.sport = ntohs(message->id.idiag_sport);
                socketInfo.dport = ntohs(message->id.idiag_dport);
                if (socketInfo.cookie != 0) completeBatch.push_back(socketInfo);
            }, dumpError, std::chrono::milliseconds(2000));
        if (complete && payloadValid) {
            // 只在收到完整 DONE 后一次性合并；失败尝试里的 partial batch 直接丢弃，
            // 因此 reconciliation 绝不会用部分结果做 closed/demote 负向推断。
            sockets.insert(sockets.end(), completeBatch.begin(), completeBatch.end());
            close(fd);
            return true;
        }
        lastError = payloadValid ? dumpError : "NETLINK_SOCK_DIAG returned malformed inet_diag payload";
    }
    error = lastError.empty() ? "NETLINK_SOCK_DIAG dump failed" : lastError;
    close(fd);
    return false;
}

bool allDigits(const char* value) {
    if (!value || value[0] == '\0') return false;
    for (const char* cursor = value; *cursor; ++cursor) {
        if (*cursor < '0' || *cursor > '9') return false;
    }
    return true;
}

std::string readFirstLine(const std::string& path) {
    std::ifstream input(path);
    std::string line;
    std::getline(input, line);
    return line;
}

std::string readCgroupPath(uint32_t pid) {
    std::ifstream input("/proc/" + std::to_string(pid) + "/cgroup");
    std::string line;
    std::string combined;
    while (std::getline(input, line)) {
        const auto position = line.find_last_of(':');
        const std::string path = position == std::string::npos ? line : line.substr(position + 1);
        if (!combined.empty()) combined.push_back(';');
        combined += path;
    }
    return combined;
}

bool resolveProcOwners(const std::unordered_set<uint64_t>& wantedInodes,
                       std::unordered_map<uint64_t, NetTrafficAnalyzer::Impl::SocketOwner>& owners) {
    DIR* proc = opendir("/proc");
    if (!proc) return false;
    for (dirent* process = readdir(proc); process != nullptr; process = readdir(proc)) {
        if (!allDigits(process->d_name)) continue;
        const uint32_t pid = static_cast<uint32_t>(std::strtoul(process->d_name, nullptr, 10));
        const std::string base = std::string("/proc/") + process->d_name;
        DIR* descriptors = opendir((base + "/fd").c_str());
        if (!descriptors) continue;

        const std::string comm = readFirstLine(base + "/comm");
        const std::string cgroup = readCgroupPath(pid);
        for (dirent* descriptor = readdir(descriptors); descriptor != nullptr;
             descriptor = readdir(descriptors)) {
            if (descriptor->d_name[0] == '.') continue;
            const std::string linkPath = base + "/fd/" + descriptor->d_name;
            std::array<char, 128> target{};
            const ssize_t length = readlink(linkPath.c_str(), target.data(), target.size() - 1);
            if (length <= 0) continue;
            target[static_cast<size_t>(length)] = '\0';
            unsigned long long inode = 0;
            if (std::sscanf(target.data(), "socket:[%llu]", &inode) != 1) continue;
            if (wantedInodes.find(static_cast<uint64_t>(inode)) == wantedInodes.end()) continue;
            owners[static_cast<uint64_t>(inode)] = {pid, comm, cgroup};
        }
        closedir(descriptors);
    }
    closedir(proc);
    return true;
}

bool deleteProtectedFlowsForCookie(int mapFd, uint64_t cookie) {
    // protected_flows 以完整 flow_key 区分方向/协议；socket 结束时按 cookie 扫描清理其少量条目。
    for (int pass = 0; pass < 3; ++pass) {
        auto values = readMap<flow_key, flow_value>(mapFd, FLOW_PROTECTED_MAX_ENTRIES);
        bool removed = false;
        for (const auto& [key, value] : values.entries) {
            (void)value;
            if (key.socket_cookie != cookie) continue;
            bpf_map_delete_elem(mapFd, &key);
            removed = true;
        }
        if (values.health.complete && !removed) return true;
    }
    return false;
}

void reconcileProtectedSockets(NetTrafficAnalyzer::Impl& state,
                               const TrafficSnapshotPtr& previousSnapshot,
                               std::vector<TrafficObservationEvent>& events) {
    const auto nowSteady = std::chrono::steady_clock::now();
    if (state.lastSockDiag.time_since_epoch().count() != 0 &&
        nowSteady - state.lastSockDiag < sockDiagInterval()) return;
    state.lastSockDiag = nowSteady;

    std::array<std::vector<NetTrafficAnalyzer::Impl::DiagSocket>, 2> socketsByFamily;
    std::string ipv4Error;
    std::string ipv6Error;
    const bool ipv4Ok = querySockDiagFamily(AF_INET, socketsByFamily[0], ipv4Error);
    const bool ipv6Ok = querySockDiagFamily(AF_INET6, socketsByFamily[1], ipv6Error);
    const std::array<bool, 2> familyAvailable{ipv4Ok, ipv6Ok};
    const bool sockDiagAvailable = ipv4Ok || ipv6Ok;
    {
        std::lock_guard<std::mutex> lock(state.configMutex);
        state.support.sockDiagAvailable = sockDiagAvailable;
        state.support.sockDiagIpv4Available = ipv4Ok;
        state.support.sockDiagIpv6Available = ipv6Ok;
        state.support.sockDiagStatus = ipv4Ok && ipv6Ok ? "full" :
            (sockDiagAvailable ? "partial" : "unavailable");
        recomputeDegradedReason(state);
    }
    if (!ipv4Ok || !ipv6Ok) {
        TrafficObservationEvent event;
        event.type = FLOW_EVENT_SOCK_DIAG_DEGRADED;
        event.timestamp = std::chrono::system_clock::now();
        if (!ipv4Ok && !ipv6Ok) {
            event.description = !ipv4Error.empty() ? ipv4Error : ipv6Error;
        } else {
            event.description = std::string("sock_diag partial coverage: IPv4=") +
                (ipv4Ok ? "ok" : ipv4Error) + ", IPv6=" + (ipv6Ok ? "ok" : ipv6Error);
        }
        events.push_back(std::move(event));
        if (!sockDiagAvailable) return;
    }

    std::unordered_set<uint64_t> wantedInodes;
    for (size_t family = 0; family < socketsByFamily.size(); ++family) {
        if (!familyAvailable[family]) continue;
        for (const auto& socket : socketsByFamily[family]) {
            if (socket.inode != 0) wantedInodes.insert(socket.inode);
        }
    }
    std::unordered_map<uint64_t, NetTrafficAnalyzer::Impl::SocketOwner> inodeOwners;
    const bool procOwnerResolution = resolveProcOwners(wantedInodes, inodeOwners);
    {
        std::lock_guard<std::mutex> lock(state.configMutex);
        state.support.procOwnerResolution = procOwnerResolution;
    }

    std::unordered_map<uint64_t, uint64_t> recentRates;
    if (previousSnapshot) {
        for (const auto& flow : previousSnapshot->flows) {
            if (flow.socketCookie != 0) recentRates[flow.socketCookie] += flow.bps;
        }
    }

    const uint64_t nowNs = monotonicNowNs();
    for (size_t family = 0; family < socketsByFamily.size(); ++family) {
        if (!familyAvailable[family]) continue;  // 未覆盖族只保留，不做 closed/demoted 负向推断。

        const uint8_t flowFamily = family == 0 ? FLOW_AF_INET4 : FLOW_AF_INET6;
        auto& installed = state.installedPoliciesByFamily[family];
        std::unordered_set<uint64_t> seenCookies;
        std::unordered_set<uint64_t> desiredPolicies;
        for (const auto& socket : socketsByFamily[family]) {
            seenCookies.insert(socket.cookie);
            state.diagFamilies[socket.cookie] = flowFamily;
            auto [first, inserted] = state.diagFirstSeen.emplace(socket.cookie, nowSteady);
            (void)inserted;
            const auto observedSeconds = static_cast<uint64_t>(
                std::chrono::duration_cast<std::chrono::seconds>(nowSteady - first->second).count());

            NetTrafficAnalyzer::Impl::SocketOwner owner;
            if (auto previousOwner = state.socketOwners.find(socket.cookie);
                previousOwner != state.socketOwners.end()) owner = previousOwner->second;
            if (auto found = inodeOwners.find(socket.inode); found != inodeOwners.end()) owner = found->second;
            state.socketOwners[socket.cookie] = owner;

            weaknet_grpc::traffic_core::LongFlowCandidate candidate;
            candidate.observed_seconds = observedSeconds;
            candidate.recent_bps = recentRates[socket.cookie];
            candidate.sport = socket.sport;
            candidate.dport = socket.dport;
            candidate.comm = owner.comm;
            candidate.cgroup = owner.cgroup;
            const auto decision = weaknet_grpc::traffic_core::evaluateLongFlowPolicy(
                state.longFlowPolicy, candidate);
            if (!decision.protect) continue;

            flow_protection_policy policy{};
            policy.observed_since_ns = nowNs - observedSeconds * 1000000000ULL;
            policy.expires_ns = nowNs + static_cast<uint64_t>(
                std::chrono::duration_cast<std::chrono::nanoseconds>(protectionTtl()).count());
            policy.tgid = owner.tgid;
            policy.reason_flags = decision.reason_flags;
            std::strncpy(policy.comm, owner.comm.c_str(), sizeof(policy.comm) - 1);
            ++state.policyUpdateAttempts;
            if (bpf_map_update_elem(state.mapProtectedPolicyFd, &socket.cookie, &policy, BPF_ANY) == 0) {
                desiredPolicies.insert(socket.cookie);
            } else {
                // 已安装策略刷新失败时保留旧状态；不能把写失败误解释为 demotion。
                if (installed.find(socket.cookie) != installed.end()) desiredPolicies.insert(socket.cookie);
                ++state.policyUpdateFailures;
                TrafficObservationEvent event;
                event.type = FLOW_EVENT_MAP_INSERT_FAILURE;
                event.reason = FLOW_VALUE_PROTECTED;
                event.socketCookie = socket.cookie;
                event.timestamp = std::chrono::system_clock::now();
                event.description = std::string("protected policy map update failed: ") + std::strerror(errno);
                events.push_back(std::move(event));
            }
        }

        const auto plan = weaknet_grpc::traffic_core::planFamilyPolicyReconciliation(
            installed, desiredPolicies, true);
        for (uint64_t cookie : plan.removals) {
            const bool socketStillOpen = seenCookies.find(cookie) != seenCookies.end();
            TrafficObservationEvent lifecycleEvent;
            lifecycleEvent.type = socketStillOpen
                ? FLOW_EVENT_PROTECTED_DEMOTED : FLOW_EVENT_PROTECTED_CLOSED;
            lifecycleEvent.socketCookie = cookie;
            lifecycleEvent.timestamp = std::chrono::system_clock::now();
            lifecycleEvent.description = socketStillOpen
                ? "protected-flow policy no longer matches; policy and non-LRU counters were removed"
                : "protected socket closed; policy and non-LRU counters were removed";
            events.push_back(std::move(lifecycleEvent));
            bpf_map_delete_elem(state.mapProtectedPolicyFd, &cookie);
            // Demotion 必须同步清 protected value；否则 refresh 的后写合并会永久覆盖新 LRU 计数。
            if (!deleteProtectedFlowsForCookie(state.mapProtectedFlowsFd, cookie)) {
                TrafficObservationEvent cleanupEvent;
                cleanupEvent.type = FLOW_EVENT_MAP_INSERT_FAILURE;
                cleanupEvent.reason = FLOW_VALUE_PROTECTED;
                cleanupEvent.socketCookie = cookie;
                cleanupEvent.timestamp = std::chrono::system_clock::now();
                cleanupEvent.description = "protected-flow cleanup could not complete map enumeration";
                events.push_back(std::move(cleanupEvent));
            }
        }
        installed = plan.next;

        // 只清理本轮成功覆盖的地址族；失败族的 duration/owner 状态完整保留到下一次成功查询。
        for (auto iterator = state.diagFirstSeen.begin(); iterator != state.diagFirstSeen.end();) {
            const uint64_t cookie = iterator->first;
            const auto knownFamily = state.diagFamilies.find(cookie);
            if (knownFamily == state.diagFamilies.end() || knownFamily->second != flowFamily ||
                seenCookies.find(cookie) != seenCookies.end()) {
                ++iterator;
                continue;
            }
            state.socketOwners.erase(cookie);
            state.diagFamilies.erase(cookie);
            iterator = state.diagFirstSeen.erase(iterator);
        }
    }
}

#endif  // defined(__linux__)

}  // namespace
#endif  // WEAKNET_HAVE_LIBBPF

NetTrafficAnalyzer::~NetTrafficAnalyzer() {
#if WEAKNET_HAVE_LIBBPF
    std::lock_guard<std::mutex> configLock(impl_->configMutex);
    if (impl_->ringBuffer) {
        ring_buffer__free(static_cast<ring_buffer*>(impl_->ringBuffer));
        impl_->ringBuffer = nullptr;
    }
    detachTc(*impl_);
    destroyLink(impl_->tcpLink);
    destroyLink(impl_->udpLink);
    if (impl_->bpfObject) {
        bpf_object__close(static_cast<bpf_object*>(impl_->bpfObject));
        impl_->bpfObject = nullptr;
    }
#endif
}

void NetTrafficAnalyzer::setBpfObjectPath(const std::string& path) {
    std::lock_guard<std::mutex> lock(impl_->configMutex);
    if (!impl_->attached) impl_->bpfObjPath = path;
}

bool NetTrafficAnalyzer::initForInterface(const std::string& ifaceName) {
#if !WEAKNET_HAVE_LIBBPF
    std::lock_guard<std::mutex> samplerLock(impl_->samplerMutex);
    std::lock_guard<std::mutex> lock(impl_->configMutex);
    impl_->boundIface = ifaceName;
    impl_->boundIfindex = if_nametoindex(ifaceName.c_str());
    impl_->captureDegradedReason = "libbpf is unavailable; traffic observation is disabled";
    recomputeDegradedReason(*impl_);
    return false;
#else
    {
        std::lock_guard<std::mutex> samplerLock(impl_->samplerMutex);
        std::lock_guard<std::mutex> lock(impl_->configMutex);
        if (impl_->attached) {
            // updateInterface 会自行获取 configMutex，不能在本锁域内递归调用。
        } else {
            libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
            bpf_object* object = bpf_object__open(impl_->bpfObjPath.c_str());
            const long openError = libbpf_get_error(object);
            if (openError || !object) {
                impl_->captureDegradedReason = "cannot open eBPF object: " + impl_->bpfObjPath;
                recomputeDegradedReason(*impl_);
                return false;
            }
            if (bpf_object__load(object) != 0) {
                impl_->captureDegradedReason = std::string("cannot load eBPF object: ") + std::strerror(errno);
                recomputeDegradedReason(*impl_);
                bpf_object__close(object);
                return false;
            }

            impl_->mapCurrentFd = bpf_object__find_map_fd_by_name(object, "current_sec");
            impl_->mapProtectedPolicyFd = bpf_object__find_map_fd_by_name(object, "protected_policy");
            impl_->mapProtectedFlowsFd = bpf_object__find_map_fd_by_name(object, "protected_flows");
            impl_->mapRuntimeConfigFd = bpf_object__find_map_fd_by_name(object, "runtime_config");
            impl_->mapStatsFd = bpf_object__find_map_fd_by_name(object, "map_stats");
            impl_->mapIfaceTotalsFd = bpf_object__find_map_fd_by_name(object, "iface_totals");
            impl_->mapEventsFd = bpf_object__find_map_fd_by_name(object, "flow_events");
            const int required[] = {impl_->mapCurrentFd, impl_->mapProtectedPolicyFd,
                                    impl_->mapProtectedFlowsFd, impl_->mapRuntimeConfigFd,
                                    impl_->mapStatsFd, impl_->mapIfaceTotalsFd, impl_->mapEventsFd};
            if (std::any_of(std::begin(required), std::end(required), [](int fd) { return fd < 0; })) {
                impl_->captureDegradedReason = "eBPF object is missing one or more ABI maps";
                recomputeDegradedReason(*impl_);
                bpf_object__close(object);
                return false;
            }

            std::string abiError;
            const bool abiOk =
                mapAbiMatches(impl_->mapCurrentFd, sizeof(flow_key), sizeof(flow_value),
                              FLOW_LRU_MAX_ENTRIES, "current_sec", abiError) &&
                mapAbiMatches(impl_->mapProtectedPolicyFd, sizeof(uint64_t), sizeof(flow_protection_policy),
                              FLOW_PROTECTED_MAX_ENTRIES,
                              "protected_policy", abiError) &&
                mapAbiMatches(impl_->mapProtectedFlowsFd, sizeof(flow_key), sizeof(flow_value),
                              FLOW_PROTECTED_MAX_ENTRIES,
                              "protected_flows", abiError) &&
                mapAbiMatches(impl_->mapRuntimeConfigFd, sizeof(uint32_t), sizeof(flow_runtime_config), 1,
                              "runtime_config", abiError) &&
                mapAbiMatches(impl_->mapStatsFd, sizeof(uint32_t), sizeof(uint64_t), FLOW_STAT_MAX,
                              "map_stats", abiError) &&
                mapAbiMatches(impl_->mapIfaceTotalsFd, sizeof(flow_iface_key), sizeof(flow_iface_counters),
                              FLOW_IFACE_MAX_ENTRIES,
                              "iface_totals", abiError) &&
                mapAbiMatches(impl_->mapEventsFd, 0, 0, 256 * 1024, "flow_events", abiError);
            if (!abiOk) {
                impl_->captureDegradedReason = abiError;
                recomputeDegradedReason(*impl_);
                bpf_object__close(object);
                return false;
            }

            impl_->bpfObject = object;
            impl_->ringBuffer = ring_buffer__new(impl_->mapEventsFd, onRingBufferEvent, impl_.get(), nullptr);
            if (!impl_->ringBuffer) {
                impl_->captureDegradedReason = "cannot create ring buffer consumer";
                recomputeDegradedReason(*impl_);
                bpf_object__close(object);
                impl_->bpfObject = nullptr;
                return false;
            }
            impl_->attached = true;
            impl_->support.bpfLoaded = true;
            impl_->support.ipv4Supported = true;
            impl_->support.ipv6Supported = true;
            impl_->support.ipv6ExtensionHeadersSupported = false;
            impl_->support.coverageLimitations =
                "IPv6 extension headers are not parsed; TC ingress can have socket_cookie=0 before socket lookup";
            impl_->captureDegradedReason = "eBPF object loaded; capture hook is not attached yet";
            recomputeDegradedReason(*impl_);
        }
    }
    return updateInterface(ifaceName);
#endif
}

bool NetTrafficAnalyzer::updateInterface(const std::string& ifaceName) {
    const uint32_t requestedIfindex = if_nametoindex(ifaceName.c_str());
    // 与 refreshSnapshot 保持 sampler -> config 的唯一锁顺序，避免 TC detach/read map 并发。
    std::lock_guard<std::mutex> samplerLock(impl_->samplerMutex);
    std::lock_guard<std::mutex> lock(impl_->configMutex);
    const bool interfaceChanged = requestedIfindex != impl_->boundIfindex;
#if WEAKNET_HAVE_LIBBPF
    const std::string previousCaptureMode = impl_->support.captureMode;
    const bool captureWasAttached =
        (impl_->support.tcIngressAttached && impl_->support.tcEgressAttached) ||
        impl_->support.tcpKprobeAttached || impl_->support.udpKprobeAttached;
#endif
    const auto resetBaseline = [&] {
        impl_->previousFlows.clear();
        impl_->everSeenFlows.clear();
        impl_->previousInterfaces.clear();
        impl_->previousSampleSteady = {};
        impl_->previousSampleWall = {};
        std::lock_guard<std::mutex> historyLock(impl_->historyMutex);
        impl_->trafficHistory.clear();
    };
    impl_->boundIface = ifaceName;
    impl_->boundIfindex = requestedIfindex;
    if (interfaceChanged) {
        // 下一次 refresh 只建立新接口基线，禁止切回旧接口后用短窗口除以陈旧累计差分。
        resetBaseline();
    }
    if (requestedIfindex == 0) {
#if WEAKNET_HAVE_LIBBPF
        detachTc(*impl_);
        destroyLink(impl_->tcpLink);
        destroyLink(impl_->udpLink);
        writeRuntimeConfig(*impl_, 0, FLOW_CAPTURE_KPROBE_FALLBACK);
#endif
        impl_->support.tcIngressAttached = false;
        impl_->support.tcEgressAttached = false;
        impl_->support.tcpKprobeAttached = false;
        impl_->support.udpKprobeAttached = false;
        impl_->support.bidirectional = false;
        impl_->support.udpInterfaceReliable = false;
        impl_->support.captureComplete = false;
        impl_->support.captureMode = "unavailable";
        impl_->support.captureCompleteness = "unavailable";
        impl_->captureDegradedReason = "cannot resolve interface name: " + ifaceName;
        recomputeDegradedReason(*impl_);
        return false;
    }
#if !WEAKNET_HAVE_LIBBPF
    impl_->captureDegradedReason = "interface resolved, but libbpf is unavailable";
    recomputeDegradedReason(*impl_);
    return false;
#else
    if (!impl_->attached || !impl_->bpfObject) return false;
    if (interfaceChanged) {
        // 先停止所有 writer，再清旧 map；若先清后 detach，旧 TC 会并发把旧接口 key 重新插入。
        detachTc(*impl_);
        destroyLink(impl_->tcpLink);
        destroyLink(impl_->udpLink);
        const bool mapsCleared =
            clearMap<flow_key>(impl_->mapCurrentFd, FLOW_LRU_MAX_ENTRIES) &&
            clearMap<flow_key>(impl_->mapProtectedFlowsFd, FLOW_PROTECTED_MAX_ENTRIES) &&
            clearMap<flow_iface_key>(impl_->mapIfaceTotalsFd, FLOW_IFACE_MAX_ENTRIES);
        if (!mapsCleared) {
            impl_->support.tcIngressAttached = false;
            impl_->support.tcEgressAttached = false;
            impl_->support.tcpKprobeAttached = false;
            impl_->support.udpKprobeAttached = false;
            impl_->support.bidirectional = false;
            impl_->support.udpInterfaceReliable = false;
            impl_->support.captureComplete = false;
            impl_->support.captureMode = "unavailable";
            impl_->support.captureCompleteness = "unavailable";
            impl_->captureDegradedReason = "interface changed but old traffic maps could not be cleared safely";
            recomputeDegradedReason(*impl_);
            return false;
        }
    }
    if (impl_->tcIfindex != requestedIfindex) detachTc(*impl_);

    bool fullTc = impl_->tcIfindex == requestedIfindex && impl_->tcIngressAttached &&
                  impl_->tcEgressAttached && tcAttachmentMatchesState(*impl_);
    if (!fullTc && impl_->tcIfindex == requestedIfindex &&
        (impl_->tcIngressAttached || impl_->tcEgressAttached)) {
        // 外部程序若替换了任一槽位，只清理仍匹配本轮 prog_id 的方向；外部槽位保持不动。
        detachTc(*impl_);
    }
    std::string tcAttachError;
    if (!fullTc) fullTc = attachTc(*impl_, requestedIfindex, tcAttachError);
    if (fullTc) {
        destroyLink(impl_->tcpLink);
        destroyLink(impl_->udpLink);
        if (!writeRuntimeConfig(*impl_, requestedIfindex, FLOW_CAPTURE_TC)) {
            detachTc(*impl_);
            impl_->support.tcIngressAttached = false;
            impl_->support.tcEgressAttached = false;
            impl_->support.tcpKprobeAttached = false;
            impl_->support.udpKprobeAttached = false;
            impl_->support.bidirectional = false;
            impl_->support.udpInterfaceReliable = false;
            impl_->support.captureComplete = false;
            impl_->support.captureMode = "unavailable";
            impl_->support.captureCompleteness = "unavailable";
            impl_->captureDegradedReason = "TC attached but runtime config update failed";
            recomputeDegradedReason(*impl_);
            resetBaseline();
            return false;
        }
        impl_->support.tcIngressAttached = true;
        impl_->support.tcEgressAttached = true;
        impl_->support.tcpKprobeAttached = false;
        impl_->support.udpKprobeAttached = false;
        impl_->support.bidirectional = true;
        impl_->support.udpInterfaceReliable = true;
        impl_->support.captureComplete = true;
        impl_->support.captureMode = "tc";
        impl_->support.captureCompleteness = "full";
        impl_->support.coverageLimitations =
            "IPv6 extension headers are not parsed; TC ingress can have socket_cookie=0 before socket lookup";
        if (!captureWasAttached || previousCaptureMode != "tc") resetBaseline();
        impl_->captureDegradedReason.clear();
        recomputeDegradedReason(*impl_);
        return true;
    }

    bool fallback = attachKprobeFallback(*impl_);
    if (fallback && !writeRuntimeConfig(*impl_, requestedIfindex, FLOW_CAPTURE_KPROBE_FALLBACK)) {
        destroyLink(impl_->tcpLink);
        destroyLink(impl_->udpLink);
        fallback = false;
        impl_->captureDegradedReason = "kprobe fallback attached but runtime config update failed";
    }
    impl_->support.tcIngressAttached = false;
    impl_->support.tcEgressAttached = false;
    impl_->support.tcpKprobeAttached = impl_->tcpLink != nullptr;
    impl_->support.udpKprobeAttached = impl_->udpLink != nullptr;
    impl_->support.bidirectional = false;
    impl_->support.udpInterfaceReliable = false;
    impl_->support.captureComplete = false;
    impl_->support.captureMode = fallback ? "kprobe-fallback" : "unavailable";
    impl_->support.captureCompleteness = fallback ? "partial" : "unavailable";
    impl_->support.coverageLimitations =
        "fallback is egress-only; unbound UDP has no reliable ifindex; IPv6 extension headers are not applicable to sock-derived keys";
    if (fallback) {
        impl_->captureDegradedReason = tcAttachError.empty() ? "TC attach failed" : tcAttachError;
        impl_->captureDegradedReason += "; kprobe fallback is partial (egress-only";
        if (!impl_->support.tcpKprobeAttached) impl_->captureDegradedReason += ", TCP hook missing";
        if (!impl_->support.udpKprobeAttached) impl_->captureDegradedReason += ", UDP hook missing";
        impl_->captureDegradedReason += ", unbound UDP cannot be attributed to an interface)";
    } else if (impl_->captureDegradedReason !=
               "kprobe fallback attached but runtime config update failed") {
        impl_->captureDegradedReason = tcAttachError.empty()
            ? "TC and kprobe attachment both failed"
            : tcAttachError + "; kprobe attachment failed";
    }
    recomputeDegradedReason(*impl_);
    if (fallback && (!captureWasAttached || previousCaptureMode != "kprobe-fallback")) resetBaseline();
    if (!fallback && captureWasAttached) resetBaseline();
    return fallback;
#endif
}

bool NetTrafficAnalyzer::isBaselinePending() const {
    std::lock_guard<std::mutex> lock(impl_->samplerMutex);
    return impl_->previousSampleSteady.time_since_epoch().count() == 0;
}

TrafficSnapshotPtr NetTrafficAnalyzer::refreshSnapshot() {
    std::lock_guard<std::mutex> samplerLock(impl_->samplerMutex);
    auto next = std::make_shared<TrafficSnapshot>();
    next->generation = ++impl_->generation;
    {
        std::lock_guard<std::mutex> configLock(impl_->configMutex);
        next->boundIfindex = impl_->boundIfindex;
        next->support = impl_->support;
    }

    auto sampleSteady = std::chrono::steady_clock::now();
    auto sampleWall = std::chrono::system_clock::now();
    bool advanceSampleBaseline = true;

#if WEAKNET_HAVE_LIBBPF
    if (impl_->attached) {
        TrafficSnapshotPtr prior;
        {
            std::lock_guard<std::mutex> snapshotLock(impl_->snapshotMutex);
            prior = impl_->latestSnapshot;
        }
#if defined(__linux__)
        // 校准可能扫描 sock_diag 和 /proc；它必须在 map read 边界之前完成，不能污染速率窗口。
        reconcileProtectedSockets(*impl_, prior, next->events);
#endif
        if (impl_->ringBuffer) ring_buffer__poll(static_cast<ring_buffer*>(impl_->ringBuffer), 0);

        const auto readBeginSteady = std::chrono::steady_clock::now();
        const auto readBeginWall = std::chrono::system_clock::now();
        const auto normalFlows = readMap<flow_key, flow_value>(
            impl_->mapCurrentFd, FLOW_LRU_MAX_ENTRIES);
        const auto protectedFlows = readMap<flow_key, flow_value>(
            impl_->mapProtectedFlowsFd, FLOW_PROTECTED_MAX_ENTRIES);
        const auto interfaceTotals = readPerCpuInterfaces(impl_->mapIfaceTotalsFd);
        const auto mapStats = readPerCpuStats(impl_->mapStatsFd);
        const auto readEndSteady = std::chrono::steady_clock::now();
        const auto readEndWall = std::chrono::system_clock::now();
        sampleSteady = mapReadBoundary<std::chrono::steady_clock>(readBeginSteady, readEndSteady);
        sampleWall = mapReadBoundary<std::chrono::system_clock>(readBeginWall, readEndWall);

        MapReadHealth aggregateHealth;
        aggregateHealth.complete = true;
        mergeMapReadHealth(aggregateHealth, normalFlows.health);
        mergeMapReadHealth(aggregateHealth, protectedFlows.health);
        mergeMapReadHealth(aggregateHealth, interfaceTotals.health);
        mergeMapReadHealth(aggregateHealth, mapStats.health);
        next->mapReadComplete = aggregateHealth.complete;
        next->mapObservability.mapReadComplete = aggregateHealth.complete;
        next->mapObservability.mapLookupMisses = aggregateHealth.lookupMisses;
        next->mapObservability.mapDuplicateKeys = aggregateHealth.duplicateKeys;
        next->mapObservability.mapReadError = aggregateHealth.error;
        next->mapObservability.lruEntries = normalFlows.entries.size();
        next->mapObservability.protectedEntries = protectedFlows.entries.size();
        next->mapStats = mapStats.totals;
        next->mapObservability.kernelCounters = next->mapStats;
        next->mapObservability.policyUpdateAttempts = impl_->policyUpdateAttempts;
        next->mapObservability.policyUpdateFailures = impl_->policyUpdateFailures;

        // 校准器可能在本轮修改支持状态，发布前复制最终状态。
        {
            std::lock_guard<std::mutex> configLock(impl_->configMutex);
            next->support = impl_->support;
        }

        for (const auto& rawEvent : impl_->pendingKernelEvents) {
            TrafficObservationEvent event;
            event.type = rawEvent.type;
            event.reason = rawEvent.reason;
            event.socketCookie = rawEvent.socket_cookie;
            event.flowKey = flowKeyToString(rawEvent.key);
            event.description = rawEvent.type == FLOW_EVENT_PROTECTED_PROMOTED
                ? "long-lived flow promoted to the non-LRU protected map"
                : "eBPF map insertion failed; observation is degraded";
            event.timestamp = sampleWall;
            next->events.push_back(std::move(event));
        }
        impl_->pendingKernelEvents.clear();

        if (!aggregateHealth.complete) {
            // 不能把部分枚举结果发布成真实低流量，也不能推进差分基线；下一次完整读取继续对齐上次完整窗口。
            advanceSampleBaseline = false;
            std::ostringstream reason;
            reason << "traffic map sampling incomplete";
            if (aggregateHealth.error != 0) reason << " (" << std::strerror(aggregateHealth.error) << ')';
            if (aggregateHealth.lookupMisses != 0) reason << ", lookup_misses=" << aggregateHealth.lookupMisses;
            if (aggregateHealth.duplicateKeys != 0) reason << ", duplicate_keys=" << aggregateHealth.duplicateKeys;
            if (!next->support.degradedReason.empty()) next->support.degradedReason += "; ";
            next->support.degradedReason += reason.str();
        } else {
        std::unordered_map<std::string, Impl::RawFlow> rawFlows;
        for (const auto& [key, value] : normalFlows.entries) {
            if (next->boundIfindex != 0 && key.ifindex != next->boundIfindex) continue;
            rawFlows[binaryKey(key)] = {key, value};
        }
        for (const auto& [key, value] : protectedFlows.entries) {
            if (next->boundIfindex != 0 && key.ifindex != next->boundIfindex) continue;
            // 同一 key 同时存在于 LRU 与保护 map 时，保护 map 是后续持续增长的权威来源。
            rawFlows[binaryKey(key)] = {key, value};
        }

        const uint64_t elapsedNs = impl_->previousSampleSteady.time_since_epoch().count() == 0
            ? 0
            : static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
                sampleSteady - impl_->previousSampleSteady).count());
        std::unordered_map<std::string, flow_value> currentBaseline;
        currentBaseline.reserve(rawFlows.size());
        for (const auto& [id, raw] : rawFlows) {
            currentBaseline[id] = raw.value;
            if (elapsedNs == 0) {
                impl_->everSeenFlows[id] = next->generation;
                continue;
            }

            const auto previous = impl_->previousFlows.find(id);
            const bool seenBefore = impl_->everSeenFlows.find(id) != impl_->everSeenFlows.end();
            CounterSample currentSample{raw.value.bytes, raw.value.packets,
                                        raw.value.first_seen_ns, raw.value.generation};
            CounterSample previousSample{};
            const CounterSample* previousPointer = nullptr;
            if (previous != impl_->previousFlows.end()) {
                previousSample = {previous->second.bytes, previous->second.packets,
                                  previous->second.first_seen_ns, previous->second.generation};
                previousPointer = &previousSample;
            }
            const auto delta = calculateCounterDelta(currentSample, previousPointer, seenBefore);
            impl_->everSeenFlows[id] = next->generation;
            if (delta.bytes == 0 && delta.packets == 0 && !delta.continuity_lost) continue;

            FlowRate flow;
            flow.src = addressToString(raw.key, true);
            flow.dst = addressToString(raw.key, false);
            flow.sport = ntohs(raw.key.sport_be);
            flow.dport = ntohs(raw.key.dport_be);
            flow.proto = protocolToString(raw.key.protocol);
            flow.direction = directionToString(raw.key.direction);
            flow.family = raw.key.family;
            flow.ifindex = raw.key.ifindex;
            flow.socketCookie = raw.key.socket_cookie;
            flow.bps = perSecond(delta.bytes, elapsedNs);
            flow.pps = perSecond(delta.packets, elapsedNs);
            flow.tgid = raw.value.tgid;
            flow.pid = raw.value.pid;
            flow.cgroupId = raw.value.cgroup_id;
            flow.comm = fixedCommToString(raw.value.comm);
            flow.protectedFlow = (raw.value.flags & FLOW_VALUE_PROTECTED) != 0;
            flow.continuityLost = delta.continuity_lost;
            flow.counterReset = delta.counter_reset;
            if (delta.continuity_lost) ++next->mapObservability.continuityLostThisWindow;
            if (delta.counter_reset) ++next->mapObservability.counterResetsThisWindow;
            if (auto owner = impl_->socketOwners.find(flow.socketCookie);
                owner != impl_->socketOwners.end() && owner->second.tgid != 0) {
                flow.tgid = owner->second.tgid;
                if (!owner->second.comm.empty()) flow.comm = owner->second.comm;
                flow.cgroupPath = owner->second.cgroup;
            }
            next->flows.push_back(std::move(flow));

            if (delta.continuity_lost) {
                TrafficObservationEvent event;
                event.type = delta.counter_reset ? FLOW_EVENT_COUNTER_RESET : FLOW_EVENT_CONTINUITY_LOST;
                event.socketCookie = raw.key.socket_cookie;
                event.flowKey = flowKeyToString(raw.key);
                event.description = delta.counter_reset
                    ? "flow counters restarted; current counters were used without unsigned underflow"
                    : "flow continuity was lost across the sampling window";
                event.timestamp = sampleWall;
                next->events.push_back(std::move(event));
            }
        }
        if (elapsedNs != 0) {
            next->mapObservability.disappearedThisWindow =
                weaknet_grpc::traffic_core::countDisappeared(impl_->previousFlows, currentBaseline);
        }
        // tombstone 不再按 6 个 generation 过期；沉默多轮后同 key 重建仍报告 continuity_lost。
        // 仅在达到四倍 LRU 容量后淘汰当前窗口外的最老可迭代项，以保持内存有界。
        const size_t maxRecentKeys = FLOW_LRU_MAX_ENTRIES * 4ULL + FLOW_PROTECTED_MAX_ENTRIES;
        for (auto iterator = impl_->everSeenFlows.begin();
             impl_->everSeenFlows.size() > maxRecentKeys && iterator != impl_->everSeenFlows.end();) {
            if (currentBaseline.find(iterator->first) == currentBaseline.end()) {
                iterator = impl_->everSeenFlows.erase(iterator);
            } else {
                ++iterator;
            }
        }
        impl_->previousFlows = std::move(currentBaseline);

        std::sort(next->flows.begin(), next->flows.end(), [](const FlowRate& left, const FlowRate& right) {
            return left.bps > right.bps;
        });

        std::unordered_map<std::string, flow_iface_counters> currentInterfaces;
        for (const auto& [key, counters] : interfaceTotals.entries) {
            if (next->boundIfindex != 0 && key.ifindex != next->boundIfindex) continue;
            const std::string id = ifaceBinaryKey(key);
            currentInterfaces[id] = counters;
            if (elapsedNs == 0) continue;
            CounterSample current{counters.bytes, counters.packets, 0, 0};
            CounterSample previous{};
            const CounterSample* previousPointer = nullptr;
            if (auto found = impl_->previousInterfaces.find(id); found != impl_->previousInterfaces.end()) {
                previous = {found->second.bytes, found->second.packets, 0, 0};
                previousPointer = &previous;
            }
            const auto delta = calculateCounterDelta(current, previousPointer,
                impl_->previousInterfaces.find(id) != impl_->previousInterfaces.end());
            InterfaceTrafficStats stats;
            stats.ifindex = key.ifindex;
            stats.family = key.family;
            stats.protocol = key.protocol;
            stats.direction = key.direction;
            stats.bps = perSecond(delta.bytes, elapsedNs);
            stats.pps = perSecond(delta.packets, elapsedNs);
            stats.continuityLost = delta.continuity_lost;
            stats.counterReset = delta.counter_reset;
            next->interfaces.push_back(stats);
        }
        impl_->previousInterfaces = std::move(currentInterfaces);
        }
    }
#endif

    next->baselineOnly = impl_->previousSampleSteady.time_since_epoch().count() == 0;
    next->windowStart = impl_->previousSampleWall.time_since_epoch().count() == 0
        ? sampleWall : impl_->previousSampleWall;
    next->windowEnd = sampleWall;
    if (advanceSampleBaseline) {
        impl_->previousSampleSteady = sampleSteady;
        impl_->previousSampleWall = sampleWall;
    }
    if (next->mapReadComplete && !next->baselineOnly) {
        std::lock_guard<std::mutex> historyLock(impl_->historyMutex);
        for (const auto& flow : next->flows) {
            // continuity_lost 是可信度事件，不可进入统计基线，否则下一轮均值会被保守重建值污染。
            if (flow.continuityLost) continue;
            const std::string key = flowHistoryKey(flow);
            auto& history = impl_->trafficHistory[key];
            history.bpsHistory.push_back(flow.bps);
            history.ppsHistory.push_back(flow.pps);
            history.totalBytes += flow.bps;
            history.totalPackets += flow.pps;
            history.lastUpdate = sampleWall;
            while (history.bpsHistory.size() > Impl::kMaxHistorySize) history.bpsHistory.pop_front();
            while (history.ppsHistory.size() > Impl::kMaxHistorySize) history.ppsHistory.pop_front();
        }
        // 在 N 代的 history 临界区内一次固化异常；后续 N+1 或 clearHistory
        // 都不能改变旧 snapshot 的诊断结果。
        next->anomalies = deriveTrafficAnomalies(next, impl_->trafficHistory,
                                                 impl_->burstThresholdBps,
                                                 impl_->suspiciousThresholdBps,
                                                 impl_->burstMultiplier);
    }
    for (const auto& anomaly : next->anomalies) {
        TrafficObservationEvent event;
        event.type = FLOW_EVENT_TRAFFIC_ANOMALY;
        event.flowKey = anomaly.flowKey;
        event.anomalyType = anomaly.anomalyType;
        event.severity = anomaly.severity;
        event.description = anomaly.description;
        event.timestamp = anomaly.timestamp;
        next->events.push_back(std::move(event));
    }
    // 事件是低频状态通道，不得因高 churn 在一代中无界增长。
    // 被截断数量单独暴露，调用方可知道 recent_events 不是全量。
    constexpr size_t kMaxObservationEventsPerSnapshot = 64;
    if (next->events.size() > kMaxObservationEventsPerSnapshot) {
        next->mapObservability.userEventsTruncated =
            next->events.size() - kMaxObservationEventsPerSnapshot;
        next->events.resize(kMaxObservationEventsPerSnapshot);
    }
    for (auto& event : next->events) {
        event.generation = next->generation;
        if (event.timestamp.time_since_epoch().count() == 0) event.timestamp = sampleWall;
    }
    {
        std::lock_guard<std::mutex> snapshotLock(impl_->snapshotMutex);
        impl_->latestSnapshot = next;
    }
    return next;
}

TrafficSnapshotPtr NetTrafficAnalyzer::getLatestSnapshot() const {
    std::lock_guard<std::mutex> lock(impl_->snapshotMutex);
    return impl_->latestSnapshot;
}

std::vector<FlowRate> NetTrafficAnalyzer::sampleTopFlows(int intervalSec, int topN) {
    (void)intervalSec;
    return sampleTopFlows(getLatestSnapshot(), topN);
}

std::vector<FlowRate> NetTrafficAnalyzer::sampleTopFlows(
    const TrafficSnapshotPtr& snapshot, int topN) const {
    if (!snapshot || topN <= 0) return {};
    const size_t count = std::min(snapshot->flows.size(), static_cast<size_t>(topN));
    return std::vector<FlowRate>(snapshot->flows.begin(), snapshot->flows.begin() + count);
}

std::vector<TrafficAnomaly> NetTrafficAnalyzer::detectAnomalies(int intervalSec,
                                                               uint64_t burstThresholdBps,
                                                               uint64_t suspiciousThresholdBps,
                                                               double burstMultiplier) {
    (void)intervalSec;
    const auto snapshot = getLatestSnapshot();
    std::lock_guard<std::mutex> lock(impl_->historyMutex);
    return deriveTrafficAnomalies(snapshot, impl_->trafficHistory,
                                  burstThresholdBps, suspiciousThresholdBps, burstMultiplier);
}

std::vector<TrafficAnomaly> NetTrafficAnalyzer::detectAnomalies(
    const TrafficSnapshotPtr& snapshot) const {
    return snapshot ? snapshot->anomalies : std::vector<TrafficAnomaly>{};
}

std::map<std::string, TrafficHistory> NetTrafficAnalyzer::getTrafficHistory() {
    std::lock_guard<std::mutex> lock(impl_->historyMutex);
    return impl_->trafficHistory;
}

void NetTrafficAnalyzer::setAnomalyDetectionParams(uint64_t burstThreshold,
                                                   uint64_t suspiciousThreshold,
                                                   double burstMultiplier) {
    std::lock_guard<std::mutex> lock(impl_->historyMutex);
    impl_->burstThresholdBps = burstThreshold;
    impl_->suspiciousThresholdBps = suspiciousThreshold;
    impl_->burstMultiplier = burstMultiplier;
}

void NetTrafficAnalyzer::setLongFlowPolicy(
    const weaknet_grpc::traffic_core::LongFlowPolicy& policy) {
    std::lock_guard<std::mutex> lock(impl_->samplerMutex);
    impl_->longFlowPolicy = policy;
}

NetTrafficAnalyzer::RealTimeStats NetTrafficAnalyzer::getRealTimeStats() const {
    return getRealTimeStats(getLatestSnapshot());
}

NetTrafficAnalyzer::RealTimeStats NetTrafficAnalyzer::getRealTimeStats(
    const TrafficSnapshotPtr& snapshot) const {
    RealTimeStats stats;
    if (!snapshot) return stats;
    stats.generation = snapshot->generation;
    stats.boundIfindex = snapshot->boundIfindex;
    stats.activeFlows = snapshot->flows.size();
    stats.timestamp = snapshot->windowEnd;
    stats.support = snapshot->support;
    stats.valid = snapshot->generation > 1 && weaknet_grpc::traffic_core::snapshotUsable(
        snapshot->baselineOnly, snapshot->support.bpfLoaded,
        snapshot->support.captureComplete, snapshot->mapReadComplete);

    bool usedInterfaceTotals = false;
    for (const auto& interface : snapshot->interfaces) {
        if (snapshot->boundIfindex != 0 && interface.ifindex != snapshot->boundIfindex) continue;
        stats.totalBps += interface.bps;
        stats.totalPps += interface.pps;
        usedInterfaceTotals = true;
    }
    if (!usedInterfaceTotals) {
        for (const auto& flow : snapshot->flows) {
            stats.totalBps += flow.bps;
            stats.totalPps += flow.pps;
        }
    }
    for (const auto& flow : snapshot->flows) {
        if (flow.continuityLost) ++stats.continuityLostFlows;
        if (flow.counterReset) ++stats.counterResetFlows;
    }
    return stats;
}

void NetTrafficAnalyzer::clearHistory() {
    // 全局锁序统一为 sampler -> history，与 refreshSnapshot/updateInterface 保持一致。
    std::lock_guard<std::mutex> samplerLock(impl_->samplerMutex);
    std::lock_guard<std::mutex> historyLock(impl_->historyMutex);
    impl_->trafficHistory.clear();
    impl_->previousFlows.clear();
    impl_->everSeenFlows.clear();
    impl_->previousInterfaces.clear();
    impl_->previousSampleSteady = {};
    impl_->previousSampleWall = {};
}
