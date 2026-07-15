// 指定网卡的 ICMP Echo 探测器：负责 IPv4 解析、报文构造、超时等待与 RTT 计算。
// Linux 使用原始套接字；其他平台保留明确失败的兼容桩实现。
#include "net_ping.h"

#if defined(__linux__)
#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <atomic>
#include <cstring>
#include <chrono>
#include <string>

namespace {
static constexpr int kPacketSize = 4096;
}

std::once_flag NetPing::s_onceFlag;
std::shared_ptr<NetPing> NetPing::s_instance;

// 通过 call_once 构造进程级实例，避免多个监控线程重复初始化探测器。
std::shared_ptr<NetPing> NetPing::getInstance() {
    std::call_once(s_onceFlag, [](){ s_instance = std::shared_ptr<NetPing>(new NetPing()); });
    return s_instance;
}

// 当前实现无需额外资源初始化，资源均按单次 ping 调用管理。
NetPing::NetPing() = default;
// 析构入口保留给未来的共享资源清理。
NetPing::~NetPing() = default;

// 兼容旧接口；当前探测器按调用即时初始化。
void NetPing::Init() {}
// 兼容旧接口；当前没有常驻资源需要关闭。
void NetPing::Shutdown() {}

// 计算 ICMP 报文的一补和校验值，并处理奇数字节尾部。
uint16_t NetPing::checksum(uint16_t* addr, int len) {
    int nleft = len;
    uint32_t sum = 0;
    uint16_t* w = addr;
    uint16_t answer = 0;

    while (nleft > 1) {
        sum += *w++;
        nleft -= 2;
    }
    if (nleft == 1) {
        uint16_t last = 0;
        *reinterpret_cast<uint8_t*>(&last) = *reinterpret_cast<uint8_t*>(w);
        sum += last;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = static_cast<uint16_t>(~sum);
    return answer;
}

// 优先解析点分十进制地址，域名则使用带 1 秒上限的异步 DNS 查询。
bool NetPing::resolveHostIPv4(const std::string& host, struct sockaddr_in& out) {
    if (inet_pton(AF_INET, host.c_str(), &out.sin_addr) == 1) {
        out.sin_family = AF_INET;
        return true;
    }

    struct addrinfo hints{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_RAW;
    hints.ai_flags = AI_ADDRCONFIG;

    struct gaicb request{};
    request.ar_name = host.c_str();
    request.ar_request = &hints;

    struct gaicb* requests[] = {&request};
    int ret = getaddrinfo_a(GAI_NOWAIT, requests, 1, nullptr);
    if (ret != 0) {
        return false;
    }

    const struct gaicb* waitList[] = {&request};
    struct timespec timeout{};
    timeout.tv_sec = 1;
    timeout.tv_nsec = 0;
    // DNS 必须受控超时，避免 RTT 监控被解析阶段无限阻塞。
    ret = gai_suspend(waitList, 1, &timeout);
    if (ret != 0) {
        gai_cancel(&request);
        return false;
    }

    ret = gai_error(&request);
    if (ret != 0 || !request.ar_result) {
        return false;
    }

    out = *reinterpret_cast<struct sockaddr_in*>(request.ar_result->ai_addr);
    freeaddrinfo(request.ar_result);
    return true;
}

// 构造 Echo Request，并把发送时刻写入数据区供回包计算 RTT。
int NetPing::packIcmp(struct icmp* icmp, uint16_t id, uint16_t seq) {
    std::memset(icmp, 0, sizeof(struct icmp));
    icmp->icmp_type = ICMP_ECHO;
    icmp->icmp_code = 0;
    icmp->icmp_id = id;
    icmp->icmp_seq = seq;
    struct timeval* tv = reinterpret_cast<struct timeval*>(icmp->icmp_data);
    gettimeofday(tv, nullptr);
    icmp->icmp_cksum = 0;
    icmp->icmp_cksum = checksum(reinterpret_cast<uint16_t*>(icmp), sizeof(struct icmp));
    return sizeof(struct icmp);
}

// 在指定接口上发送一次 ICMP Echo；成功返回带亚毫秒精度的 RTT，失败返回分阶段负错误码。
double NetPing::ping(const std::string& host, const std::string& ifaceName, int timeoutMs) {
    // RAW ICMP 需要相应系统权限，创建失败直接由错误码交给上层解释。
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockfd < 0) {
        return -1.0;
    }

    // 绑定设备确保探测走目标接口，而不是被默认路由改派到其他链路。
    struct ifreq ifr{};
    std::snprintf(ifr.ifr_name, IFNAMSIZ, "%s", ifaceName.c_str());
    if (setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(ifr)) < 0) {
        close(sockfd);
        return -2.0;
    }

    // 解析目标地址失败属于本地准备错误，此时无需进入发送和超时等待。
    struct sockaddr_in dest{};
    if (!resolveHostIPv4(host, dest)) {
        close(sockfd);
        return -3.0;
    }

    // 适当增大接收缓冲区，降低并发 ICMP 报文导致目标回包被丢弃的概率。
    int recvBuf = 64 * 1024;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &recvBuf, sizeof(recvBuf));

    // 构造包含进程标识、序列号和发送时间的 ICMP Echo Request。
    struct icmp icmpPacket{};
    const uint16_t id = static_cast<uint16_t>(getpid());
    // 后台监控与手动 Ping 会共享实例；原子序列号让并发请求拥有不同的回包匹配键。
    static std::atomic<uint32_t> nextSequence{0};
    const uint16_t requestSequence = static_cast<uint16_t>(
        nextSequence.fetch_add(1, std::memory_order_relaxed) + 1U);
    packIcmp(&icmpPacket, id, requestSequence);

    // 从发送前开始使用单调时钟计时，避免系统时间校准影响 RTT。
    const auto t0 = std::chrono::steady_clock::now();
    ssize_t sent = sendto(sockfd, &icmpPacket, sizeof(icmpPacket), 0,
                          reinterpret_cast<struct sockaddr*>(&dest), sizeof(dest));
    if (sent < 0) {
        close(sockfd);
        return -4.0;
    }

    // 多个 RAW ICMP socket 会看到彼此的回包，因此在同一总 deadline 内跳过不属于本请求的报文。
    const auto deadline = t0 + std::chrono::milliseconds(timeoutMs);
    char buf[kPacketSize];
    while (true) {
        const auto waitStartedAt = std::chrono::steady_clock::now();
        if (waitStartedAt >= deadline) {
            close(sockfd);
            return -5.0;
        }

        const auto remaining = std::chrono::duration_cast<std::chrono::microseconds>(
            deadline - waitStartedAt);
        struct timeval tv{};
        tv.tv_sec = static_cast<time_t>(remaining.count() / 1000000);
        tv.tv_usec = static_cast<suseconds_t>(remaining.count() % 1000000);

        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(sockfd, &rfds);
        const int rv = select(sockfd + 1, &rfds, nullptr, nullptr, &tv);
        if (rv == 0) {
            close(sockfd);
            return -5.0;
        }
        if (rv < 0) {
            if (errno == EINTR) continue;
            close(sockfd);
            return -6.0;
        }

        struct sockaddr_in src{};
        socklen_t slen = sizeof(src);
        const ssize_t n = recvfrom(
            sockfd, buf, sizeof(buf), 0, reinterpret_cast<struct sockaddr*>(&src), &slen);
        // 计时终点紧跟 recvfrom，避免把后续用户态解析或线程抢占时间算进网络 RTT。
        const auto receivedAt = std::chrono::steady_clock::now();
        if (n <= 0) {
            if (n < 0 && errno == EINTR) continue;
            close(sockfd);
            return -7.0;
        }

        // 先检查来源和最小 IPv4 头，再读取 IHL，避免无关/畸形 ICMP 报文越界访问。
        if (src.sin_addr.s_addr != dest.sin_addr.s_addr
            || n < static_cast<ssize_t>(sizeof(struct ip))) {
            continue;
        }
        const struct ip* iphdr = reinterpret_cast<const struct ip*>(buf);
        const int iphdrlen = iphdr->ip_hl * 4;
        if (iphdrlen < static_cast<int>(sizeof(struct ip))
            || n < iphdrlen + static_cast<ssize_t>(sizeof(struct icmp))) {
            continue;
        }

        const struct icmp* ricmp = reinterpret_cast<const struct icmp*>(buf + iphdrlen);
        if (ricmp->icmp_type != ICMP_ECHOREPLY
            || ricmp->icmp_id != id
            || ricmp->icmp_seq != requestSequence) {
            continue;
        }

        // double 毫秒保留微秒级换算结果，例如 134us 会返回 0.134ms 而不是整数 0。
        const double rttMs = std::chrono::duration<double, std::milli>(receivedAt - t0).count();
        close(sockfd);
        return rttMs;
    }
}

#else

// 非 Linux 平台没有 RAW ICMP 实现，以下桩函数保持 API 可链接并明确返回失败。
// 构造兼容桩对象。
NetPing::NetPing() {}
// 销毁兼容桩对象。
NetPing::~NetPing() {}
// 非 Linux 初始化为空操作。
void NetPing::Init() {}
// 非 Linux 关闭为空操作。
void NetPing::Shutdown() {}
// 非 Linux 不计算校验和。
uint16_t NetPing::checksum(uint16_t*, int) { return 0; }
// 非 Linux 不执行 IPv4 解析。
bool NetPing::resolveHostIPv4(const std::string&, struct sockaddr_in&) { return false; }
// 非 Linux 不构造 ICMP 报文。
int NetPing::packIcmp(struct icmp*, uint16_t, uint16_t) { return 0; }
// 非 Linux 明确返回探测不可用。
double NetPing::ping(const std::string&, const std::string&, int) { return -1.0; }

#endif
