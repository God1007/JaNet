// Linux netlink dump 完整性门禁：只有匹配 seq/port 且未截断、未中断的 NLMSG_DONE 才算成功。
// 路由初始快照与 sock_diag 共用此逻辑，避免把 EAGAIN/部分 dump 当成真实空集合。

#pragma once

#if defined(__linux__)

#include <algorithm>
#include <array>
#include <chrono>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <linux/netlink.h>
#include <poll.h>
#include <string>
#include <sys/socket.h>

namespace weaknet_grpc::netlink_dump {

// 读取已绑定 netlink socket 的本地 port id，用于拒绝不属于本次请求的应答帧。
inline uint32_t localPortId(int fd) {
    sockaddr_nl local{};
    socklen_t length = sizeof(local);
    if (getsockname(fd, reinterpret_cast<sockaddr*>(&local), &length) != 0) return 0;
    return local.nl_pid;
}

// 在统一 deadline 内接收一次 multipart dump；只有匹配 seq/port 的 NLMSG_DONE 才返回成功。
// dispatch 会收到本次 dump 的数据帧，也会收到并发到达的 seq=0 多播通知。
template <typename Dispatch>
bool receiveCompleteDump(int fd,
                         uint32_t expectedSequence,
                         Dispatch&& dispatch,
                         std::string& error,
                         std::chrono::milliseconds timeout = std::chrono::milliseconds(3000)) {
    // sequence 标识请求，port 标识本地 socket；二者共同隔离复用 socket 上的其他流量。
    const uint32_t expectedPort = localPortId(fd);
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    std::array<char, 64 * 1024> buffer{};

    while (true) {
        const auto now = std::chrono::steady_clock::now();
        if (now >= deadline) {
            error = "netlink dump timed out before matching NLMSG_DONE";
            return false;
        }
        const auto remainingMs = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now);
        pollfd descriptor{fd, POLLIN, 0};
        const int pollResult = poll(&descriptor, 1,
            std::max(1, static_cast<int>(remainingMs.count())));
        if (pollResult < 0) {
            if (errno == EINTR) continue;
            error = std::string("netlink dump poll failed: ") + std::strerror(errno);
            return false;
        }
        if (pollResult == 0) continue;
        if ((descriptor.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
            error = "netlink dump socket reported an error";
            return false;
        }
        if ((descriptor.revents & POLLIN) == 0) continue;

        // recvmsg 同时取得发送者和 MSG_TRUNC；普通 recv 无法可靠完成这两项完整性校验。
        sockaddr_nl sender{};
        iovec iov{buffer.data(), buffer.size()};
        msghdr message{};
        message.msg_name = &sender;
        message.msg_namelen = sizeof(sender);
        message.msg_iov = &iov;
        message.msg_iovlen = 1;
        const ssize_t received = recvmsg(fd, &message, 0);
        if (received < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) continue;
            error = std::string("netlink dump recvmsg failed: ") + std::strerror(errno);
            return false;
        }
        if (received == 0) {
            error = "netlink dump returned EOF before NLMSG_DONE";
            return false;
        }
        if ((message.msg_flags & MSG_TRUNC) != 0) {
            error = "netlink dump datagram was truncated";
            return false;
        }
        if (sender.nl_pid != 0) {
            // Dump 应答只信任内核 port 0，用户态注入的数据不能影响路由/连接判定。
            continue;
        }

        int bytesRemaining = static_cast<int>(received);
        for (nlmsghdr* header = reinterpret_cast<nlmsghdr*>(buffer.data());
             NLMSG_OK(header, bytesRemaining);
             header = NLMSG_NEXT(header, bytesRemaining)) {
            const bool sequenceMatches = header->nlmsg_seq == expectedSequence;
            const bool portMatches = header->nlmsg_pid == 0 || header->nlmsg_pid == expectedPort;
            if (!sequenceMatches || !portMatches) {
                // 监听 socket 在 dump 期可能同时收到 seq=0 的多播变化，先分发以免丢事件。
                if (header->nlmsg_seq == 0) dispatch(header);
                continue;
            }
            // 被中断、overrun、内核错误、畸形尾部都代表 partial dump，绝不能当作真实空集合。
            if ((header->nlmsg_flags & NLM_F_DUMP_INTR) != 0) {
                error = "netlink dump was interrupted (NLM_F_DUMP_INTR)";
                return false;
            }
            // 只有属于本请求且未标记 DUMP_INTR 的 DONE，才提交调用方构建的候选快照。
            if (header->nlmsg_type == NLMSG_DONE) return true;
            if (header->nlmsg_type == NLMSG_OVERRUN) {
                error = "netlink dump overrun";
                return false;
            }
            if (header->nlmsg_type == NLMSG_ERROR) {
                if (header->nlmsg_len < NLMSG_LENGTH(sizeof(nlmsgerr))) {
                    error = "netlink dump returned malformed NLMSG_ERROR";
                    return false;
                }
                const auto* netlinkError = reinterpret_cast<const nlmsgerr*>(NLMSG_DATA(header));
                if (netlinkError->error == 0) continue;
                const int code = netlinkError->error < 0 ? -netlinkError->error : netlinkError->error;
                error = std::string("netlink dump kernel error: ") + std::strerror(code);
                return false;
            }
            dispatch(header);
        }
        if (bytesRemaining != 0) {
            error = "netlink dump contained a malformed message tail";
            return false;
        }
    }
}

}  // namespace weaknet_grpc::netlink_dump

#endif  // defined(__linux__)
