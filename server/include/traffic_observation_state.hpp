// 流量观测发布槽：在同一临界区发布/读取 stats 与不可变 snapshot，禁止 RPC 拼接 N/N+1 代。

#pragma once

#include <mutex>

#include "net_traffic.h"

namespace weaknet_grpc {

// 线程安全的单槽发布器：stats 与 immutable snapshot 必须作为同代整体写入和读取。
class TrafficObservationStateStore {
public:
    // 一次对外可见状态；两部分必须具有相同 generation 和 boundIfindex。
    struct State {
        NetTrafficAnalyzer::RealTimeStats stats;
        TrafficSnapshotPtr snapshot;
    };

    // 只接受同 generation 的统计与快照；拒绝错代发布比对外暴露混合状态更安全。
    bool publish(const NetTrafficAnalyzer::RealTimeStats& stats, TrafficSnapshotPtr snapshot) {
        if (!snapshot || stats.generation != snapshot->generation ||
            stats.boundIfindex != snapshot->boundIfindex) return false;
        std::lock_guard<std::mutex> lock(mutex_);
        state_.stats = stats;
        state_.snapshot = std::move(snapshot);
        return true;
    }

    // 一次加锁复制整对状态，是 gRPC 等外部消费者的唯一一致读取入口。
    State load() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return state_;
    }

    // 接口重绑期立即使旧统计失效，且移除旧 snapshot，防止它被上层继续归属给新出口。
    void invalidateForRebind(uint32_t newIfindex) {
        std::lock_guard<std::mutex> lock(mutex_);
        state_.stats.valid = false;
        state_.stats.boundIfindex = newIfindex;
        state_.snapshot.reset();
    }

    // 清空整个发布槽，供服务停止或测试复位；调用后 load 返回默认无效状态。
    void reset() {
        std::lock_guard<std::mutex> lock(mutex_);
        state_ = State{};
    }

private:
    mutable std::mutex mutex_;
    State state_;
};

}  // namespace weaknet_grpc
