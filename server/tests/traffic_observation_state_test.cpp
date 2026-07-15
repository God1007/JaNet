// 并发发布契约：读者只能观察到 stats/snapshot 同 generation，错代写入必须被拒绝。

#include "traffic_observation_state.hpp"

#include <atomic>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <thread>

using weaknet_grpc::TrafficObservationStateStore;

#define CHECK(condition) do { \
    if (!(condition)) { \
        std::cerr << "CHECK failed at " << __FILE__ << ':' << __LINE__ << ": " #condition "\n"; \
        return EXIT_FAILURE; \
    } \
} while (false)

// 并发运行发布者和读取者，证明外部永远看不到 generation/ifindex 错代组合。
int main() {
    TrafficObservationStateStore store;
    NetTrafficAnalyzer::RealTimeStats mismatchedStats;
    mismatchedStats.generation = 1;
    auto mismatchedSnapshot = std::make_shared<TrafficSnapshot>();
    mismatchedSnapshot->generation = 2;
    CHECK(!store.publish(mismatchedStats, mismatchedSnapshot));
    CHECK(!store.load().snapshot);
    mismatchedStats.generation = mismatchedSnapshot->generation;
    mismatchedStats.boundIfindex = 7;
    mismatchedSnapshot->boundIfindex = 8;
    CHECK(!store.publish(mismatchedStats, mismatchedSnapshot));
    CHECK(!store.load().snapshot);

    constexpr uint64_t kLastGeneration = 20000;
    std::atomic<bool> writerDone{false};
    std::atomic<bool> mismatchObserved{false};
    // 发布线程连续切换 generation/ifindex，放大两个字段分开更新时可能出现的竞态窗口。
    std::thread writer([&] {
        for (uint64_t generation = 1; generation <= kLastGeneration; ++generation) {
            auto snapshot = std::make_shared<TrafficSnapshot>();
            snapshot->generation = generation;
            snapshot->boundIfindex = static_cast<uint32_t>(generation % 31 + 1);
            NetTrafficAnalyzer::RealTimeStats stats;
            stats.generation = generation;
            stats.boundIfindex = snapshot->boundIfindex;
            stats.valid = true;
            if (!store.publish(stats, snapshot)) mismatchObserved.store(true);
        }
        writerDone.store(true, std::memory_order_release);
    });
    // 读取线程只通过 store.load() 取整对快照；任一错代组合都立即记录失败。
    std::thread reader([&] {
        while (!writerDone.load(std::memory_order_acquire)) {
            const auto state = store.load();
            if (state.snapshot &&
                (state.stats.generation != state.snapshot->generation ||
                 state.stats.boundIfindex != state.snapshot->boundIfindex)) {
                mismatchObserved.store(true);
                return;
            }
        }
    });
    writer.join();
    reader.join();
    CHECK(!mismatchObserved.load());
    const auto finalState = store.load();
    CHECK(finalState.snapshot);
    CHECK(finalState.stats.generation == kLastGeneration);
    CHECK(finalState.snapshot->generation == kLastGeneration);

    store.invalidateForRebind(99);
    const auto invalidated = store.load();
    CHECK(!invalidated.snapshot);
    CHECK(!invalidated.stats.valid);
    CHECK(invalidated.stats.boundIfindex == 99);

    std::cout << "traffic_observation_state_test: all checks passed\n";
    return EXIT_SUCCESS;
}
