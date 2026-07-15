// ServerContext 可中断等待测试：requestStop 必须立即唤醒，而不是等完整监控周期。

#include "server.hpp"

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <iostream>
#include <thread>

// 启动真实等待线程，验证 requestStop 会在 500ms 门限内唤醒并翻转运行状态。
int main() {
    weaknet_grpc::ServerContext context;
    std::atomic<bool> observedStop{false};
    const auto begin = std::chrono::steady_clock::now();
    // 等待线程模拟 RTT/RSSI 等长周期 worker，返回值表示是否因 stop 被提前唤醒。
    std::thread waiter([&] {
        observedStop.store(context.waitForStop(std::chrono::seconds(5)));
    });
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    context.requestStop();
    waiter.join();
    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - begin);
    if (!observedStop.load() || context.running.load() || elapsed >= std::chrono::milliseconds(500)) {
        std::cerr << "ServerContext stop wakeup failed, elapsed_ms=" << elapsed.count() << '\n';
        return EXIT_FAILURE;
    }
    std::cout << "server_context_lifecycle_test: all checks passed (wake_ms="
              << elapsed.count() << ")\n";
    return EXIT_SUCCESS;
}
