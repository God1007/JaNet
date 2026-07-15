// test_client.cpp
// WeakNet 客户端 API 验证工具：覆盖查询、Ping、事件、异常处理和性能命令。

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <thread>
#include <unistd.h>
#include <vector>

#include "weaknet_client.h"

namespace {

// 汇总测试执行数量和通过率，供全量验证结束时统一输出。
struct TestStats {
    int total = 0;
    int passed = 0;
    int failed = 0;

    // 记录单个测试组的最终结果。
    void add(bool ok) {
        ++total;
        if (ok) {
            ++passed;
        } else {
            ++failed;
        }
    }

    // 输出累计通过率摘要。
    void print() const {
        const double rate = total > 0 ? (passed * 100.0 / total) : 0.0;
        std::printf("\nSummary: total=%d passed=%d failed=%d success=%.1f%%\n", total, passed, failed, rate);
    }
};

TestStats g_stats;

// 打印命令行能力和测试模式，避免各分支重复维护用法文本。
void printUsage(const char* program) {
    std::printf("WeakNet client API validation tool\n");
    std::printf("Usage:\n");
    std::printf("  %s all                    - run all validation tests\n", program);
    std::printf("  %s get                    - get current network interfaces\n", program);
    std::printf("  %s health                 - run network health check\n", program);
    std::printf("  %s file                   - read latest serialized state\n", program);
    std::printf("  %s ping HOSTNAME          - ping a host through the active interface\n", program);
    std::printf("  %s check                  - check state changes once\n", program);
    std::printf("  %s subscribe              - monitor state changes for up to 5 minutes\n", program);
    std::printf("  %s events                 - check one queued event\n", program);
    std::printf("  %s quality                - check one network quality event\n", program);
    std::printf("  %s quality-sub            - monitor quality events for up to 1 minute\n", program);
    std::printf("  %s event-types            - list supported event types\n", program);
    std::printf("  %s event-sub EVENT_TYPE   - subscribe to one event type\n", program);
    std::printf("\nTest modes:\n");
    std::printf("  %s test-basic             - basic library test\n", program);
    std::printf("  %s test-network           - network info test\n", program);
    std::printf("  %s test-ping              - ping test\n", program);
    std::printf("  %s test-events            - event system test\n", program);
    std::printf("  %s test-quality           - quality event test\n", program);
    std::printf("  %s test-quality-callback  - quality callback subscription test\n", program);
    std::printf("  %s test-errors            - error handling test\n", program);
    std::printf("  %s test-performance       - get_interfaces performance test\n", program);
}

// 输出统一断言结果，并将布尔值原样返回供测试组合。
bool assertOk(bool condition, const char* label) {
    if (condition) {
        std::printf("  OK   %s\n", label);
        return true;
    }
    std::printf("  FAIL %s\n", label);
    return false;
}

// 通用事件回调：打印 streaming 线程传入的事件上下文。
void genericEventCallback(const char* event_type, const char* message, int32_t counter, const char* source) {
    std::printf("  callback event type=%s counter=%d source=%s message=%s\n",
                event_type ? event_type : "", counter, source ? source : "", message ? message : "");
}

// 网络质量回调：累计三次后返回 false，用于验证客户端自动取消回调。
bool qualityCallback(const char* quality, const char* details, int32_t counter) {
    static int callbackCount = 0;
    ++callbackCount;
    std::printf("  quality callback #%d quality=%s counter=%d details=%s\n",
                callbackCount, quality ? quality : "", counter, details ? details : "");
    return callbackCount < 3;
}

// 验证初始化、连接状态、版本和构建信息等基础能力。
bool testBasicFunctions() {
    std::printf("\n[Test] basic functions\n");
    bool ok = true;
    char buffer[512]{};
    ok &= assertOk(weaknet_init(), "weaknet_init");
    ok &= assertOk(weaknet_is_connected(), "weaknet_is_connected");
    ok &= assertOk(weaknet_get_version(buffer, sizeof(buffer)), "weaknet_get_version");
    std::printf("  version: %s\n", buffer);
    ok &= assertOk(weaknet_get_build_info(buffer, sizeof(buffer)), "weaknet_get_build_info");
    std::printf("  build: %s\n", buffer);
    g_stats.add(ok);
    return ok;
}

// 验证接口查询、健康检查及兼容文件读取路径。
bool testNetworkInfo() {
    std::printf("\n[Test] network info\n");
    bool ok = true;
    char buffer[4096]{};
    char error[512]{};
    ok &= assertOk(weaknet_get_interfaces(buffer, sizeof(buffer), error, sizeof(error)), "weaknet_get_interfaces");
    std::printf("  interfaces: %s\n", ok ? buffer : error);
    ok &= assertOk(weaknet_health_check(buffer, sizeof(buffer), error, sizeof(error)), "weaknet_health_check");
    std::printf("  health: %s\n", ok ? buffer : error);
    if (weaknet_get_from_file(buffer, sizeof(buffer), error, sizeof(error))) {
        std::printf("  latest file state: %s\n", buffer);
    } else {
        std::printf("  latest file state unavailable: %s\n", error);
    }
    g_stats.add(ok);
    return ok;
}

// 对正常、回环和无效目标执行 Ping，覆盖成功与失败响应。
bool testPingFunction() {
    std::printf("\n[Test] ping\n");
    char result[1024]{};
    char error[512]{};
    const std::vector<std::string> targets = {"8.8.8.8", "baidu.com", "127.0.0.1", "invalidhost12345.com"};
    for (const auto& target : targets) {
        if (weaknet_ping_host(target.c_str(), result, sizeof(result), error, sizeof(error))) {
            std::printf("  ping %s -> %s\n", target.c_str(), result);
        } else {
            std::printf("  ping %s failed: %s\n", target.c_str(), error);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
    }
    g_stats.add(true);
    return true;
}

// 验证事件类型、订阅、非阻塞轮询和取消订阅的完整流程。
bool testEventSystem() {
    std::printf("\n[Test] events\n");
    bool ok = true;
    char buffer[1024]{};
    char error[512]{};
    ok &= assertOk(weaknet_get_event_types(buffer, sizeof(buffer), error, sizeof(error)), "weaknet_get_event_types");
    std::printf("  event types: %s\n", ok ? buffer : error);
    ok &= assertOk(weaknet_subscribe_event("InterfaceChanged", nullptr), "subscribe InterfaceChanged");
    ok &= assertOk(weaknet_subscribe_event("ConnectionModeChanged", nullptr), "subscribe ConnectionModeChanged");

    char eventType[128]{};
    char message[1024]{};
    char source[256]{};
    int32_t counter = 0;
    for (int i = 0; i < 5; ++i) {
        if (weaknet_check_events(eventType, sizeof(eventType), message, sizeof(message), &counter, source, sizeof(source), error, sizeof(error))) {
            std::printf("  event type=%s counter=%d source=%s message=%s\n", eventType, counter, source, message);
        } else {
            std::printf("  no event at second %d: %s\n", i + 1, error);
        }
        sleep(1);
    }

    ok &= assertOk(weaknet_unsubscribe_event("InterfaceChanged"), "unsubscribe InterfaceChanged");
    ok &= assertOk(weaknet_unsubscribe_event("ConnectionModeChanged"), "unsubscribe ConnectionModeChanged");
    g_stats.add(ok);
    return ok;
}

// 在限定窗口内轮询网络质量事件，检查无事件时的非阻塞行为。
bool testNetworkQualityEvents() {
    std::printf("\n[Test] quality events\n");
    char quality[256]{};
    char details[2048]{};
    char error[512]{};
    int32_t counter = 0;
    for (int i = 0; i < 10; ++i) {
        if (weaknet_check_network_quality(quality, sizeof(quality), details, sizeof(details), &counter, error, sizeof(error))) {
            std::printf("  quality=%s counter=%d details=%s\n", quality, counter, details);
        } else {
            std::printf("  no quality event at second %d: %s\n", i + 1, error);
        }
        sleep(1);
    }
    g_stats.add(true);
    return true;
}

// 注册网络质量回调，验证 callback 模式能与轮询模式共用事件流。
bool testNetworkQualityCallback() {
    std::printf("\n[Test] quality callback\n");
    const bool ok = weaknet_subscribe_network_quality(qualityCallback);
    assertOk(ok, "weaknet_subscribe_network_quality");
    g_stats.add(ok);
    return ok;
}

// 轮询 Changed 队列，验证状态变化兼容接口。
bool testChangeMonitoring() {
    std::printf("\n[Test] state changes\n");
    char message[1024]{};
    char error[512]{};
    int32_t counter = 0;
    for (int i = 0; i < 3; ++i) {
        if (weaknet_check_changes(message, sizeof(message), &counter, error, sizeof(error))) {
            std::printf("  change counter=%d message=%s\n", counter, message);
        } else {
            std::printf("  no state change at second %d: %s\n", i + 1, error);
        }
        sleep(1);
    }
    g_stats.add(true);
    return true;
}

// 验证空字符串和空指针主机名会在客户端侧被拒绝。
bool testErrorHandling() {
    std::printf("\n[Test] error handling\n");
    bool ok = true;
    char buffer[512]{};
    char error[512]{};
    ok &= assertOk(!weaknet_ping_host("", buffer, sizeof(buffer), error, sizeof(error)), "reject empty hostname");
    std::printf("  empty hostname error: %s\n", error);
    ok &= assertOk(!weaknet_ping_host(nullptr, buffer, sizeof(buffer), error, sizeof(error)), "reject null hostname");
    std::printf("  null hostname error: %s\n", error);
    g_stats.add(ok);
    return ok;
}

// 连续调用接口查询，粗略评估 unary RPC 的端到端耗时。
bool testPerformance() {
    std::printf("\n[Test] performance\n");
    char buffer[4096]{};
    char error[512]{};
    constexpr int testCount = 10;
    const auto start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < testCount; ++i) {
        if (!weaknet_get_interfaces(buffer, sizeof(buffer), error, sizeof(error))) {
            std::printf("  call %d failed: %s\n", i + 1, error);
            g_stats.add(false);
            return false;
        }
    }
    const auto end = std::chrono::high_resolution_clock::now();
    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    std::printf("  completed %d get_interfaces calls in %ldms, avg %.2fms/call\n", testCount, ms, ms / static_cast<double>(testCount));
    g_stats.add(true);
    return true;
}

// 初始化一次客户端并按固定顺序运行全部测试组。
bool runAllTests() {
    std::printf("Running full WeakNet client API validation\n");
    if (!weaknet_init()) {
        std::printf("FAIL weaknet_init\n");
        return false;
    }
    bool ok = true;
    ok &= testBasicFunctions();
    ok &= testNetworkInfo();
    ok &= testPingFunction();
    ok &= testEventSystem();
    ok &= testNetworkQualityEvents();
    ok &= testNetworkQualityCallback();
    ok &= testChangeMonitoring();
    ok &= testErrorHandling();
    ok &= testPerformance();
    weaknet_cleanup();
    g_stats.print();
    return ok;
}

// 为单命令模式建立客户端，统一处理初始化失败。
bool ensureClient() {
    if (weaknet_init()) {
        return true;
    }
    std::printf("FAIL weaknet_init\n");
    return false;
}

// 将命令行子命令分派到对应 C API 或测试组，并在结束时统一清理。
bool runSingleTest(const std::string& command, int argc, char* argv[]) {
    if (!ensureClient()) {
        return false;
    }

    bool ok = true;
    char buffer[4096]{};
    char error[512]{};
    int32_t counter = 0;

    if (command == "get") {
        ok = weaknet_get_interfaces(buffer, sizeof(buffer), error, sizeof(error));
        std::printf("%s interfaces: %s\n", ok ? "OK" : "FAIL", ok ? buffer : error);
    } else if (command == "health") {
        ok = weaknet_health_check(buffer, sizeof(buffer), error, sizeof(error));
        std::printf("%s health: %s\n", ok ? "OK" : "FAIL", ok ? buffer : error);
    } else if (command == "file") {
        ok = weaknet_get_from_file(buffer, sizeof(buffer), error, sizeof(error));
        std::printf("%s latest file state: %s\n", ok ? "OK" : "FAIL", ok ? buffer : error);
    } else if (command == "ping") {
        if (argc < 3) {
            std::printf("FAIL usage: %s ping HOSTNAME\n", argv[0]);
            ok = false;
        } else {
            ok = weaknet_ping_host(argv[2], buffer, sizeof(buffer), error, sizeof(error));
            std::printf("%s ping: %s\n", ok ? "OK" : "FAIL", ok ? buffer : error);
        }
    } else if (command == "check") {
        ok = weaknet_check_changes(buffer, sizeof(buffer), &counter, error, sizeof(error));
        if (ok) {
            std::printf("OK change counter=%d message=%s\n", counter, buffer);
        } else {
            std::printf("INFO no state change: %s\n", error);
            ok = true;
        }
    } else if (command == "events") {
        char eventType[128]{};
        char message[1024]{};
        char source[256]{};
        ok = weaknet_check_events(eventType, sizeof(eventType), message, sizeof(message), &counter, source, sizeof(source), error, sizeof(error));
        if (ok) {
            std::printf("OK event type=%s counter=%d source=%s message=%s\n", eventType, counter, source, message);
        } else {
            std::printf("INFO no event: %s\n", error);
            ok = true;
        }
    } else if (command == "quality") {
        char quality[256]{};
        char details[2048]{};
        ok = weaknet_check_network_quality(quality, sizeof(quality), details, sizeof(details), &counter, error, sizeof(error));
        if (ok) {
            std::printf("OK quality=%s counter=%d details=%s\n", quality, counter, details);
        } else {
            std::printf("INFO no quality event: %s\n", error);
            ok = true;
        }
    } else if (command == "quality-sub") {
        std::printf("Monitoring quality events for up to 60 seconds...\n");
        for (int i = 0; i < 60; ++i) {
            char quality[256]{};
            char details[2048]{};
            if (weaknet_check_network_quality(quality, sizeof(quality), details, sizeof(details), &counter, error, sizeof(error))) {
                std::printf("quality=%s counter=%d details=%s\n", quality, counter, details);
            }
            sleep(1);
        }
    } else if (command == "event-types") {
        ok = weaknet_get_event_types(buffer, sizeof(buffer), error, sizeof(error));
        std::printf("%s event types: %s\n", ok ? "OK" : "FAIL", ok ? buffer : error);
    } else if (command == "event-sub") {
        if (argc < 3) {
            std::printf("FAIL usage: %s event-sub EVENT_TYPE\n", argv[0]);
            ok = false;
        } else {
            ok = weaknet_subscribe_event(argv[2], genericEventCallback);
            std::printf("%s subscribed event type: %s\n", ok ? "OK" : "FAIL", argv[2]);
        }
    } else if (command == "subscribe") {
        std::printf("Monitoring state changes for up to 5 minutes...\n");
        for (int i = 0; i < 300; ++i) {
            if (weaknet_check_changes(buffer, sizeof(buffer), &counter, error, sizeof(error))) {
                std::printf("change counter=%d message=%s\n", counter, buffer);
            }
            sleep(1);
        }
    } else if (command == "test-basic") {
        ok = testBasicFunctions();
    } else if (command == "test-network") {
        ok = testNetworkInfo();
    } else if (command == "test-ping") {
        ok = testPingFunction();
    } else if (command == "test-events") {
        ok = testEventSystem();
    } else if (command == "test-errors") {
        ok = testErrorHandling();
    } else if (command == "test-performance") {
        ok = testPerformance();
    } else if (command == "test-quality") {
        ok = testNetworkQualityEvents();
    } else if (command == "test-quality-callback") {
        ok = testNetworkQualityCallback();
    } else if (command == "lib-test") {
        ok = testBasicFunctions();
    } else {
        std::printf("FAIL unknown command: %s\n", command.c_str());
        ok = false;
    }

    weaknet_cleanup();
    return ok;
}

}  // namespace

// 解析首个子命令，选择全量验证或单项执行路径。
int main(int argc, char* argv[]) {
    if (argc < 2) {
        printUsage(argv[0]);
        return 1;
    }

    const std::string command = argv[1];
    if (command == "all") {
        return runAllTests() ? 0 : 1;
    }
    return runSingleTest(command, argc, argv) ? 0 : 1;
}
