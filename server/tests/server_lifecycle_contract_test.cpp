// 无需启动 gRPC 的生命周期契约测试：锁定 signal waiter、可 join 线程与幂等路由监听器回收路径。

#include <cstdlib>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

namespace {

// 一次性读取待审计源码；测试随后只在对应函数/文件范围内检查生命周期 token。
std::string readFile(const std::string& path) {
    std::ifstream input(path);
    std::ostringstream output;
    output << input.rdbuf();
    return output.str();
}

// 要求一组并发清理标记全部存在，缺一项就输出可定位的契约名称。
bool requireTokens(const std::string& text,
                   const std::vector<std::string>& tokens,
                   const char* label) {
    for (const auto& token : tokens) {
        if (text.find(token) == std::string::npos) {
            std::cerr << label << " missing token: " << token << '\n';
            return false;
        }
    }
    return true;
}

// 拒绝已经证明会造成 detached thread 或不可回收监听器的旧实现写法。
bool rejectToken(const std::string& text, const std::string& token, const char* label) {
    if (text.find(token) == std::string::npos) return true;
    std::cerr << label << " contains forbidden token: " << token << '\n';
    return false;
}

}  // namespace

// 审计 ServerContext、server 编排与各监控线程，锁定可中断、可 join、幂等关闭协议。
int main() {
    const auto context = readFile("include/server.hpp");
    const auto server = readFile("src/server.cpp");
    const auto rtt = readFile("src/rtt_monitor.cpp");
    const auto rssi = readFile("src/rssi_monitor.cpp");
    const auto tcp = readFile("src/tcp_loss_monitor.cpp");
    const auto usingIface = readFile("src/using_iface.cpp");

    if (!requireTokens(context,
            {"std::thread rtt_thread", "std::thread rssi_thread", "requestStop()", "waitForStop"},
            "ServerContext")) return EXIT_FAILURE;
    if (!requireTokens(server,
            {"pthread_sigmask", "sigwait", "signalWaiter", "ctx.requestStop()",
             "joinIfNeeded(ctx.rtt_thread)", "joinIfNeeded(ctx.rssi_thread)",
             "UsingInterfaceManager::getInstance()->stop()", "std::make_unique<WeakNetMgr>"},
            "server lifecycle")) return EXIT_FAILURE;
    if (!requireTokens(rtt, {"ctx->rtt_thread = std::thread", "ctx->waitForStop"}, "RTT")) {
        return EXIT_FAILURE;
    }
    if (!requireTokens(rssi, {"ctx->rssi_thread = std::thread", "ctx->waitForStop"}, "RSSI")) {
        return EXIT_FAILURE;
    }
    if (!requireTokens(tcp, {"ctx->tcp_loss_thread = std::thread", "ctx->waitForStop"}, "TCP")) {
        return EXIT_FAILURE;
    }
    if (!requireTokens(usingIface,
            {"compare_exchange_strong", "void UsingInterfaceManager::stop()", "worker.join()",
             "shutdown(fd, SHUT_RDWR)"}, "using-interface lifecycle")) return EXIT_FAILURE;

    for (const auto* source : {&server, &rtt, &rssi, &tcp, &usingIface}) {
        if (!rejectToken(*source, ".detach()", "lifecycle source")) return EXIT_FAILURE;
        if (!rejectToken(*source, "new WeakNetMgr", "WeakNetMgr ownership")) return EXIT_FAILURE;
    }

    const auto runningPosition = usingIface.find("compare_exchange_strong");
    const auto workerPosition = usingIface.find("impl_->worker = std::thread", runningPosition);
    if (runningPosition == std::string::npos || workerPosition == std::string::npos ||
        runningPosition >= workerPosition) {
        std::cerr << "UsingInterfaceManager must claim running before creating its worker\n";
        return EXIT_FAILURE;
    }

    std::cout << "server_lifecycle_contract_test: all checks passed\n";
    return EXIT_SUCCESS;
}
