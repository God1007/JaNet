// 服务端生命周期与监控编排：启动 gRPC、维护共享接口快照并管理各采集线程。
// 各监控器经 WeakNetMgr 汇总状态，再由事件管理器向订阅端广播变化。

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <csignal>
#include <cstring>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <memory>
#include <net/if.h>
#include <pthread.h>
#include <string>
#include <thread>
#include <vector>

#include "common.hpp"
#include "event_manager.hpp"
#include "grpc_service.hpp"
#include "logger.hpp"
#include "network_quality_assessor.hpp"
#include "net_iface.h"
#include "net_info.hpp"
#include "rssi_monitor.hpp"
#include "rtt_monitor.hpp"
#include "serializer.hpp"
#include "server.hpp"
#include "tcp_loss_monitor.hpp"
#include "using_iface.h"
#include "weak_netmgr.hpp"

using namespace std::chrono_literals;

namespace weaknet_grpc {
namespace {

// 优先选择 usingNow 默认出口；路由标记尚未就绪时回退第一个仍存在于内核的接口。
std::string selectTrafficInterface(const std::vector<NetInfo>& interfaces) {
    for (const auto& net : interfaces) {
        if (net.usingNow() && if_nametoindex(net.ifName().c_str()) != 0) return net.ifName();
    }
    for (const auto& net : interfaces) {
        if (!net.ifName().empty() && if_nametoindex(net.ifName().c_str()) != 0) return net.ifName();
    }
    return {};
}

// 以接口名为稳定键计算新增和移除项，避免把指标变化误判成拓扑变化。
bool diffInterfaces(const std::vector<std::string>& old_names,
                    const std::vector<std::string>& new_names,
                    std::vector<std::string>& added,
                    std::vector<std::string>& removed) {
    for (const auto& name : new_names) {
        if (std::find(old_names.begin(), old_names.end(), name) == old_names.end()) {
            added.push_back(name);
        }
    }
    for (const auto& name : old_names) {
        if (std::find(new_names.begin(), new_names.end(), name) == new_names.end()) {
            removed.push_back(name);
        }
    }
    return !added.empty() || !removed.empty();
}

// 将接口快照复制到兼容上下文，供仍依赖 ServerContext 的读取路径使用。
void syncContextInterfaces(ServerContext* ctx, const std::vector<NetInfo>& interfaces) {
    if (!ctx) {
        return;
    }
    // vector 整体替换必须持锁，避免 RPC 线程读到写入中间态。
    {
        std::lock_guard<std::mutex> lk(ctx->iface_mutex);
        ctx->iface_list = interfaces;
    }
}

// 同步核心管理器和上下文镜像，使两条读取路径看到同一批接口。
void syncManagerAndContext(ServerContext* ctx, const std::vector<NetInfo>& interfaces) {
    if (!ctx) {
        return;
    }
    if (ctx->weak_mgr) {
        ctx->weak_mgr->updateInterfaces(interfaces);
    }
    syncContextInterfaces(ctx, interfaces);
}

// 只等待已成功启动且仍可连接的线程，兼容部分监控器未启动的情况。
void joinIfNeeded(std::thread& worker) {
    if (worker.joinable()) {
        worker.join();
    }
}

// 优先采用环境变量监听地址，未配置时回退到本机默认端口。
std::string configuredGrpcAddress() {
    const char* configured = std::getenv("WEAKNET_GRPC_ADDRESS");
    if (configured && configured[0] != '\0') {
        return configured;
    }
    return kGrpcDefaultAddress;
}

}  // namespace

// 先持久化兼容载荷，再把同一变化交给实时事件总线。
void publishChangedEvent(ServerContext* ctx, const std::string& message, int32_t counter) {
    (void)ctx;
    ChangedPayload payload{message, counter};
    std::string err;
    if (!serializeChangedPayloadToFile(payload, kSignalSerializedFile, &err)) {
        LOG_WARNING(LogModule::SERVER, "failed to serialize latest Changed payload: " << err);
    }

    getEventManager().emitChanged(message, counter);
}

// 启动接口拓扑轮询线程，比较默认路由接口集合并生成增删事件。
void start_iface_monitor_thread(ServerContext* ctx) {
    ctx->iface_thread = std::thread([ctx]() {
        LOG_INFO(LogModule::INTERFACE, "monitor thread started");
        if (!ctx->weak_mgr) {
            LOG_ERROR(LogModule::INTERFACE, "interface monitor has no WeakNetMgr owner");
            return;
        }

        std::vector<NetInfo> current = ctx->weak_mgr->collectCurrentInterfaces();
        syncManagerAndContext(ctx, current);
        int32_t change_counter = 0;

        while (ctx->running.load()) {
            LOG_INFO(LogModule::INTERFACE, "tick: collecting interfaces...");
            // 每轮重新向内核取快照，避免长期缓存遗漏链路或路由变化。
            std::vector<NetInfo> observed = ctx->weak_mgr->collectCurrentInterfaces();
            // 在 WeakNetMgr 的接口锁内按 ifName 合并，保留 RTT/RSSI/TCP/traffic 等并发监控值。
            std::vector<NetInfo> latest = ctx->weak_mgr->mergeTopologySnapshot(observed);
            syncContextInterfaces(ctx, latest);
            LOG_INFO(LogModule::INTERFACE, "collected " << latest.size() << " interfaces");

            for (const auto& net : latest) {
                if (net.usingNow()) {
                    LOG_INFO(LogModule::INTERFACE, "ACTIVE: " << net.ifName()
                        << " | RTT: " << net.rttMs() << "ms"
                        << " | Quality: " << static_cast<int>(net.quality())
                        << " | RSSI: " << net.rssiDbm() << "dBm"
                        << " | TCP Loss: " << net.tcpLossRate() << "% (" << net.tcpLossLevel() << ")"
                        << " | Traffic: " << (net.trafficTotalBps() / (1024 * 1024)) << "MB/s, "
                        << net.trafficActiveFlows() << " flows, " << net.trafficTotalPps() << " pps");
                } else {
                    LOG_INFO(LogModule::INTERFACE, "INACTIVE: " << net.ifName()
                        << " | RTT: " << net.rttMs() << "ms"
                        << " | Quality: " << static_cast<int>(net.quality())
                        << " | RSSI: " << net.rssiDbm() << "dBm"
                        << " | TCP Loss: " << net.tcpLossRate() << "% (" << net.tcpLossLevel() << ")");
                }
            }

            auto old_names = WeakNetMgr::namesOf(current);
            auto new_names = WeakNetMgr::namesOf(latest);
            std::vector<std::string> added;
            std::vector<std::string> removed;
            if (diffInterfaces(old_names, new_names, added, removed)) {
                current = latest;

                std::string msg = "Interfaces changed (using flags in log): +";
                for (size_t i = 0; i < added.size(); ++i) {
                    msg += (i == 0 ? "" : ",");
                    msg += added[i];
                }
                msg += " -";
                for (size_t i = 0; i < removed.size(); ++i) {
                    msg += (i == 0 ? "" : ",");
                    msg += removed[i];
                }

                LOG_INFO(LogModule::INTERFACE, msg);
                for (const auto& x : current) {
                    if (x.usingNow()) {
                        LOG_INFO(LogModule::INTERFACE, "[using] " << x.ifName() << " is current uplink");
                    }
                }

                const int32_t counter = change_counter++;
                publishChangedEvent(ctx, msg, counter);
                getEventManager().emitInterfaceChanged(msg, "network_manager");
            } else {
                current = latest;
                LOG_INFO(LogModule::INTERFACE, "no changes detected");
            }

            ctx->waitForStop(10000ms);
        }
    });
}

// 启动流量汇总线程，把 eBPF 分析结果周期写回当前活动接口。
static void start_traffic_analysis_thread(ServerContext* ctx) {
    ctx->traffic_analysis_thread = std::thread([ctx]() {
        LOG_INFO(LogModule::WEAK_MGR, "traffic analysis thread started");
        if (!ctx->weak_mgr) {
            LOG_ERROR(LogModule::WEAK_MGR, "traffic monitor has no WeakNetMgr owner");
            return;
        }

        bool analyzerStarted = false;
        int loop_count = 0;
        while (ctx->running.load()) {
            loop_count++;
            LOG_INFO(LogModule::WEAK_MGR, "traffic analysis thread running, loop=" << loop_count);
            try {
                auto current_interfaces = ctx->weak_mgr->getCurrentInterfaces();
                const std::string selectedInterface = selectTrafficInterface(current_interfaces);
                if (!analyzerStarted && !selectedInterface.empty()) {
                    ctx->weak_mgr->startTrafficAnalysis(selectedInterface, 10);
                    analyzerStarted = true;
                }

                // 通过加锁入口更新共享 NetInfo，再复制一致快照到上下文。
                bool changed = analyzerStarted && ctx->weak_mgr->updateTrafficAnalysisSafe();
                current_interfaces = ctx->weak_mgr->getCurrentInterfaces();
                syncContextInterfaces(ctx, current_interfaces);

                if (changed) {
                    LOG_INFO(LogModule::WEAK_MGR, "Traffic analysis updated - emitting event");
                    publishChangedEvent(ctx, "Traffic analysis updated", 0);
                } else {
                    LOG_INFO(LogModule::WEAK_MGR, "TRAFFIC_ANALYSIS: "
                        << (analyzerStarted ? "no changes detected" : "waiting for a valid interface")
                        << " (interfaces: " << current_interfaces.size() << ")");
                }
            } catch (const std::exception& e) {
                LOG_ERROR(LogModule::WEAK_MGR, "Traffic analysis error: " << e.what());
            }

            ctx->waitForStop(10000ms);
        }

        ctx->weak_mgr->stopTrafficAnalysis();
        LOG_INFO(LogModule::WEAK_MGR, "traffic analysis thread stopped");
    });
}

// 启动默认出口轮询线程，把路由选择结果映射为 usingNow 标志。
static void start_using_iface_thread(ServerContext* ctx) {
    ctx->using_thread = std::thread([ctx]() {
        LOG_INFO(LogModule::WEAK_MGR, "using iface monitor thread started");
        if (!ctx->weak_mgr) {
            LOG_ERROR(LogModule::WEAK_MGR, "using-interface monitor has no WeakNetMgr owner");
            return;
        }

        int loop_count = 0;
        while (ctx->running.load()) {
            loop_count++;
            bool changed = ctx->weak_mgr->updateCurrentUsingSafe();
            auto current_interfaces = ctx->weak_mgr->getCurrentInterfaces();
            syncContextInterfaces(ctx, current_interfaces);

            if (changed) {
                std::string currentIf;
                for (const auto& net : current_interfaces) {
                    if (net.usingNow()) {
                        currentIf = net.ifName();
                        break;
                    }
                }

                std::string msg = std::string("Using iface updated: ") + (currentIf.empty() ? "(none)" : currentIf);
                publishChangedEvent(ctx, msg, 0);
                getEventManager().emitConnectionModeChanged(msg, currentIf.empty() ? "none" : currentIf);
            } else {
                LOG_INFO(LogModule::WEAK_MGR, "using iface unchanged (interfaces: " << current_interfaces.size() << ")");
            }

            ctx->waitForStop(10000ms);
        }
    });
}

// 启动综合质量评估线程，并抑制同等级内的小幅分数抖动。
static void start_network_quality_thread(ServerContext* ctx) {
    ctx->network_quality_thread = std::thread([ctx]() {
        LOG_INFO(LogModule::WEAK_MGR, "network quality monitor thread started");

        NetworkQualityAssessor assessor;
        NetworkQualityResult lastQuality;
        lastQuality.level = NetworkQualityLevel::UNKNOWN;

        int loop_count = 0;
        while (ctx->running.load()) {
            loop_count++;
            LOG_INFO(LogModule::WEAK_MGR, "network quality thread running, loop=" << loop_count);
            try {
                auto currentInterfaces = ctx->weak_mgr->getCurrentInterfaces();
                syncContextInterfaces(ctx, currentInterfaces);
                NetworkQualityResult currentQuality = assessor.assessQuality(currentInterfaces);

                // 等级变化必报；同等级内只有分差超过 15 才生成事件。
                if (currentQuality.level != lastQuality.level ||
                    std::abs(currentQuality.score - lastQuality.score) > 15.0) {
                    LOG_INFO(LogModule::WEAK_MGR, "network quality changed: " << currentQuality.levelName
                        << " (score: " << std::fixed << std::setprecision(1) << currentQuality.score << ")");

                    getEventManager().emitNetworkQualityChanged(
                        currentQuality.levelName,
                        currentQuality.details,
                        "network_quality_assessor");

                    lastQuality = currentQuality;
                } else {
                    LOG_INFO(LogModule::WEAK_MGR, "network quality stable: " << currentQuality.levelName
                        << " (score: " << std::fixed << std::setprecision(1) << currentQuality.score << ")");
                }
            } catch (const std::exception& e) {
                LOG_ERROR(LogModule::WEAK_MGR, "network quality monitor error: " << e.what());
            }

            ctx->waitForStop(15000ms);
        }

        LOG_INFO(LogModule::WEAK_MGR, "network quality monitor thread stopped");
    });
}

// 按“日志→传输→事件→采集”的顺序启动，并在 gRPC 退出后回收可连接线程。
int start_server() {
    // 日志最先初始化，确保后续启动失败也能留下可定位信息。
    if (!Logger::init("server", "./logs/server", LogLevel::INFO, true)) {
        std::cerr << "Failed to initialize logger" << std::endl;
        return 1;
    }
    // 在创建任何工作线程前阻塞退出信号；后续线程继承 mask，由专用 sigwait 线程同步处理。
    sigset_t shutdownSignals;
    sigset_t previousSignals;
    sigemptyset(&shutdownSignals);
    sigaddset(&shutdownSignals, SIGINT);
    sigaddset(&shutdownSignals, SIGTERM);
    sigaddset(&shutdownSignals, SIGUSR1);  // 仅用于正常 Wait 返回时唤醒 signal waiter。
    const int maskResult = pthread_sigmask(SIG_BLOCK, &shutdownSignals, &previousSignals);
    if (maskResult != 0) {
        LOG_ERROR(LogModule::SERVER, "pthread_sigmask failed: " << std::strerror(maskResult));
        Logger::shutdown();
        return 1;
    }

    // 栈上的上下文被所有 RPC 和监控线程借用，因此必须活到线程全部退出之后。
    ServerContext ctx;
    auto weakMgrOwner = std::make_unique<WeakNetMgr>();
    ctx.weak_mgr = weakMgrOwner.get();

    // GrpcServer 同时充当 EventPublisher；事件管理器最终会把监控事件推送给它。
    GrpcServer grpcServer;
    ctx.event_publisher = &grpcServer;

    // 先开始监听，再初始化接口基线；两者之间存在 RPC 已可连接但业务快照仍为空的短暂窗口。
    const std::string address = configuredGrpcAddress();
    if (!grpcServer.start(&ctx, address)) {
        ctx.weak_mgr = nullptr;
        weakMgrOwner.reset();
        pthread_sigmask(SIG_SETMASK, &previousSignals, nullptr);
        Logger::shutdown();
        return 1;
    }

    std::atomic<bool> signalWaiterDone{false};
    std::thread signalWaiter([&]() {
        int receivedSignal = 0;
        const int waitResult = sigwait(&shutdownSignals, &receivedSignal);
        if (waitResult == 0 && receivedSignal != SIGUSR1) {
            LOG_INFO(LogModule::SERVER, "received shutdown signal " << receivedSignal);
            ctx.requestStop();
            grpcServer.shutdown();
        } else if (waitResult != 0) {
            LOG_ERROR(LogModule::SERVER, "sigwait failed: " << std::strerror(waitResult));
            ctx.requestStop();
            grpcServer.shutdown();
        }
        signalWaiterDone.store(true);
    });

    // 把全局 EventManager 的 publisher 绑定到当前 gRPC server。
    getEventManager().startEventMonitoring(&ctx);

    // 建立初始接口快照；指标线程在其上更新，但接口轮询仍会周期性整体替换列表。
    LOG_INFO(LogModule::WEAK_MGR, "initializing interface list...");
    auto initial_interfaces = ctx.weak_mgr->collectCurrentInterfaces();
    syncManagerAndContext(&ctx, initial_interfaces);
    LOG_INFO(LogModule::WEAK_MGR, "interface list initialized with " << initial_interfaces.size() << " interfaces");

    // 接口集合和默认出口分别轮询：前者关注增删，后者关注 usingNow 标记变化。
    start_iface_monitor_thread(&ctx);
    start_using_iface_thread(&ctx);

    LOG_INFO(LogModule::RTT, "starting monitor thread (target=223.5.5.5, interval=10s)");
    start_rtt_monitor_thread(&ctx, "223.5.5.5", /*intervalMs*/10000, /*timeoutMs*/800);

    LOG_INFO(LogModule::RSSI, "starting RSSI monitor thread (interval=10s)");
    start_rssi_monitor_thread(&ctx);

    LOG_INFO(LogModule::TCP_LOSS, "starting TCP loss rate monitor thread (interval=10s)");
    start_tcp_loss_monitor_thread(&ctx);

    LOG_INFO(LogModule::WEAK_MGR, "starting traffic analysis thread (interval=10s)");
    start_traffic_analysis_thread(&ctx);

    LOG_INFO(LogModule::WEAK_MGR, "starting network quality monitor thread (interval=15s)");
    start_network_quality_thread(&ctx);

    grpcServer.wait();

    // 外部 Shutdown 或信号路径都在这里汇合；唤醒所有周期等待并确保 gRPC 不再接收新 RPC。
    ctx.requestStop();
    grpcServer.shutdown();
    if (signalWaiter.joinable()) {
        if (!signalWaiterDone.load()) {
            pthread_kill(signalWaiter.native_handle(), SIGUSR1);
        }
        signalWaiter.join();
    }

    joinIfNeeded(ctx.iface_thread);
    joinIfNeeded(ctx.using_thread);
    joinIfNeeded(ctx.rtt_thread);
    joinIfNeeded(ctx.rssi_thread);
    joinIfNeeded(ctx.tcp_loss_thread);
    joinIfNeeded(ctx.traffic_analysis_thread);
    joinIfNeeded(ctx.network_quality_thread);

    // 路由监听器有独立 worker；所有使用方退出后再 stop/join，避免单例线程越过 ServerContext 生命周期。
    UsingInterfaceManager::getInstance()->stop();
    getEventManager().stopEventMonitoring();
    ctx.event_publisher = nullptr;
    ctx.weak_mgr = nullptr;
    weakMgrOwner.reset();
    pthread_sigmask(SIG_SETMASK, &previousSignals, nullptr);
    Logger::shutdown();
    return 0;
}

}  // namespace weaknet_grpc
