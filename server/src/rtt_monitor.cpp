// RTT 监控线程：周期调用 NetPing 更新各接口延迟、链路等级和 Up/Down 状态。
// 指标档位变化时发布通用 Changed 事件，并持续输出接口级诊断日志。

#include <thread>
#include <chrono>
#include <cstdio>

#include "server.hpp"
#include "weak_netmgr.hpp"
#include "rtt_monitor.hpp"
#include "logger.hpp"

using namespace std::chrono_literals;

namespace weaknet_grpc {

// 启动独立 RTT 轮询线程；目标、采样间隔和单次超时由调用方注入。
void start_rtt_monitor_thread(ServerContext* ctx, const std::string& host, int intervalMs, int timeoutMs) {
    // 线程捕获只包含稳定配置和服务上下文指针，循环由 running 统一停止。
    ctx->rtt_thread = std::thread([ctx, host, intervalMs, timeoutMs]{
        LOG_INFO(LogModule::RTT, "RTT monitor thread started");
        if (!ctx->weak_mgr) {
            LOG_ERROR(LogModule::RTT, "RTT monitor has no WeakNetMgr owner");
            return;
        }
        int loop_count = 0;
        while (ctx->running.load()) {
            loop_count++;
            LOG_INFO(LogModule::RTT, "RTT monitor thread running, loop=" << loop_count << ", ctx->running=" << ctx->running.load());
            try {
                // 更新会修改共享 NetInfo，必须通过 WeakNetMgr 的加锁入口。
                LOG_INFO(LogModule::RTT, "RTT monitor: calling updateRttAndStateSafe");
                bool changed = ctx->weak_mgr->updateRttAndStateSafe(host, timeoutMs);
                LOG_INFO(LogModule::RTT, "RTT monitor: updateRttAndStateSafe completed, changed=" << changed);
                
                // 更新后再取快照，保证日志与本轮写入的 RTT 状态一致。
                auto current_interfaces = ctx->weak_mgr->getCurrentInterfaces();
                LOG_INFO(LogModule::RTT, "RTT monitor: current interfaces count=" << current_interfaces.size());
                
                // 每个接口都记录目标和是否为当前出口，便于定位多网卡差异。
                for (const auto& net : current_interfaces) {
                    LOG_INFO(LogModule::RTT, "RTT_MONITOR: " << net.ifName() 
                        << " | RTT: " << net.rttMs() << "ms" 
                        << " | Quality: " << static_cast<int>(net.quality())
                        << " | Using: " << (net.usingNow() ? "YES" : "NO")
                        << " | Target: " << host);
                }
                
                // 只有状态或质量档位变化时发事件，避免每个数值抖动都通知客户端。
                if (changed) {
                    LOG_INFO(LogModule::RTT, "RTT/Quality updated - emitting event");
                    publishChangedEvent(ctx, "RTT/Quality updated", /*counter*/0);
                } else {
                    LOG_INFO(LogModule::RTT, "RTT_MONITOR: no changes detected (interfaces: " << current_interfaces.size() << ")");
                }
                
                LOG_INFO(LogModule::RTT, "RTT monitor: reached sleep preparation");
                LOG_INFO(LogModule::RTT, "RTT monitor: about to sleep for " << intervalMs << "ms");
                ctx->waitForStop(std::chrono::milliseconds(intervalMs));
                LOG_INFO(LogModule::RTT, "RTT monitor: woke up from sleep");
                
            // 单轮探测异常只记录日志，监控线程继续服务后续周期。
            } catch (const std::exception& e) {
                LOG_ERROR(LogModule::RTT, "RTT monitor thread exception: " << e.what());
            } catch (...) {
                LOG_ERROR(LogModule::RTT, "RTT monitor thread unknown exception");
            }
        }
        LOG_INFO(LogModule::RTT, "RTT monitor thread exiting, ctx->running=" << ctx->running.load());
    });
}

}  // namespace weaknet_grpc
