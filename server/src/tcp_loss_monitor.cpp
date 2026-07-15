// TCP 重传率代理值监控线程：对当前出口接口周期采样并计算窗口差分。
// 有效样本变化后写回 NetInfo，并发布通用 Changed 事件。

#include "server.hpp"
#include "tcp_loss_monitor.hpp"
#include "net_tcp.h"
#include "weak_netmgr.hpp"
#include "logger.hpp"
#include <cstdio>
#include <chrono>

using namespace std::chrono_literals;

namespace weaknet_grpc {

// 启动可 join 的 TCP 监控线程，生命周期由 ServerContext::running 控制。
void start_tcp_loss_monitor_thread(ServerContext* ctx) {
    ctx->tcp_loss_thread = std::thread([ctx](){
        std::printf("[tcp_loss] monitor thread started.\n");
        
        if (!ctx->weak_mgr) {
            LOG_ERROR(LogModule::TCP_LOSS, "TCP monitor has no WeakNetMgr owner");
            return;
        }
        
        auto tcpMonitor = TcpLossMonitor::getInstance();
        TcpStats prevStats, currStats;
        bool hasPrevStats = false;
        
        int loop_count = 0;
        while (ctx->running.load()) {
            loop_count++;
            LOG_INFO(LogModule::TCP_LOSS, "tick: monitoring TCP loss rate... (loop=" << loop_count << ")");
            
            // 只评估当前出口，避免把多个接口的 TCP 统计混成一个代理值。
            auto current_interfaces = ctx->weak_mgr->getCurrentInterfaces();
            std::string currentIface;
            for (const auto& net : current_interfaces) {
                if (net.usingNow()) {
                    currentIface = net.ifName();
                    break;
                }
            }
            
            if (currentIface.empty()) {
                LOG_INFO(LogModule::TCP_LOSS, "TCP_LOSS_MONITOR: no active interface found (checking " << current_interfaces.size() << " interfaces)");
                ctx->waitForStop(5000ms);  // 无活动接口时缩短重试周期，尽快感知网络恢复。
                continue;
            }
            
            LOG_INFO(LogModule::TCP_LOSS, "monitoring interface: " << currentIface);
            
            // sock_diag 采样失败时不推进基线，避免拿无效值参与下一次差分。
            if (!tcpMonitor->sampleForInterface(currentIface, currStats)) {
                LOG_ERROR(LogModule::TCP_LOSS, "failed to sample TCP stats for interface: " << currentIface);
                ctx->waitForStop(10000ms);
                continue;
            }
            
            // 至少需要前后两次有效快照才能计算窗口重传率。
            if (hasPrevStats) {
                TcpLossResult result = tcpMonitor->compute(prevStats, currStats);
                
                if (result.sentDelta >= 10) {  // 最小样本量为 10，避免少量报文放大百分比。
                    LOG_INFO(LogModule::TCP_LOSS, "TCP_LOSS_MONITOR: interface=" << currentIface 
                        << " rate=" << result.ratePercent << "%" 
                        << " delta_sent=" << result.sentDelta 
                        << " delta_retrans=" << result.retransDelta 
                        << " level=" << result.level);
                    
                    // 只在值或等级变化时更新共享快照并触发事件。
                    bool updated = ctx->weak_mgr->updateTcpLossRateSafe(currentIface, result.ratePercent, result.level);
                    if (updated) {
                        std::string msg = std::string("TCP loss rate updated for ") + currentIface + 
                                         ": " + std::to_string(result.ratePercent) + "% (" + result.level + ")";
                        LOG_INFO(LogModule::TCP_LOSS, "TCP loss rate updated - emitting event: " << msg);
                        publishChangedEvent(ctx, msg, /*counter*/0);
                    }
                }
            }
            
            // 当前有效样本成为下一窗口基线。
            prevStats = currStats;
            hasPrevStats = true;
            
            ctx->waitForStop(10000ms);
        }
        
        std::printf("[tcp_loss] monitor thread terminated.\n");
    });
}

} // namespace weaknet_grpc
