// RSSI 监控线程：周期读取 Wi-Fi 信号强度并更新 WeakNetMgr 中的接口快照。
// 只在值发生变化时发布通用 Changed 事件。

#include <thread>
#include <chrono>

#include "server.hpp"
#include "weak_netmgr.hpp"
#include "rssi_monitor.hpp"
#include "logger.hpp"

using namespace std::chrono_literals;

namespace weaknet_grpc {

// 启动独立 RSSI 轮询线程，控制目录可显式指定或交由客户端自动探测。
void start_rssi_monitor_thread(ServerContext* ctx, const std::string& ctrlDir) {
    ctx->rssi_thread = std::thread([ctx, ctrlDir]{
        LOG_INFO(LogModule::RSSI, "RSSI monitor thread started");
        if (!ctx->weak_mgr) {
            LOG_ERROR(LogModule::RSSI, "RSSI monitor has no WeakNetMgr owner");
            return;
        }
        int loop_count = 0;
        while (ctx->running.load()) {
            loop_count++;
            LOG_INFO(LogModule::RSSI, "RSSI monitor thread running, loop=" << loop_count << ", ctx->running=" << ctx->running.load());
            
            // wpa_supplicant 查询结果会写共享 NetInfo，必须走加锁入口。
            LOG_INFO(LogModule::RSSI, "RSSI monitor: calling updateWifiRssiSafe");
            bool changed = ctx->weak_mgr->updateWifiRssiSafe(ctrlDir);
            LOG_INFO(LogModule::RSSI, "RSSI monitor: updateWifiRssiSafe completed, changed=" << changed);
            
            // 更新完成后读取一致快照，避免日志观察到更新前的 RSSI。
            auto current_interfaces = ctx->weak_mgr->getCurrentInterfaces();
            LOG_INFO(LogModule::RSSI, "RSSI monitor: current interfaces count=" << current_interfaces.size());
            
            // 仅输出 Wi-Fi 接口，其他链路没有可解释的 RSSI 指标。
            for (const auto& net : current_interfaces) {
                if (net.type() == NetType::WiFi) {
                    LOG_INFO(LogModule::RSSI, "RSSI_MONITOR: " << net.ifName() 
                        << " | RSSI: " << net.rssiDbm() << "dBm" 
                        << " | Quality: " << static_cast<int>(net.quality())
                        << " | Using: " << (net.usingNow() ? "YES" : "NO"));
                }
            }
            
            // 值未变化时不产生事件，降低稳定信号下的通知噪声。
            if (changed) {
                LOG_INFO(LogModule::RSSI, "WiFi RSSI updated - emitting event");
                publishChangedEvent(ctx, "WiFi RSSI updated", /*counter*/0);
            } else {
                LOG_INFO(LogModule::RSSI, "RSSI_MONITOR: no changes detected (interfaces: " << current_interfaces.size() << ")");
            }
            ctx->waitForStop(10000ms);
        }
    });
}

}  // namespace weaknet_grpc
