// Wi-Fi RSSI 后台监控线程入口。
// 线程周期更新共享 WeakNetMgr，并以 dBm 记录信号强度。

#pragma once

#include <string>

namespace weaknet_grpc {

struct ServerContext;

// 启动由 ctx->rssi_thread 持有的可 join 轮询线程；requestStop 会唤醒周期等待。
// ctrlDir 为空时由实现自动选择 wpa_supplicant 控制目录。
void start_rssi_monitor_thread(ServerContext* ctx, const std::string& ctrlDir = "");

}  // namespace weaknet_grpc
