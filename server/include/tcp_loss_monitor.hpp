// TCP 重传率代理值后台监控线程入口。
// 线程周期采集当前上网接口的 TCP 快照，并把窗口计算结果写入共享 WeakNetMgr。

#pragma once

#include "server.hpp"

namespace weaknet_grpc {

// 创建监控线程并把句柄保存到 ctx->tcp_loss_thread；ctx 必须在线程退出前有效。
void start_tcp_loss_monitor_thread(ServerContext* ctx);

} // namespace weaknet_grpc
