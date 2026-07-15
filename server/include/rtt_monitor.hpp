// RTT 后台监控线程入口：周期调用 WeakNetMgr 更新接口 RTT、状态和链路质量。
// intervalMs 与 timeoutMs 单位均为毫秒，线程依赖 ServerContext 控制运行生命周期。

#pragma once

#include <string>

namespace weaknet_grpc {

struct ServerContext;

// 启动由 ctx->rtt_thread 持有的可 join 轮询线程；requestStop 会唤醒周期等待。
// host 为探测目标，intervalMs 和 timeoutMs 分别是轮询间隔与单次探测超时。
void start_rtt_monitor_thread(ServerContext* ctx, const std::string& host, int intervalMs = 2000, int timeoutMs = 800);

}  // namespace weaknet_grpc
