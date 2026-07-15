// WeakNet 服务端与客户端共用的 IPC 名称、RPC 名称及离线文件路径常量。
// 常量均为进程期只读配置，不承载运行时状态。

#pragma once

#include <string>

namespace weaknet_grpc {

// 遗留 D-Bus 服务、对象和接口名称；当前 gRPC 主调用链不读取这些常量。
static constexpr const char kBusName[] = "com.example.WeakNet";
static constexpr const char kObjectPath[] = "/com/example/WeakNet";
static constexpr const char kInterface[] = "com.example.WeakNet";

// gRPC 未通过环境变量覆盖时使用的本机监听/连接地址。
static constexpr const char kGrpcDefaultAddress[] = "127.0.0.1:50051";

// 遗留 IPC/日志方法名；并非全部对应当前 weaknet.proto 的 RPC（例如 ListInterfaces）。
static constexpr const char kMethodGet[] = "Get";
static constexpr const char kMethodListInterfaces[] = "ListInterfaces";
static constexpr const char kMethodGetInterfaces[] = "GetInterfaces";
static constexpr const char kMethodHealthCheck[] = "HealthCheck";
static constexpr const char kMethodPing[] = "Ping";

// 网络事件的兼容文本名称，应与 weaknet.proto 中的 EventType 语义一致。
static constexpr const char kSignalChanged[] = "Changed";
static constexpr const char kSignalInterfaceChanged[] = "InterfaceChanged";
static constexpr const char kSignalConnectionModeChanged[] = "ConnectionModeChanged";
static constexpr const char kSignalNetworkQualityChanged[] = "NetworkQualityChanged";

// 相对当前工作目录的离线序列化文件路径。
static const std::string kSignalSerializedFile = "./signal_changed.bin";
static const std::string kGetReplySerializedFile = "./get_reply.bin";

}  // namespace weaknet_grpc
