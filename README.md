# JaNet：AI-powered Network Diagnostics（gRPC / C++17）

JaNet 使用 gRPC 连接网络诊断服务、客户端与可视化 Dashboard。服务端整合网络接口、eBPF 流量、RTT、RSSI、TCP 重传率代理值和网络质量评估；客户端 `weaknet_client.h` 保留稳定的 C API。

## 目录结构

- `proto/weaknet.proto`：gRPC 服务、RPC 方法和事件流协议定义。
- `server/src/grpc_service.cpp`：gRPC 服务端实现，提供同步 RPC 与事件 streaming。
- `server/src/server.cpp`：启动 gRPC 服务和各类网络监控线程。
- `client/client.cpp`：客户端动态库实现，保留 `weaknet_*` C API。
- `Makefile`、`server/Makefile`：生成 protobuf/gRPC 代码并编译服务端、客户端库和测试程序。

## 依赖

Ubuntu/Debian 示例：

```bash
sudo apt-get install -y build-essential clang llvm pkg-config \
  libgrpc++-dev protobuf-compiler protobuf-compiler-grpc \
  libglog-dev libelf-dev zlib1g-dev libcap-dev \
  linux-headers-$(uname -r) libbpf-dev
```

也可以运行：

```bash
./install.sh --install-deps
```

## 构建

```bash
make all
```

生成：

- `server/bin/weaknet-grpc-server`
- `client/lib/libweaknet.so`
- `client/bin/test-client`

## 运行

默认监听 `127.0.0.1:50051`。如需覆盖地址，设置 `WEAKNET_GRPC_ADDRESS`。

```bash
make run-server
```

另一个终端：

```bash
make test-client COMMAND=all
```

也可以单独测试：

```bash
make test-client COMMAND=get
make test-client COMMAND=health
make test-client COMMAND=ping\ 8.8.8.8
make test-client COMMAND=events
```

## 在 macOS 上一键运行

服务端依赖 Linux netlink、sock_diag、BTF 和 TC/eBPF，因此不能直接在 macOS
内核上完整运行。仓库提供 `run-mac.sh`：Lima 运行 Linux C++ 服务端，Mac 运行
Dashboard 和本地 RAG。

宿主机先准备 Lima、Python 3.10+ 和满足 Vite 要求的 Node：

```bash
brew install lima python@3.12
nvm install 22                 # 已有 Node 20.19+ / 22.12+ 可跳过
```

```bash
./run-mac.sh setup          # 首次准备 VM 与依赖；也可以直接执行 start
./run-mac.sh start          # 等价于 ./run-mac.sh
./run-mac.sh status
./run-mac.sh test health
./run-mac.sh test ping 8.8.8.8
./run-mac.sh demo                    # 分阶段生成流量并展示 JaNet 实际观测
./run-mac.sh demo burst              # 单连接高吞吐场景
./run-mac.sh demo --explain-only     # 只查看模拟计划
./run-mac.sh logs                   # 最近 100 行，输出后退出
./run-mac.sh logs server -n 30      # 只看 Server 最近 30 行
./run-mac.sh follow                 # 持续合并 Server + Dashboard 日志
./run-mac.sh logs -f dashboard      # follow 的兼容写法，Ctrl-C 退出
./run-mac.sh stop
```

`logs` 是定长快照，每个来源默认最多输出 100 行后退出；`follow`（或 `logs -f`）
会先输出同样的历史窗口，再持续打印新日志，并用 `[server]` / `[dashboard]` 标记来源。
两种模式都支持 `all`、`server`、`dashboard` 和 `-n N`；按 `Ctrl-C` 只退出日志查看，
不会停止 JaNet 服务。

直接执行 `./run-mac.sh` 时，交互式终端会显示 JaNet 欢迎页和快速命令介绍；
`./run-mac.sh intro` 可以随时显式查看。`start` 的自动欢迎页默认不会写入 CI、
管道或重定向输出，也可通过 `WEAKNET_BANNER=always|never` 显式控制；这些配置
只控制 `start`，显式执行 `intro` 始终会展示欢迎页。

默认页面是 `http://127.0.0.1:5173`。脚本会主动查找 NVM 中满足 Vite
要求的 Node，按 `package-lock.json` 执行必要的 `npm ci`，把当前工作树复制到
Lima 隔离目录构建，并通过真实 Client RPC 和 Dashboard `/api/snapshot` 验证启动结果。

> 注意：这种方式让项目可以从 Mac 一键使用，但服务端观测的是 Lima VM 的
> Linux 网络栈，不是 Mac 的 `en0`、原生 Wi-Fi RSSI 或全部宿主流量。真正的
> macOS 原生采集需要单独实现 Darwin/CoreWLAN 等平台后端。

## gRPC 接口

- `Get`
- `GetInterfaces`
- `HealthCheck`
- `Ping`
- `SubscribeEvents`：server-streaming，替代原先的 signal 广播。

事件类型包括：

- `Changed`
- `InterfaceChanged`
- `ConnectionModeChanged`
- `NetworkQualityChanged`
- `TcpLossRateChanged`
- `RttChanged`
- `RssiChanged`

## 兼容性说明

客户端公开 C API 未改变，原有调用方通常只需要重新链接新的 `libweaknet.so`。底层不再需要会话总线；网络地址通过 `WEAKNET_GRPC_ADDRESS` 控制。
