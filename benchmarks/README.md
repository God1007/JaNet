# WeakNet 完整压力测试套件

本目录提供项目级统一编排，覆盖源码压力契约、用户态核心算法、RAG、gRPC/Dashboard、
ThreadSanitizer、真实 BPF map 和 TC/eBPF 内核闭环。每个组件先做正确性检查，再记录吞吐、
延迟、并发与资源指标；性能慢不会凭一个跨机器的固定数字直接判错，回归门禁通过同机基线完成。

所有机器可读报告使用同一个顶层协议：

- `schema_version` 必须精确等于字符串 `weaknet.benchmark.v1`；
- `summary.status` 只允许 `passed`、`failed`、`skipped`；
- 统一运行器只在套件 `passed` 时返回 `0`，失败返回 `2`；合并器在存在 failed 子报告时返回 `2`，
  否则返回 `0`（包括全为 skipped、合并状态为 `skipped` 的情形）。子组件还可能使用 `1`、`2`、
  TSan 的 `66` 等非零码，BPF 能力不支持时也可能以进程码 `0` 产出 `skipped`，所以自动化必须以
  校验后的 `summary.status` 为准；
- `skipped` 表示当前环境没有执行该能力，不等于通过；加 `--strict` 后，任何跳过都会让套件失败；
- 统一运行器会删除旧的组件输出再启动，并校验 schema、profile、component、数值类型、非空
  benchmark，以及 `passed` 与 correctness/error 字段是否自洽，不能用陈旧 JSON 伪造成功。

服务端底层微基准的单项说明见
[`server/tests/BENCHMARKS.md`](../server/tests/BENCHMARKS.md)。

## 最短运行路径

先确认解释器和依赖。不要默认系统 `python3`/`node` 一定满足项目要求：

```bash
python3 -m venv .venv
.venv/bin/pip install numpy jsonschema faiss-cpu pytest
npm --prefix dashboard install

PYTHON="$PWD/.venv/bin/python"
NODE="$(command -v node)"  # 若为空，先安装 Node，或填写可执行文件绝对路径。
"$PYTHON" -c 'import numpy, jsonschema, faiss'
"$NODE" --version
```

在仓库根目录执行。下面的 fixture 命令不要求先启动 gRPC server 或 Dashboard，适合先验证
压测 harness、报告协议和本机可运行组件：

```bash
"$PYTHON" benchmarks/run_stress_suite.py \
  --profile smoke \
  --components contracts,core,rag,service \
  --fixture \
  --events \
  --node "$NODE" \
  --strict \
  --output-dir benchmark-results/local-smoke
```

当前生产源码若没有满足某项 P0 压力契约，`contracts` 会如实生成 `failed` 并让命令返回 `2`；
这代表测试发现了产品风险，不代表压测脚本没有运行。组件原始结果仍会完整保留。

也可用根 Makefile：

```bash
make stress-smoke PYTHON="$PYTHON" NODE="$NODE"
make stress-standard PYTHON="$PYTHON" NODE="$NODE"

# 覆盖组件、输出目录和附加参数。
make stress-test \
  PYTHON="$PYTHON" NODE="$NODE" \
  STRESS_PROFILE=standard \
  STRESS_COMPONENTS=contracts,core,rag,service \
  STRESS_OUTPUT_DIR=benchmark-results/local-standard \
  STRESS_ARGS='--fixture --events --strict'
```

`make stress-smoke`/`make stress-standard` 默认走 `--components auto`，并不自动启用 fixture 或
service；需要自包含 service 测试时应显式传 `--fixture`，需要 live service 时应传 endpoint 或
显式选择 `service`。

## 组件与平台边界

| 组件 | 实际覆盖 | 可运行环境 |
| --- | --- | --- |
| `contracts` | 6 个 P0 源码/确定性模型门禁：Ping sequence 并发安全、回包 seq+target 关联、`/api/analyze` 有界准入、WebSocket backpressure、事件丢失/gap 可观测、同毫秒事件 ID 唯一性 | macOS、Linux |
| `core` | counter delta、保护策略、路由选择、事务化 snapshot retry、观测状态多读多写、56-byte canonical `flow_key` 与摘要/桶分布 | macOS、Linux |
| `rag` | artifact load、向量 retrieve、typed diagnosis、确定性、冷/热加载、RSS、384 维 feature hashing，以及运行前后 mutation guard | macOS、Linux |
| `service` | `Get`、`GetInterfaces`、`GetNetworkSnapshot`、`HealthCheck`、`Ping`、`/api/snapshot`、`/api/analyze`；可选 `SubscribeEvents` 生命周期 | macOS、Linux；live 模式要求 endpoint 可达 |
| `event-pipeline` | 真实 `NetworkEventManager → EventPublisher → subscriber queue → SubscribeEvents → eventBuffer → WebSocket` payload；快/慢消费者、交付率、ID 碰撞、p50/p95/p99、buffer cap 与 loss/backpressure 能力 | Linux driver + macOS Dashboard；建议使用独立 Lima helper |
| `sanitizer` | 用 ThreadSanitizer 重跑 `core` 覆盖到的并发路径 | 受支持的 Linux TSan runtime；macOS 明确跳过 |
| `bpf` | 真实 `bpf_map_create`/update/lookup/delete、容量语义、ABI 和并发 | Linux；需要 root/CAP_BPF，非 Linux/无权限明确跳过 |
| `kernel` | network namespace + TC/eBPF + 真实流量，LRU 压力、protected TCP 长连接、snapshot refresh 与资源占用 | Linux root；统一 `auto` 的 smoke 不运行 |

`--components auto` 的精确选择规则是：

1. 所有平台先选 `contracts,core,rag`；
2. Linux 再加 `sanitizer`；Linux root 再加 `bpf`，standard/stress 还加 `kernel`；
3. 使用 `--fixture`，或提供 service endpoint/events/targets 相关参数时，再加 `service`。

`--components all` 会请求原有七项；需要专用 live driver 的 `event-pipeline` 为 opt-in，必须显式选择
并提供 `--event-control-address` 与 `--dashboard-url`。也可传逗号分隔的显式列表。Linux 非 root若希望
编排器给 BPF/kernel 的 make 命令加 `sudo`，使用 `--sudo-linux`：

```bash
python3 benchmarks/run_stress_suite.py \
  --profile standard \
  --components core,sanitizer,bpf,kernel \
  --sudo-linux \
  --strict \
  --output-dir benchmark-results/linux-standard

# 对应快捷目标。
make stress-linux-standard
```

## smoke、standard、stress 的负载

三个 profile 不是只改变报告标签，它们会改变负载规模和组件超时。统一运行器默认进程超时分别为
300、1800、7200 秒，可用 `--timeout-seconds` 覆盖。

| 组件 | smoke | standard | stress |
| --- | --- | --- | --- |
| contracts 模型 | 同 tuple 事件 2 条；analyze burst 4 | 事件 128；burst 64 | 事件 10,000；burst 256 |
| core | 50k core、30k policy、5k route、2 reader+2 writer、10k FlowKey | 500k、300k、30k、4+4、100k FlowKey | 5,000,000 core、3,000,000 policy、100k route、8+8、500k FlowKey |
| RAG production | 并发 1/4，请求 8，warmup 2 | 并发 1/4/8/16，请求 64/256，warmup 8 | 并发 1/4/8/16，请求 1000/5000，warmup 32 |
| RAG fixture | corpus 128，请求 8，warmup 2 | corpus 1,000，请求 8/32，warmup 4 | corpus 10,000，请求 4/16，warmup 4 |
| service unary/HTTP | 并发 1/4，请求 8，warmup 2 | 并发 1/4/8/16，请求 64/256，warmup 8 | 并发 1/4/8/16，请求 1000/5000，warmup 32 |
| service event connections | 1/4 | 1/8/32 | 32/128/512 |
| event payload | fast 64；collision 32；pressure 600×1 KiB | fast 256；collision 128；pressure 2,500×4 KiB | fast 1,000；collision 512；pressure 10,000×8 KiB |
| kernel | `auto` 不运行；单独调用为 72k flow/2 sender | 72k unique flow/4 sender/1 wave | 300k unique flow/8 sender/5 wave |

`core` 表中是主要规模，详细 route entry、latency sampling 和 BPF map 各容量档见服务端文档。
RAG fixture 为了让 10k dense-vector 全扫描可完成，standard/stress 的请求档刻意小于 production 档。

统一运行器的 `--concurrency 1,4,8,16` 会同时覆盖 RAG/service 的并发列表；其 `--requests N`
只接受一个正整数并覆盖每个并发档的请求数，`--warmup N` 覆盖预热数。若要给独立 RAG/service
脚本传多档请求列表，可直接使用各脚本的 `--requests 64,256`。service JSON 同时记录请求的
`concurrency` 档和真实 worker 数 `effective_concurrency=min(concurrency,requests)`；要声称覆盖 16 并发，
每档 `requests` 必须至少为 16。

## 正确性门禁优先于性能数值

`contracts` 使用 token-aware、平衡括号的源码检查和确定性模型，而不是用宽泛全文正则判断：

- Ping 并发请求不得共享非原子的 sequence；回包必须关联本次 sequence 和目标/来源；
- `/api/analyze` 必须有有限的 active 上限、独立有限 queue 上限，满载时在启动 Python bridge 前
  返回 429/503；
- WebSocket broadcast 必须根据 `bufferedAmount` 实施有限背压；
- 每层有界事件队列的淘汰必须有专用 drop/gap/sequence 可观测链路；
- `${timestamp}-${counter}-${type}` 的重复是确定性的复合键冲突，不能当作低概率 hash collision。

`core`、RAG 和 service 也不仅统计 RPC/函数没有抛异常：它们会验证 key 字节唯一性、状态快照
generation 一致性、响应结构、Ping target 归属、RAG evidence/typed diagnosis、固定 workload 的确定性
和 mutation guard。任一 correctness error 都会使该组件 `summary.status=failed`。

## RAG：fixture 与 production read-only

自包含 synthetic 模式：

```bash
python3 benchmarks/rag_benchmark.py \
  --profile standard \
  --fixture \
  --output /tmp/weaknet-rag-fixture.json
```

`--fixture` 不是静态假响应。它使用生产同款 `StableHashEmbeddings`、真实
`_VectorKnowledgeStore.retrieve` 和 typed diagnosis core，默认 synthetic corpus 为
128/1,000/10,000，可用 `--synthetic-entries` 覆盖（至少 12）。fixture 的 QPS 是真实本地 RAG
runtime 在 synthetic corpus 上的性能。

不带 `--fixture` 时只读加载已发布 production artifact。诊断直接使用已加载 store，不进入公共
auto-rebuild 路径；运行前后对 raw/schema/golden、artifact tree、内容 hash、mtime 和 symlink target
做 mutation guard。`--offline-artifact` 还会关闭 load 时的 source validation，适合明确只以当前
artifact 为准的离线读取；它不会触发重建。

```bash
python3 benchmarks/run_stress_suite.py \
  --profile smoke \
  --components rag \
  --offline-artifact \
  --strict \
  --output-dir benchmark-results/rag-production-smoke
```

production 报告的 `environment.mutation_guard.scope` 为
`production_sources_and_artifact_tree`；任何新增、删除、内容/mtime/target 变化都会使门禁失败。

## gRPC、Dashboard 与事件流

服务已经启动时可直接跑 live endpoint：

```bash
node benchmarks/service_benchmark.mjs \
  --profile smoke \
  --grpc-address 127.0.0.1:50051 \
  --dashboard-url http://127.0.0.1:5174 \
  --ping-target 127.0.0.1 \
  --events \
  --output /tmp/weaknet-service-live.json
```

默认覆盖五个 unary RPC 和两个 HTTP API。Ping 报告把每个并发请求与其 target 绑定，并验证返回
文本仍包含该 target；同时把 gRPC 调用成功和 ICMP 业务探测成功分开，记录
`probe_success_rate`、成功探测 latency、负错误码及错误文本分布，不能用 RPC 200/OK 掩盖探测失败。
可用 `--ping-target host1,host2` 做 round-robin。`--targets` 支持：

```text
grpc-get,grpc-interfaces,grpc-snapshot,grpc-health,grpc-ping,grpc-events,
http-snapshot,http-analyze
```

也可使用 `--skip-grpc` 或 `--skip-dashboard`。live 标准/压力档会真实调用 `/api/analyze`，规模较大；
做容量探测时应先用 smoke，再按需要用 `--targets`、`--concurrency`、`--requests` 控制边界。

`--events` 增加独立流生命周期基准，不进入 unary 的 requests × concurrency 笛卡尔积。每个连接
都会验证 channel `waitForReady`、stream 创建、有界接收窗口、主动 cancel、terminal event、断开和
重连。协议没有服务端 ready ack，所以“建立成功”的硬依据是 channel ready。live 默认允许接收
窗口内没有新事件；`--require-event` 才要求初次和重连后都收到首事件。`--event-timeout-ms` 约束
ready/cancel，另有覆盖 receive+cancel 的硬 watchdog；退出会取消残留 stream 并关闭 channel。

自包含 service fixture：

```bash
node benchmarks/service_benchmark.mjs \
  --profile standard \
  --fixture \
  --events \
  --output /tmp/weaknet-service-fixture.json
```

service fixture 是固定 contract response；它的 QPS **只**代表 Promise 调度、benchmark harness 和
响应契约校验开销，不能当作 live gRPC、Dashboard 或 RAG bridge 吞吐。报告会在
`environment.fixture_qps_semantics` 中保留这一口径。

### 真实事件 payload 与慢消费者压力

`service --events` 只验证 stream 建连/取消/重连生命周期。完整 payload 路径使用独立 helper：

```bash
WEAKNET_BENCH_PYTHON="$PYTHON" \
WEAKNET_BENCH_NODE="$NODE" \
bash benchmarks/run_mac_lima_event_pipeline.sh \
  --profile smoke \
  --vm weaknet-eval \
  --output-dir benchmark-results/event-pipeline-smoke
```

helper 对当前 dirty worktree 做隔离快照，在 Lima 编译 `server/build/event_pipeline_driver`，在独立
PID/PGID 中启动真实 `GrpcServer` 和 `NetworkEventManager`，再启动未修改的 Dashboard。driver 的
本地控制端口只触发 `emitEvent`，不会给产品 proto 增加测试 RPC。运行结束无论通过、失败或被中断，
都会 TERM/KILL guest driver 与 host Dashboard 的整个进程组。

报告将阶段严格分开：

- `fast_consumer_live` 要求 injected、received、unique sequence 全等，记录完整链路 p50/p95/p99；
- `dashboard_id_collision` 固定 timestamp/counter/type，但改变 message/details.sequence，确定性验证
  Dashboard `${timestamp}-${counter}-${type}` 是否产生重复 ID；
- `slow_consumer_bounded_pressure` 暂停一个真实 WebSocket consumer，在有界 payload 压力下记录快/慢
  consumer 交付率、missing sequence、Dashboard `eventBuffer` 是否封顶 300；
- `loss_and_backpressure_contract` 同时检查静态声明和运行时证据：proto sequence/drop/gap、server
  queue eviction telemetry、实际 WebSocket payload 中的一等 sequence/drop/gap 对账，以及 Dashboard
  status 暴露的 `bufferedAmount` 高水位/慢消费者处置。仅在源码里出现 dormant token 不会转绿；当前
  产品缺少这些能力时总结果必须是 `failed`（退出 2），即使 fast path 100% 交付也不能假绿。

已手动启动 driver/Dashboard 时，也可让统一运行器包装该组件并绑定源码身份：

```bash
"$PYTHON" benchmarks/run_stress_suite.py \
  --profile smoke \
  --components event-pipeline \
  --event-control-address 127.0.0.1:50052 \
  --dashboard-url http://127.0.0.1:5174 \
  --event-run-id weaknet-event-smoke \
  --node "$NODE" \
  --output-dir benchmark-results/event-pipeline-runner
```

## macOS + Lima 的完整真实链路

macOS 不能本地执行 Linux BPF/netns。`run_mac_lima_stress.sh` 会对当前源码做干净快照，在已经运行
的 Lima VM 中重建 guest `vmlinux.h`，运行 Linux core/TSan/BPF/kernel；同时在 macOS 跑
contracts/core/RAG，并可启动 VM 内真实 gRPC server + host Dashboard 做 live service 压测，最后
严格校验并合并三份报告。

脚本不会创建 VM 或安装依赖。VM 必须已经存在并处于 Running，且包含项目编译、gRPC、libbpf、
bpftool、iproute2 等依赖；host 需要 Python、Node 和已安装的 Dashboard 依赖。示例：

```bash
npm --prefix dashboard install
limactl start weaknet-eval

WEAKNET_BENCH_PYTHON=python3 \
WEAKNET_BENCH_NODE=node \
bash benchmarks/run_mac_lima_stress.sh \
  --profile standard \
  --vm weaknet-eval \
  --fixture \
  --service-concurrency 1,4 \
  --service-requests 8 \
  --service-warmup 2 \
  --service-event-connections 1,4 \
  --output-dir benchmark-results/mac-lima-standard
```

`--output-dir` 必须是新目录或空目录。脚本会动态分配本次专用 gRPC/Dashboard 端口，ready 检查同时
绑定当前 server PID/PGID，并在退出时 TERM/KILL 整个本次进程组。`--keep-remote` 保留 VM 中临时
源码/结果，`--skip-service` 跳过真实服务链路。

这里 `--fixture` **只把 macOS RAG 切到 synthetic real-runtime**；Lima helper 启动的 service 仍然
连接真实 VM gRPC server 和真实 host Dashboard。没有 `--fixture` 时，macOS RAG 使用
`--offline-artifact` 只读 production artifact。Linux BPF/kernel 始终是真实内核能力，不会被 fixture
替代。

四个 `--service-*` 参数只收窄/覆盖 helper 最后一步的 live service 矩阵，不改变 Linux core/BPF/
kernel 或 macOS contracts/core/RAG 的 profile：

- `--service-concurrency LIST` 传给统一运行器的 `--concurrency`，例如 `1,4`；
- `--service-requests N` 是每个 unary/HTTP concurrency 档的单一正整数请求数；
- `--service-warmup N` 是每个 unary/HTTP case 的非负预热请求数；
- `--service-event-connections LIST` 只覆盖独立 event lifecycle 的连接档。

若 `--service-concurrency` 中的最大值大于 `--service-requests`，较大档只是请求的上限标签，实际并发会
被请求数截断；以每项报告的 `effective_concurrency` 为准。

全部省略时，live service 使用上表对应 profile 的完整默认矩阵。由于每次真实 `/api/analyze` 都会启动
独立 Python 诊断进程，首次联调或资源受限机器建议显式使用上例的受控矩阵；报告仍保留所选
`profile=standard`，同时在 service `environment` 中记录实际 concurrency/request/event 档位，不能把
受控矩阵误写成完整 standard 默认负载。

## 输出目录与报告合并

单机统一运行器默认写入 `benchmark-results/<timestamp>-<profile>/`：

```text
benchmark-results/<run>/
├── summary.json          # weaknet-stress-suite 聚合结果
├── report.md             # 中文摘要、指标、复现命令
└── components/
    ├── contracts.json
    ├── core.json
    ├── rag.json
    └── ...               # 只包含实际启动并产出 JSON 的组件
```

Lima helper 的根目录为合并结果，子目录保留每个阶段的完整报告：

```text
benchmark-results/<mac-lima-run>/
├── summary.json
├── report.md
├── linux/                # core/sanitizer/bpf/(kernel)
├── mac/                  # contracts/core/rag
├── service/              # live gRPC + Dashboard（未 --skip-service 时）
├── dashboard.log
└── linux-server.log      # server ready 失败时复制
```

也可手工合并同一 profile 的多个 suite summary：

```bash
python3 benchmarks/merge_stress_reports.py \
  --profile standard \
  --output-dir benchmark-results/merged-standard \
  benchmark-results/linux-standard/summary.json \
  benchmark-results/mac-standard/summary.json
```

合并器拒绝错误 schema/profile、畸形字段、重复输入路径和重复结果身份；合法的 failed/skipped 会原样
传播，不会被合并成假绿。合并 `duration_ms` 是子报告 duration 之和加合并处理耗时，并非墙钟并行时长。
每个 suite 的 `environment.source_identity` 还记录当前被测源码/benchmark 输入的组合 SHA-256 和文件数，
使 dirty worktree 结果也能绑定到精确输入，而不是只写一个不充分的 Git commit。

## 基线回归门禁

先保留一次通过的 `summary.json`，再在同一系统、架构和 CPU 数上比较：

```bash
python3 benchmarks/run_stress_suite.py \
  --profile standard \
  --components core,rag \
  --fixture \
  --strict \
  --baseline benchmark-results/baseline-standard/summary.json \
  --latency-regression-pct 20 \
  --throughput-regression-pct 15 \
  --memory-regression-pct 25 \
  --fail-on-regression \
  --output-dir benchmark-results/candidate-standard
```

基线必须具有相同 schema、suite component、profile，以及相同的
`environment.system/machine/cpu_count`，且基线自身 `summary.status=passed`、correctness 不为 false。
默认判定为：延迟增加超过 20%、吞吐下降超过 15%、内存增加超过 25%。不带
`--fail-on-regression` 时只记录 `performance_regressions`，不会因此改变已通过的正确性状态；基线
非法、不可读则无条件失败。

## 哈希与“碰撞”必须分层解释

1. **FlowKey identity**：BPF map 的语义身份是 canonical 后完整 56 字节。两个 key 完整字节相同才是
   同一个 flow；测试中的 `duplicate_full_byte_keys` 必须为 0，canonicalization/raw alias 门禁也必须
   通过。
2. **BPF bucket collision**：不同完整 key 落到同一个内核 hash bucket 时，内核仍比较完整 key，
   不会互相覆盖；影响主要是查找/update 延迟。普通 BPF API 不暴露真实 bucket collision 计数。
3. **FNV proxy**：core 报告的 FNV-1a 64-bit/lower-32 digest 和 bucket occupancy 只是用户态分布代理，
   明确标记 `proxy_not_kernel_hash=true`，不能声称测到了内核 hash 算法。
4. **生日概率**：代码报告样本量 `n` 下 b-bit 摘要至少一次碰撞的
   `1-exp(-n(n-1)/(2*2^b))`。例如 100,000 个值的 32-bit 概率约 68.78%，64-bit 约
   2.71e-10；这是摘要概率，不是完整 FlowKey 重复概率。
5. **RAG feature coordinate**：token 被 signed feature hashing 到 384 个坐标，多个 token 共用坐标
   是设计允许的降维碰撞；它不是 SHA-256 digest collision。报告会记录 unique token、occupied bucket、
   coordinate collision、max bucket load 和生日概率。
6. **事件 ID**：旧的 timestamp/type/counter 组合在同毫秒同 tuple 下是必然重复，属于确定性复合键
   冲突，不应用生日悖论解释。它由 `contracts` 的独立模型验证。

## JSON 顶层协议

组件报告和两级聚合报告至少包含以下骨架；不同组件的 correctness 字段名可能是
`correctness_pass`、`correctness_passed` 或 `correctness_gate_passed`，运行器会统一校验其类型与状态
一致性：

```json
{
  "schema_version": "weaknet.benchmark.v1",
  "component": "rag",
  "profile": "standard",
  "environment": {},
  "started_at": "2026-07-15T00:00:00Z",
  "duration_ms": 1.0,
  "benchmarks": [
    {"name": "rag.retrieve", "correctness_pass": true}
  ],
  "summary": {
    "status": "passed",
    "correctness_pass": true,
    "error_count": 0
  }
}
```

不要把单项 benchmark 内部的实现状态与顶层状态枚举混用；跨组件自动化只依赖
`summary.status` 的 `passed/failed/skipped`。完整 CLI 以代码为准：

```bash
python3 benchmarks/run_stress_suite.py --help
python3 benchmarks/rag_benchmark.py --help
node benchmarks/service_benchmark.mjs --help
bash benchmarks/run_mac_lima_stress.sh --help
make -C server benchmark-help
```
