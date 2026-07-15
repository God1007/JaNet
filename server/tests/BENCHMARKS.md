# Server traffic benchmark 使用说明

这组基准验证 `server` 底层流量观测闭环，不依赖 Dashboard/RAG，也不修改生产数据。它覆盖可移植
用户态算法、Linux ThreadSanitizer、真实 BPF map syscall，以及 network namespace + TC/eBPF 的内核
压力。项目级 contracts/RAG/service/macOS+Lima 编排见
[`benchmarks/README.md`](../../benchmarks/README.md)。

对真正执行的 workload，非零退出码表示 ABI、并发一致性、map 容量语义或 syscall 结果不符合预期；
能力不支持的 BPF binary 会以进程码 `0` 产出 `summary.status=skipped`。因此自动化不能只看退出码，
还必须读取并校验 JSON 的 `summary.status`。性能值用于保存同机基线，不设置跨机器通用的硬编码
延迟/QPS 阈值。

## 快速运行

```bash
# macOS/Linux 都能运行用户态 core；macOS 的 BPF binary 会产出 skipped JSON。
make -C server benchmark-smoke

# Linux root 完整标准档：core + 真实 BPF map + 72k TC/netns flows。
sudo make -C server benchmark-standard

# 压力档：更大迭代、并发、超容量 map 写入和 300k kernel flows。
sudo make -C server benchmark-stress
```

`make -C server benchmark` 等价于 `benchmark-standard`。server Makefile 的组合 target 不运行
`benchmark-core-tsan`；TSan 由项目级 Linux 编排器或下面的细粒度 target 单独执行。

```bash
make -C server benchmark-traffic-core \
  PROFILE=standard OUTPUT=/tmp/weaknet-core.json

make -C server benchmark-core-tsan \
  PROFILE=standard OUTPUT=/tmp/weaknet-core-tsan.json

sudo make -C server benchmark-bpf-maps \
  PROFILE=standard OUTPUT=/tmp/weaknet-bpf-maps.json

sudo make -C server benchmark-kernel-pressure \
  PROFILE=standard OUTPUT=/tmp/weaknet-kernel.json

# Linux/Lima：构建真实 EventManager + GrpcServer payload driver。
make -C server benchmark-event-driver
```

`benchmark-core-tsan` 仅在受支持的 Linux TSan runtime 上构建和执行；macOS target 会明确打印 SKIP。
非 root Linux 执行 kernel target 也会打印 SKIP 和 `sudo` 提示，不会用用户态模拟冒充内核通过。
BPF binary 在无 root/CAP_BPF 或不支持平台上生成 `summary.status=skipped` 的合法 JSON。

`benchmark-event-driver` 不修改 proto：它用测试专用 control socket 触发真实
`NetworkEventManager::emitEvent → EventPublisher::publish → GrpcServer`。完整 Dashboard/WebSocket
快慢消费者压测由 `benchmarks/run_mac_lima_event_pipeline.sh` 编排；driver 不应作为生产 server 使用。

两个独立 benchmark binary 可直接调用：

```bash
server/build/traffic_microbenchmark \
  --profile smoke --output /absolute/path/core.json

server/build/bpf_map_benchmark \
  --profile standard --output /absolute/path/maps.json
```

`--profile` 只能是 `smoke`、`standard`、`stress`；`--output` 必填。C++ benchmark 通过临时文件+
rename 写入一个完整 JSON document，stdout 只输出一行人工摘要。Makefile 未指定 `OUTPUT` 时，结果
落在 `server/build/benchmarks/`。

## 三个 profile 的真实规模

### 用户态 core

| Profile | core delta | policy | route / candidates | state ops / readers+writers | FlowKey | latency stride |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| smoke | 50,000 | 30,000 | 5,000 / 128 | 10,000 / 2+2 | 10,000 | 4 |
| standard | 500,000 | 300,000 | 30,000 / 512 | 100,000 / 4+4 | 100,000 | 16 |
| stress | 5,000,000 | 3,000,000 | 100,000 / 2,048 | 500,000 / 8+8 | 500,000 | 64 |

`state ops` 是每个 reader/writer thread 的目标操作数。`latency_stride` 表示快速 header-only 操作
每多少次取一个固定 batch 的摊销样本，不是“只执行这些操作”。

### 真实 BPF map

每种 map 的 workload 由 profile 和该 map 的生产容量共同决定：

| Profile | entry count @ threads 档位 |
| --- | --- |
| smoke | `min(256,max(1,capacity/8)) @ 1`；`min(1024,max(1,capacity/2)) @ 2` |
| standard | `min(1024,max(1,capacity/4)) @ 1`；`min(16384,max(1,capacity/2)) @ 2`；`capacity @ 1/4`；`capacity+max(64,capacity/8) @ 4` |
| stress | `capacity/2 @ 1`；`capacity @ 1/4`；`2*capacity @ 8`；`4*capacity @ 8` |

`min/max` 会针对小容量 map 截断，重复的 entry/thread case 会去重。BPF syscall latency sampling
stride 为 smoke=1、standard=8、stress=32。

### TC/eBPF kernel pressure

| Profile | Unique flows | Senders | Waves | 说明 |
| --- | ---: | ---: | ---: | --- |
| smoke（直接调用） | 72,000 | 2 | 1 | 项目级 `auto` smoke 不启动 namespace |
| standard | 72,000 | 4 | 1 | 超过 65,536 LRU 容量 |
| stress | 300,000 | 8 | 5 × 60,000 | 每波 refresh，累计跨过 266,240 tombstone gate |

stress 不是重复发送同一批 packet：五轮 source/destination port 组合保持唯一，同时维持一条受保护
TCP 长连接。报告记录 flow 生成耗时/吞吐、每波 snapshot refresh latency、LRU/protected entries、
max RSS、page faults 和 context switches。

## `traffic_microbenchmark` 覆盖范围

- `calculateCounterDelta`（报告名 `safeCounterDelta`）：单调增长、counter 重建、generation 改变和
  新 entry；
- 保护策略：端口、进程、cgroup、超长低速、duration gate；
- 大候选集合上的默认路由稳定选择；
- rtnetlink 候选 snapshot 的事务化 retry：首轮成功、generation 变化后成功、重试耗尽；
- `TrafficObservationStateStore` 多 writer + 多 reader 争用；读者任何时刻都必须得到同一
  generation/ifindex 的一致 snapshot；
- `flow_key` 生成、完整 56 字节唯一性、reserved/IPv4 tail 清零、标准布局、padding/raw alias 风险；
- FNV-1a 64-bit 与 lower-32 用户态摘要、理论 birthday probability 和经验 bucket occupancy。它们
  只用于发现 key 生成偏斜，不代表 Linux 内核 map 的 hash 实现。

每个 benchmark 记录 `operations`、`threads`、`duration_ms`、`ops_per_second`、
`latency_ns.p50/p95/p99/max` 和 `errors`。快速算法采用 fixed-batch amortized ns/op；BPF map 使用抽样
single-syscall latency，字段 `latency_method` 会明确方法，两种口径不能直接横向比较。

## 真实 BPF map 与容量语义

`bpf_map_benchmark` 使用真实 `bpf_map_create`/`bpf_map_*_elem` syscall，类型、容量和 ABI 与生产
map 对齐：

| Case | Type | Capacity | Key / value |
| --- | --- | ---: | --- |
| `current_sec_lru_hash` | `BPF_MAP_TYPE_LRU_HASH` | 65,536 | `flow_key` / `flow_value` |
| `protected_flows_hash` | `BPF_MAP_TYPE_HASH` | 4,096 | cookie / `flow_protected_record` |
| `iface_totals_percpu_hash` | `BPF_MAP_TYPE_PERCPU_HASH` | 512 | `flow_iface_key` / per-CPU counters |

每类 map 在多档 entry/thread 下分别测 update、lookup、delete。standard/stress 会越过容量：

- LRU 的所有 update 必须继续成功。达到或超过容量时，门禁按 Linux v7 common-LRU 当前实现的
  `target_free=clamp((capacity/possible_cpus)/2,1,128)` 和
  `max_slack=possible_cpus*(target_free-1)` 计算严格批量缓存上界；当前 65,536 容量/4 CPU 环境的
  可接受区间是
  `[65,028,65,536]`。低于这个区间仍然失败，不能用“LRU 会淘汰”无限放宽容量；
- exact-capacity 并发档如果发生批量提前淘汰，lookup/delete 的成功数必须等于 update 后实际枚举数，
  所有缺失必须逐条表现为数量完全相等的 `ENOENT`，且最终 delete 后必须为空；预期缺失不会计入
  correctness error，任何额外 errno、value mismatch 或枚举差异仍然失败；
- 普通 HASH/PERCPU_HASH 必须准确出现预期容量拒绝；
- `expected_capacity_rejections` 与 correctness `errors` 分开，并严格要求容量拒绝为 `E2BIG`；
  “map 满”不会被误报为产品错误；
- per-CPU value buffer 按 possible CPU 数和 libbpf 对齐 stride 构造，报告会记录 possible CPU。

`128/target_free` 是当前 Linux 内核实现细节而非稳定 userspace ABI。JSON 会记录
`lru_batch_model`、`lru_local_free_target` 和推导上界；若未来内核改变算法，测试应先失败，再根据该
内核的权威源码升级模型，不能把新差异自动当成成功。当前模型对应
[Linux v7.0 `bpf_lru_list.c`](https://github.com/torvalds/linux/blob/v7.0/kernel/bpf/bpf_lru_list.c)。

## FlowKey 与碰撞的严格口径

`flow_key` 的 map identity 是 canonical 后完整 56 字节。当前布局没有隐式 padding，但包含显式
`reserved0/reserved1`；IPv4 还必须把地址后 12 字节清零。生成器应先 value-initialize；从 raw bytes
恢复对象使用 `memcpy`，不能依赖未对齐 `reinterpret_cast` 或未初始化对象表示。

需要区分四个概念：

1. **完整 key 重复**：canonical 后 56 字节完全相同，是项目语义中的同一个 flow。不同输入发生
   raw alias/duplicate 是 correctness bug，必须为 0。
2. **kernel hash bucket collision**：两个不同完整 key 落到同一桶，内核仍比较完整 key，不会覆盖；
   它可能让 lookup/update 变慢。普通 BPF API 不暴露真实 bucket collision 数。
3. **digest collision**：测试对完整字节计算 FNV-1a 64-bit，并观察 full/lower-32 摘要是否重复。
   这是用户态 proxy，JSON 明确写 `proxy_not_kernel_hash=true`。
4. **bucket occupancy collision**：把摘要映射到测试配置的 bucket 后，超过每桶第一个元素的数量；
   它使用独立字段，不能当成 digest collision。

代码使用生日问题公式报告样本量 `n` 下 b-bit 摘要至少碰撞一次的概率：

```text
P(collision) = 1 - exp(-n(n-1) / (2 * 2^b))
```

例如 core standard 的 100,000 个 FlowKey，对 32-bit 摘要约为 68.78%，对 64-bit 摘要约为
2.71e-10。理论概率和这一次样本实际是否出现摘要碰撞是两件事；二者也都不能替代完整 key 唯一性
门禁。

## JSON contract

三个 server 组件报告都使用统一顶层 envelope。注意 `schema_version` 是字符串，且跨组件自动化只
依赖 `summary.status` 的精确枚举 `passed`、`failed`、`skipped`：

```json
{
  "schema_version": "weaknet.benchmark.v1",
  "component": "traffic_userspace_microbenchmark",
  "profile": "standard",
  "environment": {},
  "started_at": "2026-07-15T00:00:00Z",
  "duration_ms": 1.0,
  "benchmarks": [
    {"name": "safeCounterDelta", "status": "ok", "errors": 0}
  ],
  "summary": {
    "status": "passed",
    "correctness_passed": true,
    "errors": 0
  }
}
```

实际 `component` 名称以各二进制输出为准。支持能力不足的 BPF 报告使用
`summary.status="skipped"`、`correctness_passed=null` 和非空 `skip_reason`；它不应被改写为 passed。
单项 benchmark 内部可有自己的 `status`（例如 `ok`/`failed`），不要与顶层 summary 枚举混用。

项目级统一运行器会把 server 结果写入 `<output-dir>/components/core.json`、`sanitizer.json`、
`bpf.json`、`kernel.json`，并在 `<output-dir>/summary.json` 和 `report.md` 聚合：

```bash
python3 benchmarks/run_stress_suite.py \
  --profile standard \
  --components core,sanitizer,bpf,kernel \
  --sudo-linux \
  --strict \
  --output-dir benchmark-results/linux-standard
```

macOS 上执行完整双环境闭环：

```bash
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

该 helper 在 Lima 中重建 guest `vmlinux.h` 后才构建 BPF，Linux 端 strict 运行
core/sanitizer/bpf/(kernel)，macOS 端运行 contracts/core/RAG，并可启动真实 server+Dashboard 做
live service 压测。示例中的四个 `--service-*` 开关只把 live service 收窄为受控矩阵；省略时使用
profile 的默认 service 负载，不影响 Linux/server 微基准规模。VM 前置依赖、fixture/live 精确语义
和合并目录结构见项目级文档。
