#!/usr/bin/env node
// WeakNet 事件链路的确定性 live 压测入口。
//
// 配套 C++ driver 从真实 NetworkEventManager/GrpcServer 注入事件；本进程从未改造的
// Dashboard WebSocket 消费事件，分别验证快速消费者、固定 tuple 的 ID 冲突、慢消费者
// 背压和 Dashboard 固定长度缓存。即使快速链路看似正常，缺少 sequence/drop/gap 协议
// 或 WebSocket 背压策略仍会明确判失败，避免把“无法观测丢失”误报为“没有丢失”。

import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import process from "node:process";
import { createRequire } from "node:module";
import { performance } from "node:perf_hooks";
import { fileURLToPath } from "node:url";

const SCHEMA_VERSION = "weaknet.benchmark.v1";
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const projectRoot = path.resolve(__dirname, "..");
const dashboardRequire = createRequire(path.join(projectRoot, "dashboard", "package.json"));
const wsPackage = dashboardRequire("ws");
const WebSocket = wsPackage.WebSocket ?? wsPackage;

const PROFILES = {
  smoke: {
    fastEvents: 64, fastIntervalUs: 1000,
    collisionEvents: 32,
    pressureEvents: 600, pressureIntervalUs: 0, payloadBytes: 1024,
    slowPauseMs: 250, settleMs: 3000
  },
  standard: {
    fastEvents: 256, fastIntervalUs: 250,
    collisionEvents: 128,
    pressureEvents: 2500, pressureIntervalUs: 0, payloadBytes: 4096,
    slowPauseMs: 500, settleMs: 6000
  },
  stress: {
    fastEvents: 1000, fastIntervalUs: 50,
    collisionEvents: 512,
    pressureEvents: 10000, pressureIntervalUs: 0, payloadBytes: 8192,
    slowPauseMs: 1000, settleMs: 15000
  }
};

const USAGE = `Usage:
  node benchmarks/event_pipeline_benchmark.mjs --profile smoke|standard|stress --output FILE [options]

Required live services:
  1. server/tests/event_pipeline_driver.cpp running in Linux/Lima
  2. unmodified dashboard/server/index.mjs pointed at that gRPC address

Options:
  --control-address HOST:PORT   Driver control endpoint (default: 127.0.0.1:50052)
  --dashboard-url URL           Dashboard API URL (default: http://127.0.0.1:5174)
  --run-id TOKEN                Stable payload run id (default: weaknet-event-<profile>)
  --fast-events N               Fast-consumer event count
  --fast-interval-us N          Delay between fast events
  --collision-events N          Constant tuple collision probes
  --pressure-events N           Bounded slow-consumer pressure count
  --pressure-interval-us N      Delay between pressure events
  --payload-bytes N             Per-event filler bytes, max 65536
  --slow-pause-ms N             Minimum paused-consumer interval
  --settle-ms N                 Bounded receive/quiet window
  --timeout-ms N                Control/connect timeout (default: 5000)
  --expected-dashboard-cap N    Expected eventBuffer cap (default: 300)
  -h, --help                    Show this help
`;

// 统一执行参数/协议断言；condition 为假时抛出带上下文的 TypeError，无返回值。
function requireCondition(condition, message) {
  if (!condition) throw new TypeError(message);
}

// 把 CLI 字符串解析为安全整数，并限制在 min/max 内；返回校验后的 number。
function parseInteger(value, name, { min = 0, max = Number.MAX_SAFE_INTEGER } = {}) {
  const parsed = Number(value);
  requireCondition(Number.isSafeInteger(parsed) && parsed >= min && parsed <= max,
    `${name} must be an integer in [${min},${max}]`);
  return parsed;
}

// 解析 profile 和覆盖参数，补齐默认值并做边界校验；返回规范化后的运行配置。
function parseArgs(argv) {
  if (argv.includes("--help") || argv.includes("-h")) return { help: true };
  const args = {
    profile: "smoke",
    output: "",
    controlAddress: "127.0.0.1:50052",
    dashboardUrl: "http://127.0.0.1:5174",
    runId: "",
    timeoutMs: 5000,
    expectedDashboardCap: 300,
    fastEvents: null,
    fastIntervalUs: null,
    collisionEvents: null,
    pressureEvents: null,
    pressureIntervalUs: null,
    payloadBytes: null,
    slowPauseMs: null,
    settleMs: null
  };
  const flags = new Map([
    ["--profile", "profile"], ["--output", "output"],
    ["--control-address", "controlAddress"], ["--dashboard-url", "dashboardUrl"],
    ["--run-id", "runId"], ["--timeout-ms", "timeoutMs"],
    ["--expected-dashboard-cap", "expectedDashboardCap"],
    ["--fast-events", "fastEvents"], ["--fast-interval-us", "fastIntervalUs"],
    ["--collision-events", "collisionEvents"],
    ["--pressure-events", "pressureEvents"],
    ["--pressure-interval-us", "pressureIntervalUs"],
    ["--payload-bytes", "payloadBytes"], ["--slow-pause-ms", "slowPauseMs"],
    ["--settle-ms", "settleMs"]
  ]);
  for (let index = 0; index < argv.length; index += 1) {
    const raw = argv[index];
    const [flag, inline] = raw.includes("=") ? raw.split(/=(.*)/s, 2) : [raw, null];
    const field = flags.get(flag);
    if (!field) throw new TypeError(`unknown argument: ${raw}`);
    const value = inline ?? argv[++index];
    if (value === undefined) throw new TypeError(`${flag} requires a value`);
    args[field] = value;
  }
  requireCondition(Object.hasOwn(PROFILES, args.profile), "invalid --profile");
  requireCondition(args.output.length > 0, "--output is required");
  args.runId ||= `weaknet-event-${args.profile}`;
  requireCondition(/^[A-Za-z0-9._-]{1,120}$/.test(args.runId),
    "--run-id must match [A-Za-z0-9._-]{1,120}");
  requireCondition(/^https?:\/\//.test(args.dashboardUrl),
    "--dashboard-url must use http:// or https://");
  requireCondition(/^\[[^\]]+\]:\d+$/.test(args.controlAddress)
    || /^[^:]+:\d+$/.test(args.controlAddress),
  "--control-address must be HOST:PORT");

  const defaults = PROFILES[args.profile];
  for (const field of ["fastEvents", "fastIntervalUs", "collisionEvents", "pressureEvents",
    "pressureIntervalUs", "payloadBytes", "slowPauseMs", "settleMs"]) {
    args[field] = args[field] === null ? defaults[field] : args[field];
  }
  args.fastEvents = parseInteger(args.fastEvents, "--fast-events", { min: 1, max: 100000 });
  args.fastIntervalUs = parseInteger(args.fastIntervalUs, "--fast-interval-us", { max: 1000000 });
  args.collisionEvents = parseInteger(args.collisionEvents,
    "--collision-events", { min: 2, max: 100000 });
  args.pressureEvents = parseInteger(args.pressureEvents, "--pressure-events", { min: 1, max: 100000 });
  args.pressureIntervalUs = parseInteger(args.pressureIntervalUs,
    "--pressure-interval-us", { max: 1000000 });
  args.payloadBytes = parseInteger(args.payloadBytes, "--payload-bytes", { max: 65536 });
  args.slowPauseMs = parseInteger(args.slowPauseMs, "--slow-pause-ms", { min: 1, max: 60000 });
  args.settleMs = parseInteger(args.settleMs, "--settle-ms", { min: 100, max: 120000 });
  args.timeoutMs = parseInteger(args.timeoutMs, "--timeout-ms", { min: 100, max: 120000 });
  args.expectedDashboardCap = parseInteger(args.expectedDashboardCap,
    "--expected-dashboard-cap", { min: 1, max: 1000000 });
  return args;
}

// 把 HOST:PORT 或 [IPv6]:PORT 拆成 net.createConnection 所需的 host/port 对象。
function splitHostPort(value) {
  if (value.startsWith("[")) {
    const end = value.lastIndexOf("]:");
    return { host: value.slice(1, end), port: Number(value.slice(end + 2)) };
  }
  const separator = value.lastIndexOf(":");
  return { host: value.slice(0, separator), port: Number(value.slice(separator + 1)) };
}

// 将浮点指标收敛到六位小数，减少跨机器报告中的无意义浮点差异。
function round(value) {
  return Number(value.toFixed(6));
}

// 对数值样本排序并线性插值分位点；空样本返回 null。
function percentile(values, quantile) {
  if (values.length === 0) return null;
  const ordered = [...values].sort((left, right) => left - right);
  const position = (ordered.length - 1) * quantile;
  const lower = Math.floor(position);
  const upper = Math.ceil(position);
  if (lower === upper) return ordered[lower];
  return ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower);
}

// 把原始延迟数组聚合成样本数及 p50/p95/p99/max，供各阶段统一输出。
function latencySummary(values) {
  return {
    samples: values.length,
    p50: values.length ? round(percentile(values, 0.50)) : null,
    p95: values.length ? round(percentile(values, 0.95)) : null,
    p99: values.length ? round(percentile(values, 0.99)) : null,
    max: values.length ? round(Math.max(...values)) : null
  };
}

const wallAnchorNs = BigInt(Date.now()) * 1000000n;
const monotonicAnchorNs = process.hrtime.bigint();
// 用启动时 Unix 时间锚定单调时钟，返回不受系统时间回拨影响的近似 Unix 纳秒。
function unixNowNs() {
  return wallAnchorNs + (process.hrtime.bigint() - monotonicAnchorNs);
}

// 有界轮询使用的异步等待；输入毫秒数，返回到期后完成的 Promise。
function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// 先写同目录临时文件再 rename，避免进程异常时留下可被误读的半份 JSON。
function atomicWriteJson(filePath, document) {
  const absolute = path.resolve(filePath);
  fs.mkdirSync(path.dirname(absolute), { recursive: true });
  const temporary = `${absolute}.tmp-${process.pid}`;
  fs.writeFileSync(temporary, `${JSON.stringify(document, null, 2)}\n`, "utf8");
  fs.renameSync(temporary, absolute);
}

// 向 C++ driver 的 TCP 控制口发送一行命令并读取一行 JSON；超时、超大响应或拒绝均 reject。
function controlCommand(address, command, timeoutMs) {
  const { host, port } = splitHostPort(address);
  return new Promise((resolve, reject) => {
    let settled = false;
    let body = "";
    const socket = net.createConnection({ host, port });
    // 控制命令必须有硬超时，否则 driver 卡住会让整次压力测试永久悬挂。
    const timer = setTimeout(() => finish(new Error(
      `driver control timeout after ${timeoutMs}ms for ${command.split("\t", 1)[0]}`
    )), timeoutMs);
    const finish = (error, value = null) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.destroy();
      if (error) reject(error);
      else resolve(value);
    };
    socket.setNoDelay(true);
    socket.on("connect", () => socket.write(`${command}\n`));
    socket.on("data", (chunk) => {
      body += chunk.toString("utf8");
      if (body.length > 1024 * 1024) {
        finish(new Error("driver control response exceeded 1 MiB"));
        return;
      }
      const newline = body.indexOf("\n");
      if (newline === -1) return;
      try {
        const parsed = JSON.parse(body.slice(0, newline));
        if (!parsed.ok) throw new Error(parsed.error || "driver rejected command");
        finish(null, parsed);
      } catch (error) {
        finish(error);
      }
    });
    socket.on("error", (error) => finish(error));
    socket.on("end", () => {
      if (!settled) finish(new Error("driver closed control socket without a complete response"));
    });
  });
}

// macOS 与 Lima 来宾系统的墙钟可能有偏移。通过多次 PING 选择最小 RTT 样本估算偏移，
// 返回 offset/uncertainty；所选 RTT 的一半作为显式误差界，避免污染端到端延迟。
async function calibrateClock(address, timeoutMs, samples = 9) {
  const candidates = [];
  for (let index = 0; index < samples; index += 1) {
    const hostBefore = unixNowNs();
    const response = await controlCommand(address, "PING", timeoutMs);
    const hostAfter = unixNowNs();
    requireCondition(/^\d+$/.test(String(response.server_unix_ns ?? "")),
      "driver PING lacks server_unix_ns; rebuild event_pipeline_driver");
    const server = BigInt(response.server_unix_ns);
    const rtt = hostAfter - hostBefore;
    const midpoint = hostBefore + rtt / 2n;
    candidates.push({
      rttNs: rtt,
      offsetNs: server - midpoint
    });
  }
  candidates.sort((left, right) => left.rttNs < right.rttNs ? -1 : 1);
  const selected = candidates[0];
  return {
    samples,
    offsetNs: selected.offsetNs,
    uncertaintyNs: selected.rttNs / 2n,
    offset_ms: round(Number(selected.offsetNs) / 1e6),
    selected_rtt_ms: round(Number(selected.rttNs) / 1e6),
    uncertainty_ms: round(Number(selected.rttNs / 2n) / 1e6)
  };
}

// 在 timeoutMs 内 GET JSON；HTTP 非 2xx、解析失败或 Abort 都向调用方抛错。
async function fetchJson(url, timeoutMs) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(url, { signal: controller.signal });
    if (!response.ok) throw new Error(`${url} returned HTTP ${response.status}`);
    return await response.json();
  } finally {
    clearTimeout(timer);
  }
}

// 轮询 /api/status，直到 Dashboard 明确返回 ok=true 和合法 eventCount；返回首个有效状态。
async function waitForDashboard(baseUrl, timeoutMs) {
  const deadline = performance.now() + timeoutMs;
  let lastError = null;
  while (performance.now() < deadline) {
    try {
      const status = await fetchJson(`${baseUrl.replace(/\/$/, "")}/api/status`,
        Math.min(1000, timeoutMs));
      requireCondition(status?.ok === true, "Dashboard /api/status did not report ok=true");
      requireCondition(Number.isInteger(status.eventCount) && status.eventCount >= 0,
        "Dashboard /api/status eventCount is invalid");
      return status;
    } catch (error) {
      lastError = error;
      await sleep(50);
    }
  }
  throw new Error(`Dashboard did not become ready: ${lastError?.message || "timeout"}`);
}

// 将 Dashboard HTTP 基址转换为 /ws/events 的 ws/wss URL。
function websocketUrl(dashboardUrl) {
  const url = new URL(dashboardUrl);
  url.protocol = url.protocol === "https:" ? "wss:" : "ws:";
  url.pathname = `${url.pathname.replace(/\/$/, "")}/ws/events`;
  url.search = "";
  url.hash = "";
  return url.toString();
}

// 建立一个按 runId 过滤的 WebSocket 采集器；返回握手、分阶段记录、暂停/恢复和清理接口。
function connectCollector(url, runId, timeoutMs, label) {
  const socket = new WebSocket(url, { perMessageDeflate: false });
  const records = [];
  const parseErrors = [];
  let hello = null;
  let closed = false;
  let closeCode = null;
  let closeReason = "";
  let opened = false;
  let openResolve;
  let openReject;
  const openPromise = new Promise((resolve, reject) => {
    openResolve = resolve;
    openReject = reject;
  });
  const timer = setTimeout(() => openReject(new Error(
    `${label} WebSocket did not receive hello within ${timeoutMs}ms`
  )), timeoutMs);

  socket.on("open", () => { opened = true; });
  socket.on("message", (raw) => {
    const receivedAtNs = unixNowNs();
    try {
      const envelope = JSON.parse(raw.toString());
      if (envelope.type === "hello") {
        if (hello === null) {
          hello = envelope;
          clearTimeout(timer);
          openResolve(envelope);
        }
        return;
      }
      if (envelope.type !== "event" || !envelope.event) return;
      let details;
      try {
        details = JSON.parse(envelope.event.details || "{}");
      } catch (error) {
        parseErrors.push(`details JSON: ${error.message}`);
        return;
      }
      // run_id + benchmark tag 是事件相关性的核心：并行/历史流量不能混入本次统计。
      if (details.benchmark !== "weaknet.event.pipeline.v1" || details.run_id !== runId) return;
      const transportSequence = envelope.event.sequence
        ?? envelope.event.sequenceId ?? envelope.event.sequence_id ?? null;
      const transportDroppedCount = envelope.event.droppedCount
        ?? envelope.event.dropped_count ?? envelope.event.dropCount
        ?? envelope.event.drop_count ?? null;
      const transportGapCount = envelope.event.gapCount
        ?? envelope.event.gap_count ?? null;
      const transportGapDetected = envelope.event.gapDetected
        ?? envelope.event.gap_detected ?? null;
      records.push({
        id: String(envelope.event.id ?? ""),
        phase: String(details.phase ?? ""),
        sequence: Number(details.sequence),
        injectedAtUnixNs: String(details.injected_at_unix_ns ?? ""),
        receivedAtUnixNs: receivedAtNs.toString(),
        message: String(envelope.event.message ?? ""),
        type: String(envelope.event.type ?? ""),
        counter: Number(envelope.event.counter),
        timestamp: Number(envelope.event.timestamp),
        transportSequence,
        transportDroppedCount,
        transportGapCount,
        transportGapDetected
      });
    } catch (error) {
      parseErrors.push(`envelope JSON: ${error.message}`);
    }
  });
  socket.on("error", (error) => {
    if (!hello) {
      clearTimeout(timer);
      openReject(error);
    } else {
      parseErrors.push(`socket: ${error.message}`);
    }
  });
  socket.on("close", (code, reason) => {
    closed = true;
    closeCode = Number(code);
    closeReason = reason.toString();
  });

  return {
    label,
    socket,
    records,
    parseErrors,
    waitForHello: () => openPromise,
    phaseRecords: (phase) => records.filter((record) => record.phase === phase),
    // 暂停底层 TCP socket 的读取来模拟真实慢消费者，而不是人为延迟注入端。
    pause() {
      if (!opened || !socket._socket || typeof socket._socket.pause !== "function") return false;
      socket._socket.pause();
      return true;
    },
    resume() {
      if (!socket._socket || typeof socket._socket.resume !== "function") return false;
      socket._socket.resume();
      return true;
    },
    connectionState() {
      return { closed, close_code: closeCode, close_reason: closeReason };
    },
    close() {
      clearTimeout(timer);
      if (!closed) socket.close();
    }
  };
}

// 等待某阶段至少收到 expected 条事件；返回是否在期限内达到目标，不主动抛超时。
async function waitForPhaseCount(collector, phase, expected, timeoutMs) {
  const deadline = performance.now() + timeoutMs;
  while (performance.now() < deadline) {
    if (collector.phaseRecords(phase).length >= expected) return true;
    await sleep(10);
  }
  return collector.phaseRecords(phase).length >= expected;
}

// 等到目标条数或连续 quietMs 无新增；用于在有丢包时仍能有界结束并统计缺口。
async function waitUntilQuiet(collector, phase, expected, timeoutMs, quietMs = 300) {
  const deadline = performance.now() + timeoutMs;
  let previous = -1;
  let changedAt = performance.now();
  while (performance.now() < deadline) {
    const count = collector.phaseRecords(phase).length;
    if (count >= expected) return;
    if (count !== previous) {
      previous = count;
      changedAt = performance.now();
    } else if (performance.now() - changedAt >= quietMs) {
      return;
    }
    await sleep(25);
  }
}

// 校验一个注入阶段的 payload/顺序/唯一性，并结合跨系统时钟校准生成交付率和延迟摘要。
function summarizePhase(records, injected, clockCalibration) {
  const valid = [];
  let invalidPayloadCount = 0;
  for (const record of records) {
    if (!Number.isSafeInteger(record.sequence) || record.sequence < 0 || record.sequence >= injected
      || !/^\d+$/.test(record.injectedAtUnixNs)) {
      invalidPayloadCount += 1;
      continue;
    }
    valid.push(record);
  }
  const uniqueSequences = new Set(valid.map((record) => record.sequence));
  const uniqueIds = new Set(valid.map((record) => record.id));
  const duplicateSequenceCount = valid.length - uniqueSequences.size;
  const duplicateIdCount = valid.length - uniqueIds.size;
  const missing = [];
  for (let sequence = 0; sequence < injected; sequence += 1) {
    if (!uniqueSequences.has(sequence)) missing.push(sequence);
  }
  let outOfOrderCount = 0;
  let previous = -1;
  for (const record of valid) {
    if (record.sequence < previous) outOfOrderCount += 1;
    previous = record.sequence;
  }
  const latencyMs = [];
  let negativeLatencyCount = 0;
  let withinClockUncertaintyCount = 0;
  for (const record of valid) {
    const hostEquivalentInjected = BigInt(record.injectedAtUnixNs) - clockCalibration.offsetNs;
    const delta = BigInt(record.receivedAtUnixNs) - hostEquivalentInjected;
    if (delta < -clockCalibration.uncertaintyNs) {
      negativeLatencyCount += 1;
    } else {
      if (delta < 0n) withinClockUncertaintyCount += 1;
      latencyMs.push(Number(delta < 0n ? 0n : delta) / 1e6);
    }
  }
  return {
    injected,
    received: valid.length,
    unique_sequence: uniqueSequences.size,
    duplicate_sequence: duplicateSequenceCount,
    unique_id: uniqueIds.size,
    duplicate_id: duplicateIdCount,
    missing_sequence: missing.length,
    missing_sequence_sample: missing.slice(0, 64),
    out_of_order: outOfOrderCount,
    invalid_payload: invalidPayloadCount,
    negative_latency: negativeLatencyCount,
    latency_clamped_within_clock_uncertainty: withinClockUncertaintyCount,
    delivery_rate: injected > 0 ? round(uniqueSequences.size / injected) : 0,
    latency_ms: latencySummary(latencyMs)
  };
}

// 从源码字符串中截取一个具名函数体，供静态能力探测使用；找不到时返回空串。
function extractFunction(source, name, nextName) {
  const start = source.indexOf(`function ${name}`);
  if (start < 0) return "";
  const end = source.indexOf(`function ${nextName}`, start + 1);
  return source.slice(start, end < 0 ? undefined : end);
}

// 去掉源码注释，防止注释里的示例关键字被能力正则误判为真实实现。
function stripSourceComments(source) {
  return source
    .replace(/\/\*[\s\S]*?\*\//g, " ")
    .replace(/(^|[^:])\/\/.*$/gm, "$1");
}

// 检查 proto、gRPC 队列和 Dashboard 源码中的 sequence/drop/backpressure 静态契约。
// 返回逐项证据与 declared buffer cap；这里只证明“实现存在”，运行时证据另行校验。
function inspectCapabilities() {
  const protoSource = fs.readFileSync(path.join(projectRoot, "proto", "weaknet.proto"), "utf8");
  const grpcSource = fs.readFileSync(path.join(projectRoot, "server", "src", "grpc_service.cpp"), "utf8");
  const dashboardSource = fs.readFileSync(path.join(projectRoot, "dashboard", "server", "index.mjs"), "utf8");
  const eventMessage = stripSourceComments(
    protoSource.match(/message\s+NetworkEvent\s*\{([\s\S]*?)\n\}/)?.[1] ?? ""
  );
  const field = (name) => new RegExp(
    `\\b(?:u?int(?:32|64)|s?fixed(?:32|64)|string|bool)\\s+${name}\\s*=`, "i"
  ).test(eventMessage);
  const sequenceSupported = field("sequence") || field("sequence_id");
  const dropTelemetrySupported = field("drop_count") || field("dropped_count")
    || field("gap_count") || field("gap_detected");
  const queueEvictionPresent = /queue\.size\(\)\s*>=\s*kMaxQueuedEvents[\s\S]{0,180}queue\.pop_front\(\)/
    .test(grpcSource);
  const publishStart = grpcSource.indexOf("void GrpcServer::publish");
  const publishEnd = grpcSource.indexOf("void GrpcServer::addSubscriber", publishStart);
  const publishBody = stripSourceComments(grpcSource.slice(publishStart, publishEnd));
  const queueDropTelemetrySupported = /\b(?:drop\w*|gap\w*|evict\w*)\s*(?:\+\+|\+=|\.fetch_add\s*\()/i
    .test(publishBody);
  const broadcastBody = stripSourceComments(
    extractFunction(dashboardSource, "broadcast", "scheduleEventReconnect")
  );
  const websocketBackpressureSupported = /if\s*\([^)]*socket\s*\.\s*bufferedAmount\s*(?:>|>=|===?)[^)]*\)\s*\{[\s\S]{0,400}(?:socket\s*\.\s*(?:close|terminate)\s*\(|\bcontinue\b|\breturn\b)/
    .test(broadcastBody);
  const declaredCap = Number(dashboardSource.match(/const\s+maxEvents\s*=\s*(\d+)/)?.[1] ?? NaN);
  const errors = [];
  if (!sequenceSupported) errors.push("NetworkEvent lacks a first-class sequence field");
  if (!dropTelemetrySupported) errors.push("NetworkEvent lacks drop/gap telemetry fields");
  if (queueEvictionPresent && !queueDropTelemetrySupported) {
    errors.push("GrpcServer evicts its subscriber queue without observable drop/gap telemetry");
  }
  if (!websocketBackpressureSupported) {
    errors.push("Dashboard WebSocket broadcast has no bufferedAmount/drain backpressure policy");
  }
  return {
    protocol_sequence_static_contract_observed: sequenceSupported,
    protocol_drop_gap_telemetry_static_contract_observed: dropTelemetrySupported,
    server_bounded_queue_eviction_present: queueEvictionPresent,
    server_queue_drop_telemetry_static_contract_observed: queueDropTelemetrySupported,
    dashboard_websocket_backpressure_static_contract_observed: websocketBackpressureSupported,
    dashboard_declared_buffer_cap: Number.isFinite(declaredCap) ? declaredCap : null,
    static_contract_pass: errors.length === 0,
    errors
  };
}

// 按候选 key 顺序提取第一个有限数值；用于兼容遥测字段的 camel/snake 命名。
function firstFiniteNumber(object, keys) {
  if (!object || typeof object !== "object") return null;
  for (const key of keys) {
    const raw = object[key];
    if (raw === null || raw === undefined || raw === "") continue;
    const value = Number(raw);
    if (Number.isFinite(value)) return value;
  }
  return null;
}

// 静态源码命中只是设计线索。只有未改造的 WebSocket payload 暴露一等 sequence/drop/gap，
// 且慢消费者运行状态证明越过水位或执行过关闭/丢弃动作，相关能力门禁才允许通过。
function inspectRuntimeCapabilityEvidence(records, injected, missing, dashboardStatus, slowState) {
  const transportSequences = records.map((record) => record.transportSequence === null
    || record.transportSequence === undefined ? NaN : Number(record.transportSequence));
  const sequenceObserved = records.length > 0
    && transportSequences.every((value) => Number.isSafeInteger(value) && value >= 0)
    && new Set(transportSequences).size === records.length;

  const eventDropValues = records.flatMap((record) => [
    record.transportDroppedCount, record.transportGapCount
  ]).filter((value) => value !== null && value !== undefined && value !== "")
    .map(Number).filter((value) => Number.isFinite(value) && value >= 0);
  const eventGapDetected = records.some((record) => record.transportGapDetected === true);
  const deliveryTelemetry = dashboardStatus?.eventDeliveryTelemetry
    ?? dashboardStatus?.event_delivery_telemetry ?? null;
  const statusDropValue = firstFiniteNumber(deliveryTelemetry, [
    "droppedCount", "dropped_count", "dropCount", "drop_count",
    "gapCount", "gap_count"
  ]);
  const reportedDropOrGap = Math.max(0, ...eventDropValues,
    statusDropValue === null ? 0 : statusDropValue);
  const dropTelemetryObserved = eventDropValues.length > 0 || statusDropValue !== null
    || eventGapDetected || deliveryTelemetry?.gapDetected === true
    || deliveryTelemetry?.gap_detected === true;
  const dropGapReconciled = dropTelemetryObserved
    && (missing === 0 || reportedDropOrGap >= missing || eventGapDetected
      || deliveryTelemetry?.gapDetected === true || deliveryTelemetry?.gap_detected === true);

  const websocketTelemetry = dashboardStatus?.websocketBackpressure
    ?? dashboardStatus?.websocket_backpressure ?? null;
  const highWatermark = firstFiniteNumber(websocketTelemetry, [
    "highWatermarkBytes", "high_watermark_bytes", "maxBufferedBytes", "max_buffered_bytes"
  ]);
  const peakBuffered = firstFiniteNumber(websocketTelemetry, [
    "peakBufferedBytes", "peak_buffered_bytes", "maxObservedBufferedBytes",
    "max_observed_buffered_bytes"
  ]);
  const actionCount = firstFiniteNumber(websocketTelemetry, [
    "actionCount", "action_count", "slowConsumerCloseCount", "slow_consumer_close_count",
    "overLimitCount", "over_limit_count", "dropCount", "drop_count"
  ]);
  const backpressureConfigured = websocketTelemetry?.enabled === true
    && highWatermark !== null && highWatermark > 0;
  const backpressureActionObserved = backpressureConfigured
    && ((actionCount !== null && actionCount > 0)
      || (peakBuffered !== null && peakBuffered >= highWatermark)
      || (slowState.closed && slowState.close_code !== null));

  const errors = [];
  if (!sequenceObserved) {
    errors.push("runtime payload lacks a unique first-class transport sequence");
  }
  if (!dropGapReconciled) {
    errors.push("runtime payload/status does not reconcile delivery loss with drop/gap telemetry");
  }
  if (!backpressureActionObserved) {
    errors.push("runtime status does not prove a configured WebSocket backpressure action");
  }
  return {
    injected,
    received: records.length,
    missing,
    first_class_sequence_observed: sequenceObserved,
    drop_gap_telemetry_observed: dropTelemetryObserved,
    reported_drop_or_gap: reportedDropOrGap,
    drop_gap_reconciled: dropGapReconciled,
    websocket_backpressure_configured: backpressureConfigured,
    websocket_high_watermark_bytes: highWatermark,
    websocket_peak_buffered_bytes: peakBuffered,
    websocket_action_count: actionCount,
    websocket_backpressure_action_observed: backpressureActionObserved,
    correctness_pass: sequenceObserved && dropGapReconciled && backpressureActionObserved,
    errors
  };
}

// 把启动期/基础设施异常也落成统一 schema 的失败文档；返回可直接写盘的对象。
function buildFailureDocument(args, startedAt, started, error) {
  return {
    schema_version: SCHEMA_VERSION,
    component: "event-pipeline-live",
    profile: args.profile,
    mode: "live",
    environment: {
      system: os.type(), release: os.release(), machine: os.arch(), cpu_count: os.cpus().length,
      node: process.version, pid: process.pid
    },
    started_at: startedAt,
    duration_ms: round(performance.now() - started),
    benchmarks: [],
    summary: {
      status: "failed", benchmark_count: 0, request_count: 0, success_count: 0,
      failures: 1, error_count: 1, errors: 1, correctness_pass: false,
      error_messages: [error?.stack || String(error)]
    }
  };
}

// 编排完整 live 事件测试并返回进程退出码：0 为全部门禁通过，2 为有效报告但产品门禁失败。
async function run(args) {
  const startedAt = new Date().toISOString();
  const started = performance.now();
  const outputPath = path.resolve(args.output);
  fs.rmSync(outputPath, { force: true });
  const capability = inspectCapabilities();
  const runtimeErrors = [];
  const fastPhase = "fast";
  const collisionPhase = "id-collision";
  const pressurePhase = "pressure";
  let fastCollector = null;
  let slowCollector = null;

  try {
    // 先校准 host/guest 时钟并确认 Dashboard ready，之后所有延迟才有可解释性。
    const clockCalibration = await calibrateClock(args.controlAddress, args.timeoutMs);
    const initialStatus = await waitForDashboard(args.dashboardUrl, args.timeoutMs);
    fastCollector = connectCollector(websocketUrl(args.dashboardUrl), args.runId,
      args.timeoutMs, "fast consumer");
    await fastCollector.waitForHello();

    // WebSocket hello 只证明 HTTP/WS 已连通；额外注入握手事件才能证明 gRPC 订阅链已接上。
    let handshakeObserved = false;
    for (let attempt = 0; attempt < 20 && !handshakeObserved; attempt += 1) {
      const phase = `handshake-${attempt}`;
      await controlCommand(args.controlAddress,
        `INJECT\t${args.runId}\t${phase}\t1\t0\t0`, args.timeoutMs);
      handshakeObserved = await waitForPhaseCount(fastCollector, phase, 1, 150);
    }
    requireCondition(handshakeObserved,
      "Dashboard gRPC subscription did not deliver any injected handshake event");

    // 快消费者阶段建立“无刻意背压”基线，并校验全量、顺序、ID 唯一和端到端延迟。
    const statusBeforeFast = await fetchJson(
      `${args.dashboardUrl.replace(/\/$/, "")}/api/status`, args.timeoutMs);
    const fastInjection = await controlCommand(args.controlAddress,
      `INJECT\t${args.runId}\t${fastPhase}\t${args.fastEvents}\t${args.fastIntervalUs}\t0`,
      Math.max(args.timeoutMs, Math.ceil(args.fastEvents * args.fastIntervalUs / 1000) + args.timeoutMs));
    await waitForPhaseCount(fastCollector, fastPhase, args.fastEvents, args.settleMs);
    await waitUntilQuiet(fastCollector, fastPhase, args.fastEvents, args.settleMs);
    const fastStats = summarizePhase(
      fastCollector.phaseRecords(fastPhase), args.fastEvents, clockCalibration);
    // 固定 timestamp/counter/type，仅让语义 sequence/message 变化，精准复现 Dashboard ID 冲突。
    const collisionInjection = await controlCommand(args.controlAddress,
      `INJECT_FIXED_TUPLE\t${args.runId}\t${collisionPhase}`
        + `\t${args.collisionEvents}\t0\t0`, args.timeoutMs);
    await waitForPhaseCount(fastCollector, collisionPhase, args.collisionEvents, args.settleMs);
    await waitUntilQuiet(fastCollector, collisionPhase, args.collisionEvents, args.settleMs);
    const collisionStats = summarizePhase(
      fastCollector.phaseRecords(collisionPhase), args.collisionEvents, clockCalibration);
    const statusBeforePressure = await fetchJson(
      `${args.dashboardUrl.replace(/\/$/, "")}/api/status`, args.timeoutMs);

    // 第二个连接暂停 TCP 读取制造慢消费者；快速连接保持读取，用于区分全局丢失和单连接背压。
    slowCollector = connectCollector(websocketUrl(args.dashboardUrl), args.runId,
      args.timeoutMs, "slow consumer");
    await slowCollector.waitForHello();
    const slowPausedAt = performance.now();
    const slowPauseSupported = slowCollector.pause();
    if (!slowPauseSupported) runtimeErrors.push("slow consumer transport could not be paused");

    // 压力命令超时包含理论注入时长，既容纳配置间隔，又保留固定额外超时上限。
    const pressureInjection = await controlCommand(args.controlAddress,
      `INJECT\t${args.runId}\t${pressurePhase}\t${args.pressureEvents}`
        + `\t${args.pressureIntervalUs}\t${args.payloadBytes}`,
      Math.max(args.timeoutMs,
        Math.ceil(args.pressureEvents * args.pressureIntervalUs / 1000) + args.timeoutMs));
    await waitUntilQuiet(fastCollector, pressurePhase, args.pressureEvents, args.settleMs, 500);
    const pauseElapsedMs = performance.now() - slowPausedAt;
    if (pauseElapsedMs < args.slowPauseMs) await sleep(args.slowPauseMs - pauseElapsedMs);
    const statusAfterPressure = await fetchJson(
      `${args.dashboardUrl.replace(/\/$/, "")}/api/status`, args.timeoutMs);
    const slowResumedAt = performance.now();
    const slowResumeSupported = slowCollector.resume();
    await waitUntilQuiet(slowCollector, pressurePhase, args.pressureEvents,
      args.settleMs, 750);

    const pressureFastStats = summarizePhase(
      fastCollector.phaseRecords(pressurePhase), args.pressureEvents, clockCalibration);
    const pressureSlowStats = summarizePhase(
      slowCollector.phaseRecords(pressurePhase), args.pressureEvents, clockCalibration);
    const slowPauseActualMs = slowResumedAt - slowPausedAt;
    const slowConnectionState = slowCollector.connectionState();
    const runtimeCapability = inspectRuntimeCapabilityEvidence(
      fastCollector.phaseRecords(pressurePhase),
      args.pressureEvents,
      pressureFastStats.missing_sequence,
      statusAfterPressure,
      slowConnectionState
    );
    const capabilityErrors = [...capability.errors, ...runtimeCapability.errors];
    const capabilityCorrectnessPass = capability.static_contract_pass
      && runtimeCapability.correctness_pass;
    // Dashboard 只保留最近 300 条事件：同时核对源码声明、API 计数不越界和应饱和时恰好到 cap。
    const sourceCap = capability.dashboard_declared_buffer_cap;
    const effectiveCap = sourceCap ?? args.expectedDashboardCap;
    const bufferCountValid = [initialStatus, statusBeforeFast, statusBeforePressure,
      statusAfterPressure].every((status) => Number.isInteger(status.eventCount)
        && status.eventCount >= 0 && status.eventCount <= effectiveCap);
    const enoughToSaturate = statusBeforePressure.eventCount
      + pressureFastStats.unique_sequence >= effectiveCap;
    const capReachedWhenExpected = !enoughToSaturate
      || statusAfterPressure.eventCount === effectiveCap;
    const capMatchesExpected = sourceCap === args.expectedDashboardCap;
    const bufferCapPass = bufferCountValid && capReachedWhenExpected && capMatchesExpected;

    const fastErrors = [];
    if (fastInjection.injected !== args.fastEvents) fastErrors.push("driver injected count mismatch");
    if (fastStats.unique_sequence !== args.fastEvents) fastErrors.push("fast consumer lost events");
    if (fastStats.duplicate_sequence !== 0) fastErrors.push("fast consumer saw duplicate sequence");
    if (fastStats.duplicate_id !== 0) fastErrors.push("Dashboard generated duplicate event ids");
    if (fastStats.out_of_order !== 0) fastErrors.push("fast consumer saw out-of-order events");
    if (fastStats.invalid_payload !== 0) fastErrors.push("fast consumer saw invalid benchmark payload");
    if (fastStats.negative_latency !== 0) fastErrors.push("cross-host clock produced negative latency");
    if (fastCollector.parseErrors.length !== 0) fastErrors.push(...fastCollector.parseErrors);
    const fastPass = fastErrors.length === 0;

    // 先证明每个不同语义事件都准确到达，再判断相同 tuple 是否导致外部 ID 碰撞。
    const collisionErrors = [];
    const collisionRecords = fastCollector.phaseRecords(collisionPhase);
    const collisionIdentityTuples = new Set(collisionRecords.map((record) =>
      `${record.timestamp}|${record.counter}|${record.type}`));
    const collisionMessages = new Set(collisionRecords.map((record) => record.message));
    const fixedTupleVerified = collisionRecords.length === args.collisionEvents
      && collisionIdentityTuples.size === 1;
    const distinctSemanticsVerified = collisionMessages.size === args.collisionEvents;
    const collisionMeasurementPass = collisionInjection.injected === args.collisionEvents
      && collisionStats.unique_sequence === args.collisionEvents
      && collisionStats.duplicate_sequence === 0
      && collisionStats.missing_sequence === 0
      && collisionStats.invalid_payload === 0
      && fixedTupleVerified
      && distinctSemanticsVerified;
    const collisionReproduced = collisionMeasurementPass
      && collisionStats.duplicate_id === args.collisionEvents - 1
      && collisionStats.unique_id === 1;
    const collisionCorrectnessPass = collisionMeasurementPass
      && collisionStats.unique_id === args.collisionEvents
      && collisionStats.duplicate_id === 0;
    if (!collisionMeasurementPass) {
      collisionErrors.push("constant-tuple collision probe did not deliver every semantic sequence exactly once");
    }
    if (!fixedTupleVerified) collisionErrors.push("collision probe identity tuple was not constant");
    if (!distinctSemanticsVerified) collisionErrors.push("collision probe semantic messages were not distinct");
    if (collisionStats.duplicate_id > 0) {
      collisionErrors.push(
        `Dashboard event id is not unique: ${collisionStats.duplicate_id} distinct semantic events `
          + "share timestamp-counter-type ids"
      );
    }

    // 测量有效性、两类消费者交付完整性和可观测背压能力分别判定，避免互相掩盖。
    const pressureMeasurementErrors = [];
    if (pressureInjection.injected !== args.pressureEvents) {
      pressureMeasurementErrors.push("driver pressure injected count mismatch");
    }
    if (!slowPauseSupported || !slowResumeSupported) {
      pressureMeasurementErrors.push("slow consumer pause/resume failed");
    }
    if (!bufferCapPass) pressureMeasurementErrors.push("Dashboard eventBuffer cap assertion failed");
    if (pressureFastStats.invalid_payload !== 0 || pressureSlowStats.invalid_payload !== 0) {
      pressureMeasurementErrors.push("pressure path produced invalid benchmark payload");
    }
    if (fastCollector.parseErrors.length !== 0 || slowCollector.parseErrors.length !== 0) {
      pressureMeasurementErrors.push("WebSocket collector parse errors occurred");
    }
    const pressureMeasurementPass = pressureMeasurementErrors.length === 0;
    const fastPressureDeliveryPass = pressureFastStats.unique_sequence === args.pressureEvents
      && pressureFastStats.duplicate_sequence === 0
      && pressureFastStats.duplicate_id === 0
      && pressureFastStats.out_of_order === 0;
    const slowPressureDeliveryPass = pressureSlowStats.unique_sequence === args.pressureEvents
      && pressureSlowStats.duplicate_sequence === 0
      && pressureSlowStats.duplicate_id === 0
      && pressureSlowStats.out_of_order === 0
      && !slowConnectionState.closed;
    const pressureDeliveryPass = fastPressureDeliveryPass && slowPressureDeliveryPass;
    const pressureCapabilityPass = capabilityCorrectnessPass;
    const pressureErrors = [...pressureMeasurementErrors];
    if (!pressureDeliveryPass) {
      pressureErrors.push(
        `pressure delivery incomplete: fast=${pressureFastStats.unique_sequence}/${args.pressureEvents}, `
          + `slow=${pressureSlowStats.unique_sequence}/${args.pressureEvents}`
      );
    }
    if (!pressureCapabilityPass) {
      pressureErrors.push(
        "loss cannot be safely attributed because sequence/drop/gap telemetry or WebSocket backpressure is unsupported"
      );
    }
    const pressureCorrectnessPass = pressureMeasurementPass
      && pressureDeliveryPass && pressureCapabilityPass;

    const benchmarks = [
      {
        name: "event_pipeline.fast_consumer_live",
        status: fastPass ? "passed" : "failed",
        transport_path: ["NetworkEventManager", "EventPublisher", "GrpcServer subscriber queue",
          "gRPC SubscribeEvents", "Dashboard eventBuffer", "WebSocket"],
        run_id: args.runId,
        requests: args.fastEvents,
        success_count: fastStats.unique_sequence,
        injected: fastStats.injected,
        received: fastStats.received,
        unique_id: fastStats.unique_id,
        duplicate_id: fastStats.duplicate_id,
        unique_sequence: fastStats.unique_sequence,
        duplicate_sequence: fastStats.duplicate_sequence,
        missing_sequence: fastStats.missing_sequence,
        missing_sequence_sample: fastStats.missing_sequence_sample,
        out_of_order: fastStats.out_of_order,
        delivery_rate: fastStats.delivery_rate,
        latency_ms: fastStats.latency_ms,
        driver_injection_duration_ms: Number(fastInjection.duration_ms),
        correctness_pass: fastPass,
        error_count: fastErrors.length,
        errors: fastErrors
      },
      {
        name: "event_pipeline.dashboard_id_collision",
        // A product fix must be able to turn this gate green: all semantic
        // events must arrive and every externally exposed id must be unique.
        status: collisionCorrectnessPass ? "passed" : "failed",
        run_id: args.runId,
        requests: args.collisionEvents,
        success_count: collisionStats.unique_sequence,
        injected: collisionStats.injected,
        received: collisionStats.received,
        unique_sequence: collisionStats.unique_sequence,
        duplicate_sequence: collisionStats.duplicate_sequence,
        unique_id: collisionStats.unique_id,
        duplicate_id: collisionStats.duplicate_id,
        missing_sequence: collisionStats.missing_sequence,
        delivery_rate: collisionStats.delivery_rate,
        latency_ms: collisionStats.latency_ms,
        fixed_tuple: ["timestamp", "counter", "type"],
        distinct_semantics: ["details.sequence", "message"],
        observed_identity_tuple_count: collisionIdentityTuples.size,
        observed_distinct_message_count: collisionMessages.size,
        fixed_tuple_verified: fixedTupleVerified,
        distinct_semantics_verified: distinctSemanticsVerified,
        measurement_pass: collisionMeasurementPass,
        collision_reproduced: collisionReproduced,
        correctness_pass: collisionCorrectnessPass,
        error_count: collisionErrors.length,
        errors: collisionErrors
      },
      {
        name: "event_pipeline.slow_consumer_bounded_pressure",
        status: pressureCorrectnessPass ? "passed" : "failed",
        run_id: args.runId,
        requests: args.pressureEvents,
        success_count: pressureFastStats.unique_sequence,
        injected: pressureFastStats.injected,
        fast_consumer: pressureFastStats,
        slow_consumer: pressureSlowStats,
        payload_bytes: args.payloadBytes,
        total_injected_payload_bytes: args.pressureEvents * args.payloadBytes,
        slow_socket_pause_supported: slowPauseSupported,
        slow_socket_resume_supported: slowResumeSupported,
        slow_socket_paused_for_ms: round(slowPauseActualMs),
        slow_connection: {
          ...slowConnectionState,
          observable_drop_count: null,
          observable_gap_count: null,
          drop_reconciliation_supported: false
        },
        driver_injection_duration_ms: Number(pressureInjection.duration_ms),
        dashboard_buffer: {
          initial_count: initialStatus.eventCount,
          before_fast_count: statusBeforeFast.eventCount,
          before_pressure_count: statusBeforePressure.eventCount,
          after_pressure_count: statusAfterPressure.eventCount,
          source_declared_cap: sourceCap,
          expected_cap: args.expectedDashboardCap,
          cap_matches_expected: capMatchesExpected,
          count_never_exceeded_cap: bufferCountValid,
          saturation_expected: enoughToSaturate,
          cap_reached_when_expected: capReachedWhenExpected,
          correctness_pass: bufferCapPass
        },
        measurement_pass: pressureMeasurementPass,
        fast_delivery_pass: fastPressureDeliveryPass,
        slow_delivery_pass: slowPressureDeliveryPass,
        delivery_pass: pressureDeliveryPass,
        capability_supported: pressureCapabilityPass,
        correctness_pass: pressureCorrectnessPass,
        error_count: pressureErrors.length,
        errors: pressureErrors
      },
      {
        name: "event_pipeline.loss_and_backpressure_contract",
        status: capabilityCorrectnessPass ? "passed" : "failed",
        ...capability,
        runtime_evidence: runtimeCapability,
        correctness_pass: capabilityCorrectnessPass,
        errors: capabilityErrors,
        error_count: capabilityErrors.length
      }
    ];

    const errorMessages = [...runtimeErrors, ...fastErrors, ...collisionErrors,
      ...pressureErrors, ...capabilityErrors];
    const requestCount = args.fastEvents + args.collisionEvents + args.pressureEvents;
    const successCount = Math.min(requestCount,
      fastStats.unique_sequence + collisionStats.unique_sequence + pressureFastStats.unique_sequence);
    const correctnessPass = fastPass && collisionCorrectnessPass
      && pressureCorrectnessPass && capabilityCorrectnessPass
      && runtimeErrors.length === 0;
    const document = {
      schema_version: SCHEMA_VERSION,
      component: "event-pipeline-live",
      profile: args.profile,
      mode: "live",
      environment: {
        system: os.type(), release: os.release(), machine: os.arch(),
        cpu_count: os.cpus().length, node: process.version, pid: process.pid,
        dashboard_url: args.dashboardUrl, driver_control_address: args.controlAddress,
        clock: "Unix epoch anchored to process.hrtime.bigint",
        clock_calibration: {
          samples: clockCalibration.samples,
          offset_ms: clockCalibration.offset_ms,
          selected_rtt_ms: clockCalibration.selected_rtt_ms,
          uncertainty_ms: clockCalibration.uncertainty_ms
        }
      },
      started_at: startedAt,
      duration_ms: round(performance.now() - started),
      configuration: {
        run_id: args.runId,
        fast_events: args.fastEvents,
        fast_interval_us: args.fastIntervalUs,
        collision_events: args.collisionEvents,
        pressure_events: args.pressureEvents,
        pressure_interval_us: args.pressureIntervalUs,
        payload_bytes: args.payloadBytes,
        slow_pause_ms: args.slowPauseMs,
        settle_ms: args.settleMs,
        expected_dashboard_cap: args.expectedDashboardCap
      },
      benchmarks,
      summary: {
        status: correctnessPass ? "passed" : "failed",
        benchmark_count: benchmarks.length,
        passed: benchmarks.filter((item) => item.status === "passed").length,
        failed: benchmarks.filter((item) => item.status === "failed").length,
        skipped: 0,
        request_count: requestCount,
        success_count: successCount,
        failures: requestCount - successCount,
        error_count: errorMessages.length,
        errors: errorMessages.length,
        error_messages: errorMessages,
        correctness_pass: correctnessPass,
        fast_path_correctness_pass: fastPass,
        dashboard_id_collision_reproduced: collisionReproduced,
        bounded_pressure_measurement_pass: pressureMeasurementPass,
        loss_gap_protocol_supported: capability.protocol_sequence_static_contract_observed
          && capability.protocol_drop_gap_telemetry_static_contract_observed
          && capability.server_queue_drop_telemetry_static_contract_observed
          && runtimeCapability.first_class_sequence_observed
          && runtimeCapability.drop_gap_reconciled,
        websocket_backpressure_supported:
          capability.dashboard_websocket_backpressure_static_contract_observed
          && runtimeCapability.websocket_backpressure_action_observed
      }
    };
    atomicWriteJson(outputPath, document);
    return correctnessPass ? 0 : 2;
  } catch (error) {
    const failure = buildFailureDocument(args, startedAt, started, error);
    atomicWriteJson(outputPath, failure);
    return 2;
  } finally {
    fastCollector?.close();
    slowCollector?.resume();
    slowCollector?.close();
  }
}

let parsedArgs = null;
try {
  parsedArgs = parseArgs(process.argv.slice(2));
  if (parsedArgs.help) {
    process.stdout.write(USAGE);
    process.exitCode = 0;
  } else {
    process.exitCode = await run(parsedArgs);
  }
} catch (error) {
  process.stderr.write(`${error?.stack || error}\n${USAGE}`);
  if (parsedArgs?.output) {
    atomicWriteJson(parsedArgs.output,
      buildFailureDocument(parsedArgs, new Date().toISOString(), performance.now(), error));
  }
  process.exitCode = 2;
}
