#!/usr/bin/env node
// WeakNet gRPC 与 Dashboard 服务层的正确性/性能压测入口，不依赖额外 benchmark 框架。
//
// 脚本既可对真实 gRPC/HTTP 端点运行，也可用确定性 fixture 自测 harness。普通 unary/HTTP
// 请求按 requests×concurrency 矩阵采样 QPS、延迟、RSS 和契约；SubscribeEvents 单独按连接数
// 档位验证连接、取消与重连生命周期。fixture QPS 只表示 JS 调度/校验开销，不代表线上吞吐。

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import process from "node:process";
import { createRequire } from "node:module";
import { performance } from "node:perf_hooks";
import { fileURLToPath } from "node:url";


const SCHEMA_VERSION = "weaknet.benchmark.v1";
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const projectRoot = path.resolve(__dirname, "..");
// 每个 profile 同时规定请求并发矩阵和独立的流式连接矩阵；CLI 可按需覆盖各维度。
const PROFILES = {
  smoke: { concurrency: [1, 4], requests: [8], warmup: 2, eventConnections: [1, 4] },
  standard: { concurrency: [1, 4, 8, 16], requests: [64, 256], warmup: 8,
    eventConnections: [1, 8, 32] },
  stress: { concurrency: [1, 4, 8, 16], requests: [1000, 5000], warmup: 32,
    eventConnections: [32, 128, 512] }
};
const ALLOWED_DIAGNOSIS_STATUSES = new Set([
  "healthy", "degraded", "unhealthy", "unknown", "insufficient_evidence", "unavailable"
]);
const ALL_TARGETS = new Set([
  "grpc-get", "grpc-interfaces", "grpc-snapshot", "grpc-health", "grpc-ping", "grpc-events",
  "http-snapshot", "http-analyze"
]);
const USAGE = `Usage:
  node benchmarks/service_benchmark.mjs --profile smoke|standard|stress --output FILE [options]

Options:
  --fixture                 Use deterministic contract fixtures (QPS is harness overhead only).
  --grpc-address ADDRESS    gRPC endpoint (default: 127.0.0.1:50051).
  --dashboard-url URL       Dashboard API base URL (default: http://127.0.0.1:5174).
  --ping-target HOST[,HOST] Ping targets, round-robin per request (default: 127.0.0.1).
  --skip-grpc               Skip all gRPC targets.
  --skip-dashboard          Skip Dashboard snapshot/analyze targets.
  --targets LIST            Explicit target names.
  --concurrency LIST        Unary/HTTP concurrency levels.
  --requests LIST           Unary/HTTP request levels.
  --warmup N                Unary/HTTP warmup requests.
  --timeout-ms N            Unary/HTTP timeout.
  --events                  Add the independent stream lifecycle benchmark.
  --event-connections LIST  Concurrent lifecycle connection levels.
  --event-window-ms N       Bounded receive window per connection.
  --event-max-events N      Maximum accepted events per connection.
  --event-timeout-ms N      Channel-ready/cancellation timeout.
  --require-event           Require first events on initial and reconnected streams.
  -h, --help                Show this help and exit successfully.
`;


// 输入布尔条件和错误信息；条件为假时抛 TypeError，为真时无返回值。
function requireCondition(condition, message) {
  if (!condition) throw new TypeError(message);
}

// 输入逗号分隔字符串和参数名；返回正整数数组，格式错误时抛 TypeError。
function parsePositiveInts(value, name) {
  const result = String(value).split(",").filter(Boolean).map((item) => Number(item.trim()));
  if (result.length === 0 || result.some((item) => !Number.isInteger(item) || item <= 0)) {
    throw new TypeError(`${name} requires comma-separated positive integers`);
  }
  return result;
}

// 解析无第三方依赖的 CLI；输入 argv，输出完成类型/范围校验的配置；help 在 --output 前短路。
function parseArgs(argv) {
  if (argv.includes("--help") || argv.includes("-h")) return { help: true };
  const args = {
    profile: "smoke",
    output: "",
    fixture: false,
    grpcAddress: "127.0.0.1:50051",
    dashboardUrl: "http://127.0.0.1:5174",
    pingTarget: "127.0.0.1",
    skipGrpc: false,
    skipDashboard: false,
    events: false,
    requireEvent: false,
    concurrency: null,
    requests: null,
    warmup: null,
    timeoutMs: 5000,
    eventTimeoutMs: 5000,
    eventWindowMs: 50,
    eventMaxEvents: 4,
    eventConnections: null,
    targets: null
  };
  const valueFlags = new Map([
    ["--profile", "profile"], ["--output", "output"], ["--grpc-address", "grpcAddress"],
    ["--dashboard-url", "dashboardUrl"], ["--ping-target", "pingTarget"],
    ["--concurrency", "concurrency"],
    ["--requests", "requests"], ["--warmup", "warmup"], ["--timeout-ms", "timeoutMs"],
    ["--event-timeout-ms", "eventTimeoutMs"], ["--event-window-ms", "eventWindowMs"],
    ["--event-max-events", "eventMaxEvents"], ["--event-connections", "eventConnections"],
    ["--targets", "targets"]
  ]);
  for (let index = 0; index < argv.length; index += 1) {
    const raw = argv[index];
    if (raw === "--fixture") args.fixture = true;
    else if (raw === "--skip-grpc") args.skipGrpc = true;
    else if (raw === "--skip-dashboard") args.skipDashboard = true;
    else if (raw === "--events") args.events = true;
    else if (raw === "--require-event") { args.events = true; args.requireEvent = true; }
    else {
      const [flag, inlineValue] = raw.includes("=") ? raw.split(/=(.*)/s, 2) : [raw, null];
      const field = valueFlags.get(flag);
      if (!field) throw new TypeError(`unknown argument: ${raw}`);
      const value = inlineValue ?? argv[++index];
      if (value === undefined) throw new TypeError(`${flag} requires a value`);
      args[field] = value;
    }
  }
  if (!Object.hasOwn(PROFILES, args.profile)) throw new TypeError("invalid --profile");
  if (!args.output) throw new TypeError("--output is required");
  args.concurrency = args.concurrency ? parsePositiveInts(args.concurrency, "--concurrency") : null;
  args.requests = args.requests ? parsePositiveInts(args.requests, "--requests") : null;
  args.eventConnections = args.eventConnections
    ? parsePositiveInts(args.eventConnections, "--event-connections") : null;
  for (const field of ["warmup", "timeoutMs", "eventTimeoutMs", "eventWindowMs", "eventMaxEvents"]) {
    if (args[field] !== null) args[field] = Number(args[field]);
  }
  requireCondition(args.warmup === null || Number.isInteger(args.warmup) && args.warmup >= 0,
    "--warmup must be a non-negative integer");
  requireCondition(Number.isInteger(args.timeoutMs) && args.timeoutMs > 0,
    "--timeout-ms must be positive");
  requireCondition(Number.isInteger(args.eventTimeoutMs) && args.eventTimeoutMs > 0,
    "--event-timeout-ms must be positive");
  requireCondition(Number.isInteger(args.eventWindowMs) && args.eventWindowMs >= 0,
    "--event-window-ms must be non-negative");
  requireCondition(Number.isInteger(args.eventMaxEvents) && args.eventMaxEvents > 0,
    "--event-max-events must be positive");
  args.pingTargets = [...new Set(
    String(args.pingTarget).split(",").map((item) => item.trim()).filter(Boolean)
  )];
  requireCondition(args.pingTargets.length > 0, "--ping-target must not be empty");
  if (args.targets) {
    args.targets = [...new Set(
      String(args.targets).split(",").map((item) => item.trim()).filter(Boolean)
    )];
    const invalid = args.targets.filter((item) => !ALL_TARGETS.has(item));
    if (invalid.length > 0) throw new TypeError(`invalid targets: ${invalid.join(", ")}`);
    if (args.targets.includes("grpc-events")) args.events = true;
  }
  return args;
}

// 输入数值样本和 0~1 分位；用线性插值返回 percentile，保持 Python/Node 算法一致。
function percentile(values, quantile) {
  if (values.length === 0) return 0;
  const ordered = [...values].sort((left, right) => left - right);
  const position = (ordered.length - 1) * quantile;
  const lower = Math.floor(position);
  const upper = Math.ceil(position);
  if (lower === upper) return ordered[lower];
  return ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower);
}

// 输入 number，返回保留六位小数的 number，避免浮点噪声放大 JSON diff。
function round(value) {
  return Number(value.toFixed(6));
}

// 输入延迟数组，返回统一的 p50/p95/p99/max 指标对象。
function latencySummary(values) {
  return {
    p50: round(percentile(values, 0.50)),
    p95: round(percentile(values, 0.95)),
    p99: round(percentile(values, 0.99)),
    max: values.length > 0 ? round(Math.max(...values)) : 0
  };
}

// 输入任意 JSON 值，递归按 object key 排序并返回稳定字符串，供 fixture 精确指纹使用。
function stableStringify(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(",")}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`).join(",")}}`;
}

// 输入 live 响应，返回只包含字段类型/层级的 shape；允许业务值变化但契约必须稳定。
function contractShape(value) {
  if (value === null) return "null";
  if (Array.isArray(value)) return "array";
  if (typeof value !== "object") return typeof value;
  return Object.fromEntries(Object.keys(value).sort().map((key) => [key, contractShape(value[key])]));
}

// 输入任意值，仅当它是有限 number 时返回 true，严格排除 NaN/Infinity。
function finiteNumber(value) {
  return typeof value === "number" && Number.isFinite(value);
}

// 输入 legacy Get 响应并校验最小连通性契约；成功无返回值，失败抛异常。
function validateGrpcGet(value) {
  requireCondition(value && typeof value === "object", "Get response must be an object");
  requireCondition(typeof value.message === "string" && value.message.length > 0,
    "Get.message must be a non-empty string");
}

// 输入 GetInterfaces 响应并校验列表类型、非空名称和去重；成功无返回值。
function validateGrpcInterfaces(value) {
  requireCondition(value && typeof value === "object", "GetInterfaces response must be an object");
  requireCondition(Array.isArray(value.interfaces), "GetInterfaces.interfaces must be an array");
  requireCondition(value.interfaces.every((item) => typeof item === "string" && item.length > 0),
    "GetInterfaces.interfaces must contain only non-empty strings");
  requireCondition(new Set(value.interfaces).size === value.interfaces.length,
    "GetInterfaces.interfaces must not contain duplicates");
}

// 输入 typed NetworkSnapshot 并校验核心可用性字段；成功无返回值，而非只看 RPC OK。
function validateGrpcSnapshot(value) {
  requireCondition(value && typeof value === "object", "NetworkSnapshot must be an object");
  requireCondition(typeof value.hasActiveInterface === "boolean", "hasActiveInterface must be boolean");
  requireCondition(Array.isArray(value.interfaces), "interfaces must be an array");
  requireCondition(value.quality && typeof value.quality === "object", "quality must be an object");
  requireCondition(value.trafficObservation && typeof value.trafficObservation === "object",
    "trafficObservation must be an object");
  requireCondition(typeof value.observedAtUnixMs === "string" || finiteNumber(value.observedAtUnixMs),
    "observedAtUnixMs must be an int64 string or number");
  requireCondition(typeof value.activeInterface === "string", "activeInterface must be a string");
  requireCondition(typeof value.quality.degraded === "boolean", "quality.degraded must be boolean");
  requireCondition(Array.isArray(value.quality.issues) && Array.isArray(value.quality.missingMetrics),
    "quality issues/missingMetrics must be arrays");
  requireCondition(typeof value.trafficObservation.valid === "boolean",
    "trafficObservation.valid must be boolean");
  for (const item of value.interfaces) {
    requireCondition(item && typeof item === "object", "interface snapshot must be an object");
    requireCondition(typeof item.interfaceName === "string" && item.interfaceName.length > 0,
      "interfaceName must be a non-empty string");
    requireCondition(typeof item.usingNow === "boolean", "interface usingNow must be boolean");
  }
}

// 输入项目自定义 HealthCheck 响应；解析并校验 details 为 JSON object，成功无返回值。
function validateGrpcHealth(value) {
  requireCondition(value && typeof value === "object", "HealthCheck response must be an object");
  requireCondition(typeof value.details === "string", "HealthCheck.details must be a string");
  const details = JSON.parse(value.details);
  requireCondition(details && typeof details === "object" && !Array.isArray(details),
    "HealthCheck.details must contain a JSON object");
}

// 输入 {requestTarget,response}；校验 Ping 业务语义及并发响应归属，成功无返回值。
function validateGrpcPing(value) {
  requireCondition(value && typeof value === "object", "Ping invocation must be an object");
  requireCondition(typeof value.requestTarget === "string" && value.requestTarget.length > 0,
    "Ping request target is missing");
  const response = value.response;
  requireCondition(response && typeof response === "object", "Ping response must be an object");
  requireCondition(typeof response.success === "boolean", "Ping.success must be boolean");
  requireCondition(typeof response.result === "string" && response.result.length > 0,
    "Ping.result must be a non-empty string");
  requireCondition(typeof response.error === "string", "Ping.error must be a string");
  requireCondition(Number.isInteger(response.latencyMs), "Ping.latencyMs must be an integer");
  requireCondition(typeof response.interfaceName === "string" && response.interfaceName.length > 0,
    "Ping.interfaceName must be a non-empty string");
  requireCondition(response.result.includes(value.requestTarget),
    `Ping response is not associated with request target ${value.requestTarget}`);
  if (response.success) {
    requireCondition(response.latencyMs >= 0, "successful Ping must have non-negative latencyMs");
    requireCondition(response.error.length === 0, "successful Ping must have an empty error");
  } else {
    requireCondition(response.latencyMs < 0, "failed Ping must have a negative latencyMs error code");
    requireCondition(response.error.length > 0, "failed Ping must have a non-empty error");
  }
}

// 输入一条 NetworkEvent 并执行字段契约校验；成功无返回值，失败抛异常。
function validateGrpcEvent(value) {
  requireCondition(value && typeof value === "object", "NetworkEvent must be an object");
  requireCondition(typeof value.eventType === "string", "NetworkEvent.eventType must be a string");
  requireCondition(typeof value.message === "string", "NetworkEvent.message must be a string");
  requireCondition(typeof value.source === "string", "NetworkEvent.source must be a string");
}

// 输入单次 cycle、标签和是否强制收事件；验证 ready/有界接收/cancel/disconnect，成功无返回值。
function validateEventCycle(value, label, requireEvent) {
  requireCondition(value && typeof value === "object", `${label} event cycle must be an object`);
  for (const field of [
    "channel_ready_latency_ms", "stream_connect_latency_ms", "receive_window_ms",
    "disconnect_latency_ms"
  ]) {
    requireCondition(finiteNumber(value[field]) && value[field] >= 0,
      `${label}.${field} must be a non-negative finite number`);
  }
  requireCondition(value.connected === true, `${label} stream was not connected`);
  requireCondition(typeof value.first_event_received === "boolean",
    `${label}.first_event_received must be boolean`);
  requireCondition(value.disconnect_observed === true, `${label} disconnect was not observed`);
  requireCondition(Number.isInteger(value.received_count) && value.received_count >= 0,
    `${label}.received_count must be non-negative`);
  requireCondition(Number.isInteger(value.receive_limit) && value.receive_limit > 0,
    `${label}.receive_limit must be positive`);
  requireCondition(value.received_count <= value.receive_limit,
    `${label} exceeded its bounded receive limit`);
  requireCondition(value.receive_limit_respected === true,
    `${label} did not report a respected receive bound`);
  requireCondition(Array.isArray(value.events) && value.events.length === value.received_count,
    `${label}.events must match received_count`);
  for (const event of value.events) validateGrpcEvent(event);
  requireCondition(value.first_event_received === (value.received_count > 0),
    `${label}.first_event_received is inconsistent with received_count`);
  if (value.first_event_received) {
    requireCondition(finiteNumber(value.first_event_latency_ms) && value.first_event_latency_ms >= 0,
      `${label}.first_event_latency_ms must be non-negative when an event was received`);
    validateGrpcEvent(value.first_event);
  } else {
    requireCondition(value.first_event === null && value.first_event_latency_ms === null,
      `${label} must use null first-event fields when no event was received`);
  }
  if (requireEvent) requireCondition(value.first_event_received, `${label} did not receive a required event`);
}

// 输入包含 initial/reconnect 的 lifecycle；校验两次连接及重连间隔，成功无返回值。
function validateEventLifecycle(value, requireEvent = false) {
  requireCondition(value && typeof value === "object", "event lifecycle must be an object");
  validateEventCycle(value.initial, "initial", requireEvent);
  validateEventCycle(value.reconnect, "reconnect", requireEvent);
  requireCondition(finiteNumber(value.reconnect_gap_ms) && value.reconnect_gap_ms >= 0,
    "reconnect_gap_ms must be non-negative");
}

// 输入 Dashboard /api/snapshot 响应并校验聚合契约；成功无返回值。
function validateHttpSnapshot(value) {
  requireCondition(value && typeof value === "object", "Dashboard snapshot must be an object");
  requireCondition(finiteNumber(value.generatedAt), "snapshot.generatedAt must be finite");
  requireCondition(value.grpc && typeof value.grpc.ok === "boolean" && Array.isArray(value.grpc.errors),
    "snapshot.grpc contract is invalid");
  requireCondition(Array.isArray(value.interfaces), "snapshot.interfaces must be an array");
  requireCondition(value.networkSnapshot && typeof value.networkSnapshot === "object",
    "snapshot.networkSnapshot must be an object");
  requireCondition(value.health && typeof value.health === "object", "snapshot.health must be an object");
  requireCondition(Array.isArray(value.pings) && Array.isArray(value.events),
    "snapshot pings/events must be arrays");
}

// 输入 Dashboard /api/analyze 响应并校验统一诊断 schema；成功无返回值。
function validateHttpAnalyze(value) {
  requireCondition(value && typeof value === "object", "Dashboard diagnosis must be an object");
  requireCondition(value.schema_version === "weaknet.diagnosis.v1",
    "diagnosis.schema_version is invalid");
  requireCondition(ALLOWED_DIAGNOSIS_STATUSES.has(value.status), "diagnosis.status is invalid");
  for (const field of ["evidence", "knowledge_entry_ids", "actions"]) {
    requireCondition(Array.isArray(value[field]), `diagnosis.${field} must be an array`);
  }
  requireCondition(finiteNumber(value.confidence) && value.confidence >= 0 && value.confidence <= 1,
    "diagnosis.confidence must be within [0, 1]");
  requireCondition(value.evidence.every((item) => item && typeof item === "object"),
    "diagnosis.evidence must contain only objects");
  requireCondition(value.knowledge_entry_ids.every((item) => typeof item === "string" && item.length > 0),
    "diagnosis.knowledge_entry_ids must contain non-empty strings");
  requireCondition(new Set(value.knowledge_entry_ids).size === value.knowledge_entry_ids.length,
    "diagnosis.knowledge_entry_ids must be unique");
  requireCondition(value.actions.every((item) => typeof item === "string" && item.length > 0),
    "diagnosis.actions must contain non-empty strings");
  requireCondition(typeof value.degraded === "boolean", "diagnosis.degraded must be boolean");
  requireCondition(typeof value.provider === "string" && value.provider.length > 0,
    "diagnosis.provider is missing");
  requireCondition(typeof value.artifact_version === "string" && value.artifact_version.length > 0,
    "diagnosis.artifact_version is missing");
  requireCondition(Number.isInteger(value.top_k) && value.top_k > 0, "diagnosis.top_k is invalid");
  requireCondition(finiteNumber(value.similarity_threshold),
    "diagnosis.similarity_threshold must be finite");
  requireCondition(typeof value.error === "string", "diagnosis.error must be a string");
  requireCondition(typeof value.analysis === "string" && finiteNumber(value.generatedAt),
    "diagnosis analysis/generatedAt contract is invalid");
}

// 输入已通过 schema 的 diagnosis，返回精简业务样本；HTTP 2xx 不代表 RAG bridge 未降级。
function diagnosisSampleMetrics(value) {
  const provider = value.provider;
  const responseError = value.error;
  // degraded 描述网络证据/诊断质量；只有 provider 明确进入 fallback 才算 bridge 回退。
  // 两者必须分开，否则 VM 缺少 RSSI 等正常 degraded 状态会被误报成 Python bridge 崩溃。
  const bridgeFallback = provider.toLowerCase().includes("fallback");
  return {
    diagnosis_status: value.status,
    degraded: value.degraded,
    provider,
    artifact_version: value.artifact_version,
    response_error: responseError,
    bridge_fallback: bridgeFallback,
    // status 描述网络健康度；这里的 business_healthy 额外要求证据未降级，供比例展示。
    business_healthy: !value.degraded && !bridgeFallback && responseError.length === 0
  };
}

// 输入诊断样本和请求上下文，返回传输/Schema 与业务两层聚合，避免 fallback HTTP 200 假绿。
function summarizeDiagnosisMetrics(samples, context) {
  const countBy = (field, predicate = () => true) => {
    const counts = new Map();
    for (const sample of samples) {
      if (!predicate(sample)) continue;
      const key = String(sample[field]);
      counts.set(key, (counts.get(key) || 0) + 1);
    }
    return Object.fromEntries(
      [...counts.entries()].sort(([left], [right]) => left.localeCompare(right))
    );
  };
  const sampleCount = samples.length;
  const degradedCount = samples.filter((item) => item.degraded).length;
  const bridgeFallbackCount = samples.filter((item) => item.bridge_fallback).length;
  const responseErrorCount = samples.filter((item) => item.response_error.length > 0).length;
  const businessHealthyCount = samples.filter((item) => item.business_healthy).length;
  const rate = (count) => sampleCount > 0 ? round(count / sampleCount) : 0;
  return {
    transport_schema: {
      request_count: context.requestCount,
      validated_response_count: context.successCount,
      rejected_response_count: context.requestCount - context.successCount,
      success_rate: context.requestCount > 0 ? round(context.successCount / context.requestCount) : 0
    },
    business: {
      evaluated_response_count: sampleCount,
      business_healthy_count: businessHealthyCount,
      business_healthy_rate: rate(businessHealthyCount),
      non_degraded_count: sampleCount - degradedCount,
      non_degraded_rate: rate(sampleCount - degradedCount),
      degraded_count: degradedCount,
      degraded_rate: rate(degradedCount),
      bridge_fallback_count: bridgeFallbackCount,
      bridge_fallback_rate: rate(bridgeFallbackCount),
      response_error_count: responseErrorCount,
      response_error_rate: rate(responseErrorCount),
      status_counts: countBy("diagnosis_status"),
      provider_counts: countBy("provider"),
      artifact_version_counts: countBy("artifact_version"),
      error_counts: countBy("response_error", (item) => item.response_error.length > 0)
    }
  };
}

// 输入 diagnosis 聚合指标，返回 {pass,reasons}。网络 status 可为 unhealthy/degraded；
// 门禁拒绝 bridge fallback、显式 error 和“全量 degraded”，但不误伤部分真实网络降级。
function assessDiagnosisBusiness(metrics) {
  const business = metrics.business;
  const reasons = [];
  if (business.evaluated_response_count === 0) {
    reasons.push("no schema-valid diagnosis response was available for business evaluation");
  }
  if (business.bridge_fallback_count > 0) {
    reasons.push(`${business.bridge_fallback_count} diagnosis responses used bridge fallback`);
  }
  if (business.response_error_count > 0) {
    reasons.push(`${business.response_error_count} diagnosis responses contained error`);
  }
  if (
    business.evaluated_response_count > 0
    && business.degraded_count === business.evaluated_response_count
  ) {
    reasons.push(
      `all ${business.evaluated_response_count} diagnosis responses were degraded`
    );
  }
  return { pass: reasons.length === 0, reasons };
}

// 输入运行参数，返回 fixture operation 表；只测 harness/并发调度/契约开销，不冒充 live 吞吐。
function fixtureOperations(args) {
  const defer = (value) => new Promise((resolve) => setImmediate(() => resolve(value)));
  const snapshot = {
    observedAtUnixMs: "1784000000000",
    hasActiveInterface: true,
    activeInterface: "eth0",
    interfaces: [{ interfaceName: "eth0", usingNow: true }],
    quality: { level: "NETWORK_QUALITY_LEVEL_GOOD", score: 90, issues: [], degraded: false,
      missingMetrics: [] },
    trafficObservation: { availability: "METRIC_AVAILABILITY_AVAILABLE", valid: true,
      captureComplete: true, mapReadComplete: true }
  };
  const dashboardSnapshot = {
    generatedAt: 1784000000000,
    grpcAddress: args.grpcAddress,
    grpc: { ok: true, errors: [] },
    stream: { connected: true, error: "", startedAt: 1784000000000 },
    ai: { configured: true, provider: "versioned-rag-bridge" },
    interfaces: ["eth0"],
    networkSnapshot: snapshot,
    health: { level: "good", score: 90 },
    pings: [], latencySeries: [], events: [], eventStats: {}
  };
  const diagnosis = {
    schema_version: "weaknet.diagnosis.v1",
    status: "healthy", evidence: [], knowledge_entry_ids: [], confidence: 1,
    actions: [], degraded: false, provider: "fixture-rag", artifact_version: "fixture-v1",
    top_k: 4, similarity_threshold: 0.08, error: "", analysis: "healthy",
    generatedAt: 1784000000000
  };
  const event = {
    eventType: "Changed", message: "fixture", source: "fixture", details: "{}", counter: 1,
    priority: 0, timestampUnixMs: "1784000000000"
  };
  const eventCycle = (offset) => {
    const events = Array.from({ length: Math.min(2, args.eventMaxEvents) }, () => event);
    return {
      connected: true,
      channel_ready_latency_ms: 0.1 + offset,
      stream_connect_latency_ms: 0.2 + offset,
      first_event_received: true,
      first_event_latency_ms: 0.3 + offset,
      first_event: event,
      events,
      received_count: events.length,
      receive_limit: args.eventMaxEvents,
      receive_limit_respected: true,
      receive_window_ms: args.eventWindowMs,
      disconnect_observed: true,
      disconnect_latency_ms: 0.1 + offset
    };
  };
  const eventLifecycle = {
    initial: eventCycle(0),
    reconnect: eventCycle(0.1),
    reconnect_gap_ms: 0.1
  };
  const exact = (value) => stableStringify(value);
  return {
    "grpc-get": { name: "grpc.get", transport: "grpc", endpoint: "WeakNet/Get",
      call: () => defer({ message: "ready" }), validate: validateGrpcGet, fingerprint: exact },
    "grpc-interfaces": { name: "grpc.get_interfaces", transport: "grpc",
      endpoint: "WeakNet/GetInterfaces", call: () => defer({ interfaces: ["eth0", "wlan0"] }),
      validate: validateGrpcInterfaces, fingerprint: exact },
    "grpc-snapshot": { name: "grpc.network_snapshot", transport: "grpc",
      endpoint: "WeakNet/GetNetworkSnapshot", call: () => defer(snapshot),
      validate: validateGrpcSnapshot, fingerprint: exact },
    "grpc-health": { name: "grpc.health_check", transport: "grpc",
      endpoint: "WeakNet/HealthCheck", call: () => defer({ details: "{\"status\":\"good\"}" }),
      validate: validateGrpcHealth, fingerprint: exact },
    "grpc-ping": { name: "grpc.ping", transport: "grpc", endpoint: "WeakNet/Ping",
      call: (index) => {
        const requestTarget = args.pingTargets[index % args.pingTargets.length];
        return defer({ requestTarget, response: { success: true,
          result: `PING ${requestTarget} via lo: 0ms`, error: "", latencyMs: 0,
          interfaceName: "lo" } });
      },
      validate: validateGrpcPing, fingerprint: exact,
      determinismKey: (value) => value.requestTarget, workloads: args.pingTargets.length,
      sampleMetrics: pingSampleMetrics,
      summarizeMetrics: summarizePingMetrics },
    "grpc-events": { name: "grpc.event_stream", transport: "grpc",
      endpoint: "WeakNet/SubscribeEvents", call: () => defer(eventLifecycle),
      validate: (value) => validateEventLifecycle(value, true), fingerprint: exact,
      sampleMetrics: eventLifecycleSample,
      summarizeMetrics: summarizeEventMetrics },
    "http-snapshot": { name: "dashboard.snapshot", transport: "http",
      endpoint: "/api/snapshot", call: () => defer(dashboardSnapshot),
      validate: validateHttpSnapshot, fingerprint: exact },
    "http-analyze": { name: "dashboard.analyze", transport: "http",
      endpoint: "/api/analyze", call: () => defer(diagnosis),
      validate: validateHttpAnalyze, fingerprint: exact,
      sampleMetrics: diagnosisSampleMetrics,
      summarizeMetrics: summarizeDiagnosisMetrics,
      assessBusinessMetrics: assessDiagnosisBusiness }
  };
}

// 复用 Dashboard 已安装的 grpc-js/proto-loader；输入服务地址，返回 grpc 模块和 WeakNet client。
function loadGrpcClient(address) {
  const dashboardRequire = createRequire(path.join(projectRoot, "dashboard", "package.json"));
  const grpc = dashboardRequire("@grpc/grpc-js");
  const protoLoader = dashboardRequire("@grpc/proto-loader");
  const definition = protoLoader.loadSync(path.join(projectRoot, "proto", "weaknet.proto"), {
    keepCase: false,
    longs: String,
    enums: String,
    defaults: true,
    oneofs: true
  });
  const loaded = grpc.loadPackageDefinition(definition);
  const client = new loaded.weaknet.v1.WeakNet(address, grpc.credentials.createInsecure());
  return { grpc, client };
}

// 把带 deadline 的 unary callback 封装成 Promise；输入 client/method/request/超时，返回 RPC 响应。
function unary(client, method, request, timeoutMs) {
  return new Promise((resolve, reject) => {
    client[method](request, { deadline: Date.now() + timeoutMs }, (error, response) => {
      if (error) reject(error);
      else resolve(response);
    });
  });
}

// grpc-js 的 deadline 是首层保护；额外 JS timer 保证 callback 异常丢失时也能 reject 收敛。
function waitForReady(client, timeoutMs) {
  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = (error) => {
      if (settled) return;
      settled = true;
      clearTimeout(watchdog);
      if (error) reject(error);
      else resolve();
    };
    const watchdog = setTimeout(() => finish(new Error(
      `gRPC channel waitForReady hard timeout after ${timeoutMs}ms`
    )), timeoutMs);
    try {
      client.waitForReady(Date.now() + timeoutMs, finish);
    } catch (error) {
      finish(error);
    }
  });
}

// 统一跟踪尚未看到 terminal event 的 stream；返回 track/release/cancel/close 清理接口。
// 退出时先 cancel 再关闭底层 channel，防止并发连接在异常路径泄漏。
function createStreamRegistry(client) {
  const activeCalls = new Set();
  let closed = false;
  const cancel = (call) => {
    try {
      call.cancel();
    } catch {
      // close/cancel 是幂等清理路径；原始 benchmark 错误由调用方保留。
    }
  };
  return {
    track(call) {
      if (closed) {
        cancel(call);
        throw new Error("gRPC stream registry is already closed");
      }
      activeCalls.add(call);
    },
    release(call) {
      activeCalls.delete(call);
    },
    cancel,
    close() {
      if (closed) return;
      closed = true;
      for (const call of activeCalls) cancel(call);
      activeCalls.clear();
      client.close();
    }
  };
}

// 在固定窗口/条数上限内收事件，然后主动 cancel 并等待断开信号；返回单次生命周期指标。
async function collectEventCycle(client, streamRegistry, timeoutMs, receiveWindowMs, receiveLimit) {
  const channelStarted = performance.now();
  await waitForReady(client, timeoutMs);
  const channelReadyLatencyMs = performance.now() - channelStarted;
  const streamStarted = performance.now();
  const call = client.subscribeEvents({ types: [] });
  streamRegistry.track(call);
  const connectedAt = performance.now();
  return new Promise((resolve, reject) => {
    const events = [];
    let firstEventAt = null;
    let disconnectStarted = null;
    let settled = false;
    let receiveTimer = null;
    let disconnectTimer = null;
    let lifecycleTimer = null;

    // 一个 cycle 同时存在接收、断开和总生命周期三层 timer；任一路结束都必须全量清掉。
    const cleanup = () => {
      clearTimeout(receiveTimer);
      clearTimeout(disconnectTimer);
      clearTimeout(lifecycleTimer);
    };
    const finishError = (error) => {
      if (settled) return;
      settled = true;
      cleanup();
      // 保留在 registry 中，直到 terminal event 到达或 finally 关闭整个 channel。
      streamRegistry.cancel(call);
      reject(error);
    };
    const finishDisconnect = () => {
      if (settled || disconnectStarted === null) return;
      settled = true;
      const finishedAt = performance.now();
      cleanup();
      streamRegistry.release(call);
      resolve({
        connected: true,
        channel_ready_latency_ms: round(channelReadyLatencyMs),
        stream_connect_latency_ms: round(connectedAt - streamStarted),
        first_event_received: firstEventAt !== null,
        first_event_latency_ms: firstEventAt === null ? null : round(firstEventAt - streamStarted),
        first_event: events[0] ?? null,
        events,
        received_count: events.length,
        receive_limit: receiveLimit,
        receive_limit_respected: events.length <= receiveLimit,
        receive_window_ms: round(disconnectStarted - streamStarted),
        disconnect_observed: true,
        disconnect_latency_ms: round(finishedAt - disconnectStarted)
      });
    };
    // cancel 后必须观察 error/status/end；只调用 cancel 不算完成生命周期门禁。
    const beginDisconnect = () => {
      if (settled || disconnectStarted !== null) return;
      disconnectStarted = performance.now();
      clearTimeout(receiveTimer);
      disconnectTimer = setTimeout(() => finishError(new Error(
        `SubscribeEvents cancellation was not observed within ${timeoutMs}ms`
      )), timeoutMs);
      streamRegistry.cancel(call);
    };
    // 独立于 receive/cancel 两个阶段 timer 的总 watchdog，避免某个回调链失效后悬空。
    const lifecycleTimeoutMs = receiveWindowMs + timeoutMs
      + Math.max(25, Math.ceil(timeoutMs * 0.05));
    lifecycleTimer = setTimeout(() => finishError(new Error(
      `SubscribeEvents lifecycle hard timeout after ${lifecycleTimeoutMs}ms`
    )), lifecycleTimeoutMs);
    receiveTimer = setTimeout(beginDisconnect, receiveWindowMs);

    call.on("data", (event) => {
      if (settled || disconnectStarted !== null) return;
      const observedAt = performance.now();
      if (firstEventAt === null) firstEventAt = observedAt;
      if (events.length < receiveLimit) events.push(event);
      if (events.length >= receiveLimit) beginDisconnect();
    });
    call.on("error", (error) => {
      if (settled) {
        streamRegistry.release(call);
        return;
      }
      if (disconnectStarted !== null && error.code === 1) finishDisconnect();
      else finishError(error);
    });
    call.on("status", (status) => {
      if (settled) {
        streamRegistry.release(call);
        return;
      }
      if (disconnectStarted !== null && (status.code === 0 || status.code === 1)) finishDisconnect();
      else if (disconnectStarted === null) {
        finishError(new Error(`SubscribeEvents ended unexpectedly with status ${status.code}`));
      }
    });
    call.on("end", () => {
      if (settled) {
        streamRegistry.release(call);
        return;
      }
      if (disconnectStarted !== null) finishDisconnect();
      else finishError(new Error("SubscribeEvents ended before the benchmark disconnected it"));
    });
  });
}

// 执行首次订阅和重新订阅，输入共享 client/registry/config，返回两次 cycle 与 reconnect gap。
async function eventLifecycle(client, streamRegistry, args) {
  const initial = await collectEventCycle(
    client, streamRegistry, args.eventTimeoutMs, args.eventWindowMs, args.eventMaxEvents
  );
  const initialDisconnectedAt = performance.now();
  await Promise.resolve();
  const reconnectStarted = performance.now();
  const reconnect = await collectEventCycle(
    client, streamRegistry, args.eventTimeoutMs, args.eventWindowMs, args.eventMaxEvents
  );
  return {
    initial,
    reconnect,
    reconnect_gap_ms: round(reconnectStarted - initialDisconnectedAt)
  };
}

// 输入完整 lifecycle，返回只含数值的精简样本，避免在结果中保留所有事件 payload。
function eventLifecycleSample(value) {
  return {
    initial_channel_ready_latency_ms: value.initial.channel_ready_latency_ms,
    initial_stream_connect_latency_ms: value.initial.stream_connect_latency_ms,
    initial_first_event_latency_ms: value.initial.first_event_latency_ms,
    initial_receive_window_ms: value.initial.receive_window_ms,
    initial_disconnect_latency_ms: value.initial.disconnect_latency_ms,
    initial_received_count: value.initial.received_count,
    reconnect_gap_ms: value.reconnect_gap_ms,
    reconnect_channel_ready_latency_ms: value.reconnect.channel_ready_latency_ms,
    reconnect_stream_connect_latency_ms: value.reconnect.stream_connect_latency_ms,
    reconnect_first_event_latency_ms: value.reconnect.first_event_latency_ms,
    reconnect_receive_window_ms: value.reconnect.receive_window_ms,
    reconnect_disconnect_latency_ms: value.reconnect.disconnect_latency_ms,
    reconnect_received_count: value.reconnect.received_count,
    receive_limit: value.initial.receive_limit
  };
}

// 输入多个 lifecycle 样本，返回连接/首事件/窗口/断开/重连延迟及接收数量聚合。
function summarizeEventMetrics(samples) {
  const latency = (field) => latencySummary(
    samples.map((item) => item[field]).filter((value) => finiteNumber(value))
  );
  const total = (field) => samples.reduce((sum, item) => sum + item[field], 0);
  const observed = (field) => samples.filter((item) => finiteNumber(item[field])).length;
  return {
    lifecycle_samples: samples.length,
    initial: {
      channel_ready_latency_ms: latency("initial_channel_ready_latency_ms"),
      stream_connect_latency_ms: latency("initial_stream_connect_latency_ms"),
      first_event_latency_ms: latency("initial_first_event_latency_ms"),
      first_event_received_count: observed("initial_first_event_latency_ms"),
      receive_window_ms: latency("initial_receive_window_ms"),
      disconnect_latency_ms: latency("initial_disconnect_latency_ms"),
      received_count: total("initial_received_count")
    },
    reconnect: {
      gap_ms: latency("reconnect_gap_ms"),
      channel_ready_latency_ms: latency("reconnect_channel_ready_latency_ms"),
      stream_connect_latency_ms: latency("reconnect_stream_connect_latency_ms"),
      first_event_latency_ms: latency("reconnect_first_event_latency_ms"),
      first_event_received_count: observed("reconnect_first_event_latency_ms"),
      receive_window_ms: latency("reconnect_receive_window_ms"),
      disconnect_latency_ms: latency("reconnect_disconnect_latency_ms"),
      received_count: total("reconnect_received_count")
    },
    receive_limit_per_connection: samples[0]?.receive_limit ?? 0,
    receive_limit_respected: samples.every((item) =>
      item.initial_received_count <= item.receive_limit
      && item.reconnect_received_count <= item.receive_limit)
  };
}

// 输入关联 requestTarget 的 PingReply，返回业务探测样本；RPC OK 不等于探测成功。
function pingSampleMetrics(value) {
  return {
    request_target: value.requestTarget,
    probe_success: value.response.success,
    probe_latency_ms: value.response.latencyMs,
    probe_error: value.response.error
  };
}

// 输入 Ping 业务样本，返回 target 归属、真实探测成功率和负错误码分布。
function summarizePingMetrics(samples) {
  const targetCounts = {};
  const failureCodeCounts = {};
  const failureErrorCounts = {};
  const successfulLatencies = [];
  let probeSuccessCount = 0;
  for (const sample of samples) {
    targetCounts[sample.request_target] = (targetCounts[sample.request_target] || 0) + 1;
    if (sample.probe_success) {
      probeSuccessCount += 1;
      successfulLatencies.push(sample.probe_latency_ms);
      continue;
    }
    const code = String(sample.probe_latency_ms);
    failureCodeCounts[code] = (failureCodeCounts[code] || 0) + 1;
    const error = sample.probe_error || "unspecified";
    failureErrorCounts[error] = (failureErrorCounts[error] || 0) + 1;
  }
  const probeFailureCount = samples.length - probeSuccessCount;
  return {
    associated_response_count: samples.length,
    request_target_counts: targetCounts,
    probe_success_count: probeSuccessCount,
    probe_failure_count: probeFailureCount,
    probe_success_rate: samples.length > 0 ? round(probeSuccessCount / samples.length) : 0,
    successful_probe_latency_ms: successfulLatencies.length > 0
      ? latencySummary(successfulLatencies) : null,
    failure_code_counts: failureCodeCounts,
    failure_error_counts: failureErrorCounts
  };
}

// 使用 Node 内建 fetch；输入 URL/method/body/超时，返回 JSON，并拒绝超时、非 2xx 或非 JSON。
async function fetchJson(url, method, body, timeoutMs) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(new Error(`HTTP timeout after ${timeoutMs}ms`)), timeoutMs);
  try {
    const response = await fetch(url, {
      method,
      signal: controller.signal,
      headers: body ? { "content-type": "application/json" } : undefined,
      body: body ? JSON.stringify(body) : undefined
    });
    const text = await response.text();
    if (!response.ok) throw new Error(`${method} ${url} returned ${response.status}: ${text.slice(0, 500)}`);
    try {
      return JSON.parse(text);
    } catch (error) {
      throw new Error(`${method} ${url} returned invalid JSON: ${error.message}`);
    }
  } finally {
    clearTimeout(timer);
  }
}

// 绑定全部安全 unary、可选 stream lifecycle 和两个 Dashboard API；返回 operation 表和 close。
function liveOperations(args) {
  const operations = {};
  let grpcClient = null;
  let streamRegistry = null;
  if (!args.skipGrpc) {
    grpcClient = loadGrpcClient(args.grpcAddress).client;
    streamRegistry = createStreamRegistry(grpcClient);
    operations["grpc-get"] = { name: "grpc.get", transport: "grpc", endpoint: "WeakNet/Get",
      call: () => unary(grpcClient, "get", {}, args.timeoutMs), validate: validateGrpcGet };
    operations["grpc-interfaces"] = { name: "grpc.get_interfaces", transport: "grpc",
      endpoint: "WeakNet/GetInterfaces",
      call: () => unary(grpcClient, "getInterfaces", {}, args.timeoutMs),
      validate: validateGrpcInterfaces };
    operations["grpc-snapshot"] = { name: "grpc.network_snapshot", transport: "grpc",
      endpoint: "WeakNet/GetNetworkSnapshot",
      call: () => unary(grpcClient, "getNetworkSnapshot", {}, args.timeoutMs),
      validate: validateGrpcSnapshot };
    operations["grpc-health"] = { name: "grpc.health_check", transport: "grpc",
      endpoint: "WeakNet/HealthCheck",
      call: () => unary(grpcClient, "healthCheck", {}, args.timeoutMs),
      validate: validateGrpcHealth };
    operations["grpc-ping"] = { name: "grpc.ping", transport: "grpc", endpoint: "WeakNet/Ping",
      call: async (index) => {
        const requestTarget = args.pingTargets[index % args.pingTargets.length];
        const response = await unary(grpcClient, "ping", { hostname: requestTarget }, args.timeoutMs);
        return { requestTarget, response };
      },
      validate: validateGrpcPing,
      determinismKey: (value) => value.requestTarget,
      workloads: args.pingTargets.length,
      sampleMetrics: pingSampleMetrics,
      summarizeMetrics: summarizePingMetrics };
    if (args.events) {
      operations["grpc-events"] = { name: "grpc.event_stream", transport: "grpc",
        endpoint: "WeakNet/SubscribeEvents",
        call: () => eventLifecycle(grpcClient, streamRegistry, args),
        validate: (value) => validateEventLifecycle(value, args.requireEvent),
        fingerprint: () => "event-lifecycle-contract-v1", sampleMetrics: eventLifecycleSample,
        summarizeMetrics: summarizeEventMetrics };
    }
  }
  if (!args.skipDashboard) {
    const base = args.dashboardUrl.replace(/\/+$/, "");
    operations["http-snapshot"] = { name: "dashboard.snapshot", transport: "http",
      endpoint: "/api/snapshot", call: () => fetchJson(`${base}/api/snapshot`, "GET", null, args.timeoutMs),
      validate: validateHttpSnapshot };
    operations["http-analyze"] = { name: "dashboard.analyze", transport: "http",
      endpoint: "/api/analyze", call: () => fetchJson(`${base}/api/analyze`, "POST", {
        top_k: 4, similarity_threshold: 0.08
      }, args.timeoutMs), validate: validateHttpAnalyze,
      sampleMetrics: diagnosisSampleMetrics,
      summarizeMetrics: summarizeDiagnosisMetrics,
      assessBusinessMetrics: assessDiagnosisBusiness };
  }
  for (const operation of Object.values(operations)) {
    operation.fingerprint ||= (value) => stableStringify(contractShape(value));
  }
  return { operations, close: () => streamRegistry?.close() };
}

// 运行一格 benchmark；输入 operation/并发/请求数/warmup/模式，返回该矩阵格的完整指标。
// warmup 建确定性基线，固定大小 worker pool 负责有界并发，避免一次创建 requests 个 Promise。
async function runOne(operation, concurrency, requestCount, warmup, fixture) {
  const warmupCount = Math.max(warmup, operation.workloads || 1);
  const errors = [];
  const baselines = new Map();
  for (let index = 0; index < warmupCount; index += 1) {
    try {
      const value = await operation.call(index);
      operation.validate(value);
      const fingerprint = operation.fingerprint(value);
      const key = operation.determinismKey ? operation.determinismKey(value, index) : "default";
      if (baselines.has(key) && baselines.get(key) !== fingerprint) {
        throw new Error(`warmup determinism mismatch for ${key}`);
      }
      baselines.set(key, fingerprint);
    } catch (error) {
      errors.push({ phase: "warmup", index, type: error?.name || "Error",
        message: String(error?.message || error).slice(0, 500) });
    }
  }
  const rssBefore = process.memoryUsage().rss;
  let peakRss = rssBefore;
  const outcomes = new Array(requestCount);
  let nextIndex = 0;
  const measuredStarted = performance.now();
  // 并发值是上限；请求量更小时主动收窄 worker 数，报告同时保留 requested/effective 两个值。
  const effectiveConcurrency = Math.min(concurrency, requestCount);
  // nextIndex 在单线程 event loop 中递增，每个响应仍保留自己的请求索引/target 闭包。
  const workers = Array.from({ length: effectiveConcurrency }, async () => {
    while (true) {
      const index = nextIndex++;
      if (index >= requestCount) return;
      const started = performance.now();
      try {
        const value = await operation.call(index);
        operation.validate(value);
        const fingerprint = operation.fingerprint(value);
        const key = operation.determinismKey ? operation.determinismKey(value, index) : "default";
        const sample = operation.sampleMetrics ? operation.sampleMetrics(value) : null;
        outcomes[index] = { ok: true,
          mismatch: !baselines.has(key) || baselines.get(key) !== fingerprint,
          latencyMs: performance.now() - started, sample };
      } catch (error) {
        outcomes[index] = { ok: false, mismatch: false, latencyMs: performance.now() - started,
          index, type: error?.name || "Error", message: String(error?.message || error).slice(0, 500) };
      }
      peakRss = Math.max(peakRss, process.memoryUsage().rss);
    }
  });
  await Promise.all(workers);
  const durationMs = Math.max(performance.now() - measuredStarted, 0.000001);
  const rssAfter = process.memoryUsage().rss;
  peakRss = Math.max(peakRss, rssAfter);
  for (const outcome of outcomes) {
    if (!outcome.ok) errors.push({ phase: "measure", index: outcome.index, type: outcome.type,
      message: outcome.message });
  }
  const mismatches = outcomes.filter((item) => item.mismatch).length;
  const successCount = outcomes.filter((item) => item.ok).length;
  const samples = outcomes.filter((item) => item.ok && item.sample !== null).map((item) => item.sample);
  const operationMetrics = operation.summarizeMetrics
    ? operation.summarizeMetrics(samples, { requestCount, successCount }) : {};
  const businessGate = operation.assessBusinessMetrics
    ? operation.assessBusinessMetrics(operationMetrics) : null;
  const transportSchemaPass = errors.length === 0 && mismatches === 0 && successCount === requestCount;
  return {
    name: operation.name,
    transport: operation.transport,
    endpoint: operation.endpoint,
    // concurrency 是请求的上限档；请求数不足时 effective_concurrency 才是真实 worker 数。
    concurrency,
    effective_concurrency: effectiveConcurrency,
    requests: requestCount,
    warmup_requests: warmupCount,
    duration_ms: round(durationMs),
    latency_ms: latencySummary(outcomes.map((item) => item.latencyMs)),
    qps: round(requestCount / (durationMs / 1000)),
    success_count: successCount,
    error_count: errors.length,
    errors: errors.slice(0, 10),
    determinism_mismatch_count: mismatches,
    determinism_mode: fixture ? "exact_response_by_fixed_fixture" : "contract_shape",
    transport_schema_pass: transportSchemaPass,
    ...(businessGate ? {
      business_gate_pass: businessGate.pass,
      business_gate_reasons: businessGate.reasons
    } : {}),
    operation_metrics: operationMetrics,
    rss_bytes: { before: rssBefore, after: rssAfter, delta: rssAfter - rssBefore, peak: peakRss },
    correctness_pass: transportSchemaPass && (businessGate?.pass ?? true)
  };
}

// 输入全部矩阵格结果，返回总 summary；任一 warmup/contract/determinism 失败即关闭门禁。
function summarize(results) {
  const correctnessPass = results.length > 0 && results.every((item) => item.correctness_pass);
  return {
    status: correctnessPass ? "passed" : "failed",
    benchmark_count: results.length,
    request_count: results.reduce((sum, item) => sum + item.requests, 0),
    success_count: results.reduce((sum, item) => sum + item.success_count, 0),
    error_count: results.reduce((sum, item) => sum + item.error_count, 0),
    determinism_mismatch_count: results.reduce((sum, item) => sum + item.determinism_mismatch_count, 0),
    correctness_pass: correctnessPass
  };
}

// 解析配置、拆分 unary 与 event 负载矩阵、落盘统一 JSON；返回 0(通过) 或 2(门禁失败)。
async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) {
    process.stdout.write(USAGE);
    return 0;
  }
  const profile = PROFILES[args.profile];
  const concurrencies = args.concurrency || profile.concurrency;
  const requestLevels = args.requests || profile.requests;
  const eventConnections = args.eventConnections || profile.eventConnections;
  const warmup = args.warmup ?? profile.warmup;
  const startedAt = new Date().toISOString();
  const overallStarted = performance.now();
  let close = () => {};
  let operations;
  if (args.fixture) operations = fixtureOperations(args);
  else ({ operations, close } = liveOperations(args));
  let targetNames = args.targets || Object.keys(operations);
  if (!args.events) targetNames = targetNames.filter((name) => name !== "grpc-events");
  if (args.skipGrpc) targetNames = targetNames.filter((name) => !name.startsWith("grpc-"));
  if (args.skipDashboard) targetNames = targetNames.filter((name) => !name.startsWith("http-"));
  const benchmarks = [];
  try {
    // target 校验也必须处在 finally 保护下；否则 live client 已创建后抛错会泄漏 channel。
    for (const name of targetNames) {
      requireCondition(operations[name], `target ${name} is not available with current flags`);
    }
    for (const name of targetNames) {
      // Stream 只按独立连接档运行：每个 connectionCount 同时是请求数和并发数；
      // 避免它进入普通 requests×concurrency 笛卡尔积而意外放大长连接数量。
      if (name === "grpc-events") {
        for (const connectionCount of eventConnections) {
          benchmarks.push(await runOne(
            operations[name], connectionCount, connectionCount, Math.min(warmup, 1), args.fixture
          ));
        }
        continue;
      }
      // unary/HTTP 按完整 requests×concurrency 矩阵运行，便于观察固定请求量下的并发拐点。
      for (const requestCount of requestLevels) {
        for (const concurrency of concurrencies) {
          benchmarks.push(await runOne(
            operations[name], concurrency, requestCount, warmup, args.fixture
          ));
        }
      }
    }
  } finally {
    // 无论哪一格抛错，都关闭 stream registry/channel，避免测试进程因活跃句柄无法退出。
    close();
  }
  const document = {
    schema_version: SCHEMA_VERSION,
    component: "service",
    profile: args.profile,
    environment: {
      node: process.version,
      platform: `${os.platform()}-${os.arch()} ${os.release()}`,
      pid: process.pid,
      fixture: args.fixture,
      engine: args.fixture ? "static-contract-fixture" : "live-network-endpoints",
      fixture_qps_semantics: args.fixture
        ? "harness and contract-validation overhead only; not live gRPC/Dashboard throughput"
        : "live endpoint throughput for the configured gRPC/Dashboard targets",
      grpc_address: args.grpcAddress,
      dashboard_url: args.dashboardUrl,
      ping_targets: args.pingTargets,
      timeout_ms: args.timeoutMs,
      event_timeout_ms: args.eventTimeoutMs,
      event_window_ms: args.eventWindowMs,
      event_max_events: args.eventMaxEvents,
      event_connection_levels: eventConnections,
      event_connection_semantics: (
        "channel waitForReady plus stream creation; SubscribeEvents has no server-side ready ack"
      ),
      require_event: args.events ? (args.fixture ? true : args.requireEvent) : false,
      concurrency: concurrencies,
      concurrency_semantics: (
        "benchmark.concurrency is the requested upper bound; "
        + "benchmark.effective_concurrency=min(concurrency, requests)"
      ),
      request_levels: requestLevels,
      targets: targetNames,
      skipped_targets: [
        ...(!args.events && !args.skipGrpc
          ? [{ target: "grpc-events", reason: "optional stream benchmark not requested" }] : []),
        ...(args.skipGrpc ? [...ALL_TARGETS].filter((name) => name.startsWith("grpc-"))
          .map((target) => ({ target, reason: "--skip-grpc" })) : []),
        ...(args.skipDashboard ? [...ALL_TARGETS].filter((name) => name.startsWith("http-"))
          .map((target) => ({ target, reason: "--skip-dashboard" })) : [])
      ]
    },
    started_at: startedAt,
    duration_ms: round(performance.now() - overallStarted),
    benchmarks,
    summary: summarize(benchmarks)
  };
  const output = path.resolve(args.output);
  fs.mkdirSync(path.dirname(output), { recursive: true });
  const serialized = JSON.stringify(document, null, 2);
  fs.writeFileSync(output, `${serialized}\n`);
  process.stdout.write(`${serialized}\n`);
  return document.summary.correctness_pass ? 0 : 2;
}

main().then((code) => {
  process.exitCode = code;
}).catch((error) => {
  process.stderr.write(`service benchmark failed: ${error?.stack || error}\n`);
  process.exitCode = 2;
});
