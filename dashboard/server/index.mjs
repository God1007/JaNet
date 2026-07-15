// Dashboard 本地 BFF：把 WeakNet gRPC 查询和事件流转换为 REST/WebSocket，并在服务端编排 AI 诊断。

import express from "express";
import grpc from "@grpc/grpc-js";
import { execFileSync, spawn } from "node:child_process";
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import protoLoader from "@grpc/proto-loader";
import { WebSocketServer } from "ws";
import { fileURLToPath } from "node:url";
import {
  buildDegradedDiagnosis,
  formatDiagnosis,
  normalizeDiagnosis
} from "./diagnosis_contract.mjs";
import { preferredMetricNumber } from "./metric_compat.mjs";
import {
  buildRuntimeResources,
  normalizeEngineProcessResources
} from "./process_resource_contract.mjs";
import { createProcessResourceSampler } from "./process_resource_sampler.mjs";
import { createRequestFailureMonitor } from "./request_failure_monitor.mjs";
import {
  attachSecureWebSocketUpgrade,
  defaultDashboardOrigins,
  installApiSecurity
} from "./origin_security.mjs";
import {
  admitWebSocketConnection,
  boundedInteger,
  createConcurrencyGate,
  createRetiringResourceTracker,
  sendWebSocketMessage
} from "./resource_guards.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const dashboardRoot = path.resolve(__dirname, "..");
const projectRoot = path.resolve(dashboardRoot, "..");
const protoPath = path.join(projectRoot, "proto", "weaknet.proto");
const protectedEnvKeys = new Set(Object.keys(process.env));

// 解析轻量 .env 值，兼容引号、常见转义和行尾注释。
function parseEnvValue(rawValue) {
  let value = rawValue.trim();
  const quote = value[0];

  if ((quote === "\"" || quote === "'") && value.endsWith(quote)) {
    value = value.slice(1, -1);
    if (quote === "\"") {
      value = value
        .replace(/\\n/g, "\n")
        .replace(/\\r/g, "\r")
        .replace(/\\t/g, "\t")
        .replace(/\\"/g, "\"")
        .replace(/\\\\/g, "\\");
    }
    return value;
  }

  return value.replace(/\s+#.*$/, "").trim();
}

// 读取单个 .env 文件；启动进程显式传入的环境变量拥有最高优先级。
function loadEnvFile(filePath) {
  if (!fs.existsSync(filePath)) {
    return;
  }

  const lines = fs.readFileSync(filePath, "utf8").replace(/^\uFEFF/, "").split(/\r?\n/);
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) {
      continue;
    }

    const match = trimmed.match(/^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/);
    if (!match) {
      continue;
    }

    const [, key, rawValue] = match;
    if (!protectedEnvKeys.has(key)) {
      process.env[key] = parseEnvValue(rawValue);
    }
  }
}

// 按项目根目录、Dashboard 目录顺序加载本地配置。
function loadLocalEnvFiles() {
  loadEnvFile(path.join(projectRoot, ".env"));
  loadEnvFile(path.join(dashboardRoot, ".env"));
}

loadLocalEnvFiles();

let ragBridgePath = process.env.WEAKNET_RAG_BRIDGE
  || path.join(projectRoot, "AI-assisted analysis", "rag_diagnosis_bridge.py");

let grpcAddress = process.env.WEAKNET_GRPC_ADDRESS || "127.0.0.1:50051";
const apiPort = Number(process.env.DASHBOARD_API_PORT || 5174);
const webPort = boundedInteger(
  process.env.DASHBOARD_WEB_PORT,
  5173,
  { min: 1, max: 65_535 }
);
const dashboardAllowedOrigins = defaultDashboardOrigins(webPort);
const pingTargets = (process.env.DASHBOARD_PING_TARGETS || "127.0.0.1,8.8.8.8,baidu.com")
  .split(",")
  .map((item) => item.trim())
  .filter(Boolean);
// 长时运行保护采用小而明确的默认上限；需要时可通过环境变量调高，但仍保留硬上界。
const analyzeMaxConcurrency = boundedInteger(
  process.env.DASHBOARD_ANALYZE_MAX_CONCURRENCY,
  2,
  { min: 1, max: 32 }
);
const wsMaxConnections = boundedInteger(
  process.env.DASHBOARD_WS_MAX_CONNECTIONS,
  32,
  { min: 1, max: 1024 }
);
const wsMaxBufferedBytes = boundedInteger(
  process.env.DASHBOARD_WS_MAX_BUFFERED_BYTES,
  256 * 1024,
  { min: 16 * 1024, max: 16 * 1024 * 1024 }
);
const requestFailureWindowSeconds = boundedInteger(
  process.env.DASHBOARD_REQUEST_FAILURE_WINDOW_SEC,
  300,
  { min: 10, max: 24 * 60 * 60 }
);
const requestFailureThreshold = boundedInteger(
  process.env.DASHBOARD_REQUEST_FAILURE_THRESHOLD,
  5,
  { min: 1, max: 10_000 }
);
const requestFailureMaxRecent = boundedInteger(
  process.env.DASHBOARD_REQUEST_FAILURE_MAX_RECENT,
  500,
  { min: 10, max: 10_000 }
);

// 根据显式 provider 或现有 Key 选择 AI 服务及默认模型。
function resolveAiConfig() {
  const requestedProvider = (process.env.AI_PROVIDER || "").trim().toLowerCase();
  const provider =
    requestedProvider ||
    (process.env.DEEPSEEK_API_KEY
      ? "deepseek"
      : process.env.DASHSCOPE_API_KEY
        ? "dashscope"
        : process.env.OPENAI_API_KEY
          ? "openai"
          : "deepseek");

  if (provider === "dashscope") {
    return {
      provider,
      key: process.env.DASHSCOPE_API_KEY || "",
      baseUrl: process.env.DASHSCOPE_BASE_URL || "https://dashscope.aliyuncs.com/compatible-mode/v1",
      model: process.env.DASHSCOPE_MODEL || "qwen-plus"
    };
  }

  if (provider === "openai") {
    return {
      provider,
      key: process.env.OPENAI_API_KEY || "",
      baseUrl: process.env.OPENAI_BASE_URL || "https://api.openai.com/v1",
      model: process.env.OPENAI_MODEL || "gpt-4.1-mini"
    };
  }

  return {
    provider: "deepseek",
    key: process.env.DEEPSEEK_API_KEY || "",
    baseUrl: process.env.DEEPSEEK_BASE_URL || "https://api.deepseek.com",
    model: process.env.DEEPSEEK_MODEL || "deepseek-chat"
  };
}

const aiConfig = resolveAiConfig();
let aiApiKey = aiConfig.key;
let aiProvider = aiConfig.provider;
let aiBaseUrl = aiConfig.baseUrl;
let aiModel = aiConfig.model;

// 请求到来时重新加载 .env，使本地配置修改无需重启即可生效。
function refreshAiConfig() {
  loadLocalEnvFiles();
  ragBridgePath = process.env.WEAKNET_RAG_BRIDGE
    || path.join(projectRoot, "AI-assisted analysis", "rag_diagnosis_bridge.py");
  const nextAiConfig = resolveAiConfig();
  aiApiKey = nextAiConfig.key;
  aiProvider = nextAiConfig.provider;
  aiBaseUrl = nextAiConfig.baseUrl;
  aiModel = nextAiConfig.model;
}

const packageDefinition = protoLoader.loadSync(protoPath, {
  keepCase: false,
  longs: String,
  enums: String,
  defaults: true,
  oneofs: true
});
const proto = grpc.loadPackageDefinition(packageDefinition);
const WeakNet = proto.weaknet.v1.WeakNet;
// 主 client 切换时先进入 retiring，等现有 unary RPC 完成后再 close，避免打断在途请求。
const grpcClients = createRetiringResourceTracker((grpcClient) => {
  try {
    grpcClient.close();
  } catch (error) {
    console.warn(`Failed to close gRPC client: ${error?.message || error}`);
  }
});
let client = createWeakNetClient(grpcAddress);

const app = express();
const server = http.createServer(app);
// noServer 模式确保 Origin/路径检查发生在 WebSocket 被纳入 clients 集合之前。
const wss = new WebSocketServer({ noServer: true });

const eventBuffer = [];
const pingHistory = [];
const maxEvents = 300;
const maxPings = 240;
let streamConnected = false;
let streamError = "";
let streamStartedAt = 0;
let streamCall = null;
let reconnectTimer = null;
let lastGrpcProbeAt = 0;
let shuttingDown = false;
const analyzeGate = createConcurrencyGate(analyzeMaxConcurrency);
const activeRagChildren = new Set();
// BFF 与 Engine 分开采样：两者属于不同进程，不能用 Node 指标代替 Linux 守护进程开销。
const dashboardResourceSampler = createProcessResourceSampler();
// 这里只聚合浏览器扩展旁路上报的真实终态，不主动访问任何业务 URL。
const requestFailureMonitor = createRequestFailureMonitor({
  windowMs: requestFailureWindowSeconds * 1000,
  threshold: requestFailureThreshold,
  maxRecent: requestFailureMaxRecent
});

// 扩展上报与 Dashboard 页面使用不同 Origin 策略；两条链都先鉴权，再解析 JSON/执行采样。
installApiSecurity(app, {
  allowedOrigins: dashboardAllowedOrigins,
  getFailureAuthConfig: () => {
    loadLocalEnvFiles();
    return {
      expectedExtensionId: process.env.DASHBOARD_BROWSER_EXTENSION_ID || "",
      expectedToken: process.env.DASHBOARD_BROWSER_EXTENSION_TOKEN || ""
    };
  },
  jsonParser: express.json({ limit: "1mb" }),
  failureIngestHandler: ingestBrowserFailures
});
attachSecureWebSocketUpgrade({ server, wss, allowedOrigins: dashboardAllowedOrigins });

// 在 Windows 宿主上探测 WSL 地址，补充跨边界访问 gRPC 的候选目标。
function detectWslAddress() {
  if (process.platform !== "win32") {
    return "";
  }

  try {
    const output = execFileSync("wsl.exe", ["-e", "bash", "-lc", "hostname -I"], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
      timeout: 2000,
      windowsHide: true
    });
    const match = output.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/);
    return match ? `${match[0]}:50051` : "";
  } catch {
    return "";
  }
}

// 去除空值和重复项，同时保留候选地址的优先顺序。
function uniqueItems(items) {
  return Array.from(new Set(items.filter(Boolean)));
}

// 汇总显式地址、本机地址和 WSL 地址，供失败切换逐一探测。
function grpcAddressCandidates() {
  return uniqueItems([
    grpcAddress,
    process.env.WEAKNET_GRPC_ADDRESS || "",
    "127.0.0.1:50051",
    "localhost:50051",
    detectWslAddress()
  ]);
}

// 为指定地址创建明文的本地 WeakNet gRPC 客户端。
function createWeakNetClient(address) {
  return grpcClients.register(new WeakNet(address, grpc.credentials.createInsecure()));
}

// 统一生成毫秒级时间戳。
function now() {
  return Date.now();
}

// 把 proto/JSON 值安全转换为有限数值。
function toNumber(value, fallback = 0) {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : fallback;
}

// proto-loader 以枚举名返回可用性；数值模式也保持兼容，避免把默认零值误当有效采样。
function metricIsAvailable(value) {
  return value === "METRIC_AVAILABILITY_AVAILABLE" || value === 1 || value === "1";
}

// 去掉 protobuf 稳定前缀，给 REST/UI 暴露紧凑但仍可读的枚举名称。
function compactProtoEnum(value, prefix, fallback = "UNSPECIFIED") {
  const text = String(value || "");
  return text.startsWith(prefix) ? text.slice(prefix.length) : text || fallback;
}

// 快照 recent_events 与实时 NetworkEvent 共用同一个 typed 载荷契约。
function normalizeTrafficObservationEvent(item) {
  if (!item || typeof item !== "object") return null;
  return {
    type: compactProtoEnum(item.type, "TRAFFIC_OBSERVATION_EVENT_"),
    reason: toNumber(item.reason, 0),
    // protobuf-loader 已将 uint64 配置为 String，不转 Number 以免丢失 socket cookie 精度。
    socketCookie: String(item.socketCookie ?? "0"),
    flowKey: item.flowKey || "",
    description: item.description || "",
    timestampUnixMs: toNumber(item.timestampUnixMs, 0),
    generation: toNumber(item.generation, 0),
    anomalyType: item.anomalyType || "",
    severity: toNumber(item.severity, 0)
  };
}

// 将 GetNetworkSnapshot 的 protobuf 对象规范化，同时保留每项指标的 availability 语义。
function normalizeNetworkSnapshot(raw) {
  const interfaces = (raw.interfaces || []).map((item) => ({
    interfaceName: item.interfaceName || "",
    isDefaultRoute: Boolean(item.isDefaultRoute),
    interfaceType: compactProtoEnum(item.interfaceType, "INTERFACE_TYPE_"),
    state: compactProtoEnum(item.state, "INTERFACE_STATE_"),
    usingNow: Boolean(item.usingNow),
    // 新服务端提供 optional double 精确值；滚动升级期间仍兼容旧 int32 字段。
    rttMs: metricIsAvailable(item.rttAvailability)
      ? preferredMetricNumber(item, "rttMsPrecise", "rttMs")
      : null,
    previousRttMs: metricIsAvailable(item.rttAvailability)
      ? preferredMetricNumber(item, "previousRttMsPrecise", "previousRttMs")
      : null,
    rttAvailability: compactProtoEnum(item.rttAvailability, "METRIC_AVAILABILITY_"),
    linkQuality: compactProtoEnum(item.linkQuality, "LINK_QUALITY_"),
    rssiDbm: metricIsAvailable(item.rssiAvailability) ? toNumber(item.rssiDbm, null) : null,
    rssiAvailability: compactProtoEnum(item.rssiAvailability, "METRIC_AVAILABILITY_"),
    tcpRetransmissionRatePercent: metricIsAvailable(item.tcpRetransmissionAvailability)
      ? toNumber(item.tcpRetransmissionRatePercent, null)
      : null,
    tcpRetransmissionLevel: item.tcpRetransmissionLevel || "",
    tcpRetransmissionAvailability: compactProtoEnum(
      item.tcpRetransmissionAvailability,
      "METRIC_AVAILABILITY_"
    ),
    trafficBytesPerSecond: metricIsAvailable(item.trafficAvailability)
      ? toNumber(item.trafficBytesPerSecond, null)
      : null,
    trafficPacketsPerSecond: metricIsAvailable(item.trafficAvailability)
      ? toNumber(item.trafficPacketsPerSecond, null)
      : null,
    activeFlows: metricIsAvailable(item.trafficAvailability) ? toNumber(item.activeFlows, null) : null,
    trafficAvailability: compactProtoEnum(item.trafficAvailability, "METRIC_AVAILABILITY_")
  }));
  const quality = raw.quality || {};
  const traffic = raw.trafficObservation || {};
  const map = traffic.mapObservability || {};
  const engineResources = normalizeEngineProcessResources(raw.engineResources);

  return {
    observedAt: toNumber(raw.observedAtUnixMs, now()),
    hasActiveInterface: Boolean(raw.hasActiveInterface),
    activeInterface: raw.activeInterface || "",
    previousActiveInterface: raw.previousActiveInterface || "",
    defaultRouteChanged: Boolean(raw.defaultRouteChanged),
    routeGeneration: toNumber(raw.routeGeneration, 0),
    routeChangedAtUnixMs: toNumber(raw.routeChangedAtUnixMs, 0),
    currentDefaultRouteInterface: raw.currentDefaultRouteInterface || "",
    interfaces,
    engineResources,
    quality: {
      level: compactProtoEnum(quality.level, "NETWORK_QUALITY_LEVEL_", "UNKNOWN"),
      score: toNumber(quality.score, null),
      issues: Array.isArray(quality.issues) ? quality.issues : [],
      degraded: Boolean(quality.degraded),
      missingMetrics: Array.isArray(quality.missingMetrics) ? quality.missingMetrics : []
    },
    trafficObservation: {
      availability: compactProtoEnum(traffic.availability, "METRIC_AVAILABILITY_"),
      valid: Boolean(traffic.valid),
      generation: toNumber(traffic.generation, 0),
      sampledAt: toNumber(traffic.sampledAtUnixMs, 0),
      boundIfindex: toNumber(traffic.boundIfindex, 0),
      captureMode: traffic.captureMode || "unavailable",
      degradedReason: traffic.degradedReason || "",
      libbpfAvailable: Boolean(traffic.libbpfAvailable),
      bpfLoaded: Boolean(traffic.bpfLoaded),
      tcIngressAttached: Boolean(traffic.tcIngressAttached),
      tcEgressAttached: Boolean(traffic.tcEgressAttached),
      tcpKprobeAttached: Boolean(traffic.tcpKprobeAttached),
      udpKprobeAttached: Boolean(traffic.udpKprobeAttached),
      sockDiagAvailable: Boolean(traffic.sockDiagAvailable),
      sockDiagIpv4Available: Boolean(traffic.sockDiagIpv4Available),
      sockDiagIpv6Available: Boolean(traffic.sockDiagIpv6Available),
      procOwnerResolution: Boolean(traffic.procOwnerResolution),
      ipv4Supported: Boolean(traffic.ipv4Supported),
      ipv6Supported: Boolean(traffic.ipv6Supported),
      ipv6ExtensionHeadersSupported: Boolean(traffic.ipv6ExtensionHeadersSupported),
      bidirectional: Boolean(traffic.bidirectional),
      udpInterfaceReliable: Boolean(traffic.udpInterfaceReliable),
      sockDiagStatus: traffic.sockDiagStatus || "not-attempted",
      coverageLimitations: traffic.coverageLimitations || "",
      captureComplete: Boolean(traffic.captureComplete),
      captureCompleteness: traffic.captureCompleteness || "unavailable",
      mapReadComplete: Boolean(traffic.mapReadComplete),
      baselineOnly: Boolean(traffic.baselineOnly),
      mapObservability: {
        lruCapacity: toNumber(map.lruCapacity, 0),
        protectedCapacity: toNumber(map.protectedCapacity, 0),
        lruEntries: toNumber(map.lruEntries, 0),
        protectedEntries: toNumber(map.protectedEntries, 0),
        disappearedThisWindow: toNumber(map.disappearedThisWindow, 0),
        continuityLostThisWindow: toNumber(map.continuityLostThisWindow, 0),
        counterResetsThisWindow: toNumber(map.counterResetsThisWindow, 0),
        policyUpdateAttempts: toNumber(map.policyUpdateAttempts, 0),
        policyUpdateFailures: toNumber(map.policyUpdateFailures, 0),
        readComplete: Boolean(map.readComplete),
        lookupMisses: toNumber(map.lookupMisses, 0),
        duplicateKeys: toNumber(map.duplicateKeys, 0),
        readError: toNumber(map.readError, 0),
        lruInsertFailures: toNumber(map.lruInsertFailures, 0),
        protectedInsertFailures: toNumber(map.protectedInsertFailures, 0),
        interfaceInsertFailures: toNumber(map.interfaceInsertFailures, 0),
        eventDrops: toNumber(map.eventDrops, 0),
        packetsSeen: toNumber(map.packetsSeen, 0),
        interfaceRejected: toNumber(map.interfaceRejected, 0),
        parseFailures: toNumber(map.parseFailures, 0),
        lruLookupMisses: toNumber(map.lruLookupMisses, 0),
        lruInsertAttempts: toNumber(map.lruInsertAttempts, 0),
        lruInsertSuccesses: toNumber(map.lruInsertSuccesses, 0),
        protectedHits: toNumber(map.protectedHits, 0),
        protectedInsertAttempts: toNumber(map.protectedInsertAttempts, 0),
        protectedInsertSuccesses: toNumber(map.protectedInsertSuccesses, 0),
        interfaceInsertAttempts: toNumber(map.interfaceInsertAttempts, 0),
        eventsEmitted: toNumber(map.eventsEmitted, 0),
        userEventsTruncated: toNumber(map.userEventsTruncated, 0),
        kernelCounters: Array.isArray(map.kernelCounters)
          ? map.kernelCounters.map((counter) => toNumber(counter, 0))
          : []
      },
      recentEvents: Array.isArray(traffic.recentEvents)
        ? traffic.recentEvents.map(normalizeTrafficObservationEvent).filter(Boolean)
        : []
    }
  };
}

// 由 typed snapshot 生成旧 UI 仍使用的 health 兼容视图，不再读取 HealthCheck.details JSON。
function healthFromNetworkSnapshot(snapshot) {
  const active = snapshot.interfaces.find((item) => item.usingNow)
    || snapshot.interfaces.find((item) => item.interfaceName === snapshot.activeInterface)
    || snapshot.interfaces[0]
    || null;
  const parsed = active
    ? {
        interface: active.interfaceName,
        rtt_ms: active.rttMs,
        tcp_loss_rate: active.tcpRetransmissionRatePercent,
        rssi_dbm: active.rssiDbm,
        traffic_bps: active.trafficBytesPerSecond,
        traffic_pps: active.trafficPacketsPerSecond,
        active_flows: active.activeFlows,
        using_now: active.usingNow,
        missing_metrics: snapshot.quality.missingMetrics
      }
    : null;

  return {
    raw: "",
    parsed,
    score: snapshot.quality.score,
    level: snapshot.quality.level,
    issues: snapshot.quality.issues,
    degraded: snapshot.quality.degraded,
    missingMetrics: snapshot.quality.missingMetrics
  };
}

// 提取适合返回给前端的紧凑错误信息。
function compactError(error) {
  if (!error) return "";
  return error.details || error.message || String(error);
}

// 对外的 unary RPC 包装，默认允许切换到其他可达地址后重试一次。
function rpc(method, request = {}, timeoutMs = 5000) {
  return rpcWithFallback(method, request, timeoutMs, true);
}

// 在单个 client 上发起带 deadline 的 unary RPC，并转为 Promise。
function rpcOnce(targetClient, method, request = {}, timeoutMs = 5000) {
  // gRPC 回调只负责把单次结果桥接到 Promise 的 resolve/reject。
  return new Promise((resolve, reject) => {
    const deadline = new Date(Date.now() + timeoutMs);
    let releaseClient;
    try {
      // 记录在途调用，使地址切换只能在该 RPC 回调结束后关闭旧 client。
      releaseClient = grpcClients.acquire(targetClient);
      // 原生 gRPC 回调在错误时 reject，成功时只返回响应体。
      targetClient[method](request, { deadline }, (error, response) => {
        releaseClient();
        if (error) {
          reject(error);
          return;
        }
        resolve(response);
      });
    } catch (error) {
      releaseClient?.();
      reject(error);
    }
  });
}

// 当前地址调用失败后重新探测本机候选地址，再用新 client 重放一次请求。
async function rpcWithFallback(method, request = {}, timeoutMs = 5000, allowFallback = true) {
  try {
    return await rpcOnce(client, method, request, timeoutMs);
  } catch (error) {
    // 仅首轮失败允许地址切换，重试失败直接保留原始 RPC 错误。
    if (!allowFallback) {
      throw error;
    }

    const switched = await selectReachableGrpcAddress(true);
    if (!switched) {
      throw error;
    }
    return rpcWithFallback(method, request, timeoutMs, false);
  }
}

// 通过轻量 Get RPC 判断候选 gRPC 地址是否可达。
async function probeGrpcAddress(address) {
  const probeClient = createWeakNetClient(address);
  try {
    await rpcOnce(probeClient, "get", {}, 1600);
  } finally {
    // 探测 client 不复用，无论成功、超时还是 RPC 失败都必须及时释放 channel。
    grpcClients.retire(probeClient);
  }
}

// 节流扫描候选地址；切换目标时同时取消旧事件流，促使其在新地址重连。
async function selectReachableGrpcAddress(force = false) {
  if (shuttingDown) {
    return false;
  }
  const current = Date.now();
  if (!force && current - lastGrpcProbeAt < 5000) {
    return false;
  }
  lastGrpcProbeAt = current;

  for (const candidate of grpcAddressCandidates()) {
    try {
      await probeGrpcAddress(candidate);
      // 信号退出可能发生在探测等待期间；此时不再创建或切换任何主 client。
      if (shuttingDown) {
        return false;
      }
      if (candidate !== grpcAddress) {
        const oldClient = client;
        const nextClient = createWeakNetClient(candidate);
        grpcAddress = candidate;
        client = nextClient;
        if (streamCall) {
          const oldStreamCall = streamCall;
          streamCall = null;
          oldStreamCall.cancel();
        }
        // streaming 已取消；旧 client 的 unary RPC 若仍在执行，tracker 会等其回调后再 close。
        grpcClients.retire(oldClient);
        streamError = "";
        console.log(`WeakNet dashboard switched gRPC target to ${grpcAddress}`);
      }
      return true;
    } catch {
      // 当前候选不可达，继续尝试下一个本机目标。
    }
  }

  return false;
}

// 把 proto 事件规范化为前端稳定使用的字段和事件标识。
function normalizeEvent(event) {
  const timestamp = toNumber(event.timestampUnixMs, now());
  return {
    id: `${timestamp}-${event.counter || 0}-${event.eventType || event.type || "event"}`,
    type: event.eventType || event.type || "Unknown",
    message: event.message || "",
    source: event.source || "weaknet",
    details: event.details || "",
    counter: toNumber(event.counter, 0),
    priority: toNumber(event.priority, 0),
    timestamp,
    trafficObservation: normalizeTrafficObservationEvent(event.trafficObservation)
  };
}

// 保存最近事件并实施固定容量淘汰，防止本地服务长期运行时无限增长。
function rememberEvent(event) {
  eventBuffer.push(event);
  while (eventBuffer.length > maxEvents) {
    eventBuffer.shift();
  }
}

// 保存最近 Ping 结果，供延迟趋势图跨 snapshot 展示。
function rememberPing(ping) {
  pingHistory.push(ping);
  while (pingHistory.length > maxPings) {
    pingHistory.shift();
  }
}

// 广播前实施待发送字节上限；慢客户端会被断开，避免单个页面拖出无界发送缓冲区。
function broadcast(payload) {
  const message = JSON.stringify(payload);
  for (const socket of wss.clients) {
    sendWebSocketMessage(socket, message, wsMaxBufferedBytes);
  }
}

// 合并并发断流通知，确保五秒窗口内只安排一次重连。
function scheduleEventReconnect() {
  if (shuttingDown || reconnectTimer) {
    return;
  }
  // 定时器到期后清除占位，再重新建立 streaming，允许后续断流继续调度。
  reconnectTimer = setTimeout(() => {
    reconnectTimer = null;
    connectEventStream();
  }, 5000);
}

// 建立 gRPC server-streaming，并把事件缓存后实时转发到浏览器。
async function connectEventStream() {
  if (shuttingDown) {
    return;
  }
  streamStartedAt = now();
  streamConnected = false;
  streamError = "";
  await selectReachableGrpcAddress();
  // shutdown 可能发生在地址探测期间，返回后再次检查，避免退出过程中创建新 stream。
  if (shuttingDown) {
    return;
  }

  let call;
  try {
    if (streamCall) {
      streamCall.cancel();
      streamCall = null;
    }
    call = client.subscribeEvents({ types: [] });
    streamCall = call;
  } catch (error) {
    // streaming 创建可能同步抛错，此时记录原因并进入统一重连节奏。
    streamError = compactError(error);
    scheduleEventReconnect();
    return;
  }

  let closed = false;
  // 统一处理 error/end，更新连接状态并安排下一次重连。
  const closeOnce = (error = null) => {
    if (closed) {
      return;
    }
    closed = true;
    if (streamCall === call) {
      streamCall = null;
    }
    streamConnected = false;
    if (error) {
      streamError = compactError(error);
    }
    broadcast({ type: "stream", connected: false, error: streamError });
    scheduleEventReconnect();
  };

  // 每条 proto 事件先规范化和入缓存，再广播给 WebSocket 客户端。
  call.on("data", (event) => {
    streamConnected = true;
    streamError = "";
    const normalized = normalizeEvent(event);
    rememberEvent(normalized);
    broadcast({ type: "event", event: normalized });
  });

  // gRPC error 和正常 end 都复用幂等关闭流程。
  call.on("error", (error) => {
    closeOnce(error);
  });

  // 服务端正常结束流也按断流处理，保持 Dashboard 长期订阅。
  call.on("end", () => {
    closeOnce();
  });
}

// 解析 HealthCheck.details JSON，并根据质量分数补充统一等级。
function parseHealth(details) {
  if (!details) {
    return { raw: "", parsed: null, score: null, level: "UNKNOWN", issues: [] };
  }

  try {
    const parsed = JSON.parse(details);
    const score = typeof parsed.quality_score === "number" ? parsed.quality_score : null;
    let level = "UNKNOWN";
    if (score !== null && score >= 90) level = "EXCELLENT";
    else if (score !== null && score >= 75) level = "GOOD";
    else if (score !== null && score >= 50) level = "FAIR";
    else if (score !== null) level = "POOR";

    return {
      raw: details,
      parsed,
      score,
      level,
      issues: Array.isArray(parsed.issues) ? parsed.issues : []
    };
  } catch {
    // 非 JSON details 仍保留原文，并作为 issue 交给 UI 和 AI。
    return { raw: details, parsed: null, score: null, level: "UNKNOWN", issues: [details] };
  }
}

// 聚合事件类型分布和分钟级时间桶，生成图表直接消费的数据。
function buildEventStats(events) {
  const byTypeMap = new Map();
  const buckets = new Map();

  for (const event of events) {
    byTypeMap.set(event.type, (byTypeMap.get(event.type) || 0) + 1);
    const bucketTime = Math.floor(event.timestamp / 60000) * 60000;
    const bucket = buckets.get(bucketTime) || { time: new Date(bucketTime).toLocaleTimeString(), total: 0 };
    bucket.total += 1;
    bucket[event.type] = (bucket[event.type] || 0) + 1;
    buckets.set(bucketTime, bucket);
  }

  return {
    byType: Array.from(byTypeMap.entries())
      .map(([name, value]) => ({ name, value }))
      .sort((a, b) => b.value - a.value),
    timeline: Array.from(buckets.entries())
      .sort(([a], [b]) => a - b)
      .map(([, value]) => value)
      .slice(-30)
  };
}

// 把 Ping RPC 的成功或异常结果收敛为同一前端模型。
function normalizePing(target, response, error = null) {
  const timestamp = now();
  if (error) {
    return {
      target,
      timestamp,
      success: false,
      latencyMs: null,
      interfaceName: "",
      result: "",
      error: compactError(error)
    };
  }

  return {
    target,
    timestamp,
    success: Boolean(response.success),
    // 手动 Ping 与后台 RTT 使用相同的 precise-first/legacy-fallback 兼容策略。
    latencyMs: response.success
      ? preferredMetricNumber(response, "latencyMsPrecise", "latencyMs")
      : null,
    interfaceName: response.interfaceName || "",
    result: response.result || "",
    error: response.error || ""
  };
}

// 调用 Ping RPC，并无论成功失败都把结果写入历史缓存。
async function pingTarget(target) {
  try {
    const response = await rpc("ping", { hostname: target }, 7000);
    const ping = normalizePing(target, response);
    rememberPing(ping);
    return ping;
  } catch (error) {
    // transport 异常也写入历史，使失败探测在趋势和诊断证据中可见。
    const ping = normalizePing(target, null, error);
    rememberPing(ping);
    return ping;
  }
}

// 采集服务端一次性 typed snapshot，再执行默认探测并组装完整 Dashboard snapshot。
async function collectSnapshot() {
  const generatedAt = now();
  refreshAiConfig();
  await selectReachableGrpcAddress();
  const [networkSnapshotResult] = await Promise.allSettled([rpc("getNetworkSnapshot", {}, 5000)]);

  const errors = [];
  let networkSnapshot = null;
  let interfaces = [];
  let health = parseHealth("");

  if (networkSnapshotResult.status === "fulfilled") {
    networkSnapshot = normalizeNetworkSnapshot(networkSnapshotResult.value);
    interfaces = networkSnapshot.interfaces.map((item) => item.interfaceName);
    health = healthFromNetworkSnapshot(networkSnapshot);
  } else {
    errors.push(compactError(networkSnapshotResult.reason));
  }

  const pings = await Promise.all(pingTargets.map((target) => pingTarget(target)));
  const recentEvents = eventBuffer.slice(-120);
  // 在本轮 RPC/探测完成后采样 BFF，使开销量化覆盖完整的一次 snapshot 编排工作。
  const runtimeResources = buildRuntimeResources(
    networkSnapshot?.engineResources ?? null,
    dashboardResourceSampler.sample()
  );
  const requestFailures = requestFailureMonitor.snapshot();

  return {
    generatedAt,
    grpcAddress,
    grpc: {
      ok: errors.length === 0,
      errors
    },
    stream: {
      connected: streamConnected,
      error: streamError,
      startedAt: streamStartedAt
    },
    ai: {
      configured: fs.existsSync(ragBridgePath),
      provider: "versioned-rag-bridge",
      generationProvider: aiProvider,
      baseUrl: aiBaseUrl,
      model: aiModel,
      bridgePath: ragBridgePath
    },
    interfaces,
    networkSnapshot,
    runtimeResources,
    requestFailures,
    health,
    pings,
    latencySeries: pingHistory.slice(-120).map((item) => ({
      // 保留原始毫秒时间戳，前端可以按真实采样顺序绘制，而不是依赖格式化后的时钟文本。
      timestamp: item.timestamp,
      time: new Date(item.timestamp).toLocaleTimeString(),
      target: item.target,
      latencyMs: item.latencyMs,
      success: item.success
    })),
    events: recentEvents,
    eventStats: buildEventStats(recentEvents)
  };
}

// 启动本地 JSONL bridge；stdin 只传 typed NetworkSnapshot，stdout 只接受一行诊断 JSON。
function runRagBridge(networkSnapshot) {
  return new Promise((resolve, reject) => {
    if (!networkSnapshot) {
      reject(new Error("typed NetworkSnapshot is unavailable"));
      return;
    }
    if (!fs.existsSync(ragBridgePath)) {
      reject(new Error(`RAG bridge not found: ${ragBridgePath}`));
      return;
    }

    const python = process.env.WEAKNET_RAG_PYTHON || process.env.PYTHON || "python3";
    const timeoutMs = Math.max(1000, Number(process.env.DASHBOARD_RAG_TIMEOUT_MS || 15000));
    const child = spawn(python, [ragBridgePath], {
      cwd: projectRoot,
      env: { ...process.env, PYTHONUNBUFFERED: "1" },
      stdio: ["pipe", "pipe", "pipe"]
    });
    activeRagChildren.add(child);
    let stdout = "";
    let stderr = "";
    let settled = false;
    let timer = null;

    // 异常路径主动杀掉仍存活的 bridge，防止 stdin/pipe 错误留下孤儿 Python 进程。
    const terminateChild = () => {
      if (child.exitCode === null && child.signalCode === null) {
        child.kill("SIGKILL");
      }
    };
    const finish = (callback, { killChild = false } = {}) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      activeRagChildren.delete(child);
      if (killChild) {
        terminateChild();
      }
      callback();
    };
    const appendBounded = (current, chunk) => `${current}${chunk}`.slice(-1024 * 1024);

    child.stdout.on("data", (chunk) => {
      stdout = appendBounded(stdout, chunk);
    });
    child.stderr.on("data", (chunk) => {
      stderr = appendBounded(stderr, chunk);
    });
    child.stdout.on("error", (error) => finish(() => reject(error), { killChild: true }));
    child.stderr.on("error", (error) => finish(() => reject(error), { killChild: true }));
    child.stdin.on("error", (error) => finish(() => reject(error), { killChild: true }));
    child.on("error", (error) => finish(() => reject(error), { killChild: true }));
    child.on("close", (code) => {
      finish(() => {
        if (code !== 0) {
          reject(new Error(`RAG bridge exited with code ${code}: ${stderr.trim() || "no diagnostic"}`));
          return;
        }
        const lines = stdout.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
        if (lines.length !== 1) {
          reject(new Error(`RAG bridge protocol violation: expected one JSONL response, received ${lines.length}`));
          return;
        }
        try {
          resolve(normalizeDiagnosis(JSON.parse(lines[0])));
        } catch (error) {
          reject(new Error(`invalid RAG bridge response: ${compactError(error)}`));
        }
      });
    });

    timer = setTimeout(() => {
      finish(
        () => reject(new Error(`RAG bridge timed out after ${timeoutMs}ms`)),
        { killChild: true }
      );
    }, timeoutMs);

    try {
      child.stdin.end(`${JSON.stringify(networkSnapshot)}\n`);
    } catch (error) {
      finish(() => reject(error), { killChild: true });
    }
  });
}

// 统一在线诊断入口：优先使用版本化知识库 bridge，失败时返回显式 degraded typed-rule 结果。
async function runUnifiedDiagnosis(snapshot, diagnosisConfig = {}) {
  const networkSnapshot = {
    ...snapshot.networkSnapshot,
    diagnosisConfig
  };
  try {
    return await runRagBridge(networkSnapshot);
  } catch (error) {
    console.error(`RAG bridge degraded fallback: ${compactError(error)}`);
    return buildDegradedDiagnosis(networkSnapshot, compactError(error));
  }
}

// 返回 BFF、gRPC stream 和 AI 配置的轻量运行状态。
app.get("/api/status", (_request, response) => {
  refreshAiConfig();
  const requestFailures = requestFailureMonitor.snapshot();
  response.json({
    ok: true,
    grpcAddress,
    apiPort,
    aiProvider,
    aiConfigured: fs.existsSync(ragBridgePath),
    aiBaseUrl,
    aiModel,
    ragBridgePath,
    streamConnected,
    streamError,
    eventCount: eventBuffer.length,
    analyzeConcurrency: {
      active: analyzeGate.active,
      limit: analyzeGate.limit
    },
    websocket: {
      connections: wss.clients.size,
      maxConnections: wsMaxConnections,
      maxBufferedBytes: wsMaxBufferedBytes
    },
    browserRequestFailures: {
      connectedRecent: requestFailures.connectedRecent,
      lastHeartbeatAt: requestFailures.lastHeartbeatAt,
      lastReceivedAt: requestFailures.lastReceivedAt,
      totalFailures: requestFailures.totalFailures,
      activeAlerts: requestFailures.activeAlerts.length,
      threshold: requestFailures.threshold,
      windowSeconds: requestFailures.windowSeconds,
      extensionIdRestricted: Boolean(process.env.DASHBOARD_BROWSER_EXTENSION_ID),
      tokenRequired: Boolean(process.env.DASHBOARD_BROWSER_EXTENSION_TOKEN)
    }
  });
});

// Chrome MV3 失败批次到达这里时已经通过独立 Origin/ID/token 守卫并完成有上限的 JSON 解析。
function ingestBrowserFailures(request, response) {
  try {
    const result = requestFailureMonitor.ingest(request.body, { receivedAt: now() });
    response.status(202).json(result);
  } catch (error) {
    response.status(error?.statusCode || 400).json({ error: compactError(error) });
  }
}

// 即时采集并返回一次完整 snapshot。
app.get("/api/snapshot", async (_request, response) => {
  try {
    response.json(await collectSnapshot());
  } catch (error) {
    // snapshot 采集异常统一收敛为 HTTP 500 JSON。
    response.status(500).json({ error: compactError(error) });
  }
});

// 接收浏览器手动目标并转发到 WeakNet Ping RPC。
app.post("/api/ping", async (request, response) => {
  const hostname = String(request.body?.hostname || "").trim();
  if (!hostname) {
    response.status(400).json({ error: "hostname is required" });
    return;
  }

  response.json(await pingTarget(hostname));
});

// 重新采集最新证据后发起 AI 诊断，避免使用前端可篡改的 snapshot。
app.post("/api/analyze", async (request, response) => {
  // 不排队等待：达到上限立即返回 429，避免慢 AI 调用把请求和 Python 子进程堆进内存。
  const releaseAnalyzeSlot = analyzeGate.tryAcquire();
  if (!releaseAnalyzeSlot) {
    response
      .set("Retry-After", "1")
      .status(429)
      .json({ error: `too many concurrent analysis requests (limit=${analyzeGate.limit})` });
    return;
  }

  try {
    const snapshot = await collectSnapshot();
    const diagnosisConfig = {
      topK: request.body?.top_k ?? request.body?.topK ?? process.env.RAG_TOP_K ?? 4,
      similarityThreshold:
        request.body?.similarity_threshold
        ?? request.body?.similarityThreshold
        ?? process.env.RAG_SIMILARITY_THRESHOLD
        ?? 0.08
    };
    const diagnosis = await runUnifiedDiagnosis(snapshot, diagnosisConfig);
    response.json({
      ...diagnosis,
      analysis: formatDiagnosis(diagnosis),
      generatedAt: now()
    });
  } catch (error) {
    // 仅 snapshot 采集本身完全失败时返回错误；RAG 不可用会转为明确 degraded 响应。
    response.status(error.statusCode || 500).json({ error: compactError(error) });
  } finally {
    // success、degraded 和异常响应都释放槽位，保证并发计数不会永久占用。
    releaseAnalyzeSlot();
  }
});

// 浏览器建立 WebSocket 时先发送 stream 状态和最近事件，缩短首屏空窗。
wss.on("connection", (socket) => {
  // error handler 必须先于限流判断安装；超限连接立即硬断开，不能滞留在 close 握手期。
  if (!admitWebSocketConnection(socket, wss.clients.size, wsMaxConnections)) {
    return;
  }

  sendWebSocketMessage(
    socket,
    JSON.stringify({
      type: "hello",
      stream: { connected: streamConnected, error: streamError },
      recentEvents: eventBuffer.slice(-30)
    }),
    wsMaxBufferedBytes
  );
});

// 信号退出时停止重连、取消 stream、终止 bridge，并关闭主 client，避免后台资源遗留。
function shutdown(signal) {
  if (shuttingDown) {
    return;
  }
  shuttingDown = true;
  console.log(`WeakNet dashboard received ${signal}, shutting down...`);

  if (reconnectTimer) {
    clearTimeout(reconnectTimer);
    reconnectTimer = null;
  }
  if (streamCall) {
    const activeStream = streamCall;
    streamCall = null;
    activeStream.cancel();
  }
  grpcClients.retire(client);

  for (const child of activeRagChildren) {
    if (child.exitCode === null && child.signalCode === null) {
      child.kill("SIGKILL");
    }
  }
  activeRagChildren.clear();

  for (const socket of wss.clients) {
    socket.terminate();
  }
  wss.close();

  const exitCleanly = () => process.exit(0);
  if (server.listening) {
    server.close(exitCleanly);
  } else {
    exitCleanly();
  }

  // 极端情况下仍给退出设置硬期限，避免系统 stop 命令永远等待。
  const forceExitTimer = setTimeout(exitCleanly, 3000);
  forceExitTimer.unref();
}

process.once("SIGINT", () => shutdown("SIGINT"));
process.once("SIGTERM", () => shutdown("SIGTERM"));

// 启动顺序：探测 gRPC、建立事件流，最后监听本地 HTTP 端口。
await selectReachableGrpcAddress(true);
connectEventStream();

// HTTP 监听成功后输出最终生效的端口、gRPC 目标和 AI 配置摘要。
server.listen(apiPort, "127.0.0.1", () => {
  console.log(`WeakNet dashboard API listening on http://127.0.0.1:${apiPort}`);
  console.log(`WeakNet gRPC target: ${grpcAddress}`);
  console.log(`AI provider: ${aiProvider} ${aiModel} at ${aiBaseUrl}`);
  console.log(`RAG diagnosis bridge: ${fs.existsSync(ragBridgePath) ? ragBridgePath : "not configured"}`);
});
