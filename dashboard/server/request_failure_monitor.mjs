// 真实 Chrome 请求失败的 BFF 侧契约与有界聚合：校验扩展批次、幂等去重并生成滑窗告警。

import { timingSafeEqual } from "node:crypto";
import { isIP } from "node:net";

export const REQUEST_FAILURE_SCHEMA_VERSION = 1;
export const REQUEST_FAILURE_SOURCE = "chrome-mv3-webrequest";

const DEFAULT_WINDOW_MS = 5 * 60_000;
const DEFAULT_THRESHOLD = 5;
const DEFAULT_CONNECTED_GRACE_MS = 2 * 60_000;
const DEFAULT_MAX_BATCH = 100;
const DEFAULT_MAX_RECENT = 500;
const DEFAULT_MAX_GROUPS = 512;
const DEFAULT_MAX_DEDUPE = 5000;
const DEFAULT_MAX_IPS_PER_GROUP = 8;
const DEFAULT_MAX_WINDOW_EVENTS_PER_GROUP = 512;
const DEFAULT_MAX_TRANSITIONS = 120;
const DEFAULT_GROUP_TTL_MS = 60 * 60_000;
const DEFAULT_DEDUPE_TTL_MS = 30 * 60_000;
const DEFAULT_MAX_FUTURE_SKEW_MS = 60_000;
const DEFAULT_MAX_CLIENT_PAST_MS = 24 * 60 * 60_000;

const CANCELLED_CODES = new Set([
  "NET::ERR_ABORTED",
  "NET::ERR_BLOCKED_BY_CLIENT"
]);
const POLICY_CODES = new Set([
  "NET::ERR_BLOCKED_BY_ADMINISTRATOR",
  "NET::ERR_ACCESS_DENIED",
  "NET::ERR_BLOCKED_BY_CSP",
  "NET::ERR_BLOCKED_BY_RESPONSE"
]);

export class RequestFailureValidationError extends Error {
  constructor(message, statusCode = 400) {
    super(message);
    this.name = "RequestFailureValidationError";
    this.statusCode = statusCode;
  }
}

function boundedInteger(value, fallback, min, max) {
  const parsed = Number(value);
  const candidate = Number.isFinite(parsed) ? parsed : fallback;
  return Math.min(max, Math.max(min, Math.trunc(candidate)));
}

function boundedString(value, name, maxLength, { allowEmpty = false } = {}) {
  const text = String(value ?? "").trim();
  if ((!allowEmpty && !text) || text.length > maxLength || /[\u0000-\u001f\u007f]/.test(text)) {
    throw new RequestFailureValidationError(`invalid ${name}`);
  }
  return text;
}

function canonicalExtensionId(value) {
  const id = String(value || "").trim().toLowerCase();
  return /^[a-p]{32}$/.test(id) ? id : "";
}

function extensionIdFromOrigin(origin) {
  const match = String(origin || "").match(/^chrome-extension:\/\/([a-p]{32})$/);
  return match ? match[1] : "";
}

// 默认接受任一合法 Chrome extension Origin，便于 unpacked 演示；配置 ID 后收紧为精确配对。
export function isAllowedExtensionOrigin(origin, expectedExtensionId) {
  const actualId = extensionIdFromOrigin(origin);
  if (!actualId) return false;
  const expectedId = canonicalExtensionId(expectedExtensionId);
  return !expectedExtensionId || (Boolean(expectedId) && actualId === expectedId);
}

export function isLoopbackRemoteAddress(remoteAddress) {
  const address = String(remoteAddress || "").toLowerCase().split("%")[0];
  if (address === "::1") return true;
  const ipv4 = address.startsWith("::ffff:") ? address.slice(7) : address;
  return /^127(?:\.\d{1,3}){3}$/.test(ipv4);
}

export function constantTimeTokenEquals(providedToken, expectedToken) {
  const expected = Buffer.from(String(expectedToken || ""));
  const provided = Buffer.from(String(providedToken || ""));
  // 未配置 token 时依靠 loopback + extension Origin；部署者配置后才启用常量时间校验。
  return expected.length === 0
    || (expected.length === provided.length
      && timingSafeEqual(expected, provided));
}

// index.mjs 可直接消费该 helper；ID/token 是可选加固，loopback 与合法 extension Origin 永远必需。
export function authorizeFailureIngest({
  origin,
  expectedExtensionId,
  remoteAddress,
  providedToken,
  expectedToken
}) {
  if (!isLoopbackRemoteAddress(remoteAddress)) {
    return { ok: false, statusCode: 403, reason: "ingest accepts loopback clients only" };
  }
  if (!isAllowedExtensionOrigin(origin, expectedExtensionId)) {
    return { ok: false, statusCode: 403, reason: "extension origin is not paired" };
  }
  if (!constantTimeTokenEquals(providedToken, expectedToken)) {
    return { ok: false, statusCode: 401, reason: "extension token is invalid" };
  }
  return { ok: true, statusCode: 202, reason: "accepted" };
}

function sanitizeSafeUrl(rawValue) {
  let parsed;
  try {
    parsed = new URL(String(rawValue || ""));
  } catch {
    throw new RequestFailureValidationError("invalid safeUrl");
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new RequestFailureValidationError("safeUrl must use http or https");
  }
  parsed.username = "";
  parsed.password = "";
  parsed.search = "";
  parsed.hash = "";
  // 旧版或被篡改的扩展仍可能发送 pathname；BFF 侧再次强制降为 origin-only。
  const safeUrl = `${parsed.protocol}//${parsed.host}/`;
  return {
    scheme: parsed.protocol.slice(0, -1),
    host: parsed.hostname.toLowerCase().replace(/\.$/, ""),
    port: parsed.port || (parsed.protocol === "https:" ? "443" : "80"),
    safeUrl
  };
}

function normalizeIp(value) {
  if (value === undefined || value === null || value === "") return null;
  const ip = String(value).trim().split("%")[0];
  if (!isIP(ip)) throw new RequestFailureValidationError("invalid serverIp");
  return ip;
}

// Chrome 文档声明 network error 字符串可能跨版本变化；始终保留原码，分类只用于降噪展示。
export function classifyFailureCode(statusCode, rawNetworkError) {
  if (Number.isInteger(statusCode)) {
    return { category: "http", alertEligible: statusCode >= 400 && statusCode <= 599 };
  }
  const code = String(rawNetworkError || "").trim().toUpperCase();
  if (CANCELLED_CODES.has(code) || code.includes("ERR_ABORTED")) {
    return { category: "cancelled", alertEligible: false };
  }
  if (POLICY_CODES.has(code) || code.includes("BLOCKED_BY")) {
    return { category: "policy", alertEligible: false };
  }
  if (code.includes("NAME_NOT_RESOLVED") || code.includes("DNS_")) {
    return { category: "dns", alertEligible: true };
  }
  if (code.includes("CERT_") || code.includes("SSL_") || code.includes("TLS_")) {
    return { category: "tls", alertEligible: true };
  }
  if (
    code.includes("CONNECTION_")
    || code.includes("ADDRESS_UNREACHABLE")
    || code.includes("NETWORK_CHANGED")
    || code.includes("INTERNET_DISCONNECTED")
    || code.includes("TIMED_OUT")
  ) {
    return { category: "connection", alertEligible: true };
  }
  // 未知码仍然代表 onErrorOccurred 终态失败；仅明确的主动取消/策略拦截参与降噪。
  return { category: "network", alertEligible: true };
}

function normalizeOccurredAt(rawValue, receivedAt, {
  alertWindowMs = DEFAULT_WINDOW_MS,
  maxFutureSkewMs = DEFAULT_MAX_FUTURE_SKEW_MS,
  maxClientPastMs = DEFAULT_MAX_CLIENT_PAST_MS
} = {}) {
  const serverTime = Number(receivedAt);
  const clientTime = Number(rawValue);
  if (!Number.isFinite(clientTime) || clientTime <= 0) {
    return {
      occurredAt: serverTime,
      timestampAdjusted: true,
      timestampTrusted: false,
      staleBacklog: false,
      timestampAlertEligible: false
    };
  }
  if (clientTime > serverTime + maxFutureSkewMs) {
    return {
      occurredAt: serverTime,
      timestampAdjusted: true,
      timestampTrusted: false,
      staleBacklog: false,
      timestampAlertEligible: false
    };
  }
  if (clientTime < serverTime - maxClientPastMs) {
    return {
      occurredAt: serverTime - maxClientPastMs,
      timestampAdjusted: true,
      timestampTrusted: false,
      staleBacklog: true,
      timestampAlertEligible: false
    };
  }

  // Chrome 与本机 BFF 共用系统时钟；只信任有界值。轻微未来偏差钳制到接收时刻，绝不进入未来窗口。
  const occurredAt = Math.min(clientTime, serverTime);
  const staleBacklog = serverTime - occurredAt > alertWindowMs;
  return {
    occurredAt,
    timestampAdjusted: occurredAt !== clientTime,
    timestampTrusted: true,
    staleBacklog,
    timestampAlertEligible: !staleBacklog
  };
}

export function validateRequestFailureEvent(rawEvent, receivedAt = Date.now(), timingOptions = {}) {
  if (!rawEvent || typeof rawEvent !== "object" || Array.isArray(rawEvent)) {
    throw new RequestFailureValidationError("event must be an object");
  }
  const terminal = boundedString(rawEvent.terminal, "terminal", 16);
  if (terminal !== "completed" && terminal !== "error") {
    throw new RequestFailureValidationError("terminal must be completed or error");
  }
  const url = sanitizeSafeUrl(rawEvent.safeUrl);
  if (rawEvent.host && String(rawEvent.host).toLowerCase().replace(/\.$/, "") !== url.host) {
    throw new RequestFailureValidationError("host does not match safeUrl");
  }
  if (rawEvent.scheme && String(rawEvent.scheme).toLowerCase() !== url.scheme) {
    throw new RequestFailureValidationError("scheme does not match safeUrl");
  }

  let statusCode = null;
  let networkError = null;
  let failureCode;
  if (terminal === "completed") {
    statusCode = Number(rawEvent.statusCode);
    if (!Number.isInteger(statusCode) || statusCode < 400 || statusCode > 599) {
      throw new RequestFailureValidationError("completed event must contain an HTTP 4xx or 5xx status");
    }
    failureCode = `HTTP_${statusCode}`;
  } else {
    if (rawEvent.statusCode !== null && rawEvent.statusCode !== undefined) {
      throw new RequestFailureValidationError("network error must not contain statusCode");
    }
    networkError = boundedString(rawEvent.networkError || rawEvent.failureCode, "networkError", 128);
    failureCode = networkError;
  }
  const classification = classifyFailureCode(statusCode, networkError);
  const timing = normalizeOccurredAt(rawEvent.occurredAt, Number(receivedAt), timingOptions);
  const alertEligible = classification.alertEligible && timing.timestampAlertEligible;
  const alertEligibilityReason = !classification.alertEligible
    ? "classification_filtered"
    : timing.staleBacklog
      ? "stale_backlog"
      : !timing.timestampTrusted
        ? "untrusted_timestamp"
        : "eligible";

  return {
    eventId: boundedString(rawEvent.eventId, "eventId", 256),
    occurredAt: timing.occurredAt,
    timestampAdjusted: timing.timestampAdjusted,
    timestampTrusted: timing.timestampTrusted,
    staleBacklog: timing.staleBacklog,
    receivedAt: Number(receivedAt),
    terminal,
    ...url,
    method: boundedString(rawEvent.method || "GET", "method", 16).toUpperCase(),
    resourceType: boundedString(rawEvent.resourceType || "other", "resourceType", 40),
    serverIp: normalizeIp(rawEvent.serverIp),
    fromCache: Boolean(rawEvent.fromCache),
    statusCode,
    failureCode,
    networkError,
    category: classification.category,
    classificationAlertEligible: classification.alertEligible,
    alertEligible,
    alertEligibilityReason
  };
}

export function validateRequestFailureBatch(rawBatch, {
  receivedAt = Date.now(),
  maxBatch = DEFAULT_MAX_BATCH,
  alertWindowMs = DEFAULT_WINDOW_MS,
  maxFutureSkewMs = DEFAULT_MAX_FUTURE_SKEW_MS,
  maxClientPastMs = DEFAULT_MAX_CLIENT_PAST_MS
} = {}) {
  if (!rawBatch || typeof rawBatch !== "object" || Array.isArray(rawBatch)) {
    throw new RequestFailureValidationError("batch must be an object");
  }
  if (Number(rawBatch.schemaVersion) !== REQUEST_FAILURE_SCHEMA_VERSION) {
    throw new RequestFailureValidationError("unsupported schemaVersion");
  }
  const kind = rawBatch.kind === "heartbeat" ? "heartbeat" : rawBatch.kind === "failures" ? "failures" : "";
  if (!kind) throw new RequestFailureValidationError("kind must be heartbeat or failures");
  const events = Array.isArray(rawBatch.events) ? rawBatch.events : null;
  if (!events || events.length > maxBatch || (kind === "heartbeat" && events.length !== 0)) {
    throw new RequestFailureValidationError("invalid events batch size");
  }
  if (kind === "failures" && events.length === 0) {
    throw new RequestFailureValidationError("failure batch must not be empty");
  }

  const validEvents = [];
  const rejected = [];
  for (let index = 0; index < events.length; index += 1) {
    try {
      validEvents.push(validateRequestFailureEvent(events[index], receivedAt, {
        alertWindowMs,
        maxFutureSkewMs,
        maxClientPastMs
      }));
    } catch (error) {
      rejected.push({ index, reason: String(error?.message || error).slice(0, 160) });
    }
  }
  return {
    schemaVersion: REQUEST_FAILURE_SCHEMA_VERSION,
    kind,
    browserSessionId: boundedString(rawBatch.browserSessionId, "browserSessionId", 128),
    batchId: boundedString(rawBatch.batchId, "batchId", 128),
    sentAt: Number.isFinite(Number(rawBatch.sentAt)) ? Number(rawBatch.sentAt) : Number(receivedAt),
    clientDropped: boundedInteger(rawBatch.clientDropped, 0, 0, 1_000_000_000),
    events: validEvents,
    rejected
  };
}

function incrementBoundedMap(map, key, at, limit) {
  const current = map.get(key) || { value: key, count: 0, lastSeenAt: 0 };
  current.count += 1;
  current.lastSeenAt = at;
  map.delete(key);
  map.set(key, current);
  let evictions = 0;
  while (map.size > limit) {
    map.delete(map.keys().next().value);
    evictions += 1;
  }
  return evictions;
}

function mapCounts(map) {
  return Array.from(map.values())
    .sort((left, right) => right.count - left.count || right.lastSeenAt - left.lastSeenAt)
    .map((item) => ({ ...item }));
}

export function createRequestFailureMonitor(options = {}) {
  const windowMs = boundedInteger(options.windowMs, DEFAULT_WINDOW_MS, 10_000, 24 * 60 * 60_000);
  const threshold = boundedInteger(options.threshold, DEFAULT_THRESHOLD, 1, 10_000);
  const connectedGraceMs = boundedInteger(
    options.connectedGraceMs,
    DEFAULT_CONNECTED_GRACE_MS,
    30_000,
    10 * 60_000
  );
  const maxRecent = boundedInteger(options.maxRecent, DEFAULT_MAX_RECENT, 1, 10_000);
  const maxGroups = boundedInteger(options.maxGroups, DEFAULT_MAX_GROUPS, 1, 10_000);
  const maxDedupe = boundedInteger(options.maxDedupe, DEFAULT_MAX_DEDUPE, 1, 100_000);
  const maxIpsPerGroup = boundedInteger(options.maxIpsPerGroup, DEFAULT_MAX_IPS_PER_GROUP, 1, 64);
  const maxWindowEventsPerGroup = boundedInteger(
    options.maxWindowEventsPerGroup,
    DEFAULT_MAX_WINDOW_EVENTS_PER_GROUP,
    threshold,
    10_000
  );
  const maxTransitions = boundedInteger(options.maxTransitions, DEFAULT_MAX_TRANSITIONS, 1, 1000);
  const groupTtlMs = boundedInteger(options.groupTtlMs, DEFAULT_GROUP_TTL_MS, windowMs, 7 * 24 * 60 * 60_000);
  const dedupeTtlMs = boundedInteger(options.dedupeTtlMs, DEFAULT_DEDUPE_TTL_MS, windowMs, 24 * 60 * 60_000);
  const maxFutureSkewMs = boundedInteger(
    options.maxFutureSkewMs,
    DEFAULT_MAX_FUTURE_SKEW_MS,
    0,
    10 * 60_000
  );
  const maxClientPastMs = boundedInteger(
    options.maxClientPastMs,
    DEFAULT_MAX_CLIENT_PAST_MS,
    windowMs,
    7 * 24 * 60 * 60_000
  );
  const clock = typeof options.now === "function" ? options.now : Date.now;
  const onTransition = typeof options.onTransition === "function" ? options.onTransition : () => {};

  const recentFailures = [];
  const groups = new Map();
  const dedupe = new Map();
  const alertTransitions = [];
  let lastHeartbeatAt = 0;
  let lastReceivedAt = 0;
  let totalFailures = 0;
  let totalDuplicates = 0;
  let totalRejected = 0;
  let clientDropped = 0;
  let groupEvictions = 0;
  // 分组被淘汰后只保留“至少仍有一条遗漏在窗口内”的到期边界，不让历史淘汰永久污染 capped。
  let evictedWindowExpiryAt = 0;

  function emitTransition(transition) {
    alertTransitions.push(transition);
    if (alertTransitions.length > maxTransitions) {
      alertTransitions.splice(0, alertTransitions.length - maxTransitions);
    }
    try {
      onTransition(transition);
    } catch {
      // 观察者失败不能破坏采集和告警状态机。
    }
  }

  function pruneDedupe(at) {
    for (const [key, seenAt] of dedupe) {
      if (at - seenAt <= dedupeTtlMs && dedupe.size <= maxDedupe) break;
      dedupe.delete(key);
    }
    while (dedupe.size > maxDedupe) dedupe.delete(dedupe.keys().next().value);
  }

  function pruneGroupWindow(group, at) {
    while (group.allWindowAt.length && at - group.allWindowAt[0] > windowMs) {
      group.allWindowAt.shift();
    }
    while (group.alertWindowAt.length && at - group.alertWindowAt[0] > windowMs) {
      group.alertWindowAt.shift();
    }
    if (at > group.windowOverflowExpiryAt) {
      group.windowOverflowExpiryAt = 0;
    }
    if (group.activeAlert && group.alertWindowAt.length < threshold) {
      const transition = {
        ...group.activeAlert,
        state: "resolved",
        resolvedAt: at,
        countInWindow: group.alertWindowAt.length
      };
      group.activeAlert = null;
      emitTransition(transition);
    } else if (group.activeAlert) {
      group.activeAlert.countInWindow = group.alertWindowAt.length;
    }
  }

  function sweep(at = clock()) {
    pruneDedupe(at);
    for (const [key, group] of groups) {
      pruneGroupWindow(group, at);
      if (!group.activeAlert && at - group.lastSeenAt > groupTtlMs) groups.delete(key);
    }
  }

  function evictOneGroup(at) {
    let candidateKey = null;
    let candidate = null;
    for (const [key, group] of groups) {
      if (
        !candidate
        || (candidate.activeAlert && !group.activeAlert)
        || (Boolean(candidate.activeAlert) === Boolean(group.activeAlert) && group.lastSeenAt < candidate.lastSeenAt)
      ) {
        candidateKey = key;
        candidate = group;
      }
    }
    if (candidateKey !== null) {
      pruneGroupWindow(candidate, at);
      if (candidate.allWindowAt.length > 0) {
        const newestOmittedAt = candidate.allWindowAt[candidate.allWindowAt.length - 1];
        evictedWindowExpiryAt = Math.max(evictedWindowExpiryAt, newestOmittedAt + windowMs);
      }
      groups.delete(candidateKey);
      groupEvictions += 1;
    }
  }

  function groupFor(event, at) {
    const key = `${event.host}\u0000${event.failureCode}`;
    let group = groups.get(key);
    if (!group) {
      if (groups.size >= maxGroups) evictOneGroup(at);
      group = {
        key,
        host: event.host,
        failureCode: event.failureCode,
        statusCode: event.statusCode,
        networkError: event.networkError,
        category: event.category,
        // 分组表达错误类型是否可告警；单条事件还会因 stale/untrusted timestamp 被降为不可告警。
        alertEligible: event.classificationAlertEligible,
        totalCount: 0,
        firstSeenAt: at,
        lastSeenAt: at,
        lastOccurredAt: event.occurredAt,
        lastFailure: event,
        allWindowAt: [],
        alertWindowAt: [],
        windowOverflowExpiryAt: 0,
        ipEvictions: 0,
        ips: new Map(),
        resourceTypes: new Map(),
        activeAlert: null
      };
      groups.set(key, group);
    } else {
      groups.delete(key);
      groups.set(key, group);
    }
    return group;
  }

  function recordEvent(event, _browserSessionId, receivedAt) {
    // eventId 已包含扩展生成时的 browserSessionId；仅以它去重，浏览器重启后重放仍保持幂等。
    const dedupeKey = event.eventId;
    if (dedupe.has(dedupeKey)) {
      // 响应丢失会让扩展持续重试同一 eventId；刷新 TTL 可防止长重试后被再次累计。
      dedupe.delete(dedupeKey);
      dedupe.set(dedupeKey, receivedAt);
      totalDuplicates += 1;
      return { accepted: false, duplicate: true };
    }
    dedupe.set(dedupeKey, receivedAt);
    pruneDedupe(receivedAt);

    const normalized = { ...event, receivedAt };
    recentFailures.push(normalized);
    if (recentFailures.length > maxRecent) {
      recentFailures.splice(0, recentFailures.length - maxRecent);
    }
    totalFailures += 1;
    lastReceivedAt = receivedAt;

    const group = groupFor(normalized, receivedAt);
    pruneGroupWindow(group, receivedAt);
    group.totalCount += 1;
    group.lastSeenAt = receivedAt;
    group.lastOccurredAt = normalized.occurredAt;
    group.lastFailure = normalized;
    // 有界且可信的 occurredAt 决定当前窗口；receivedAt 仅用于接收顺序、在线状态和去重 TTL。
    group.allWindowAt.push(normalized.occurredAt);
    group.allWindowAt.sort((left, right) => left - right);
    if (group.allWindowAt.length > maxWindowEventsPerGroup) {
      const overflow = group.allWindowAt.length - maxWindowEventsPerGroup;
      const omitted = group.allWindowAt.splice(0, overflow);
      const newestOmittedAt = omitted[omitted.length - 1];
      group.windowOverflowExpiryAt = Math.max(
        group.windowOverflowExpiryAt,
        newestOmittedAt + windowMs
      );
    }
    incrementBoundedMap(group.resourceTypes, normalized.resourceType, receivedAt, 32);
    if (normalized.serverIp) {
      group.ipEvictions += incrementBoundedMap(
        group.ips,
        normalized.serverIp,
        receivedAt,
        maxIpsPerGroup
      );
    }

    if (normalized.alertEligible) {
      group.alertWindowAt.push(normalized.occurredAt);
      group.alertWindowAt.sort((left, right) => left - right);
      if (group.alertWindowAt.length > maxWindowEventsPerGroup) {
        group.alertWindowAt.splice(
          0,
          group.alertWindowAt.length - maxWindowEventsPerGroup
        );
      }
      if (!group.activeAlert && group.alertWindowAt.length >= threshold) {
        group.activeAlert = {
          id: `${group.host}:${group.failureCode}:${receivedAt}`,
          state: "firing",
          host: group.host,
          failureCode: group.failureCode,
          statusCode: group.statusCode,
          networkError: group.networkError,
          category: group.category,
          threshold,
          windowSeconds: Math.round(windowMs / 1000),
          startedAt: receivedAt,
          lastSeenAt: receivedAt,
          countInWindow: group.alertWindowAt.length,
          lastIp: normalized.serverIp,
          resourceType: normalized.resourceType
        };
        emitTransition({ ...group.activeAlert });
      } else if (group.activeAlert) {
        group.activeAlert.lastSeenAt = receivedAt;
        group.activeAlert.countInWindow = group.alertWindowAt.length;
        group.activeAlert.lastIp = normalized.serverIp;
        group.activeAlert.resourceType = normalized.resourceType;
      }
    }
    return { accepted: true, duplicate: false };
  }

  function ingest(rawBatch, { receivedAt = clock() } = {}) {
    const batch = validateRequestFailureBatch(rawBatch, {
      receivedAt,
      alertWindowMs: windowMs,
      maxFutureSkewMs,
      maxClientPastMs
    });
    totalRejected += batch.rejected.length;
    if (batch.kind === "heartbeat") {
      lastHeartbeatAt = Number(receivedAt);
      return {
        kind: "heartbeat",
        accepted: 0,
        duplicates: 0,
        rejected: 0,
        lastHeartbeatAt
      };
    }

    let accepted = 0;
    let duplicates = 0;
    for (const event of batch.events) {
      const outcome = recordEvent(event, batch.browserSessionId, Number(receivedAt));
      if (outcome.accepted) accepted += 1;
      if (outcome.duplicate) duplicates += 1;
    }
    // 同一批响应丢失后事件会命中 dedupe；只在确有新事件时接纳扩展的 dropped delta。
    if (accepted > 0) clientDropped += batch.clientDropped;
    return {
      kind: "failures",
      accepted,
      duplicates,
      rejected: batch.rejected.length,
      rejectedEvents: batch.rejected
    };
  }

  function serializeGroup(group, at) {
    pruneGroupWindow(group, at);
    return {
      host: group.host,
      failureCode: group.failureCode,
      statusCode: group.statusCode,
      networkError: group.networkError,
      category: group.category,
      alertEligible: group.alertEligible,
      totalCount: group.totalCount,
      countInWindow: group.allWindowAt.length,
      alertEligibleCountInWindow: group.alertWindowAt.length,
      windowCountCapped: group.windowOverflowExpiryAt > 0,
      // 只报告可证明仍处于当前窗口的遗漏 lower bound；不再暴露历史累计 overflow。
      windowOverflowCount: group.windowOverflowExpiryAt > 0 ? 1 : 0,
      ipEvictions: group.ipEvictions,
      firstSeenAt: group.firstSeenAt,
      lastSeenAt: group.lastSeenAt,
      lastOccurredAt: group.lastOccurredAt,
      lastFailure: { ...group.lastFailure },
      ips: mapCounts(group.ips),
      resourceTypes: mapCounts(group.resourceTypes),
      activeAlert: group.activeAlert ? { ...group.activeAlert } : null
    };
  }

  function snapshot(at = clock()) {
    sweep(at);
    const serializedGroups = Array.from(groups.values())
      .map((group) => serializeGroup(group, at))
      .sort((left, right) => right.lastSeenAt - left.lastSeenAt);
    const activeAlerts = serializedGroups
      .filter((group) => group.activeAlert)
      .map((group) => group.activeAlert)
      .sort((left, right) => right.lastSeenAt - left.lastSeenAt);
    // 以分组的有界滑窗求和；发生容量截断时由 windowCountCapped 明确暴露，而不假装精确。
    const failuresInWindow = serializedGroups.reduce((count, group) => count + group.countInWindow, 0);
    const byHostMap = new Map();
    const byFailureCodeMap = new Map();
    for (const group of serializedGroups) {
      const host = byHostMap.get(group.host) || { host: group.host, totalCount: 0, countInWindow: 0, activeAlerts: 0, lastSeenAt: 0 };
      host.totalCount += group.totalCount;
      host.countInWindow += group.countInWindow;
      host.activeAlerts += group.activeAlert ? 1 : 0;
      host.lastSeenAt = Math.max(host.lastSeenAt, group.lastSeenAt);
      byHostMap.set(group.host, host);

      const code = byFailureCodeMap.get(group.failureCode) || {
        failureCode: group.failureCode,
        category: group.category,
        totalCount: 0,
        countInWindow: 0,
        activeAlerts: 0,
        lastSeenAt: 0
      };
      code.totalCount += group.totalCount;
      code.countInWindow += group.countInWindow;
      code.activeAlerts += group.activeAlert ? 1 : 0;
      code.lastSeenAt = Math.max(code.lastSeenAt, group.lastSeenAt);
      byFailureCodeMap.set(group.failureCode, code);
    }

    const lastContactAt = Math.max(lastHeartbeatAt, lastReceivedAt);
    const evictedWindowLowerBound = at <= evictedWindowExpiryAt && evictedWindowExpiryAt > 0 ? 1 : 0;
    const retainedOverflowLowerBound = serializedGroups.reduce(
      (count, group) => count + group.windowOverflowCount,
      0
    );
    const failuresInWindowOverflow = evictedWindowLowerBound + retainedOverflowLowerBound;
    return {
      enabled: true,
      source: REQUEST_FAILURE_SOURCE,
      lastReceivedAt,
      lastHeartbeatAt,
      // 成功上报失败与 heartbeat 都能证明扩展近期在线，避免事件刚到却显示 offline。
      lastContactAt,
      connectedRecent: lastContactAt > 0 && at - lastContactAt <= connectedGraceMs,
      totalFailures,
      windowSeconds: Math.round(windowMs / 1000),
      threshold,
      failuresInWindow,
      failuresInWindowCapped: failuresInWindowOverflow > 0,
      failuresInWindowOverflow,
      activeAlerts,
      recentFailures: recentFailures.slice().reverse(),
      byHost: Array.from(byHostMap.values()).sort((left, right) => right.countInWindow - left.countInWindow || right.lastSeenAt - left.lastSeenAt),
      byFailureCode: Array.from(byFailureCodeMap.values()).sort((left, right) => right.countInWindow - left.countInWindow || right.lastSeenAt - left.lastSeenAt),
      groups: serializedGroups,
      alertTransitions: alertTransitions.slice().reverse(),
      stats: {
        duplicates: totalDuplicates,
        rejected: totalRejected,
        clientDropped,
        groupEvictions,
        recentSize: recentFailures.length,
        groupSize: groups.size,
        dedupeSize: dedupe.size
      }
    };
  }

  return {
    ingest,
    snapshot,
    sweep,
    config: {
      windowMs,
      threshold,
      connectedGraceMs,
      maxRecent,
      maxGroups,
      maxDedupe,
      maxIpsPerGroup,
      maxWindowEventsPerGroup,
      maxFutureSkewMs,
      maxClientPastMs
    }
  };
}
