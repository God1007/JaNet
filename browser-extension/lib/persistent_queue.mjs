// MV3 service worker 可随时休眠，因此待上报失败写入 chrome.storage.local，并始终保持固定容量。

export const DEFAULT_QUEUE_LIMIT = 1000;
export const DEFAULT_BATCH_LIMIT = 100;

export function emptyQueueState() {
  return {
    items: [],
    droppedSinceLastAck: 0,
    retryCount: 0,
    nextAttemptAt: 0
  };
}

// 与 BFF 默认 5 分钟告警窗口一致：扩展离线或电脑休眠后，不重放已经离开当前窗口的旧失败。
export const DEFAULT_QUEUE_TTL_MS = 5 * 60_000;

const QUEUED_AT_FIELD = "__janetQueuedAt";

export function normalizeQueueState(rawState) {
  const raw = rawState && typeof rawState === "object" ? rawState : {};
  return {
    items: Array.isArray(raw.items) ? raw.items.filter(Boolean).slice(-DEFAULT_QUEUE_LIMIT) : [],
    droppedSinceLastAck: Math.max(0, Math.trunc(Number(raw.droppedSinceLastAck) || 0)),
    retryCount: Math.max(0, Math.trunc(Number(raw.retryCount) || 0)),
    nextAttemptAt: Math.max(0, Number(raw.nextAttemptAt) || 0)
  };
}

function boundedNow(value) {
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : Date.now();
}

function queuedAtFor(item, at) {
  const persisted = Number(item?.[QUEUED_AT_FIELD]);
  if (Number.isFinite(persisted) && persisted > 0) return Math.min(persisted, at);
  // 兼容升级前已落盘的队列：旧条目没有内部入队时间，只能用本机 webRequest 时间迁移。
  const legacyOccurredAt = Number(item?.occurredAt);
  if (Number.isFinite(legacyOccurredAt) && legacyOccurredAt > 0) {
    return Math.min(legacyOccurredAt, at);
  }
  // 无可用时间的旧条目从本次加载开始计时，避免升级时误删仍可能有效的事件。
  return at;
}

// TTL 清理会计入 clientDropped；边界上的事件仍可发送，超过 TTL 1ms 才过期。
export function pruneExpired(
  rawState,
  at = Date.now(),
  ttlMs = DEFAULT_QUEUE_TTL_MS
) {
  const state = normalizeQueueState(rawState);
  const now = boundedNow(at);
  const ttl = Math.max(1000, Math.trunc(Number(ttlMs) || DEFAULT_QUEUE_TTL_MS));
  const before = state.items.length;
  state.items = state.items.filter((item) => now - queuedAtFor(item, now) <= ttl);
  state.droppedSinceLastAck += before - state.items.length;
  if (state.items.length === 0) {
    state.retryCount = 0;
    state.nextAttemptAt = 0;
  }
  return state;
}

export function enqueueBounded(
  rawState,
  event,
  limit = DEFAULT_QUEUE_LIMIT,
  at = Date.now(),
  ttlMs = DEFAULT_QUEUE_TTL_MS
) {
  const now = boundedNow(at);
  const state = pruneExpired(rawState, now, ttlMs);
  const safeLimit = Math.max(1, Math.trunc(Number(limit) || DEFAULT_QUEUE_LIMIT));
  if (state.items.some((item) => item.eventId === event?.eventId)) return state;

  state.items.push({ ...event, [QUEUED_AT_FIELD]: now });
  if (state.items.length > safeLimit) {
    const overflow = state.items.length - safeLimit;
    state.items.splice(0, overflow);
    state.droppedSinceLastAck += overflow;
  }
  return state;
}

export function takeBatch(rawState, limit = DEFAULT_BATCH_LIMIT) {
  const state = normalizeQueueState(rawState);
  const safeLimit = Math.max(1, Math.trunc(Number(limit) || DEFAULT_BATCH_LIMIT));
  return {
    // 内部入队时间只服务于本地 TTL，不进入 BFF 的请求事件契约。
    events: state.items.slice(0, safeLimit).map((item) => {
      const event = { ...item };
      delete event[QUEUED_AT_FIELD];
      return event;
    }),
    droppedSinceLastAck: state.droppedSinceLastAck,
    nextAttemptAt: state.nextAttemptAt
  };
}

export function resetQueueRetry(rawState) {
  const state = normalizeQueueState(rawState);
  state.retryCount = 0;
  state.nextAttemptAt = 0;
  return state;
}

// 只按 eventId 删除本批 ACK，避免网络等待期间新入队事件被错误 slice 掉。
export function acknowledgeBatch(rawState, eventIds, acknowledgedDropped = 0) {
  const state = normalizeQueueState(rawState);
  const acknowledged = new Set(eventIds || []);
  state.items = state.items.filter((item) => !acknowledged.has(item.eventId));
  state.droppedSinceLastAck = Math.max(
    0,
    state.droppedSinceLastAck - Math.max(0, Math.trunc(Number(acknowledgedDropped) || 0))
  );
  state.retryCount = 0;
  state.nextAttemptAt = 0;
  return state;
}

// 失败批次保留原事件并指数退避；30 秒 alarm 是 service worker 被回收后的兜底重试入口。
export function markBatchRetry(rawState, at = Date.now()) {
  const state = normalizeQueueState(rawState);
  state.retryCount = Math.min(10, state.retryCount + 1);
  const delayMs = Math.min(5 * 60_000, 1000 * (2 ** (state.retryCount - 1)));
  state.nextAttemptAt = Number(at) + delayMs;
  return state;
}
