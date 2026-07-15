// JaNet Chrome MV3 后台：被动观察真实浏览器请求的终态，只批量上报失败元数据。

import {
  completedFailureFromWebRequest,
  networkFailureFromWebRequest,
  normalizeIngestUrl
} from "./lib/failure_event.mjs";
import {
  DEFAULT_BATCH_LIMIT,
  DEFAULT_QUEUE_LIMIT,
  DEFAULT_QUEUE_TTL_MS,
  acknowledgeBatch,
  emptyQueueState,
  enqueueBounded,
  markBatchRetry,
  normalizeQueueState,
  pruneExpired,
  resetQueueRetry,
  takeBatch
} from "./lib/persistent_queue.mjs";
import {
  DEFAULT_FETCH_TIMEOUT_MS,
  fetchWithTimeout
} from "./lib/fetch_with_timeout.mjs";
import {
  SETTINGS_UPDATED_MESSAGE,
  applySettingsUpdate
} from "./lib/settings_update.mjs";

const QUEUE_KEY = "janetFailureQueueV1";
const SETTINGS_KEY = "janetSettingsV1";
const SESSION_KEY = "janetBrowserSessionIdV1";
const HEARTBEAT_KEY = "janetLastHeartbeatAtV1";
const HEARTBEAT_ATTEMPT_KEY = "janetLastHeartbeatAttemptAtV1";
const FLUSH_ALARM = "janet-failure-flush";
const HEARTBEAT_INTERVAL_MS = 60_000;
const UNEXPECTED_RETRY_MS = 30_000;
let storageMutation = Promise.resolve();
let flushPromise = null;
let flushTimer = null;

function serializedStorage(task) {
  const result = storageMutation.then(task, task);
  storageMutation = result.catch(() => {});
  return result;
}

async function readSettings() {
  const stored = await chrome.storage.local.get(SETTINGS_KEY);
  const raw = stored[SETTINGS_KEY] || {};
  return {
    enabled: raw.enabled !== false,
    ingestUrl: normalizeIngestUrl(raw.ingestUrl),
    token: String(raw.token || "").slice(0, 256)
  };
}

async function browserSessionId() {
  const stored = await chrome.storage.session.get(SESSION_KEY);
  if (stored[SESSION_KEY]) return stored[SESSION_KEY];
  const next = crypto.randomUUID();
  await chrome.storage.session.set({ [SESSION_KEY]: next });
  return next;
}

async function mutateQueue(mutator) {
  return serializedStorage(async () => {
    const stored = await chrome.storage.local.get(QUEUE_KEY);
    const next = mutator(normalizeQueueState(stored[QUEUE_KEY]));
    await chrome.storage.local.set({ [QUEUE_KEY]: next });
    return next;
  });
}

async function persistFailureIfEnabled(event) {
  return serializedStorage(async () => {
    // 与 Options 的禁用消息串行交汇：禁用前入队会随后被清空，禁用后到达则不会重新写回。
    const stored = await chrome.storage.local.get([SETTINGS_KEY, QUEUE_KEY]);
    if (stored[SETTINGS_KEY]?.enabled === false) return false;
    const next = enqueueBounded(
      normalizeQueueState(stored[QUEUE_KEY]),
      event,
      DEFAULT_QUEUE_LIMIT,
      Date.now(),
      DEFAULT_QUEUE_TTL_MS
    );
    await chrome.storage.local.set({ [QUEUE_KEY]: next });
    return true;
  });
}

function scheduleFlush(delayMs = 250) {
  if (flushTimer !== null) return;
  flushTimer = setTimeout(() => {
    flushTimer = null;
    void flushQueue();
  }, Math.max(0, delayMs));
}

async function queueFailure(factory, details) {
  try {
    const settings = await readSettings();
    if (!settings.enabled) return;
    const event = factory(details, {
      browserSessionId: await browserSessionId(),
      ingestUrl: settings.ingestUrl
    });
    if (!event) return;
    if (await persistFailureIfEnabled(event)) scheduleFlush();
  } catch {
    // webRequest 回调不能影响页面请求；持久化失败只在下一条事件或 alarm 时重试。
  }
}

async function performFlush() {
  let settings = await readSettings();
  if (!settings.enabled) return;
  // 即使失败队列持续非空，也保持独立的一分钟心跳；心跳失败不阻塞真实失败批次。
  await sendHeartbeatIfDue(settings).catch(() => {});
  // Options 可能在 heartbeat 等待期间关闭采集或替换 endpoint；批次发送前重新读取一次。
  settings = await readSettings();
  if (!settings.enabled) return;
  await storageMutation;
  // 每次 alarm / startup / 新事件触发 flush 时先持久化 TTL 清理，防止休眠积压被当成刚发生的突发。
  const queue = await mutateQueue((state) => pruneExpired(
    state,
    Date.now(),
    DEFAULT_QUEUE_TTL_MS
  ));
  const batch = takeBatch(queue, DEFAULT_BATCH_LIMIT);
  if (batch.events.length === 0) return;
  if (Date.now() < batch.nextAttemptAt) {
    scheduleFlush(batch.nextAttemptAt - Date.now());
    return;
  }

  const payload = {
    schemaVersion: 1,
    kind: "failures",
    browserSessionId: await browserSessionId(),
    batchId: crypto.randomUUID(),
    sentAt: Date.now(),
    clientDropped: batch.droppedSinceLastAck,
    events: batch.events
  };

  try {
    const response = await fetchWithTimeout(fetch, settings.ingestUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-JaNet-Extension-Token": settings.token
      },
      body: JSON.stringify(payload),
      cache: "no-store",
      credentials: "omit"
    }, {
      timeoutMs: DEFAULT_FETCH_TIMEOUT_MS
    });
    if (!response.ok) throw new Error(`ingest returned ${response.status}`);
    const acknowledgedIds = batch.events.map((event) => event.eventId);
    await mutateQueue((state) => acknowledgeBatch(
      state,
      acknowledgedIds,
      batch.droppedSinceLastAck
    ));
    // 一次最多确认 100 条；若仍有积压，继续以小批次排空而不是创建并行 fetch。
    const after = await chrome.storage.local.get(QUEUE_KEY);
    if (normalizeQueueState(after[QUEUE_KEY]).items.length > 0) scheduleFlush(50);
  } catch {
    const next = await mutateQueue((state) => markBatchRetry(state));
    scheduleFlush(Math.max(0, next.nextAttemptAt - Date.now()));
  }
}

// 心跳不携带浏览记录，只用于区分“扩展在线但暂无失败”和“扩展未连接”。
async function sendHeartbeatIfDue(settings, force = false) {
  const stored = await chrome.storage.local.get([HEARTBEAT_KEY, HEARTBEAT_ATTEMPT_KEY]);
  const lastAttemptAt = Number(stored[HEARTBEAT_ATTEMPT_KEY]) || 0;
  if (!force && Date.now() - lastAttemptAt < HEARTBEAT_INTERVAL_MS) return;
  // 先记录 attempt，BFF 离线时也严格限制为每分钟最多一次，不让心跳本身形成噪声流量。
  await chrome.storage.local.set({ [HEARTBEAT_ATTEMPT_KEY]: Date.now() });

  const response = await fetchWithTimeout(fetch, settings.ingestUrl, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-JaNet-Extension-Token": settings.token
    },
    body: JSON.stringify({
      schemaVersion: 1,
      kind: "heartbeat",
      browserSessionId: await browserSessionId(),
      batchId: crypto.randomUUID(),
      sentAt: Date.now(),
      clientDropped: 0,
      events: []
    }),
    cache: "no-store",
    credentials: "omit"
  }, {
    timeoutMs: DEFAULT_FETCH_TIMEOUT_MS
  });
  if (!response.ok) throw new Error(`heartbeat returned ${response.status}`);
  await chrome.storage.local.set({ [HEARTBEAT_KEY]: Date.now() });
}

function flushQueue() {
  if (flushPromise) return flushPromise;
  flushPromise = performFlush()
    .catch(() => {
      // storage/session 等非批次 fetch 异常也必须留下重试入口；alarm 仍是 worker 回收后的兜底。
      scheduleFlush(UNEXPECTED_RETRY_MS);
    })
    .finally(() => {
      // fetch 有硬超时，因此成功、拒绝、abort 和原先会悬挂的路径最终都会释放单飞锁。
      flushPromise = null;
    });
  return flushPromise;
}

async function applySavedSettings() {
  const settings = await readSettings();
  return applySettingsUpdate(settings, {
    clearQueue: async () => {
      // 等已有单飞在硬超时内退出后再清空，避免失败路径把 retry 状态写回空队列。
      const activeFlush = flushPromise;
      if (activeFlush) await activeFlush;
      if (flushTimer !== null) {
        clearTimeout(flushTimer);
        flushTimer = null;
      }
      await mutateQueue(() => emptyQueueState());
    },
    refresh: async () => {
      // endpoint/token 保存后使用新配置立即启动一次 flush，并强制发送无浏览记录的 heartbeat。
      const activeFlush = flushPromise;
      if (activeFlush) await activeFlush;
      if (flushTimer !== null) {
        clearTimeout(flushTimer);
        flushTimer = null;
      }
      await mutateQueue((state) => resetQueueRetry(state));
      await chrome.storage.local.remove(HEARTBEAT_ATTEMPT_KEY);
      await flushQueue();
    }
  });
}

async function ensureFlushAlarm() {
  const existing = await chrome.alarms.get(FLUSH_ALARM);
  if (!existing) {
    await chrome.alarms.create(FLUSH_ALARM, { periodInMinutes: 0.5 });
  }
}

// 监听器必须在 service worker 顶层同步注册，避免 worker 被唤醒时漏掉首个终态事件。
const requestFilter = { urls: ["http://*/*", "https://*/*"] };
chrome.webRequest.onCompleted.addListener(
  (details) => void queueFailure(completedFailureFromWebRequest, details),
  requestFilter
);
chrome.webRequest.onErrorOccurred.addListener(
  (details) => void queueFailure(networkFailureFromWebRequest, details),
  requestFilter
);

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === FLUSH_ALARM) void flushQueue();
});
chrome.runtime.onInstalled.addListener(() => {
  void ensureFlushAlarm();
  void flushQueue();
});
chrome.runtime.onStartup.addListener(() => {
  void ensureFlushAlarm();
  void flushQueue();
});
chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message?.type !== SETTINGS_UPDATED_MESSAGE) return false;
  void applySavedSettings()
    .then((result) => sendResponse({ ok: true, ...result }))
    .catch((error) => sendResponse({
      ok: false,
      error: String(error?.message || error).slice(0, 160)
    }));
  // 异步 sendResponse 需要保持 message channel；Options 会据此反馈清队列或刷新结果。
  return true;
});

// alarm 可能在浏览器更新或扩展 reload 后丢失，每次 worker 初始化都幂等补齐。
void ensureFlushAlarm();
