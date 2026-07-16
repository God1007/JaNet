// 实时前端生命周期：批量事件、稳定去重，并为断线重连提供有上限的退避。

import { trimChartWindow } from "./chart_window.mjs";

export function mergeEventHistory(history, incoming, options = {}) {
  const unique = new Map();
  for (const event of [
    ...(Array.isArray(history) ? history : []),
    ...(Array.isArray(incoming) ? incoming : [])
  ]) {
    const id = String(event?.id || "");
    const timestamp = Number(event?.timestamp);
    if (!id || !Number.isFinite(timestamp) || timestamp <= 0) continue;
    unique.set(id, event);
  }

  const ordered = Array.from(unique.values()).sort((left, right) => (
    Number(left.timestamp) - Number(right.timestamp)
      || String(left.id).localeCompare(String(right.id))
  ));
  return trimChartWindow(ordered, options);
}

// 首次快速恢复，连续失败后指数退避；抖动避免多个标签页同时冲击刚恢复的 BFF。
export function reconnectDelay(attempt, options = {}) {
  const safeAttempt = Math.max(0, Math.trunc(Number(attempt) || 0));
  const initialMs = Math.max(100, Number(options.initialMs) || 750);
  const maxMs = Math.max(initialMs, Number(options.maxMs) || 15_000);
  const jitterRatio = Math.min(0.5, Math.max(0, Number(options.jitterRatio) || 0));
  const random = typeof options.random === "function" ? options.random : Math.random;
  const exponential = Math.min(maxMs, initialMs * (2 ** safeAttempt));
  const jitter = exponential * jitterRatio * ((random() * 2) - 1);
  return Math.max(100, Math.min(maxMs, Math.round(exponential + jitter)));
}

/**
 * 把短时间内到达的事件合成一次 React 状态提交。
 * 达到批量上限时立即 flush，低流量时只增加一个短 timer，close 前会交付剩余事件。
 */
export function createEventBatcher(onFlush, options = {}) {
  if (typeof onFlush !== "function") throw new TypeError("onFlush must be a function");
  const delayMs = Math.max(0, Number(options.delayMs) || 80);
  const maxBatchSize = Math.max(1, Math.trunc(Number(options.maxBatchSize) || 64));
  const schedule = options.schedule || ((callback, delay) => setTimeout(callback, delay));
  const cancel = options.cancel || ((timer) => clearTimeout(timer));
  let pending = [];
  let timer = null;
  let closed = false;

  function flush() {
    if (timer !== null) {
      cancel(timer);
      timer = null;
    }
    if (!pending.length) return;
    const batch = pending;
    pending = [];
    onFlush(batch);
  }

  function pushMany(items) {
    if (closed || !Array.isArray(items) || !items.length) return;
    pending.push(...items);
    if (pending.length >= maxBatchSize) {
      flush();
      return;
    }
    if (timer === null) timer = schedule(flush, delayMs);
  }

  return {
    get size() {
      return pending.length;
    },
    push(item) {
      pushMany([item]);
    },
    pushMany,
    flush,
    close() {
      if (closed) return;
      closed = true;
      flush();
    },
    discard() {
      if (closed) return;
      closed = true;
      if (timer !== null) {
        cancel(timer);
        timer = null;
      }
      pending = [];
    }
  };
}
