// 事件趋势聚合：在 5 小时窗口内生成连续分钟桶，避免稀疏事件被画成紧邻峰值。

import {
  CHART_WINDOW_MS,
  trimChartWindow
} from "./chart_window.mjs";

const MINUTE_MS = 60 * 1000;
export const EVENT_HISTORY_LIMIT = 300;

// 分钟桶代表 [timestamp, timestamp + 1min)；用桶结束时刻判断可见性，
// 避免 5 小时边界落在分钟中间时误删仍含有效事件的首桶。
export function trimEventTimeline(timeline, options = {}) {
  return trimChartWindow(timeline, {
    ...options,
    getTimestamp: (point) => Number(point?.timestamp) + MINUTE_MS - 1
  });
}

export function buildEventStats(events, options = {}) {
  const referenceTime = Number.isFinite(Number(options.now)) && Number(options.now) > 0
    ? Number(options.now)
    : Date.now();
  const maxEvents = Number.isFinite(Number(options.maxEvents)) && Number(options.maxEvents) > 0
    ? Math.max(1, Math.trunc(Number(options.maxEvents)))
    : EVENT_HISTORY_LIMIT;
  const recentEvents = trimChartWindow(events, {
    now: referenceTime,
    maxPoints: maxEvents
  });
  const byTypeMap = new Map();
  const buckets = new Map();
  const currentBucket = Math.floor(referenceTime / MINUTE_MS) * MINUTE_MS;

  for (const event of recentEvents) {
    const type = String(event?.type || "Unknown");
    byTypeMap.set(type, (byTypeMap.get(type) || 0) + 1);
    // 小幅未来时钟漂移归入当前分钟，避免异常时间戳制造超大空桶数组。
    const bucketTime = Math.min(
      currentBucket,
      Math.floor(Number(event.timestamp) / MINUTE_MS) * MINUTE_MS
    );
    const bucket = buckets.get(bucketTime) || {
      timestamp: bucketTime,
      time: new Date(bucketTime).toLocaleTimeString(),
      total: 0
    };
    bucket.total += 1;
    bucket[type] = (bucket[type] || 0) + 1;
    buckets.set(bucketTime, bucket);
  }

  const timeline = [];
  if (buckets.size > 0) {
    const firstBucket = Math.max(
      Math.floor((referenceTime - CHART_WINDOW_MS) / MINUTE_MS) * MINUTE_MS,
      Math.min(...buckets.keys())
    );
    for (let timestamp = firstBucket; timestamp <= currentBucket; timestamp += MINUTE_MS) {
      timeline.push(buckets.get(timestamp) || {
        timestamp,
        time: new Date(timestamp).toLocaleTimeString(),
        total: 0
      });
    }
  }

  return {
    byType: Array.from(byTypeMap.entries())
      .map(([name, value]) => ({ name, value }))
      .sort((left, right) => right.value - left.value),
    timeline
  };
}
