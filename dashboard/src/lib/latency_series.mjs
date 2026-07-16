// Probe Rhythm 图表数据适配器：按探测目标隔离曲线，并保留失败与非法采样的空值语义。

import {
  CHART_SAMPLE_LIMIT,
  CHART_WINDOW_MS,
  trimChartWindow
} from "./chart_window.mjs";

// 最多按五个并行目标预留原始点，异常目标爆炸时仍有明确的浏览器内存保险丝。
export const PROBE_HISTORY_LIMIT = CHART_SAMPLE_LIMIT * 5;

// 时延只接受非负有限数；0 ms 是合法采样，失败、负数和非数值都保持为 null。
function normalizeLatency(value) {
  if (value === null || value === undefined || value === "") return null;
  const numeric = Number(value);
  return Number.isFinite(numeric) && numeric >= 0 ? numeric : null;
}

// Unix 毫秒时间戳必须可排序；无效时间无法安全进入时间轴，直接丢弃对应输入项。
function normalizeTimestamp(value) {
  if (value === null || value === undefined || value === "") return null;
  const numeric = Number(value);
  return Number.isFinite(numeric) && numeric >= 0 ? numeric : null;
}

/**
 * 把 BFF 每轮返回的短历史增量合并为浏览器本地 5 小时窗口。
 * target + timestamp 共同去重，避免不同目标恰好同刻采样时互相覆盖。
 */
export function mergeProbeHistory(history, incoming, options = {}) {
  const combined = [
    ...(Array.isArray(history) ? history : []),
    ...(Array.isArray(incoming) ? incoming : [])
  ];
  const unique = new Map();

  for (const item of combined) {
    const target = String(item?.target ?? "").trim();
    const timestamp = normalizeTimestamp(item?.timestamp);
    if (!target || timestamp === null) continue;
    unique.set(`${target}\u0000${timestamp}`, item);
  }

  const ordered = Array.from(unique.values()).sort((left, right) => (
    Number(left.timestamp) - Number(right.timestamp)
      || String(left.target).localeCompare(String(right.target))
  ));

  return trimChartWindow(ordered, {
    now: options.now,
    windowMs: CHART_WINDOW_MS,
    maxPoints: options.maxPoints ?? PROBE_HISTORY_LIMIT
  });
}

/**
 * 将扁平 Ping 历史转换为 Recharts 可消费的数据。
 *
 * 每个 target 获得 probe_0 这类安全 dataKey，避免把 8.8.8.8 当成对象路径解析；
 * 同一毫秒的多个目标合并到一个 point，不同目标的值仍写在各自的 key 下。
 */
export function buildProbeRhythm(items) {
  if (!Array.isArray(items) || items.length === 0) {
    return { points: [], series: [] };
  }

  const samples = items
    .map((item, inputIndex) => {
      const target = String(item?.target ?? "").trim();
      const timestamp = normalizeTimestamp(item?.timestamp);
      if (!target || timestamp === null) return null;

      const success = item?.success === true;
      return {
        inputIndex,
        target,
        timestamp,
        success,
        // 即使异常载荷携带 latency，失败采样也必须绘制为空值而不是伪造成功点。
        latencyMs: success ? normalizeLatency(item?.latencyMs) : null
      };
    })
    .filter(Boolean)
    .sort((left, right) => left.timestamp - right.timestamp || left.inputIndex - right.inputIndex);

  const seriesByTarget = new Map();
  for (const sample of samples) {
    if (!seriesByTarget.has(sample.target)) {
      seriesByTarget.set(sample.target, {
        target: sample.target,
        key: `probe_${seriesByTarget.size}`,
        successes: 0,
        failures: 0
      });
    }

    const targetSeries = seriesByTarget.get(sample.target);
    if (sample.success) targetSeries.successes += 1;
    else targetSeries.failures += 1;
  }

  const pointsByTimestamp = new Map();
  for (const sample of samples) {
    const point = pointsByTimestamp.get(sample.timestamp) || { timestamp: sample.timestamp };
    const targetSeries = seriesByTarget.get(sample.target);
    point[targetSeries.key] = sample.latencyMs;
    pointsByTimestamp.set(sample.timestamp, point);
  }

  return {
    points: Array.from(pointsByTimestamp.values()),
    series: Array.from(seriesByTarget.values())
  };
}
