// 曲线图统一时间窗口：最多展示最近 5 小时，同时用点数上限兜住异常高频刷新。

export const CHART_WINDOW_MS = 5 * 60 * 60 * 1000;
export const CHART_WINDOW_LABEL = "Last 5 hours";
export const CHART_SAMPLE_INTERVAL_MS = 10 * 1000;
export const CHART_SAMPLE_LIMIT = Math.ceil(CHART_WINDOW_MS / CHART_SAMPLE_INTERVAL_MS) + 1;

function positiveNumber(value, fallback) {
  const numeric = Number(value);
  return Number.isFinite(numeric) && numeric > 0 ? numeric : fallback;
}

/**
 * 按真实时间戳裁剪曲线数据，而不是假设采样周期永远稳定。
 *
 * 时间 TTL 决定业务可见窗口；maxPoints 是异常刷新频率下的内存与渲染保险丝。
 * 函数保持输入顺序且不修改原数组，调用方可以继续依赖 generation/到达顺序语义。
 */
export function trimChartWindow(items, options = {}) {
  if (!Array.isArray(items) || items.length === 0) return [];

  const referenceTime = positiveNumber(options.now, Date.now());
  const windowMs = positiveNumber(options.windowMs, CHART_WINDOW_MS);
  const maxPoints = Math.max(1, Math.trunc(positiveNumber(options.maxPoints, CHART_SAMPLE_LIMIT)));
  const getTimestamp = typeof options.getTimestamp === "function"
    ? options.getTimestamp
    : (item) => item?.timestamp;
  const cutoff = referenceTime - windowMs;

  return items
    .filter((item) => {
      const timestamp = Number(getTimestamp(item));
      return Number.isFinite(timestamp) && timestamp > 0 && timestamp >= cutoff;
    })
    .slice(-maxPoints);
}
