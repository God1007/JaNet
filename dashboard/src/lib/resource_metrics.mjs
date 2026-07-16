// 资源看板纯函数：规范化可缺失的进程指标，并维护最近 5 小时的浏览器本地趋势。

import {
  CHART_SAMPLE_LIMIT,
  CHART_WINDOW_MS,
  trimChartWindow
} from "./chart_window.mjs";

export const RESOURCE_HISTORY_LIMIT = CHART_SAMPLE_LIMIT;

const byteUnits = ["B", "KiB", "MiB", "GiB", "TiB"];
const countFormatter = new Intl.NumberFormat("en-US", { maximumFractionDigits: 1 });

// 后端以 null 表示平台不支持；这里只接收非负有限数，绝不把缺失值转换成零。
function nonNegativeNumber(value) {
  if (value === null || value === undefined || value === "") return null;
  const numeric = Number(value);
  return Number.isFinite(numeric) && numeric >= 0 ? numeric : null;
}

function sampledMetric(process, field) {
  if (!process?.available) return null;
  return nonNegativeNumber(process[field]);
}

// 把 Engine 与 BFF 的同轮采样压成图表需要的稳定 dataKey。
export function createResourceSample(runtimeResources) {
  if (!runtimeResources) return null;

  const timestamp = [
    runtimeResources.sampledAt,
    runtimeResources.engine?.sampledAt,
    runtimeResources.dashboard?.sampledAt
  ]
    .map(nonNegativeNumber)
    .filter((value) => value !== null && value > 0)
    .reduce((latest, value) => Math.max(latest, value), 0);

  if (timestamp <= 0) return null;

  return {
    timestamp,
    time: new Date(timestamp).toLocaleTimeString(),
    engineCpuPercent: sampledMetric(runtimeResources.engine, "cpuPercent"),
    dashboardCpuPercent: sampledMetric(runtimeResources.dashboard, "cpuPercent"),
    engineResidentMemoryBytes: sampledMetric(runtimeResources.engine, "residentMemoryBytes"),
    dashboardResidentMemoryBytes: sampledMetric(runtimeResources.dashboard, "residentMemoryBytes"),
    combinedResidentMemoryBytes: nonNegativeNumber(runtimeResources.combinedResidentMemoryBytes)
  };
}

// 同一采样时刻覆盖末项；其余采样按到达顺序追加，并按 5 小时 TTL 与点数上限双重裁剪。
export function appendResourceSample(history, sample, limit = RESOURCE_HISTORY_LIMIT) {
  const numericLimit = Number(limit);
  const safeLimit = Number.isFinite(numericLimit) && numericLimit > 0
    ? Math.max(1, Math.trunc(numericLimit))
    : RESOURCE_HISTORY_LIMIT;
  const previous = history.at(-1);

  if (previous?.timestamp === sample.timestamp) {
    return trimChartWindow([...history.slice(0, -1), sample], {
      now: sample.timestamp,
      windowMs: CHART_WINDOW_MS,
      maxPoints: safeLimit
    });
  }
  return trimChartWindow([...history, sample], {
    now: sample.timestamp,
    windowMs: CHART_WINDOW_MS,
    maxPoints: safeLimit
  });
}

// 内存按 1024 进位展示；合法 0 B 与不可用 n/a 保持严格区分。
export function formatResourceBytes(value, fallback = "n/a") {
  const numeric = nonNegativeNumber(value);
  if (numeric === null) return fallback;

  let scaled = numeric;
  let unitIndex = 0;
  while (scaled >= 1024 && unitIndex < byteUnits.length - 1) {
    scaled /= 1024;
    unitIndex += 1;
  }

  const digits = unitIndex === 0 ? 0 : scaled >= 100 ? 0 : scaled >= 10 ? 1 : 2;
  return `${scaled.toFixed(digits).replace(/\.0+$|(?<=\.[0-9])0$/, "")} ${byteUnits[unitIndex]}`;
}

// 运行时长使用紧凑单位，避免工程指标卡因完整时间串而换行遮挡。
export function formatUptime(value, fallback = "n/a") {
  const seconds = nonNegativeNumber(value);
  if (seconds === null) return fallback;
  if (seconds < 60) return `${Math.floor(seconds)}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${Math.floor(seconds % 60)}s`;
  const hours = Math.floor(seconds / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  if (hours < 24) return `${hours}h ${minutes}m`;
  return `${Math.floor(hours / 24)}d ${hours % 24}h`;
}
