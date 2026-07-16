// 流量看板纯函数：统一单位、构造趋势采样，并隔离服务重启与计数器重置语义。

import {
  CHART_SAMPLE_LIMIT,
  CHART_WINDOW_MS,
  trimChartWindow
} from "./chart_window.mjs";

export const TRAFFIC_HISTORY_LIMIT = CHART_SAMPLE_LIMIT;

const byteUnits = ["B/s", "KiB/s", "MiB/s", "GiB/s", "TiB/s"];
const packetUnits = ["pkt/s", "K pkt/s", "M pkt/s", "B pkt/s", "T pkt/s"];
const countFormatter = new Intl.NumberFormat("en-US", {
  maximumFractionDigits: 1
});

// 将可能来自 JSON 的值收敛为非负有限数；null 表示不可用而不是零。
function nonNegativeNumber(value) {
  if (value === null || value === undefined || value === "") return null;
  const numeric = Number(value);
  return Number.isFinite(numeric) && numeric >= 0 ? numeric : null;
}

// 去掉缩放值末尾无意义的零，保持指标卡紧凑且不丢掉必要的小数。
function compactDecimal(value) {
  const rounded = Math.round((value + Number.EPSILON) * 10) / 10;
  return rounded.toFixed(1).replace(/\.0$/, "");
}

// 按 1024 进位格式化字节吞吐，不把合法的 0 B/s 当成缺失值。
export function formatBytesPerSecond(value, fallback = "n/a") {
  const numeric = nonNegativeNumber(value);
  if (numeric === null) return fallback;

  let scaled = numeric;
  let unitIndex = 0;
  while (scaled >= 1024 && unitIndex < byteUnits.length - 1) {
    scaled /= 1024;
    unitIndex += 1;
  }

  const text = unitIndex === 0 ? countFormatter.format(scaled) : compactDecimal(scaled);
  return `${text} ${byteUnits[unitIndex]}`;
}

// 按十进制网络速率习惯格式化包速率，便于与吞吐并排比较。
export function formatPacketsPerSecond(value, fallback = "n/a") {
  const numeric = nonNegativeNumber(value);
  if (numeric === null) return fallback;

  let scaled = numeric;
  let unitIndex = 0;
  while (scaled >= 1000 && unitIndex < packetUnits.length - 1) {
    scaled /= 1000;
    unitIndex += 1;
  }

  const text = unitIndex === 0 ? countFormatter.format(scaled) : compactDecimal(scaled);
  return `${text} ${packetUnits[unitIndex]}`;
}

// 统一格式化累计计数器和活跃流数，保留最多一位小数。
export function formatCount(value, fallback = "n/a") {
  const numeric = nonNegativeNumber(value);
  return numeric === null ? fallback : countFormatter.format(numeric);
}

// 百分比展示仅负责添加单位；调用方决定指标本身是否需要裁剪。
export function formatPercent(value, fallback = "n/a") {
  const numeric = nonNegativeNumber(value);
  return numeric === null ? fallback : `${compactDecimal(numeric)}%`;
}

// 仅从完整可信的观测中生成采样，避免把预热、断流或 Map 读取失败误画成真实零。
export function createTrafficSample(networkSnapshot) {
  if (!networkSnapshot?.hasActiveInterface) return null;

  const activeInterface =
    networkSnapshot.interfaces.find(
      (item) => item.interfaceName === networkSnapshot.activeInterface
    )
    || networkSnapshot.interfaces.find((item) => item.usingNow)
    || null;
  const traffic = networkSnapshot.trafficObservation;
  const counters = traffic.mapObservability;

  // availability 与完整性位共同构成数据可信度门禁，任何一项失败都不产生图表点。
  const observationUsable =
    activeInterface?.trafficAvailability === "AVAILABLE"
    && traffic.availability === "AVAILABLE"
    && traffic.valid
    && !traffic.baselineOnly
    && traffic.mapReadComplete
    && counters.readComplete;
  if (!observationUsable) return null;

  const timestamp = traffic.sampledAt > 0 ? traffic.sampledAt : networkSnapshot.observedAt;

  return {
    timestamp,
    time: timestamp > 0 ? new Date(timestamp).toLocaleTimeString() : "n/a",
    generation: traffic.generation,
    interfaceName: activeInterface?.interfaceName || networkSnapshot.activeInterface,
    bytesPerSecond: activeInterface?.trafficBytesPerSecond ?? null,
    packetsPerSecond: activeInterface?.trafficPacketsPerSecond ?? null,
    activeFlows: activeInterface?.activeFlows ?? null,
    packetsSeen: counters.packetsSeen,
    eventDrops: counters.eventDrops,
    parseFailures: counters.parseFailures,
    continuityLost: counters.continuityLostThisWindow,
    counterResets: counters.counterResetsThisWindow
  };
}

// 维护不可变的 5 小时历史；同代更新覆盖末项，代数回退代表服务重启并清空旧曲线。
export function appendTrafficSample(history, sample, limit = TRAFFIC_HISTORY_LIMIT) {
  const numericLimit = Number(limit);
  const safeLimit = Number.isFinite(numericLimit) && numericLimit > 0
    ? Math.max(1, Math.trunc(numericLimit))
    : TRAFFIC_HISTORY_LIMIT;
  const previous = history.at(-1);

  if (!previous || sample.generation < previous.generation) {
    return [sample];
  }

  if (sample.generation === previous.generation) {
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

// 累计计数器只有单调递增时才计算窗口增量；回退返回 null 提醒 UI 发生了重置。
export function counterDelta(current, previous) {
  const currentNumber = nonNegativeNumber(current);
  const previousNumber = nonNegativeNumber(previous);
  if (currentNumber === null || previousNumber === null || currentNumber < previousNumber) {
    return null;
  }
  return currentNumber - previousNumber;
}

// 计算 Map 容量占用百分比；零容量不可计算，异常超量值按 100% 呈现。
export function capacityPercent(entries, capacity) {
  const entryCount = nonNegativeNumber(entries);
  const capacityCount = nonNegativeNumber(capacity);
  if (entryCount === null || capacityCount === null || capacityCount <= 0) return null;
  return Math.min(100, Math.max(0, (entryCount / capacityCount) * 100));
}
