// Probe Rhythm 图表数据适配器：按探测目标隔离曲线，并保留失败与非法采样的空值语义。

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
