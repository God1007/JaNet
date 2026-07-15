// Probe Rhythm 纯函数的 TypeScript 契约，供 React 页面在 strict 模式下安全消费动态 dataKey。

export type ProbeRhythmInput = {
  target?: unknown;
  timestamp?: unknown;
  latencyMs?: unknown;
  success?: unknown;
};

export type ProbeRhythmPoint = {
  timestamp: number;
  [seriesKey: string]: number | null;
};

export type ProbeRhythmSeries = {
  target: string;
  key: string;
  successes: number;
  failures: number;
};

export function buildProbeRhythm(
  items: readonly ProbeRhythmInput[] | null | undefined
): {
  points: ProbeRhythmPoint[];
  series: ProbeRhythmSeries[];
};
