// TypeScript 契约：浏览器与 BFF 共享同一套 5 小时时间窗口语义。

export const CHART_WINDOW_MS: number;
export const CHART_WINDOW_LABEL: string;
export const CHART_SAMPLE_INTERVAL_MS: number;
export const CHART_SAMPLE_LIMIT: number;

export function trimChartWindow<T>(
  items: readonly T[] | null | undefined,
  options?: {
    now?: number;
    windowMs?: number;
    maxPoints?: number;
    getTimestamp?: (item: T) => unknown;
  }
): T[];
