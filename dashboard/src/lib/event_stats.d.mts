// TypeScript 契约：事件构成与分钟趋势必须来自同一份 5 小时证据窗口。

import type { EventTimelinePoint, NetworkEvent } from "./types";

export const EVENT_HISTORY_LIMIT: number;

export function trimEventTimeline(
  timeline: readonly EventTimelinePoint[] | null | undefined,
  options?: {
    now?: number;
    windowMs?: number;
    maxPoints?: number;
  }
): EventTimelinePoint[];

export function buildEventStats(
  events: readonly NetworkEvent[] | null | undefined,
  options?: {
    now?: number;
    maxEvents?: number;
  }
): {
  byType: Array<{ name: string; value: number }>;
  timeline: EventTimelinePoint[];
};
