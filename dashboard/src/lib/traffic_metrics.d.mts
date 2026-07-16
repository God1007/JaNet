// TypeScript 声明与 plain ESM 实现分离，使浏览器源码和 Node 单测复用同一套纯函数。

import type { NetworkSnapshot, TrafficSample } from "./types";

export function formatBytesPerSecond(value: unknown, fallback?: string): string;
export function formatPacketsPerSecond(value: unknown, fallback?: string): string;
export function formatCount(value: unknown, fallback?: string): string;
export function formatPercent(value: unknown, fallback?: string): string;
export const TRAFFIC_HISTORY_LIMIT: number;
export function createTrafficSample(networkSnapshot: NetworkSnapshot | null): TrafficSample | null;
export function appendTrafficSample(
  history: readonly TrafficSample[],
  sample: TrafficSample,
  limit?: number
): TrafficSample[];
export function counterDelta(current: unknown, previous: unknown): number | null;
export function capacityPercent(entries: unknown, capacity: unknown): number | null;
