// TypeScript 声明：让 React 源码复用可由 Node 直接单测的资源指标纯函数。

import type { ResourceSample, RuntimeResources } from "./types";

export const RESOURCE_HISTORY_LIMIT: number;
export function createResourceSample(runtimeResources: RuntimeResources | null | undefined): ResourceSample | null;
export function appendResourceSample(
  history: readonly ResourceSample[],
  sample: ResourceSample,
  limit?: number
): ResourceSample[];
export function formatResourceBytes(value: unknown, fallback?: string): string;
export function formatUptime(value: unknown, fallback?: string): string;
