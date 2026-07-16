// TypeScript 声明与 realtime_lifecycle.mjs 保持同步。

import type { NetworkEvent } from "./types";

export function mergeEventHistory(
  history: readonly NetworkEvent[],
  incoming: readonly NetworkEvent[],
  options?: { now?: number; windowMs?: number; maxPoints?: number }
): NetworkEvent[];

export function reconnectDelay(
  attempt: number,
  options?: {
    initialMs?: number;
    maxMs?: number;
    jitterRatio?: number;
    random?: () => number;
  }
): number;

export function createEventBatcher<T>(
  onFlush: (items: T[]) => void,
  options?: {
    delayMs?: number;
    maxBatchSize?: number;
    schedule?: (callback: () => void, delay: number) => unknown;
    cancel?: (timer: unknown) => void;
  }
): {
  readonly size: number;
  push(item: T): void;
  pushMany(items: T[]): void;
  flush(): void;
  close(): void;
  discard(): void;
};
