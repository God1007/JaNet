// TypeScript 声明与 http_client.mjs 保持同步，供严格模式 React 源码直接复用。

export class HttpRequestError extends Error {
  status: number;
  retryAfterMs: number | null;
}

export class HttpTimeoutError extends Error {
  timeoutMs: number;
}

export function isAbortError(error: unknown): boolean;

export function fetchJson<T>(
  input: RequestInfo | URL,
  init?: RequestInit,
  options?: {
    timeoutMs?: number;
    label?: string;
    fetchImpl?: typeof fetch;
  }
): Promise<T>;
