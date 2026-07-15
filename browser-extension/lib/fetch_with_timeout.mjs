// 为 MV3 service worker 的本机上报提供硬超时，避免悬挂 fetch 永久占住单飞 flush。

export const DEFAULT_FETCH_TIMEOUT_MS = 5_000;

export class FetchTimeoutError extends Error {
  constructor(timeoutMs) {
    super(`fetch timed out after ${timeoutMs}ms`);
    this.name = "FetchTimeoutError";
    this.timeoutMs = timeoutMs;
  }
}

export async function fetchWithTimeout(
  fetchImpl,
  input,
  init = {},
  {
    timeoutMs = DEFAULT_FETCH_TIMEOUT_MS,
    setTimeoutImpl = setTimeout,
    clearTimeoutImpl = clearTimeout
  } = {}
) {
  if (typeof fetchImpl !== "function") throw new TypeError("fetchImpl must be a function");
  const boundedTimeoutMs = Number.isFinite(Number(timeoutMs))
    ? Math.max(1, Math.trunc(Number(timeoutMs)))
    : DEFAULT_FETCH_TIMEOUT_MS;
  const controller = new AbortController();
  const timeoutError = new FetchTimeoutError(boundedTimeoutMs);
  const timer = setTimeoutImpl(() => controller.abort(timeoutError), boundedTimeoutMs);

  try {
    return await fetchImpl(input, { ...init, signal: controller.signal });
  } finally {
    // 成功、网络拒绝和 abort 都必须释放 timer，避免 worker 被无意义地继续唤醒。
    clearTimeoutImpl(timer);
  }
}
