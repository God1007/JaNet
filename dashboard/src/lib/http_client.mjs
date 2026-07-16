// Dashboard HTTP 生命周期：统一 JSON 解析、可取消超时和面向用户的错误信息。

const defaultTimeoutMs = 10_000;

function positiveTimeout(value) {
  const numeric = Number(value);
  return Number.isFinite(numeric) && numeric > 0 ? numeric : defaultTimeoutMs;
}

function retryAfterMilliseconds(value, now = Date.now()) {
  if (!value) return null;
  const seconds = Number(value);
  if (Number.isFinite(seconds) && seconds >= 0) return Math.ceil(seconds * 1000);
  const retryAt = Date.parse(value);
  return Number.isFinite(retryAt) ? Math.max(0, retryAt - now) : null;
}

function payloadMessage(payload, fallback) {
  if (payload && typeof payload === "object") {
    const message = payload.error || payload.message;
    if (typeof message === "string" && message.trim()) return message.trim();
  }
  if (typeof payload === "string" && payload.trim()) return payload.trim();
  return fallback;
}

export class HttpRequestError extends Error {
  constructor(message, { status = 0, retryAfterMs = null } = {}) {
    super(message);
    this.name = "HttpRequestError";
    this.status = status;
    this.retryAfterMs = retryAfterMs;
  }
}

export class HttpTimeoutError extends Error {
  constructor(label, timeoutMs) {
    super(`${label} timed out after ${Math.ceil(timeoutMs / 1000)}s`);
    this.name = "HttpTimeoutError";
    this.timeoutMs = timeoutMs;
  }
}

export function isAbortError(error) {
  return Boolean(error && (error.name === "AbortError" || error.code === "ABORT_ERR"));
}

/**
 * 执行一个只接受 JSON 的 HTTP 请求。
 *
 * 独立 AbortController 同时接收调用方取消和本地 deadline；finally 必定清理 timer，
 * 因此页面卸载、切换网络和慢 BFF 都不会留下悬挂的前端请求。
 */
export async function fetchJson(input, init = {}, options = {}) {
  const timeoutMs = positiveTimeout(options.timeoutMs);
  const label = String(options.label || "Request");
  const fetchImpl = options.fetchImpl || globalThis.fetch;
  if (typeof fetchImpl !== "function") throw new Error("fetch is unavailable");

  const callerSignal = init.signal;
  const controller = new AbortController();
  let timedOut = false;
  const forwardAbort = () => controller.abort();

  if (callerSignal?.aborted) {
    controller.abort();
  } else {
    callerSignal?.addEventListener("abort", forwardAbort, { once: true });
  }

  const timer = setTimeout(() => {
    timedOut = true;
    controller.abort();
  }, timeoutMs);

  try {
    const response = await fetchImpl(input, { ...init, signal: controller.signal });
    const text = await response.text();
    let payload = null;

    if (text) {
      try {
        payload = JSON.parse(text);
      } catch {
        if (response.ok) {
          throw new HttpRequestError(`${label} returned invalid JSON`, { status: response.status });
        }
        payload = text;
      }
    }

    if (!response.ok) {
      const retryAfterMs = retryAfterMilliseconds(response.headers.get("retry-after"));
      const fallback = `${label} failed with HTTP ${response.status}`;
      const baseMessage = payloadMessage(payload, fallback);
      const message = retryAfterMs === null
        ? baseMessage
        : `${baseMessage}. Retry in ${Math.max(1, Math.ceil(retryAfterMs / 1000))}s.`;
      throw new HttpRequestError(message, { status: response.status, retryAfterMs });
    }

    return payload;
  } catch (error) {
    if (timedOut && controller.signal.aborted) {
      throw new HttpTimeoutError(label, timeoutMs);
    }
    throw error;
  } finally {
    clearTimeout(timer);
    callerSignal?.removeEventListener("abort", forwardAbort);
  }
}
