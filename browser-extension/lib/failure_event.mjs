// Chrome webRequest 终态事件的最小化模型：只保留定位失败所需字段，并在浏览器侧先完成脱敏。

export const INGEST_PATH = "/api/browser-failures";
export const DEFAULT_INGEST_URL = `http://127.0.0.1:5174${INGEST_PATH}`;

const LOOPBACK_HOSTS = new Set(["127.0.0.1", "localhost"]);
const MAX_ERROR_LENGTH = 128;

function boundedText(value, maxLength) {
  return String(value ?? "").trim().slice(0, maxLength);
}

function normalizePort(url) {
  if (url.port) return url.port;
  return url.protocol === "https:" ? "443" : "80";
}

// 只接受本机 JaNet ingest 地址，避免扩展配置被误用为任意跨域数据出口。
export function normalizeIngestUrl(rawValue) {
  let parsed;
  try {
    parsed = new URL(String(rawValue || DEFAULT_INGEST_URL));
  } catch {
    return DEFAULT_INGEST_URL;
  }

  if (parsed.protocol !== "http:" || !LOOPBACK_HOSTS.has(parsed.hostname.toLowerCase())) {
    return DEFAULT_INGEST_URL;
  }
  parsed.username = "";
  parsed.password = "";
  parsed.search = "";
  parsed.hash = "";
  return parsed.toString().replace(/\/$/, "");
}

// 判断当前失败是否来自 JaNet 自己的上报请求；必须在 enqueue 前执行，防止 BFF 离线时递归自激。
export function isJaNetIngestRequest(rawUrl, configuredIngestUrl = DEFAULT_INGEST_URL) {
  let observed;
  try {
    observed = new URL(String(rawUrl));
  } catch {
    return false;
  }

  const normalizedPath = observed.pathname.replace(/\/+$/, "") || "/";
  const hardCodedLocalIngest = LOOPBACK_HOSTS.has(observed.hostname.toLowerCase())
    && normalizedPath === INGEST_PATH;
  if (hardCodedLocalIngest) return true;

  try {
    const configured = new URL(normalizeIngestUrl(configuredIngestUrl));
    return observed.origin === configured.origin
      && normalizedPath === (configured.pathname.replace(/\/+$/, "") || "/");
  } catch {
    return false;
  }
}

// 默认只保留 origin：pathname 也可能携带用户 ID、文件名或业务主键，因此固定归一到根路径。
export function sanitizeObservedUrl(rawUrl) {
  let parsed;
  try {
    parsed = new URL(String(rawUrl));
  } catch {
    return null;
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return null;

  parsed.username = "";
  parsed.password = "";
  parsed.search = "";
  parsed.hash = "";
  const safeUrl = `${parsed.protocol}//${parsed.host}/`;
  return {
    scheme: parsed.protocol.slice(0, -1),
    host: parsed.hostname.toLowerCase().replace(/\.$/, ""),
    port: normalizePort(parsed),
    safeUrl
  };
}

function normalizeNetworkError(value) {
  const text = boundedText(value || "net::ERR_FAILED", MAX_ERROR_LENGTH);
  return text || "net::ERR_FAILED";
}

function normalizeIp(value) {
  const text = boundedText(value, 128);
  return text || null;
}

function baseFailure(details, browserSessionId, terminal, configuredIngestUrl) {
  if (!details || isJaNetIngestRequest(details.url, configuredIngestUrl)) return null;
  const url = sanitizeObservedUrl(details.url);
  if (!url) return null;

  const requestId = boundedText(details.requestId || "unknown", 160);
  return {
    eventId: `${boundedText(browserSessionId, 80)}:${requestId}:${terminal}`,
    occurredAt: Number.isFinite(Number(details.timeStamp)) ? Number(details.timeStamp) : Date.now(),
    terminal,
    ...url,
    method: boundedText(details.method || "GET", 16).toUpperCase(),
    resourceType: boundedText(details.type || "other", 40),
    serverIp: normalizeIp(details.ip),
    fromCache: Boolean(details.fromCache)
  };
}

// onCompleted 只上传 4xx/5xx；2xx/3xx 不进入队列，从源头控制采集量和隐私面。
export function completedFailureFromWebRequest(
  details,
  { browserSessionId, ingestUrl = DEFAULT_INGEST_URL } = {}
) {
  const statusCode = Number(details?.statusCode);
  if (!Number.isInteger(statusCode) || statusCode < 400 || statusCode > 599) return null;
  const base = baseFailure(details, browserSessionId, "completed", ingestUrl);
  if (!base) return null;
  return {
    ...base,
    statusCode,
    failureCode: `HTTP_${statusCode}`,
    networkError: null
  };
}

// onErrorOccurred 没有稳定 HTTP 状态码；保留 Chrome 给出的终态错误字符串，但不读取任何 header/body。
export function networkFailureFromWebRequest(
  details,
  { browserSessionId, ingestUrl = DEFAULT_INGEST_URL } = {}
) {
  const base = baseFailure(details, browserSessionId, "error", ingestUrl);
  if (!base) return null;
  const networkError = normalizeNetworkError(details?.error);
  return {
    ...base,
    statusCode: null,
    failureCode: networkError,
    networkError
  };
}
