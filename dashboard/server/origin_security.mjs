// Dashboard 本机 HTTP/WS 信任边界：隔离页面、Chrome 扩展和无 Origin 的运维客户端。

import {
  authorizeFailureIngest,
  isAllowedExtensionOrigin,
  isLoopbackRemoteAddress
} from "./request_failure_monitor.mjs";

const DASHBOARD_METHODS = new Set(["GET", "POST"]);
const DASHBOARD_HEADERS = new Set(["content-type"]);
const EXTENSION_HEADERS = new Set(["content-type", "x-janet-extension-token"]);
const PREFLIGHT_MAX_AGE_SECONDS = 600;

// Origin 是精确安全边界，不把带 path、query、credentials 或 "null" 的值宽松归一化。
function canonicalOrigin(value) {
  const raw = String(value ?? "").trim();
  if (!raw || raw === "null") return "";
  try {
    const parsed = new URL(raw);
    if ((parsed.protocol !== "http:" && parsed.protocol !== "https:")
        || parsed.username || parsed.password || parsed.pathname !== "/"
        || parsed.search || parsed.hash || parsed.origin !== raw) {
      return "";
    }
    return parsed.origin;
  } catch {
    return "";
  }
}

function requestHeader(request, name) {
  if (typeof request?.get === "function") {
    return request.get(name);
  }
  const value = request?.headers?.[String(name).toLowerCase()];
  return Array.isArray(value) ? value[0] : value;
}

function headerNames(value) {
  if (!value) return [];
  return String(value)
    .split(",")
    .map((item) => item.trim().toLowerCase())
    .filter(Boolean);
}

function headersAreAllowed(value, allowedHeaders) {
  return headerNames(value).every((name) => allowedHeaders.has(name));
}

function setResponseHeaders(response, headers) {
  for (const [name, value] of Object.entries(headers)) {
    response.set(name, value);
  }
}

function rejectJson(response, decision) {
  response.status(decision.statusCode || 403).json({ error: decision.reason });
}

// Vite 默认只在这两个等价 loopback 页面 Origin 上运行；API 端口不属于页面 Origin。
export function defaultDashboardOrigins(webPort) {
  const parsedPort = Number(webPort);
  if (!Number.isInteger(parsedPort) || parsedPort < 1 || parsedPort > 65_535) {
    throw new TypeError("webPort must be an integer between 1 and 65535");
  }
  return new Set([
    `http://127.0.0.1:${parsedPort}`,
    `http://localhost:${parsedPort}`
  ]);
}

// 浏览器请求必须来自已知 Dashboard 页面；无 Origin 仅为 loopback curl/脚本保留兼容。
export function authorizeDashboardApiRequest({
  origin,
  remoteAddress,
  allowedOrigins,
  secFetchSite
}) {
  if (!isLoopbackRemoteAddress(remoteAddress)) {
    return {
      ok: false,
      statusCode: 403,
      reason: "dashboard API accepts loopback clients only",
      corsOrigin: ""
    };
  }

  const rawOrigin = String(origin ?? "").trim();
  if (!rawOrigin) {
    // Chrome no-cors fetch/img 可能省略 Origin，但不可伪造的 Fetch Metadata 仍会标明跨站来源。
    const fetchSite = String(secFetchSite || "").trim().toLowerCase();
    if (fetchSite && fetchSite !== "none") {
      return {
        ok: false,
        statusCode: 403,
        reason: "browser request without Origin is not a local operator request",
        corsOrigin: ""
      };
    }
    return { ok: true, statusCode: 200, reason: "loopback client without Origin", corsOrigin: "" };
  }

  const normalized = canonicalOrigin(rawOrigin);
  if (!normalized || !allowedOrigins.has(normalized)) {
    return {
      ok: false,
      statusCode: 403,
      reason: "browser Origin is not an allowed Dashboard page",
      corsOrigin: ""
    };
  }
  return { ok: true, statusCode: 200, reason: "allowed Dashboard Origin", corsOrigin: normalized };
}

// 预检只开放 Dashboard 实际使用的 GET/POST 和 JSON Content-Type。
export function authorizeDashboardPreflight({ requestedMethod, requestedHeaders }) {
  const method = String(requestedMethod || "").trim().toUpperCase();
  if (!DASHBOARD_METHODS.has(method)) {
    return { ok: false, statusCode: 403, reason: "CORS method is not allowed" };
  }
  if (!headersAreAllowed(requestedHeaders, DASHBOARD_HEADERS)) {
    return { ok: false, statusCode: 403, reason: "CORS request header is not allowed" };
  }
  return { ok: true, statusCode: 204, reason: "preflight accepted" };
}

export function dashboardCorsHeaders(origin, { preflight = false } = {}) {
  const headers = {
    "Access-Control-Allow-Origin": origin,
    Vary: preflight ? "Origin, Access-Control-Request-Headers" : "Origin"
  };
  if (preflight) {
    headers["Access-Control-Allow-Methods"] = "GET, POST";
    headers["Access-Control-Allow-Headers"] = "Content-Type";
    headers["Access-Control-Max-Age"] = String(PREFLIGHT_MAX_AGE_SECONDS);
  }
  return headers;
}

// 该 middleware 位于通用 JSON parser 前；恶意网页 POST 不会触发解析或业务逻辑。
export function createDashboardApiSecurityMiddleware({ allowedOrigins }) {
  return (request, response, next) => {
    const decision = authorizeDashboardApiRequest({
      origin: requestHeader(request, "Origin"),
      remoteAddress: request.socket?.remoteAddress,
      allowedOrigins,
      secFetchSite: requestHeader(request, "Sec-Fetch-Site")
    });
    if (!decision.ok) {
      rejectJson(response, decision);
      return;
    }

    if (String(request.method || "").toUpperCase() === "OPTIONS") {
      // 手工 loopback OPTIONS 不需要 CORS；浏览器预检则必须声明真实目标方法。
      if (!decision.corsOrigin) {
        response.set("Allow", "GET, POST, OPTIONS").status(204).end();
        return;
      }
      const preflight = authorizeDashboardPreflight({
        requestedMethod: requestHeader(request, "Access-Control-Request-Method"),
        requestedHeaders: requestHeader(request, "Access-Control-Request-Headers")
      });
      if (!preflight.ok) {
        rejectJson(response, preflight);
        return;
      }
      setResponseHeaders(response, dashboardCorsHeaders(decision.corsOrigin, { preflight: true }));
      response.status(204).end();
      return;
    }

    if (decision.corsOrigin) {
      setResponseHeaders(response, dashboardCorsHeaders(decision.corsOrigin));
    }
    next();
  };
}

// 扩展预检不能携带 token 值，因此这里只校验 loopback、扩展 Origin/ID、方法和请求头。
export function authorizeExtensionPreflight({
  origin,
  remoteAddress,
  expectedExtensionId,
  requestedMethod,
  requestedHeaders
}) {
  if (!isLoopbackRemoteAddress(remoteAddress)) {
    return { ok: false, statusCode: 403, reason: "ingest accepts loopback clients only" };
  }
  if (!isAllowedExtensionOrigin(origin, expectedExtensionId)) {
    return { ok: false, statusCode: 403, reason: "extension origin is not paired" };
  }
  if (String(requestedMethod || "").trim().toUpperCase() !== "POST") {
    return { ok: false, statusCode: 403, reason: "extension ingest only allows POST" };
  }
  if (!headersAreAllowed(requestedHeaders, EXTENSION_HEADERS)) {
    return { ok: false, statusCode: 403, reason: "extension CORS request header is not allowed" };
  }
  return { ok: true, statusCode: 204, reason: "preflight accepted" };
}

export function extensionCorsHeaders(origin, { preflight = false } = {}) {
  const headers = {
    "Access-Control-Allow-Origin": String(origin),
    Vary: preflight ? "Origin, Access-Control-Request-Headers" : "Origin"
  };
  if (preflight) {
    headers["Access-Control-Allow-Methods"] = "POST";
    headers["Access-Control-Allow-Headers"] = "Content-Type, X-JaNet-Extension-Token";
    headers["Access-Control-Max-Age"] = String(PREFLIGHT_MAX_AGE_SECONDS);
  }
  return headers;
}

export function createExtensionPreflightMiddleware({ getFailureAuthConfig }) {
  return (request, response) => {
    const config = getFailureAuthConfig();
    const origin = requestHeader(request, "Origin");
    const decision = authorizeExtensionPreflight({
      origin,
      remoteAddress: request.socket?.remoteAddress,
      expectedExtensionId: config.expectedExtensionId,
      requestedMethod: requestHeader(request, "Access-Control-Request-Method"),
      requestedHeaders: requestHeader(request, "Access-Control-Request-Headers")
    });
    if (!decision.ok) {
      rejectJson(response, decision);
      return;
    }
    setResponseHeaders(response, extensionCorsHeaders(origin, { preflight: true }));
    response.status(204).end();
  };
}

// 完整扩展 ID/token 鉴权先于 JSON parser；配对扩展即使 token 错误也能读取明确的 401。
export function createExtensionIngestSecurityMiddleware({ getFailureAuthConfig }) {
  return (request, response, next) => {
    const config = getFailureAuthConfig();
    const origin = requestHeader(request, "Origin");
    const remoteAddress = request.socket?.remoteAddress;

    if (isLoopbackRemoteAddress(remoteAddress)
        && isAllowedExtensionOrigin(origin, config.expectedExtensionId)) {
      setResponseHeaders(response, extensionCorsHeaders(origin));
    }

    const decision = authorizeFailureIngest({
      origin,
      expectedExtensionId: config.expectedExtensionId,
      remoteAddress,
      providedToken: requestHeader(request, "X-JaNet-Extension-Token"),
      expectedToken: config.expectedToken
    });
    if (!decision.ok) {
      rejectJson(response, decision);
      return;
    }
    next();
  };
}

// 注册顺序就是安全属性：扩展专用链先鉴权再解析，随后才安装普通 Dashboard API 守卫。
export function installApiSecurity(app, {
  allowedOrigins,
  getFailureAuthConfig,
  jsonParser,
  failureIngestHandler
}) {
  const extensionPreflight = createExtensionPreflightMiddleware({ getFailureAuthConfig });
  const extensionGuard = createExtensionIngestSecurityMiddleware({ getFailureAuthConfig });
  const dashboardGuard = createDashboardApiSecurityMiddleware({ allowedOrigins });

  app.options("/api/browser-failures", extensionPreflight);
  app.post("/api/browser-failures", extensionGuard, jsonParser, failureIngestHandler);
  app.use("/api", dashboardGuard);
  app.use(jsonParser);

  return { extensionPreflight, extensionGuard, dashboardGuard };
}

// WS 不受浏览器 CORS 保护，因此在 HTTP Upgrade 阶段复用同一 Origin/loopback 策略。
export function authorizeDashboardWebSocketUpgrade({
  requestUrl,
  origin,
  remoteAddress,
  allowedOrigins,
  secFetchSite
}) {
  if (String(requestUrl || "") !== "/ws/events") {
    return { ok: false, statusCode: 404, reason: "WebSocket endpoint not found" };
  }
  const decision = authorizeDashboardApiRequest({
    origin,
    remoteAddress,
    allowedOrigins,
    secFetchSite
  });
  return decision.ok
    ? { ...decision, statusCode: 101 }
    : decision;
}

export function rejectWebSocketUpgrade(socket, statusCode = 403) {
  const notFound = statusCode === 404;
  const reason = notFound ? "Not Found" : "Forbidden";
  const body = `${reason}\n`;
  socket.end(
    `HTTP/1.1 ${notFound ? 404 : 403} ${reason}\r\n`
    + "Connection: close\r\n"
    + "Content-Type: text/plain; charset=utf-8\r\n"
    + `Content-Length: ${Buffer.byteLength(body)}\r\n`
    + "\r\n"
    + body
  );
}

// noServer 模式让任何 socket 在进入 ws clients 集合前先完成路径和 Origin 校验。
export function attachSecureWebSocketUpgrade({ server, wss, allowedOrigins }) {
  const onUpgrade = (request, socket, head) => {
    socket.on("error", () => socket.destroy());
    const decision = authorizeDashboardWebSocketUpgrade({
      requestUrl: request.url,
      origin: requestHeader(request, "Origin"),
      remoteAddress: request.socket?.remoteAddress,
      allowedOrigins,
      secFetchSite: requestHeader(request, "Sec-Fetch-Site")
    });
    if (!decision.ok) {
      rejectWebSocketUpgrade(socket, decision.statusCode);
      return;
    }
    wss.handleUpgrade(request, socket, head, (webSocket) => {
      wss.emit("connection", webSocket, request);
    });
  };
  server.on("upgrade", onUpgrade);
  return onUpgrade;
}
