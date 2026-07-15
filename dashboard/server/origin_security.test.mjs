// Node 内建测试：锁定 Dashboard REST/CORS、扩展前置鉴权和 WebSocket Upgrade 的本机边界。

import assert from "node:assert/strict";
import http from "node:http";
import test from "node:test";
import express from "express";
import {
  attachSecureWebSocketUpgrade,
  authorizeDashboardApiRequest,
  authorizeDashboardWebSocketUpgrade,
  authorizeExtensionPreflight,
  createDashboardApiSecurityMiddleware,
  defaultDashboardOrigins,
  installApiSecurity
} from "./origin_security.mjs";

const webPort = 5173;
const origins = defaultDashboardOrigins(webPort);
const extensionId = "a".repeat(32);

function requestDouble({
  method = "GET",
  origin,
  remoteAddress = "127.0.0.1",
  headers = {},
  url = "/api/status"
} = {}) {
  const normalizedHeaders = Object.fromEntries(
    Object.entries(headers).map(([name, value]) => [name.toLowerCase(), value])
  );
  if (origin !== undefined) normalizedHeaders.origin = origin;
  return {
    method,
    url,
    headers: normalizedHeaders,
    socket: { remoteAddress },
    get(name) {
      return normalizedHeaders[String(name).toLowerCase()];
    }
  };
}

function responseDouble() {
  return {
    headers: {},
    statusCode: 200,
    jsonBody: undefined,
    ended: false,
    set(name, value) {
      this.headers[name] = value;
      return this;
    },
    status(value) {
      this.statusCode = value;
      return this;
    },
    json(value) {
      this.jsonBody = value;
      this.ended = true;
      return this;
    },
    end() {
      this.ended = true;
      return this;
    }
  };
}

async function runHandlers(handlers, request, response) {
  let index = 0;
  async function next(error) {
    if (error) throw error;
    const handler = handlers[index];
    index += 1;
    if (handler) await handler(request, response, next);
  }
  await next();
}

async function listenOnLoopback(server) {
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  return server.address().port;
}

test("Dashboard browser access is exact-origin and loopback only", () => {
  for (const origin of [
    "http://127.0.0.1:5173",
    "http://localhost:5173"
  ]) {
    const decision = authorizeDashboardApiRequest({
      origin,
      remoteAddress: "::ffff:127.0.0.1",
      allowedOrigins: origins
    });
    assert.equal(decision.ok, true);
    assert.equal(decision.corsOrigin, origin);
  }

  for (const origin of [
    "https://evil.example",
    "null",
    "http://localhost:5174",
    "http://localhost:5173/evil"
  ]) {
    assert.equal(authorizeDashboardApiRequest({
      origin,
      remoteAddress: "127.0.0.1",
      allowedOrigins: origins
    }).ok, false);
  }
});

test("Origin-less operations remain available only to loopback clients", () => {
  assert.equal(authorizeDashboardApiRequest({
    origin: undefined,
    remoteAddress: "127.0.0.1",
    allowedOrigins: origins
  }).ok, true);
  assert.equal(authorizeDashboardApiRequest({
    origin: "",
    remoteAddress: "::1",
    allowedOrigins: origins
  }).ok, true);
  assert.equal(authorizeDashboardApiRequest({
    origin: undefined,
    remoteAddress: "192.0.2.10",
    allowedOrigins: origins
  }).ok, false);
  // no-cors fetch/img can omit Origin; Fetch Metadata keeps those browser requests out of CLI mode.
  assert.equal(authorizeDashboardApiRequest({
    origin: undefined,
    remoteAddress: "127.0.0.1",
    allowedOrigins: origins,
    secFetchSite: "cross-site"
  }).ok, false);
  assert.equal(authorizeDashboardApiRequest({
    origin: undefined,
    remoteAddress: "127.0.0.1",
    allowedOrigins: origins,
    secFetchSite: "none"
  }).ok, true);
});

test("malicious browser Origin is rejected before REST handlers run", () => {
  const guard = createDashboardApiSecurityMiddleware({ allowedOrigins: origins });
  for (const path of ["/api/status", "/api/snapshot", "/api/ping", "/api/analyze"]) {
    const request = requestDouble({
      method: path === "/api/status" || path === "/api/snapshot" ? "GET" : "POST",
      origin: "https://evil.example",
      url: path
    });
    const response = responseDouble();
    let businessHandlerRan = false;
    guard(request, response, () => {
      businessHandlerRan = true;
    });
    assert.equal(response.statusCode, 403, path);
    assert.equal(response.headers["Access-Control-Allow-Origin"], undefined, path);
    assert.equal(businessHandlerRan, false, path);
  }
});

test("Dashboard CORS reflects only the allowed page and rejects broadened preflights", () => {
  const guard = createDashboardApiSecurityMiddleware({ allowedOrigins: origins });
  const allowedRequest = requestDouble({
    method: "OPTIONS",
    origin: "http://localhost:5173",
    headers: {
      "Access-Control-Request-Method": "POST",
      "Access-Control-Request-Headers": "Content-Type"
    }
  });
  const allowedResponse = responseDouble();
  guard(allowedRequest, allowedResponse, () => assert.fail("preflight must finish in the guard"));
  assert.equal(allowedResponse.statusCode, 204);
  assert.equal(allowedResponse.headers["Access-Control-Allow-Origin"], "http://localhost:5173");
  assert.equal(allowedResponse.headers["Access-Control-Allow-Methods"], "GET, POST");
  assert.equal(allowedResponse.headers["Access-Control-Allow-Headers"], "Content-Type");

  for (const headers of [
    { "Access-Control-Request-Method": "DELETE" },
    {
      "Access-Control-Request-Method": "POST",
      "Access-Control-Request-Headers": "Authorization"
    }
  ]) {
    const response = responseDouble();
    guard(requestDouble({
      method: "OPTIONS",
      origin: "http://localhost:5173",
      headers
    }), response, () => assert.fail("invalid preflight must not continue"));
    assert.equal(response.statusCode, 403);
  }
});

test("Chrome extension preflight stays separate from Dashboard page CORS", () => {
  assert.equal(authorizeExtensionPreflight({
    origin: `chrome-extension://${extensionId}`,
    remoteAddress: "127.0.0.1",
    expectedExtensionId: extensionId,
    requestedMethod: "POST",
    requestedHeaders: "content-type, x-janet-extension-token"
  }).ok, true);
  assert.equal(authorizeExtensionPreflight({
    origin: "http://localhost:5173",
    remoteAddress: "127.0.0.1",
    expectedExtensionId: extensionId,
    requestedMethod: "POST",
    requestedHeaders: "content-type"
  }).ok, false);
  assert.equal(authorizeExtensionPreflight({
    origin: `chrome-extension://${extensionId}`,
    remoteAddress: "127.0.0.1",
    expectedExtensionId: extensionId,
    requestedMethod: "POST",
    requestedHeaders: "authorization"
  }).ok, false);
});

test("browser failure authentication is installed before its JSON parser", async () => {
  const registrations = [];
  const app = {
    options(path, ...handlers) {
      registrations.push({ method: "OPTIONS", path, handlers });
    },
    post(path, ...handlers) {
      registrations.push({ method: "POST", path, handlers });
    },
    use(...args) {
      registrations.push({ method: "USE", path: typeof args[0] === "string" ? args[0] : "*", handlers: typeof args[0] === "string" ? args.slice(1) : args });
    }
  };
  let parserRuns = 0;
  let ingestRuns = 0;
  const jsonParser = (_request, _response, next) => {
    parserRuns += 1;
    next();
  };
  const failureIngestHandler = (_request, response) => {
    ingestRuns += 1;
    response.status(202).json({ accepted: true });
  };

  installApiSecurity(app, {
    allowedOrigins: origins,
    getFailureAuthConfig: () => ({
      expectedExtensionId: extensionId,
      expectedToken: "pair-token"
    }),
    jsonParser,
    failureIngestHandler
  });

  assert.deepEqual(registrations.map(({ method, path }) => `${method} ${path}`), [
    "OPTIONS /api/browser-failures",
    "POST /api/browser-failures",
    "USE /api",
    "USE *"
  ]);
  const postHandlers = registrations[1].handlers;
  assert.equal(postHandlers[1], jsonParser);

  await runHandlers(
    postHandlers,
    requestDouble({
      method: "POST",
      origin: "https://evil.example",
      headers: { "X-JaNet-Extension-Token": "pair-token" },
      url: "/api/browser-failures"
    }),
    responseDouble()
  );
  assert.equal(parserRuns, 0);
  assert.equal(ingestRuns, 0);

  const allowedResponse = responseDouble();
  await runHandlers(
    postHandlers,
    requestDouble({
      method: "POST",
      origin: `chrome-extension://${extensionId}`,
      headers: { "X-JaNet-Extension-Token": "pair-token" },
      url: "/api/browser-failures"
    }),
    allowedResponse
  );
  assert.equal(parserRuns, 1);
  assert.equal(ingestRuns, 1);
  assert.equal(allowedResponse.statusCode, 202);
  assert.equal(
    allowedResponse.headers["Access-Control-Allow-Origin"],
    `chrome-extension://${extensionId}`
  );
});

test("real Express routing blocks hostile REST work and keeps the extension chain usable", async (context) => {
  const app = express();
  let statusRuns = 0;
  let snapshotRuns = 0;
  let analyzeRuns = 0;
  let ingestRuns = 0;
  installApiSecurity(app, {
    allowedOrigins: origins,
    getFailureAuthConfig: () => ({
      expectedExtensionId: extensionId,
      expectedToken: "pair-token"
    }),
    jsonParser: express.json({ limit: "1mb" }),
    failureIngestHandler: (request, response) => {
      ingestRuns += 1;
      response.status(202).json({ kind: request.body.kind });
    }
  });
  app.get("/api/status", (_request, response) => {
    statusRuns += 1;
    response.json({ ok: true });
  });
  app.get("/api/snapshot", (_request, response) => {
    snapshotRuns += 1;
    response.json({ ok: true });
  });
  app.post("/api/analyze", (_request, response) => {
    analyzeRuns += 1;
    response.json({ ok: true });
  });

  const server = http.createServer(app);
  const port = await listenOnLoopback(server);
  context.after(() => new Promise((resolve) => server.close(resolve)));
  const base = `http://127.0.0.1:${port}`;

  for (const [path, method] of [
    ["/api/status", "GET"],
    ["/api/snapshot", "GET"],
    ["/api/analyze", "POST"]
  ]) {
    const response = await fetch(`${base}${path}`, {
      method,
      headers: { Origin: "https://evil.example" }
    });
    assert.equal(response.status, 403, path);
    assert.equal(response.headers.get("access-control-allow-origin"), null, path);
  }
  assert.deepEqual({ statusRuns, snapshotRuns, analyzeRuns }, {
    statusRuns: 0,
    snapshotRuns: 0,
    analyzeRuns: 0
  });

  const allowed = await fetch(`${base}/api/status`, {
    headers: { Origin: "http://localhost:5173" }
  });
  assert.equal(allowed.status, 200);
  assert.equal(allowed.headers.get("access-control-allow-origin"), "http://localhost:5173");
  const cli = await fetch(`${base}/api/status`);
  assert.equal(cli.status, 200);
  assert.equal(cli.headers.get("access-control-allow-origin"), null);

  // 非法 JSON 若先到 parser 会返回 400；这里必须在不解析 body 的情况下由 Origin guard 返回 403。
  const hostileIngest = await fetch(`${base}/api/browser-failures`, {
    method: "POST",
    headers: {
      Origin: "https://evil.example",
      "Content-Type": "application/json",
      "X-JaNet-Extension-Token": "pair-token"
    },
    body: "{not-json"
  });
  assert.equal(hostileIngest.status, 403);
  assert.equal(ingestRuns, 0);

  const extensionOrigin = `chrome-extension://${extensionId}`;
  const preflight = await fetch(`${base}/api/browser-failures`, {
    method: "OPTIONS",
    headers: {
      Origin: extensionOrigin,
      "Access-Control-Request-Method": "POST",
      "Access-Control-Request-Headers": "content-type,x-janet-extension-token"
    }
  });
  assert.equal(preflight.status, 204);
  assert.equal(preflight.headers.get("access-control-allow-origin"), extensionOrigin);

  const acceptedIngest = await fetch(`${base}/api/browser-failures`, {
    method: "POST",
    headers: {
      Origin: extensionOrigin,
      "Content-Type": "application/json",
      "X-JaNet-Extension-Token": "pair-token"
    },
    body: JSON.stringify({ kind: "heartbeat" })
  });
  assert.equal(acceptedIngest.status, 202);
  assert.equal(acceptedIngest.headers.get("access-control-allow-origin"), extensionOrigin);
  assert.equal(ingestRuns, 1);
});

test("WebSocket Upgrade accepts the Dashboard/no-Origin loopback clients and rejects web attackers", () => {
  assert.equal(authorizeDashboardWebSocketUpgrade({
    requestUrl: "/ws/events",
    origin: "http://127.0.0.1:5173",
    remoteAddress: "127.0.0.1",
    allowedOrigins: origins
  }).ok, true);
  assert.equal(authorizeDashboardWebSocketUpgrade({
    requestUrl: "/ws/events",
    origin: undefined,
    remoteAddress: "127.0.0.1",
    allowedOrigins: origins
  }).ok, true);
  assert.equal(authorizeDashboardWebSocketUpgrade({
    requestUrl: "/ws/events",
    origin: undefined,
    remoteAddress: "127.0.0.1",
    allowedOrigins: origins,
    secFetchSite: "cross-site"
  }).ok, false);
  assert.equal(authorizeDashboardWebSocketUpgrade({
    requestUrl: "/ws/events",
    origin: "https://evil.example",
    remoteAddress: "127.0.0.1",
    allowedOrigins: origins
  }).ok, false);
  assert.equal(authorizeDashboardWebSocketUpgrade({
    requestUrl: "/ws/other",
    origin: "http://127.0.0.1:5173",
    remoteAddress: "127.0.0.1",
    allowedOrigins: origins
  }).statusCode, 404);
});

test("secure WebSocket attachment rejects before handleUpgrade and accepts the real endpoint", () => {
  let upgradeListener;
  const server = {
    on(event, listener) {
      assert.equal(event, "upgrade");
      upgradeListener = listener;
    }
  };
  let handleUpgradeRuns = 0;
  let connectionEmits = 0;
  const wss = {
    handleUpgrade(_request, _socket, _head, callback) {
      handleUpgradeRuns += 1;
      callback({ readyState: 1 });
    },
    emit(event) {
      if (event === "connection") connectionEmits += 1;
    }
  };
  attachSecureWebSocketUpgrade({ server, wss, allowedOrigins: origins });

  const rejectedSocket = {
    response: "",
    on() {},
    destroy() {},
    end(value) {
      this.response += value;
    }
  };
  upgradeListener(
    requestDouble({ url: "/ws/events", origin: "https://evil.example" }),
    rejectedSocket,
    Buffer.alloc(0)
  );
  assert.match(rejectedSocket.response, /^HTTP\/1\.1 403 Forbidden/);
  assert.equal(handleUpgradeRuns, 0);

  const acceptedSocket = { on() {}, destroy() {}, end() {} };
  upgradeListener(
    requestDouble({ url: "/ws/events", origin: "http://localhost:5173" }),
    acceptedSocket,
    Buffer.alloc(0)
  );
  assert.equal(handleUpgradeRuns, 1);
  assert.equal(connectionEmits, 1);
});
