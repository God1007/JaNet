import assert from "node:assert/strict";
import test from "node:test";
import {
  DEFAULT_INGEST_URL,
  completedFailureFromWebRequest,
  isJaNetIngestRequest,
  networkFailureFromWebRequest,
  normalizeIngestUrl,
  sanitizeObservedUrl
} from "../lib/failure_event.mjs";

const context = { browserSessionId: "session-1", ingestUrl: DEFAULT_INGEST_URL };

test("completed collector accepts only HTTP 4xx and 5xx", () => {
  const base = { requestId: "7", url: "https://github.com/api?q=secret", timeStamp: 10, method: "GET", type: "xmlhttprequest", ip: "140.82.1.1" };
  assert.equal(completedFailureFromWebRequest({ ...base, statusCode: 399 }, context), null);
  const failure = completedFailureFromWebRequest({ ...base, statusCode: 429 }, context);
  assert.equal(failure.failureCode, "HTTP_429");
  assert.equal(failure.serverIp, "140.82.1.1");
  assert.equal(failure.safeUrl, "https://github.com/");
  assert.equal(failure.safeUrl.includes("secret"), false);
  const httpFailure = completedFailureFromWebRequest({
    ...base,
    requestId: "http-500",
    url: "http://example.com/plain?q=secret",
    statusCode: 500
  }, context);
  assert.equal(httpFailure.scheme, "http");
  assert.equal(httpFailure.failureCode, "HTTP_500");
});

test("URL sanitizer retains only origin and drops credentials path query and fragment", () => {
  const safe = sanitizeObservedUrl("https://user:pass@example.com:8443/path?q=token#private");
  assert.deepEqual(safe, {
    scheme: "https",
    host: "example.com",
    port: "8443",
    safeUrl: "https://example.com:8443/"
  });
});

test("URL sanitizer never retains identifiers embedded in pathname", () => {
  const safe = sanitizeObservedUrl("https://example.com/users/account-123/private/report.pdf");
  assert.equal(safe.safeUrl, "https://example.com/");
  assert.equal(safe.safeUrl.includes("account-123"), false);
  assert.equal(safe.safeUrl.includes("report.pdf"), false);
});

test("network terminal error retains bounded Chrome code with optional IP", () => {
  const failure = networkFailureFromWebRequest({
    requestId: "8",
    url: "https://github.com/",
    timeStamp: 11,
    method: "GET",
    type: "main_frame",
    error: "net::ERR_CONNECTION_RESET"
  }, context);
  assert.equal(failure.statusCode, null);
  assert.equal(failure.failureCode, "net::ERR_CONNECTION_RESET");
  assert.equal(failure.serverIp, null);
});

test("WebSocket HTTP upgrade failures are captured while successful 101 is not a failure", () => {
  const base = {
    requestId: "ws-1",
    url: "https://socket.example/ws",
    timeStamp: 12,
    method: "GET",
    type: "websocket"
  };
  assert.equal(completedFailureFromWebRequest({ ...base, statusCode: 101 }, context), null);
  const rejected = completedFailureFromWebRequest({ ...base, statusCode: 403 }, context);
  assert.equal(rejected.resourceType, "websocket");
  assert.equal(rejected.failureCode, "HTTP_403");
});

test("JaNet ingest is hard-excluded even when its own request fails", () => {
  assert.equal(isJaNetIngestRequest("http://127.0.0.1:9999/api/browser-failures?retry=1"), true);
  assert.equal(networkFailureFromWebRequest({
    requestId: "loop",
    url: "http://127.0.0.1:5174/api/browser-failures",
    error: "net::ERR_CONNECTION_REFUSED"
  }, context), null);
});

test("ingest configuration cannot exfiltrate to a remote host", () => {
  assert.equal(normalizeIngestUrl("https://evil.example/collect"), DEFAULT_INGEST_URL);
  assert.equal(normalizeIngestUrl("http://[::1]:5174/api/browser-failures"), DEFAULT_INGEST_URL);
  assert.equal(normalizeIngestUrl("http://localhost:5174/api/browser-failures"), "http://localhost:5174/api/browser-failures");
});
