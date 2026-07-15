import assert from "node:assert/strict";
import test from "node:test";
import {
  authorizeFailureIngest,
  classifyFailureCode,
  createRequestFailureMonitor,
  isAllowedExtensionOrigin,
  validateRequestFailureBatch,
  validateRequestFailureEvent
} from "./request_failure_monitor.mjs";

const extensionId = "a".repeat(32);

function failureEvent(overrides = {}) {
  return {
    eventId: "session:req:completed",
    occurredAt: 1000,
    terminal: "completed",
    scheme: "https",
    host: "github.com",
    port: "443",
    safeUrl: "https://github.com/api?q=secret#fragment",
    method: "GET",
    resourceType: "xmlhttprequest",
    serverIp: "140.82.1.1",
    fromCache: false,
    statusCode: 429,
    failureCode: "untrusted-client-value",
    networkError: null,
    ...overrides
  };
}

function failureBatch(events, overrides = {}) {
  return {
    schemaVersion: 1,
    kind: "failures",
    browserSessionId: "browser-session",
    batchId: "batch-1",
    sentAt: 1000,
    clientDropped: 0,
    events,
    ...overrides
  };
}

test("extension ingest defaults to valid Origin plus loopback and optionally enforces pairing", () => {
  assert.equal(isAllowedExtensionOrigin(`chrome-extension://${extensionId}`, ""), true);
  assert.equal(isAllowedExtensionOrigin(`chrome-extension://${extensionId}`, extensionId), true);
  assert.equal(isAllowedExtensionOrigin(`chrome-extension://${"b".repeat(32)}`, extensionId), false);
  assert.equal(isAllowedExtensionOrigin("https://example.com", extensionId), false);
  assert.deepEqual(authorizeFailureIngest({
    origin: `chrome-extension://${extensionId}`,
    expectedExtensionId: "",
    remoteAddress: "127.0.0.1",
    providedToken: "",
    expectedToken: ""
  }), { ok: true, statusCode: 202, reason: "accepted" });
  assert.deepEqual(authorizeFailureIngest({
    origin: `chrome-extension://${extensionId}`,
    expectedExtensionId: extensionId,
    remoteAddress: "::ffff:127.0.0.1",
    providedToken: "pair-secret",
    expectedToken: "pair-secret"
  }), { ok: true, statusCode: 202, reason: "accepted" });
  assert.equal(authorizeFailureIngest({
    origin: `chrome-extension://${extensionId}`,
    expectedExtensionId: extensionId,
    remoteAddress: "127.0.0.1",
    providedToken: "wrong",
    expectedToken: "pair-secret"
  }).statusCode, 401);
});

test("BFF canonicalizes URL again and derives HTTP failure code itself", () => {
  const normalized = validateRequestFailureEvent(failureEvent({
    safeUrl: "https://user:pass@GitHub.com/api?q=token#private"
  }), 2000);
  assert.equal(normalized.host, "github.com");
  assert.equal(normalized.safeUrl, "https://github.com/");
  assert.equal(normalized.safeUrl.includes("token"), false);
  assert.equal(normalized.safeUrl.includes("/api"), false);
  assert.equal(normalized.failureCode, "HTTP_429");
  assert.equal(normalized.category, "http");
  assert.equal(normalized.alertEligible, true);
});

test("heartbeat updates liveness without creating a failure", () => {
  const monitor = createRequestFailureMonitor({ now: () => 10_000 });
  const outcome = monitor.ingest({
    schemaVersion: 1,
    kind: "heartbeat",
    browserSessionId: "browser-session",
    batchId: "heartbeat-1",
    sentAt: 10_000,
    clientDropped: 0,
    events: []
  });
  assert.equal(outcome.accepted, 0);
  const snapshot = monitor.snapshot(10_001);
  assert.equal(snapshot.lastHeartbeatAt, 10_000);
  assert.equal(snapshot.lastContactAt, 10_000);
  assert.equal(snapshot.connectedRecent, true);
  assert.equal(snapshot.lastReceivedAt, 0);
  assert.equal(snapshot.totalFailures, 0);
});

test("a delivered failure proves recent extension contact before the next heartbeat", () => {
  const monitor = createRequestFailureMonitor({ now: () => 20_000 });
  monitor.ingest(failureBatch([failureEvent({ eventId: "contact-by-failure" })]), {
    receivedAt: 20_000
  });

  const snapshot = monitor.snapshot(20_001);
  assert.equal(snapshot.lastHeartbeatAt, 0);
  assert.equal(snapshot.lastContactAt, 20_000);
  assert.equal(snapshot.connectedRecent, true);
});

test("same host and HTTP code crosses threshold across IPs and resource types", () => {
  let now = 1000;
  const transitions = [];
  const monitor = createRequestFailureMonitor({
    threshold: 3,
    windowMs: 60_000,
    now: () => now,
    onTransition: (transition) => transitions.push(transition)
  });
  for (let index = 0; index < 3; index += 1) {
    now += 1000;
    monitor.ingest(failureBatch([failureEvent({
      eventId: `event-${index}`,
      serverIp: index === 1 ? "140.82.1.2" : "140.82.1.1",
      resourceType: index === 2 ? "main_frame" : "xmlhttprequest"
    })], { batchId: `batch-${index}` }), { receivedAt: now });
  }
  const snapshot = monitor.snapshot(now);
  assert.equal(snapshot.activeAlerts.length, 1);
  assert.equal(snapshot.activeAlerts[0].failureCode, "HTTP_429");
  assert.equal(snapshot.activeAlerts[0].countInWindow, 3);
  assert.equal(snapshot.groups[0].ips.length, 2);
  assert.equal(snapshot.groups[0].resourceTypes.length, 2);
  assert.equal(transitions.length, 1, "threshold crossing emits one firing transition");
});

test("sliding window uses bounded occurrence time and resolves after expiry", () => {
  let now = 1_700_000_000_000;
  const monitor = createRequestFailureMonitor({ threshold: 2, windowMs: 10_000, now: () => now });
  monitor.ingest(failureBatch([failureEvent({ eventId: "current-1", occurredAt: now })]), { receivedAt: now });
  now += 1000;
  monitor.ingest(failureBatch([failureEvent({ eventId: "current-2", occurredAt: now })]), { receivedAt: now });
  const firing = monitor.snapshot(now);
  assert.equal(firing.activeAlerts.length, 1);
  now += 11_000;
  const after = monitor.snapshot(now);
  assert.equal(after.activeAlerts.length, 0);
  assert.equal(after.alertTransitions[0].state, "resolved");
});

test("far future, far past, and missing client timestamps are clamped and never alert", () => {
  const now = 1_700_000_000_000;
  const monitor = createRequestFailureMonitor({ threshold: 1, windowMs: 10_000, now: () => now });
  monitor.ingest(failureBatch([
    failureEvent({ eventId: "future-client", occurredAt: 9e15 }),
    failureEvent({ eventId: "past-client", occurredAt: 1 }),
    failureEvent({ eventId: "missing-client", occurredAt: null })
  ]), { receivedAt: now });

  const snapshot = monitor.snapshot(now);
  assert.equal(snapshot.activeAlerts.length, 0);
  assert.equal(snapshot.totalFailures, 3, "untrusted events remain available in recent diagnostics");
  assert.equal(snapshot.recentFailures.every((event) => event.timestampAdjusted), true);
  assert.equal(snapshot.recentFailures.every((event) => event.timestampTrusted === false), true);
  assert.equal(snapshot.recentFailures.every((event) => event.alertEligible === false), true);
  assert.equal(snapshot.recentFailures.every((event) => Number.isFinite(event.occurredAt)), true);
});

test("offline stale backlog remains in recent records but cannot trigger a current burst", () => {
  const now = 1_700_000_000_000;
  const windowMs = 10_000;
  const monitor = createRequestFailureMonitor({ threshold: 3, windowMs, now: () => now });
  const events = Array.from({ length: 5 }, (_, index) => failureEvent({
    eventId: `stale-${index}`,
    occurredAt: now - windowMs - 1
  }));
  monitor.ingest(failureBatch(events), { receivedAt: now });

  const snapshot = monitor.snapshot(now);
  assert.equal(snapshot.totalFailures, 5);
  assert.equal(snapshot.recentFailures.length, 5);
  assert.equal(snapshot.failuresInWindow, 0);
  assert.equal(snapshot.activeAlerts.length, 0);
  assert.equal(snapshot.groups[0].alertEligible, true, "HTTP failures remain an alertable category");
  assert.equal(snapshot.groups[0].lastFailure.staleBacklog, true);
  assert.equal(snapshot.groups[0].lastFailure.alertEligibilityReason, "stale_backlog");
});

test("an event exactly on the alert-window boundary is eligible, then expires one millisecond later", () => {
  let now = 100_000;
  const monitor = createRequestFailureMonitor({ threshold: 1, windowMs: 10_000, now: () => now });
  monitor.ingest(failureBatch([failureEvent({
    eventId: "window-boundary",
    occurredAt: now - 10_000
  })]), { receivedAt: now });
  assert.equal(monitor.snapshot(now).activeAlerts.length, 1);

  now += 1;
  const expired = monitor.snapshot(now);
  assert.equal(expired.activeAlerts.length, 0);
  assert.equal(expired.failuresInWindow, 0);
});

test("small future clock skew is clamped to server time but remains alert eligible", () => {
  const now = 500_000;
  const normalized = validateRequestFailureEvent(failureEvent({ occurredAt: now + 30_000 }), now, {
    alertWindowMs: 10_000,
    maxFutureSkewMs: 60_000
  });
  assert.equal(normalized.occurredAt, now);
  assert.equal(normalized.timestampAdjusted, true);
  assert.equal(normalized.timestampTrusted, true);
  assert.equal(normalized.alertEligible, true);
});

test("retry is idempotent through bounded TTL dedupe", () => {
  const monitor = createRequestFailureMonitor({ threshold: 2, windowMs: 60_000, now: () => 5000 });
  const batch = failureBatch([failureEvent()]);
  assert.equal(monitor.ingest(batch, { receivedAt: 5000 }).accepted, 1);
  const retry = monitor.ingest({
    ...batch,
    batchId: "retry-new-batch-id",
    browserSessionId: "new-session-after-browser-restart"
  }, { receivedAt: 5001 });
  assert.equal(retry.accepted, 0);
  assert.equal(retry.duplicates, 1);
  const snapshot = monitor.snapshot(5001);
  assert.equal(snapshot.totalFailures, 1);
  assert.equal(snapshot.stats.dedupeSize, 1);
});

test("repeated delivery refreshes dedupe TTL until the extension receives its ACK", () => {
  let now = 100_000;
  const monitor = createRequestFailureMonitor({
    threshold: 2,
    windowMs: 10_000,
    dedupeTtlMs: 10_000,
    now: () => now
  });
  const batch = failureBatch([failureEvent({ eventId: "long-retry" })]);
  assert.equal(monitor.ingest(batch, { receivedAt: now }).accepted, 1);
  now += 9000;
  assert.equal(monitor.ingest(batch, { receivedAt: now }).duplicates, 1);
  now += 9000;
  assert.equal(monitor.ingest(batch, { receivedAt: now }).duplicates, 1);
  assert.equal(monitor.snapshot(now).totalFailures, 1);
});

test("cancelled and policy failures remain visible but do not alert", () => {
  let now = 1000;
  const monitor = createRequestFailureMonitor({ threshold: 1, windowMs: 60_000, now: () => now });
  for (const [index, code] of ["net::ERR_ABORTED", "net::ERR_BLOCKED_BY_CLIENT"].entries()) {
    now += 1;
    monitor.ingest(failureBatch([failureEvent({
      eventId: `cancel-${index}`,
      terminal: "error",
      statusCode: null,
      failureCode: code,
      networkError: code
    })]), { receivedAt: now });
  }
  const snapshot = monitor.snapshot(now);
  assert.equal(snapshot.totalFailures, 2);
  assert.equal(snapshot.activeAlerts.length, 0);
  assert.deepEqual(new Set(snapshot.recentFailures.map((event) => event.category)), new Set(["cancelled"]));
  assert.equal(snapshot.groups.every((group) => group.alertEligible === false), true);
});

test("DNS TLS and connection browser errors are alert eligible", () => {
  assert.deepEqual(classifyFailureCode(null, "net::ERR_NAME_NOT_RESOLVED"), { category: "dns", alertEligible: true });
  assert.deepEqual(classifyFailureCode(null, "net::ERR_CERT_DATE_INVALID"), { category: "tls", alertEligible: true });
  assert.deepEqual(classifyFailureCode(null, "net::ERR_CONNECTION_REFUSED"), { category: "connection", alertEligible: true });
  assert.deepEqual(classifyFailureCode(null, "net::ERR_FAILED"), { category: "network", alertEligible: true });
});

test("active alert count follows pruning while it remains above threshold", () => {
  let now = 1000;
  const monitor = createRequestFailureMonitor({ threshold: 2, windowMs: 10_000, now: () => now });
  for (let index = 0; index < 3; index += 1) {
    now += 1000;
    monitor.ingest(failureBatch([failureEvent({ eventId: `prune-${index}`, occurredAt: now })]), { receivedAt: now });
  }
  assert.equal(monitor.snapshot(now).activeAlerts[0].countInWindow, 3);
  now = 12_500;
  assert.equal(monitor.snapshot(now).activeAlerts[0].countInWindow, 2);
});

test("all memory dimensions stay bounded under high-cardinality input", () => {
  let now = 1000;
  const monitor = createRequestFailureMonitor({
    threshold: 2,
    windowMs: 60_000,
    maxRecent: 3,
    maxGroups: 2,
    maxDedupe: 4,
    maxIpsPerGroup: 2,
    maxWindowEventsPerGroup: 3,
    now: () => now
  });
  for (let index = 0; index < 8; index += 1) {
    now += 1;
    monitor.ingest(failureBatch([failureEvent({
      eventId: `bounded-${index}`,
      host: `host-${index % 3}.example`,
      safeUrl: `https://host-${index % 3}.example/path`,
      serverIp: `203.0.113.${index + 1}`,
      statusCode: 400 + (index % 3)
    })]), { receivedAt: now });
  }
  const snapshot = monitor.snapshot(now);
  assert.equal(snapshot.recentFailures.length, 3);
  assert.ok(snapshot.groups.length <= 2);
  assert.ok(snapshot.stats.dedupeSize <= 4);
  assert.ok(snapshot.groups.every((group) => group.ips.length <= 2));
  assert.ok(snapshot.groups.every((group) => group.countInWindow <= 3));
  assert.equal(snapshot.failuresInWindowCapped, true);

  now += 60_001;
  const afterWindow = monitor.snapshot(now);
  assert.equal(afterWindow.failuresInWindowCapped, false, "historic group evictions must not cap later windows");
  assert.equal(afterWindow.failuresInWindowOverflow, 0);
  assert.ok(afterWindow.stats.groupEvictions > 0, "lifetime diagnostic stats remain cumulative");
});

test("per-group overflow is reported only as a current-window lower bound", () => {
  let now = 10_000;
  const monitor = createRequestFailureMonitor({
    threshold: 2,
    windowMs: 10_000,
    maxWindowEventsPerGroup: 3,
    now: () => now
  });
  for (let index = 0; index < 4; index += 1) {
    now += 1;
    monitor.ingest(failureBatch([failureEvent({
      eventId: `overflow-${index}`,
      occurredAt: now
    })]), { receivedAt: now });
  }
  const capped = monitor.snapshot(now);
  assert.equal(capped.failuresInWindow, 3);
  assert.equal(capped.failuresInWindowCapped, true);
  assert.equal(capped.failuresInWindowOverflow, 1);
  assert.equal(capped.groups[0].windowOverflowCount, 1);

  now = 20_002;
  const noLongerCapped = monitor.snapshot(now);
  assert.equal(noLongerCapped.failuresInWindow, 3, "retained newer events are still in the window");
  assert.equal(noLongerCapped.failuresInWindowCapped, false, "the omitted oldest event has expired");
  assert.equal(noLongerCapped.failuresInWindowOverflow, 0);
  assert.equal(noLongerCapped.groups[0].windowOverflowCount, 0);

  now = 20_005;
  assert.equal(monitor.snapshot(now).failuresInWindow, 0);
});

test("threshold above the default window capacity remains reachable", () => {
  let now = 1000;
  const monitor = createRequestFailureMonitor({
    threshold: 513,
    windowMs: 60_000,
    now: () => now
  });
  for (let index = 0; index < 513; index += 1) {
    now += 1;
    monitor.ingest(failureBatch([failureEvent({ eventId: `large-threshold-${index}` })]), { receivedAt: now });
  }
  assert.equal(monitor.config.maxWindowEventsPerGroup, 513);
  assert.equal(monitor.snapshot(now).activeAlerts.length, 1);
});

test("batch validates event count and preserves per-event rejection", () => {
  const parsed = validateRequestFailureBatch(failureBatch([
    failureEvent({ eventId: "valid" }),
    failureEvent({ eventId: "invalid", statusCode: 200 })
  ]), { receivedAt: 1000 });
  assert.equal(parsed.events.length, 1);
  assert.equal(parsed.rejected.length, 1);
  assert.throws(
    () => validateRequestFailureBatch(failureBatch(Array.from({ length: 101 }, (_, index) => failureEvent({ eventId: String(index) })) )),
    /batch size/
  );
});
