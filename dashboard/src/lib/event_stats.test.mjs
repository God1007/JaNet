// 事件趋势单测：覆盖连续空分钟、5 小时 TTL 和未来时钟漂移收敛。

import assert from "node:assert/strict";
import test from "node:test";

import { CHART_WINDOW_MS } from "./chart_window.mjs";
import { buildEventStats, trimEventTimeline } from "./event_stats.mjs";

const minute = 60 * 1000;

test("fills empty minutes between event peaks on a numeric time axis", () => {
  const now = 600 * minute;
  const stats = buildEventStats([
    { timestamp: now - 3 * minute, type: "ROUTE" },
    { timestamp: now, type: "TRAFFIC" }
  ], { now });

  assert.deepEqual(stats.timeline.map((point) => point.total), [1, 0, 0, 1]);
  assert.deepEqual(stats.timeline.map((point) => point.timestamp), [
    now - 3 * minute,
    now - 2 * minute,
    now - minute,
    now
  ]);
});

test("drops events older than five hours and preserves type counts for retained events", () => {
  const now = 10 * CHART_WINDOW_MS;
  const stats = buildEventStats([
    { timestamp: now - CHART_WINDOW_MS - 1, type: "EXPIRED" },
    { timestamp: now - minute, type: "ROUTE" },
    { timestamp: now, type: "ROUTE" }
  ], { now });

  assert.deepEqual(stats.byType, [{ name: "ROUTE", value: 2 }]);
  assert.equal(stats.timeline.length, 2);
});

test("clamps future event skew into the current minute", () => {
  const now = 800 * minute;
  const stats = buildEventStats([
    { timestamp: now + 30 * minute, type: "FUTURE" }
  ], { now });

  assert.equal(stats.timeline.length, 1);
  assert.equal(stats.timeline[0].timestamp, now);
  assert.equal(stats.timeline[0].total, 1);
});

test("keeps the partial first minute when the five-hour cutoff falls inside its bucket", () => {
  const now = 900 * minute + 30_000;
  const stats = buildEventStats([
    { timestamp: now - CHART_WINDOW_MS, type: "BOUNDARY" }
  ], { now });
  const visible = trimEventTimeline(stats.timeline, {
    now,
    windowMs: CHART_WINDOW_MS,
    maxPoints: 301
  });

  assert.equal(visible.length, 301);
  assert.equal(visible[0].total, 1);
  assert.deepEqual(stats.byType, [{ name: "BOUNDARY", value: 1 }]);
});
