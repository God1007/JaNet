// 曲线窗口单测：验证 5 小时 TTL、边界点、点数保险丝和输入不可变性。

import assert from "node:assert/strict";
import test from "node:test";

import {
  CHART_WINDOW_MS,
  trimChartWindow
} from "./chart_window.mjs";

test("keeps only samples inside the five-hour window including the cutoff", () => {
  const now = 10 * CHART_WINDOW_MS;
  const input = [
    { timestamp: now - CHART_WINDOW_MS - 1, value: "expired" },
    { timestamp: now - CHART_WINDOW_MS, value: "boundary" },
    { timestamp: now, value: "latest" }
  ];

  const result = trimChartWindow(input, { now });

  assert.deepEqual(result.map((item) => item.value), ["boundary", "latest"]);
  assert.equal(input.length, 3);
});

test("uses a maximum point count as a fail-safe without changing order", () => {
  const input = Array.from({ length: 8 }, (_, index) => ({ timestamp: 1000 + index, index }));
  const result = trimChartWindow(input, { now: 2000, windowMs: 5000, maxPoints: 3 });

  assert.deepEqual(result.map((item) => item.index), [5, 6, 7]);
});

test("supports custom timestamp fields and drops unusable axis rows", () => {
  const input = [
    { sampledAt: 1000, value: 1 },
    { sampledAt: "invalid", value: 2 },
    { sampledAt: 2000, value: 3 }
  ];
  const result = trimChartWindow(input, {
    now: 2500,
    windowMs: 2000,
    getTimestamp: (item) => item.sampledAt
  });

  assert.deepEqual(result.map((item) => item.value), [1, 3]);
});
