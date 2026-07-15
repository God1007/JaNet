// 资源趋势纯函数单测：覆盖合法零值、缺失语义、同刻替换与 72 点上限。

import assert from "node:assert/strict";
import test from "node:test";

import {
  RESOURCE_HISTORY_LIMIT,
  appendResourceSample,
  createResourceSample,
  formatResourceBytes,
  formatUptime
} from "./resource_metrics.mjs";

function processMetrics(component, overrides = {}) {
  return {
    component,
    available: true,
    sampledAt: 1000,
    cpuPercent: 0,
    residentMemoryBytes: 0,
    ...overrides
  };
}

function sample(timestamp, overrides = {}) {
  return {
    timestamp,
    time: `t${timestamp}`,
    engineCpuPercent: 1,
    dashboardCpuPercent: 2,
    engineResidentMemoryBytes: 3,
    dashboardResidentMemoryBytes: 4,
    combinedResidentMemoryBytes: 7,
    ...overrides
  };
}

test("builds one sample without converting valid zero metrics to missing", () => {
  const result = createResourceSample({
    sampledAt: 2000,
    combinedResidentMemoryBytes: 0,
    engine: processMetrics("engine", { sampledAt: 1900 }),
    dashboard: processMetrics("dashboard", { sampledAt: 2000 })
  });

  assert.equal(result.timestamp, 2000);
  assert.equal(result.engineCpuPercent, 0);
  assert.equal(result.dashboardResidentMemoryBytes, 0);
  assert.equal(result.combinedResidentMemoryBytes, 0);
});

test("keeps unavailable and malformed process metrics as null", () => {
  const result = createResourceSample({
    sampledAt: 2000,
    combinedResidentMemoryBytes: "invalid",
    engine: processMetrics("engine", { available: false, cpuPercent: 99 }),
    dashboard: processMetrics("dashboard", { cpuPercent: Number.NaN, residentMemoryBytes: -1 })
  });

  assert.equal(result.engineCpuPercent, null);
  assert.equal(result.dashboardCpuPercent, null);
  assert.equal(result.dashboardResidentMemoryBytes, null);
  assert.equal(result.combinedResidentMemoryBytes, null);
  assert.equal(createResourceSample(null), null);
  assert.equal(createResourceSample({ sampledAt: 0, engine: null, dashboard: null }), null);
});

test("replaces the same timestamp immutably", () => {
  const original = [sample(1), sample(2)];
  const replaced = appendResourceSample(original, sample(2, { engineCpuPercent: 8 }));

  assert.equal(original[1].engineCpuPercent, 1);
  assert.equal(replaced.length, 2);
  assert.equal(replaced[1].engineCpuPercent, 8);
});

test("retains at most 72 resource samples by default", () => {
  let history = [];
  for (let index = 1; index <= RESOURCE_HISTORY_LIMIT + 5; index += 1) {
    history = appendResourceSample(history, sample(index));
  }

  assert.equal(history.length, RESOURCE_HISTORY_LIMIT);
  assert.equal(history[0].timestamp, 6);
  assert.equal(history.at(-1).timestamp, RESOURCE_HISTORY_LIMIT + 5);
});

test("formats memory and uptime while preserving missing values", () => {
  assert.equal(formatResourceBytes(0), "0 B");
  assert.equal(formatResourceBytes(1536), "1.5 KiB");
  assert.equal(formatResourceBytes(1024 * 1024), "1 MiB");
  assert.equal(formatResourceBytes(null), "n/a");
  assert.equal(formatUptime(0), "0s");
  assert.equal(formatUptime(65), "1m 5s");
  assert.equal(formatUptime(90061), "1d 1h");
  assert.equal(formatUptime(undefined), "n/a");
});
