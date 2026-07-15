// Probe Rhythm 数据适配单测：覆盖多目标隔离、失败空值、安全 key 与时间排序。

import assert from "node:assert/strict";
import test from "node:test";

import { buildProbeRhythm } from "./latency_series.mjs";

test("isolates multiple targets behind safe data keys and sorts numeric timestamps", () => {
  const rhythm = buildProbeRhythm([
    { timestamp: 3000, target: "8.8.8.8", latencyMs: 31, success: true },
    { timestamp: 1000, target: "baidu.com", latencyMs: 12, success: true },
    { timestamp: 2000, target: "8.8.8.8", latencyMs: 25, success: true }
  ]);

  assert.deepEqual(rhythm.points.map((point) => point.timestamp), [1000, 2000, 3000]);
  assert.equal(rhythm.series.length, 2);

  const dns = rhythm.series.find((item) => item.target === "8.8.8.8");
  const baidu = rhythm.series.find((item) => item.target === "baidu.com");
  assert.match(dns.key, /^probe_\d+$/);
  assert.match(baidu.key, /^probe_\d+$/);
  assert.notEqual(dns.key, baidu.key);
  assert.notEqual(dns.key, dns.target);
  assert.equal(rhythm.points[0][baidu.key], 12);
  assert.equal(rhythm.points[0][dns.key], undefined);
  assert.equal(rhythm.points[1][dns.key], 25);
  assert.equal(rhythm.points[2][dns.key], 31);
});

test("keeps failed probes null and reports per-target success and failure counts", () => {
  const rhythm = buildProbeRhythm([
    { timestamp: 1000, target: "127.0.0.1", latencyMs: 0, success: true },
    { timestamp: 2000, target: "127.0.0.1", latencyMs: 999, success: false },
    { timestamp: 3000, target: "127.0.0.1", latencyMs: 4, success: true }
  ]);
  const local = rhythm.series[0];

  assert.deepEqual(
    { successes: local.successes, failures: local.failures },
    { successes: 2, failures: 1 }
  );
  assert.equal(rhythm.points[0][local.key], 0);
  assert.equal(rhythm.points[1][local.key], null);
  assert.equal(rhythm.points[2][local.key], 4);
});

test("normalizes invalid successful latency values to null without losing the samples", () => {
  const rhythm = buildProbeRhythm([
    { timestamp: 1000, target: "probe.test", latencyMs: Number.NaN, success: true },
    { timestamp: 2000, target: "probe.test", latencyMs: -1, success: true },
    { timestamp: 3000, target: "probe.test", latencyMs: Number.POSITIVE_INFINITY, success: true },
    { timestamp: 4000, target: "probe.test", latencyMs: "7.5", success: true }
  ]);
  const series = rhythm.series[0];

  assert.deepEqual(
    rhythm.points.map((point) => point[series.key]),
    [null, null, null, 7.5]
  );
  assert.equal(series.successes, 4);
  assert.equal(series.failures, 0);
});

test("merges targets sampled at the same millisecond and ignores unusable axis rows", () => {
  const rhythm = buildProbeRhythm([
    { timestamp: 1000, target: "one.test", latencyMs: 10, success: true },
    { timestamp: 1000, target: "two.test", latencyMs: 20, success: true },
    { timestamp: "invalid", target: "one.test", latencyMs: 30, success: true },
    { timestamp: 2000, target: "", latencyMs: 40, success: true }
  ]);
  const one = rhythm.series.find((item) => item.target === "one.test");
  const two = rhythm.series.find((item) => item.target === "two.test");

  assert.equal(rhythm.points.length, 1);
  assert.equal(rhythm.points[0].timestamp, 1000);
  assert.equal(rhythm.points[0][one.key], 10);
  assert.equal(rhythm.points[0][two.key], 20);
  assert.equal(one.successes, 1);
  assert.equal(two.successes, 1);
});

test("returns empty collections for missing input", () => {
  assert.deepEqual(buildProbeRhythm(null), { points: [], series: [] });
  assert.deepEqual(buildProbeRhythm([]), { points: [], series: [] });
});
