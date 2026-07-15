// Node 内建测试：锁定 Engine proto3 缺省语义、单位换算和双进程内存汇总。

import assert from "node:assert/strict";
import test from "node:test";

import {
  buildRuntimeResources,
  normalizeEngineProcessResources
} from "./process_resource_contract.mjs";

test("engine resource contract honors unavailable metrics instead of proto zero values", () => {
  const resources = normalizeEngineProcessResources({
    sampledAtUnixMs: "1700000000000",
    sampleWindowMs: "1000",
    cpuPercent: 0,
    userCpuTimeMicros: "2500000",
    systemCpuTimeMicros: "500000",
    rssBytes: "4096",
    peakRssBytes: "8192",
    virtualMemoryBytes: "16384",
    threadCount: 7,
    openFdCount: 0,
    uptimeSeconds: 15,
    voluntaryContextSwitches: "12",
    involuntaryContextSwitches: "2",
    logicalCpuCount: 4,
    unavailableMetrics: ["cpu_percent", "open_fd_count"]
  });

  assert.equal(resources.available, true);
  assert.equal(resources.cpuPercent, null);
  assert.equal(resources.openFileDescriptors, null);
  assert.equal(resources.userCpuSeconds, 2.5);
  assert.equal(resources.systemCpuSeconds, 0.5);
  assert.equal(resources.residentMemoryBytes, 4096);
  assert.equal(resources.threadCount, 7);
});

test("missing resource message stays explicitly unavailable", () => {
  const resources = normalizeEngineProcessResources(null);
  assert.equal(resources.available, false);
  assert.equal(resources.residentMemoryBytes, null);
  assert.deepEqual(resources.unavailableMetrics, ["process_resource_snapshot"]);
});

test("runtime resource summary combines only available resident memory samples", () => {
  const engine = normalizeEngineProcessResources({
    sampledAtUnixMs: 100,
    rssBytes: 1024,
    unavailableMetrics: ["cpu_percent"]
  });
  const dashboard = {
    component: "dashboard-bff",
    available: true,
    sampledAt: 200,
    residentMemoryBytes: 2048
  };
  const summary = buildRuntimeResources(engine, dashboard);

  assert.equal(summary.sampledAt, 200);
  assert.equal(summary.combinedResidentMemoryBytes, 3072);
  assert.equal(summary.combinedResidentMemoryComplete, true);
  assert.equal(summary.cpuSemantics, "one-logical-core-is-100-percent");
});

test("runtime summary never labels one process RSS as a complete total", () => {
  const summary = buildRuntimeResources(null, {
    component: "dashboard-bff",
    available: true,
    sampledAt: 200,
    residentMemoryBytes: 2048
  });

  assert.equal(summary.combinedResidentMemoryBytes, null);
  assert.equal(summary.combinedResidentMemoryComplete, false);
});
