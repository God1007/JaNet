// Node 内建测试：锁定 BFF CPU 差分、资源字段和平台降级语义。

import assert from "node:assert/strict";
import test from "node:test";

import {
  countOpenFileDescriptors,
  createProcessResourceSampler,
  parseDarwinThreadCount,
  readDarwinProcessThreadCount,
  readProcessThreadCount
} from "./process_resource_sampler.mjs";

test("process sampler converts cumulative CPU into one-core percentage", () => {
  const clocks = [1000, 2000];
  const cpus = [
    { user: 1_000_000, system: 500_000 },
    { user: 1_200_000, system: 600_000 }
  ];
  const sampler = createProcessResourceSampler({
    clock: () => clocks.shift(),
    wallClock: () => 1234,
    cpuUsage: () => cpus.shift(),
    memoryUsage: () => ({ rss: 100, heapUsed: 50, heapTotal: 80, external: 10, arrayBuffers: 2 }),
    resourceUsage: () => ({
      userCPUTime: 1_200_000,
      systemCPUTime: 600_000,
      maxRSS: 2,
      voluntaryContextSwitches: 4,
      involuntaryContextSwitches: 3,
      minorPageFault: 9,
      majorPageFault: 1
    }),
    uptime: () => 12,
    activeResources: () => ["Timer"],
    logicalCpuCount: () => 8,
    openFdCount: () => 7,
    threadCount: () => 5
  });

  const sample = sampler.sample();
  assert.equal(sample.cpuPercent, 30);
  assert.equal(sample.sampleWindowMs, 1000);
  assert.equal(sample.userCpuSeconds, 1.2);
  assert.equal(sample.systemCpuSeconds, 0.6);
  assert.equal(sample.peakResidentMemoryBytes, 2048);
  assert.equal(sample.threadCount, 5);
  assert.equal(sample.openFileDescriptors, 7);
  assert.deepEqual(sample.unavailableMetrics, []);
});

test("process sampler reports unavailable optional platform metrics", () => {
  const clocks = [10, 10];
  const cpus = [{ user: 0, system: 0 }, { user: 0, system: 0 }];
  const sampler = createProcessResourceSampler({
    clock: () => clocks.shift(),
    cpuUsage: () => cpus.shift(),
    memoryUsage: () => ({ rss: 1, heapUsed: 1, heapTotal: 1, external: 0, arrayBuffers: 0 }),
    resourceUsage: () => ({
      userCPUTime: 0,
      systemCPUTime: 0,
      maxRSS: 1,
      voluntaryContextSwitches: 0,
      involuntaryContextSwitches: 0,
      minorPageFault: 0,
      majorPageFault: 0
    }),
    openFdCount: () => null,
    threadCount: () => null
  });

  const sample = sampler.sample();
  assert.equal(sample.cpuPercent, null);
  assert.deepEqual(sample.unavailableMetrics.sort(), [
    "cpu_percent",
    "open_file_descriptors",
    "thread_count"
  ]);
});

test("fd and Linux thread helpers parse only authoritative numeric entries", () => {
  assert.equal(countOpenFileDescriptors(
    () => ["0", "1", "2", "9", "self", "."],
    (fd) => {
      if (fd === 9) throw new Error("directory fd already closed");
      return {};
    }
  ), 3);
  assert.equal(readProcessThreadCount({
    platform: "linux",
    readFile: () => "Name:\tnode\nThreads:\t11\n"
  }), 11);
  assert.equal(parseDarwinThreadCount("PID THREAD\n1 main\n1 worker\n"), 2);
});

test("Darwin thread sampling completes asynchronously", async () => {
  const count = await readDarwinProcessThreadCount({
    pid: 7,
    run: (_file, args, _options, callback) => {
      assert.deepEqual(args, ["-M", "-p", "7"]);
      queueMicrotask(() => callback(null, "PID THREAD\n7 main\n7 worker\n"));
    }
  });
  assert.equal(count, 2);
});

test("short CPU windows keep the prior baseline for the next stable sample", () => {
  const clocks = [0, 10, 120];
  const cpus = [
    { user: 0, system: 0 },
    { user: 10_000, system: 0 },
    { user: 120_000, system: 0 }
  ];
  const sampler = createProcessResourceSampler({
    clock: () => clocks.shift(),
    cpuUsage: () => cpus.shift(),
    memoryUsage: () => ({ rss: 1, heapUsed: 1, heapTotal: 1, external: 0, arrayBuffers: 0 }),
    resourceUsage: () => ({
      userCPUTime: 0,
      systemCPUTime: 0,
      maxRSS: 1,
      voluntaryContextSwitches: 0,
      involuntaryContextSwitches: 0,
      minorPageFault: 0,
      majorPageFault: 0
    }),
    threadCount: () => 1,
    openFdCount: () => 1
  });

  assert.equal(sampler.sample().cpuPercent, null);
  assert.equal(sampler.sample().cpuPercent, 100);
});
