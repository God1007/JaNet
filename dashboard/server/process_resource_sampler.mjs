// Dashboard BFF 进程资源采样器：用累计 CPU 差分和瞬时内存/调度数据量化自身开销。

import fs from "node:fs";
import os from "node:os";
import process from "node:process";
import { execFile } from "node:child_process";
import { performance } from "node:perf_hooks";

function finiteOrNull(value) {
  // Number(null) 和 Number("") 都是 0；这里的空值表示“平台未提供”，不能伪装成真实零值。
  if (value === null || value === undefined || value === "") return null;
  const number = Number(value);
  return Number.isFinite(number) && number >= 0 ? number : null;
}

// readdir 会临时打开目录；随后逐个 fstat，只统计读取结束后仍属于进程的真实 fd。
export function countOpenFileDescriptors(readdir = fs.readdirSync, fstat = fs.fstatSync) {
  for (const directory of ["/proc/self/fd", "/dev/fd"]) {
    try {
      return readdir(directory)
        .filter((entry) => /^\d+$/.test(entry))
        .filter((entry) => {
          try {
            fstat(Number(entry));
            return true;
          } catch {
            // readdir 自身的目录 fd 已在返回前关闭，不应计入结果。
            return false;
          }
        }).length;
    } catch {
      // 当前平台没有这个伪文件系统时继续尝试下一种来源。
    }
  }
  return null;
}

// Linux 直接读取 /proc，不创建子进程；其他平台由异步刷新器提供缓存值。
export function readProcessThreadCount({
  platform = process.platform,
  readFile = fs.readFileSync
} = {}) {
  if (platform === "linux") {
    try {
      const status = readFile("/proc/self/status", "utf8");
      const match = status.match(/^Threads:\s+(\d+)$/m);
      return match ? Number(match[1]) : null;
    } catch {
      return null;
    }
  }

  return null;
}

export function parseDarwinThreadCount(output) {
  const rows = String(output || "").split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
  return rows.length > 1 ? rows.length - 1 : null;
}

// macOS 的 ps 查询放到事件循环之外执行；sample() 始终只读取上一次完成的结果。
export function readDarwinProcessThreadCount({
  run = execFile,
  pid = process.pid
} = {}) {
  return new Promise((resolve) => {
    run("/bin/ps", ["-M", "-p", String(pid)], {
      encoding: "utf8",
      timeout: 1000
    }, (error, stdout) => {
      resolve(error ? null : parseDarwinThreadCount(stdout));
    });
  });
}

// 依赖均可注入，单元测试可以锁定 CPU 差分、缺失字段和线程缓存语义。
export function createProcessResourceSampler({
  clock = () => performance.now(),
  wallClock = () => Date.now(),
  cpuUsage = () => process.cpuUsage(),
  memoryUsage = () => process.memoryUsage(),
  resourceUsage = () => process.resourceUsage(),
  uptime = () => process.uptime(),
  activeResources = () => process.getActiveResourcesInfo?.() ?? [],
  logicalCpuCount = () => os.availableParallelism?.() ?? os.cpus().length,
  openFdCount = () => countOpenFileDescriptors(),
  threadCount,
  threadCountAsync,
  platform = process.platform,
  threadRefreshMs = 60_000,
  minimumCpuWindowMs = 100
} = {}) {
  let previousAt = clock();
  let previousCpu = cpuUsage();
  let cachedThreadCount = null;
  let threadCountSampledAt = Number.NEGATIVE_INFINITY;
  let threadRefreshPending = false;

  const synchronousThreadCount = typeof threadCount === "function"
    ? threadCount
    : platform === "linux"
      ? () => readProcessThreadCount({ platform })
      : null;
  const asynchronousThreadCount = typeof threadCountAsync === "function"
    ? threadCountAsync
    : platform === "darwin"
      ? () => readDarwinProcessThreadCount()
      : null;

  return {
    sample() {
      const sampledAt = wallClock();
      const currentAt = clock();
      const currentCpu = cpuUsage();
      const windowMs = Math.max(0, currentAt - previousAt);
      const userDeltaMicros = Math.max(0, currentCpu.user - previousCpu.user);
      const systemDeltaMicros = Math.max(0, currentCpu.system - previousCpu.system);
      const cpuPercent = windowMs >= minimumCpuWindowMs
        ? ((userDeltaMicros + systemDeltaMicros) / (windowMs * 1000)) * 100
        : null;
      // 极短调用不移动累计基线，下一次正常窗口仍包含这段 CPU，而不是持续得到噪声或空值。
      if (windowMs >= minimumCpuWindowMs) {
        previousAt = currentAt;
        previousCpu = currentCpu;
      }

      if (currentAt - threadCountSampledAt >= threadRefreshMs) {
        threadCountSampledAt = currentAt;
        if (synchronousThreadCount) {
          cachedThreadCount = finiteOrNull(synchronousThreadCount());
        } else if (asynchronousThreadCount && !threadRefreshPending) {
          threadRefreshPending = true;
          Promise.resolve(asynchronousThreadCount())
            .then((value) => {
              cachedThreadCount = finiteOrNull(value);
            })
            .catch(() => {
              cachedThreadCount = null;
            })
            .finally(() => {
              threadRefreshPending = false;
            });
        }
      }

      const memory = memoryUsage();
      const resources = resourceUsage();
      const unavailableMetrics = [];
      const fdCount = finiteOrNull(openFdCount());
      if (cpuPercent === null) unavailableMetrics.push("cpu_percent");
      if (cachedThreadCount === null) unavailableMetrics.push("thread_count");
      if (fdCount === null) unavailableMetrics.push("open_file_descriptors");

      return {
        component: "dashboard-bff",
        available: true,
        sampledAt,
        cpuPercent,
        userCpuSeconds: finiteOrNull(resources.userCPUTime / 1_000_000),
        systemCpuSeconds: finiteOrNull(resources.systemCPUTime / 1_000_000),
        residentMemoryBytes: finiteOrNull(memory.rss),
        peakResidentMemoryBytes: finiteOrNull(resources.maxRSS * 1024),
        virtualMemoryBytes: null,
        heapUsedBytes: finiteOrNull(memory.heapUsed),
        heapTotalBytes: finiteOrNull(memory.heapTotal),
        externalMemoryBytes: finiteOrNull(memory.external),
        arrayBufferBytes: finiteOrNull(memory.arrayBuffers),
        threadCount: cachedThreadCount,
        openFileDescriptors: fdCount,
        activeResources: activeResources().length,
        uptimeSeconds: finiteOrNull(uptime()),
        voluntaryContextSwitches: finiteOrNull(resources.voluntaryContextSwitches),
        involuntaryContextSwitches: finiteOrNull(resources.involuntaryContextSwitches),
        minorPageFaults: finiteOrNull(resources.minorPageFault),
        majorPageFaults: finiteOrNull(resources.majorPageFault),
        sampleWindowMs: windowMs,
        logicalCpuCount: Math.max(1, Math.trunc(finiteOrNull(logicalCpuCount()) ?? 1)),
        unavailableMetrics
      };
    }
  };
}
