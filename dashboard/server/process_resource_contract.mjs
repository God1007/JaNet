// 资源契约适配层：把 Engine protobuf 数值规范化为与 Dashboard BFF 一致的进程资源模型。

function finiteOrNull(value) {
  if (value === null || value === undefined || value === "") return null;
  const number = Number(value);
  return Number.isFinite(number) && number >= 0 ? number : null;
}

function unavailableProcessResources(component) {
  return {
    component,
    available: false,
    sampledAt: 0,
    cpuPercent: null,
    userCpuSeconds: null,
    systemCpuSeconds: null,
    residentMemoryBytes: null,
    peakResidentMemoryBytes: null,
    virtualMemoryBytes: null,
    heapUsedBytes: null,
    heapTotalBytes: null,
    externalMemoryBytes: null,
    arrayBufferBytes: null,
    threadCount: null,
    openFileDescriptors: null,
    activeResources: null,
    uptimeSeconds: null,
    voluntaryContextSwitches: null,
    involuntaryContextSwitches: null,
    minorPageFaults: null,
    majorPageFaults: null,
    sampleWindowMs: null,
    logicalCpuCount: null,
    unavailableMetrics: ["process_resource_snapshot"]
  };
}

// proto3 标量缺省值都是 0；只有 sampled_at 和 unavailable_metrics 一起才能区分真实零与未采集。
export function normalizeEngineProcessResources(raw) {
  const sampledAt = finiteOrNull(raw?.sampledAtUnixMs) ?? 0;
  if (!raw || sampledAt <= 0) {
    return unavailableProcessResources("linux-engine");
  }

  const unavailableMetrics = Array.isArray(raw.unavailableMetrics)
    ? raw.unavailableMetrics.map(String)
    : [];
  const unavailable = new Set(unavailableMetrics);
  const metric = (property, unavailableName, scale = 1) => {
    if (unavailable.has(unavailableName)) return null;
    const value = finiteOrNull(raw[property]);
    return value === null ? null : value * scale;
  };

  return {
    component: "linux-engine",
    available: true,
    sampledAt,
    cpuPercent: metric("cpuPercent", "cpu_percent"),
    userCpuSeconds: metric("userCpuTimeMicros", "user_cpu_time_micros", 1 / 1_000_000),
    systemCpuSeconds: metric("systemCpuTimeMicros", "system_cpu_time_micros", 1 / 1_000_000),
    residentMemoryBytes: metric("rssBytes", "rss_bytes"),
    peakResidentMemoryBytes: metric("peakRssBytes", "peak_rss_bytes"),
    virtualMemoryBytes: metric("virtualMemoryBytes", "virtual_memory_bytes"),
    // 原生 Engine 没有 JavaScript heap 概念；这些字段只由 BFF 提供。
    heapUsedBytes: null,
    heapTotalBytes: null,
    externalMemoryBytes: null,
    arrayBufferBytes: null,
    threadCount: metric("threadCount", "thread_count"),
    openFileDescriptors: metric("openFdCount", "open_fd_count"),
    activeResources: null,
    uptimeSeconds: metric("uptimeSeconds", "uptime_seconds"),
    voluntaryContextSwitches: metric(
      "voluntaryContextSwitches",
      "voluntary_context_switches"
    ),
    involuntaryContextSwitches: metric(
      "involuntaryContextSwitches",
      "involuntary_context_switches"
    ),
    minorPageFaults: null,
    majorPageFaults: null,
    sampleWindowMs: metric("sampleWindowMs", "cpu_percent"),
    logicalCpuCount: metric("logicalCpuCount", "logical_cpu_count"),
    unavailableMetrics
  };
}

// 顶层摘要保留两个进程各自的调度语义，同时给出当前可量化的合计常驻内存。
export function buildRuntimeResources(engine, dashboard) {
  const normalizedEngine = engine ?? unavailableProcessResources("linux-engine");
  const normalizedDashboard = dashboard ?? unavailableProcessResources("dashboard-bff");
  const engineResident = normalizedEngine.available
    ? finiteOrNull(normalizedEngine.residentMemoryBytes)
    : null;
  const dashboardResident = normalizedDashboard.available
    ? finiteOrNull(normalizedDashboard.residentMemoryBytes)
    : null;
  const combinedResidentMemoryComplete = engineResident !== null && dashboardResident !== null;

  return {
    sampledAt: Math.max(
      finiteOrNull(normalizedEngine.sampledAt) ?? 0,
      finiteOrNull(normalizedDashboard.sampledAt) ?? 0
    ),
    cpuSemantics: "one-logical-core-is-100-percent",
    // 合计只在两侧样本都有效时成立；部分值不能冒充整个 JaNet 的常驻内存。
    combinedResidentMemoryBytes: combinedResidentMemoryComplete
      ? engineResident + dashboardResident
      : null,
    combinedResidentMemoryComplete,
    engine: normalizedEngine,
    dashboard: normalizedDashboard
  };
}
