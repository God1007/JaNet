// Dashboard 前端数据契约：描述 Node BFF 返回的事件、探测、健康状态和完整快照。

// GetNetworkSnapshot 中每张网卡的实时指标与可用性状态。
export type InterfaceSnapshot = {
  interfaceName: string;
  isDefaultRoute: boolean;
  interfaceType: string;
  state: string;
  usingNow: boolean;
  rttMs: number | null;
  previousRttMs: number | null;
  rttAvailability: string;
  linkQuality: string;
  rssiDbm: number | null;
  rssiAvailability: string;
  tcpRetransmissionRatePercent: number | null;
  tcpRetransmissionLevel: string;
  tcpRetransmissionAvailability: string;
  trafficBytesPerSecond: number | null;
  trafficPacketsPerSecond: number | null;
  activeFlows: number | null;
  trafficAvailability: string;
};

// 多项链路指标汇总后的质量结论；degraded 表示结论基于不完整输入。
export type NetworkQualitySummary = {
  level: string;
  score: number | null;
  issues: string[];
  degraded: boolean;
  missingMetrics: string[];
};

// eBPF/TC 流量 Map 的容量、连续性、插入路径和事件路径计数器。
export type TrafficMapObservability = {
  lruCapacity: number;
  protectedCapacity: number;
  lruEntries: number;
  protectedEntries: number;
  disappearedThisWindow: number;
  continuityLostThisWindow: number;
  counterResetsThisWindow: number;
  policyUpdateAttempts: number;
  policyUpdateFailures: number;
  readComplete: boolean;
  lookupMisses: number;
  duplicateKeys: number;
  readError: number;
  lruInsertFailures: number;
  protectedInsertFailures: number;
  interfaceInsertFailures: number;
  eventDrops: number;
  packetsSeen: number;
  interfaceRejected: number;
  parseFailures: number;
  lruLookupMisses: number;
  lruInsertAttempts: number;
  lruInsertSuccesses: number;
  protectedHits: number;
  protectedInsertAttempts: number;
  protectedInsertSuccesses: number;
  interfaceInsertAttempts: number;
  eventsEmitted: number;
  userEventsTruncated: number;
  kernelCounters: number[];
};

// 快照或实时 NetworkEvent 中复用的流量异常载荷。
export type TrafficObservationEvent = {
  type: string;
  reason: number;
  // protobuf uint64 以字符串保存，避免超过 JavaScript 安全整数后丢精度。
  socketCookie: string;
  flowKey: string;
  description: string;
  timestampUnixMs: number;
  generation: number;
  anomalyType: string;
  severity: number;
};

// 当前流量采集器的装载、挂载、协议覆盖和 Map 读取完整性。
export type TrafficObservationStatus = {
  availability: string;
  valid: boolean;
  generation: number;
  sampledAt: number;
  boundIfindex: number;
  captureMode: string;
  degradedReason: string;
  libbpfAvailable: boolean;
  bpfLoaded: boolean;
  tcIngressAttached: boolean;
  tcEgressAttached: boolean;
  tcpKprobeAttached: boolean;
  udpKprobeAttached: boolean;
  sockDiagAvailable: boolean;
  sockDiagIpv4Available: boolean;
  sockDiagIpv6Available: boolean;
  procOwnerResolution: boolean;
  ipv4Supported: boolean;
  ipv6Supported: boolean;
  ipv6ExtensionHeadersSupported: boolean;
  bidirectional: boolean;
  udpInterfaceReliable: boolean;
  sockDiagStatus: string;
  coverageLimitations: string;
  captureComplete: boolean;
  captureCompleteness: string;
  mapReadComplete: boolean;
  baselineOnly: boolean;
  mapObservability: TrafficMapObservability;
  recentEvents: TrafficObservationEvent[];
};

// 单个常驻进程的一次资源快照。所有可缺失指标都用 null 表达，避免把平台不支持误报为 0。
export type ProcessResourceMetrics = {
  component: string;
  available: boolean;
  sampledAt: number;
  cpuPercent: number | null;
  userCpuSeconds: number | null;
  systemCpuSeconds: number | null;
  residentMemoryBytes: number | null;
  peakResidentMemoryBytes: number | null;
  virtualMemoryBytes: number | null;
  heapUsedBytes: number | null;
  heapTotalBytes: number | null;
  externalMemoryBytes: number | null;
  arrayBufferBytes: number | null;
  threadCount: number | null;
  openFileDescriptors: number | null;
  activeResources: number | null;
  uptimeSeconds: number | null;
  voluntaryContextSwitches: number | null;
  involuntaryContextSwitches: number | null;
  minorPageFaults: number | null;
  majorPageFaults: number | null;
  sampleWindowMs: number | null;
  logicalCpuCount: number | null;
  unavailableMetrics: string[];
};

// BFF 把 Linux engine 与本地 Dashboard 进程的采样合并，供同一时间轴比较开销。
export type RuntimeResources = {
  sampledAt: number;
  cpuSemantics: string;
  combinedResidentMemoryBytes: number | null;
  combinedResidentMemoryComplete: boolean;
  engine: ProcessResourceMetrics | null;
  dashboard: ProcessResourceMetrics | null;
};

// Node BFF 对 GetNetworkSnapshot 的稳定规范化结果。
export type NetworkSnapshot = {
  observedAt: number;
  hasActiveInterface: boolean;
  activeInterface: string;
  previousActiveInterface: string;
  defaultRouteChanged: boolean;
  routeGeneration: number;
  routeChangedAtUnixMs: number;
  currentDefaultRouteInterface: string;
  interfaces: InterfaceSnapshot[];
  quality: NetworkQualitySummary;
  trafficObservation: TrafficObservationStatus;
  engineResources: ProcessResourceMetrics | null;
};

// 资源趋势图的一次浏览器本地采样；null 会在图中保留为缺口而不是伪造零值。
export type ResourceSample = {
  timestamp: number;
  time: string;
  engineCpuPercent: number | null;
  dashboardCpuPercent: number | null;
  engineResidentMemoryBytes: number | null;
  dashboardResidentMemoryBytes: number | null;
  combinedResidentMemoryBytes: number | null;
};

// 流量趋势图的一次采样；累计计数器同时支持展示窗口增量。
export type TrafficSample = {
  timestamp: number;
  time: string;
  generation: number;
  interfaceName: string;
  bytesPerSecond: number | null;
  packetsPerSecond: number | null;
  activeFlows: number | null;
  packetsSeen: number;
  eventDrops: number;
  parseFailures: number;
  continuityLost: number;
  counterResets: number;
};

// 经 Node 规范化后供 WebSocket、时间线和统计图共用的事件模型。
export type NetworkEvent = {
  id: string;
  type: string;
  message: string;
  source: string;
  details: string;
  counter: number;
  priority: number;
  timestamp: number;
  trafficObservation: TrafficObservationEvent | null;
};

// 单次 Ping RPC 在前端使用的统一成功/失败结果。
export type PingResult = {
  target: string;
  timestamp: number;
  success: boolean;
  latencyMs: number | null;
  interfaceName: string;
  result: string;
  error: string;
};

// HealthCheck.details 解析后的原文、结构化字段和派生质量等级。
export type HealthInfo = {
  raw: string;
  parsed: Record<string, unknown> | null;
  score: number | null;
  level: string;
  issues: string[];
  degraded: boolean;
  missingMetrics: string[];
};

// Chrome webRequest 终态分为收到 HTTP 响应和浏览器网络错误；后者没有 HTTP 状态码。
export type RequestFailureCategory =
  | "http"
  | "dns"
  | "tls"
  | "connection"
  | "network"
  | "cancelled"
  | "policy";

export type RequestFailureEvent = {
  eventId: string;
  occurredAt: number;
  receivedAt: number;
  timestampAdjusted?: boolean;
  timestampTrusted?: boolean;
  staleBacklog?: boolean;
  terminal: "completed" | "error";
  scheme: "http" | "https";
  host: string;
  port: string;
  safeUrl: string;
  method: string;
  resourceType: string;
  serverIp: string | null;
  fromCache: boolean;
  statusCode: number | null;
  failureCode: string;
  networkError: string | null;
  category: RequestFailureCategory;
  classificationAlertEligible?: boolean;
  alertEligible: boolean;
  alertEligibilityReason?: "eligible" | "classification_filtered" | "stale_backlog" | "untrusted_timestamp";
};

export type RequestFailureAlert = {
  id: string;
  state: "firing" | "resolved";
  host: string;
  failureCode: string;
  statusCode: number | null;
  networkError: string | null;
  category: RequestFailureCategory;
  threshold: number;
  windowSeconds: number;
  startedAt: number;
  lastSeenAt: number;
  countInWindow: number;
  lastIp: string | null;
  resourceType: string;
  resolvedAt?: number;
};

export type RequestFailureValueCount = {
  value: string;
  count: number;
  lastSeenAt: number;
};

export type RequestFailureGroup = {
  host: string;
  failureCode: string;
  statusCode: number | null;
  networkError: string | null;
  category: RequestFailureCategory;
  alertEligible: boolean;
  totalCount: number;
  countInWindow: number;
  alertEligibleCountInWindow: number;
  windowCountCapped: boolean;
  windowOverflowCount: number;
  ipEvictions: number;
  firstSeenAt: number;
  lastSeenAt: number;
  lastOccurredAt: number;
  lastFailure: RequestFailureEvent;
  ips: RequestFailureValueCount[];
  resourceTypes: RequestFailureValueCount[];
  activeAlert: RequestFailureAlert | null;
};

// BFF 仅保留有界的近期失败、分组和告警转换；浏览器不再复制一份长期历史。
export type RequestFailureSnapshot = {
  enabled: boolean;
  source: string;
  lastReceivedAt: number;
  lastHeartbeatAt: number;
  lastContactAt: number;
  connectedRecent: boolean;
  totalFailures: number;
  windowSeconds: number;
  threshold: number;
  failuresInWindow: number;
  failuresInWindowCapped?: boolean;
  failuresInWindowOverflow?: number;
  activeAlerts: RequestFailureAlert[];
  recentFailures: RequestFailureEvent[];
  byHost: Array<{
    host: string;
    totalCount: number;
    countInWindow: number;
    activeAlerts: number;
    lastSeenAt: number;
  }>;
  byFailureCode: Array<{
    failureCode: string;
    category: RequestFailureCategory;
    totalCount: number;
    countInWindow: number;
    activeAlerts: number;
    lastSeenAt: number;
  }>;
  groups: RequestFailureGroup[];
  alertTransitions: RequestFailureAlert[];
  stats: {
    duplicates: number;
    rejected: number;
    clientDropped: number;
    groupEvictions: number;
    recentSize: number;
    groupSize: number;
    dedupeSize: number;
  };
};

export type EventTimelinePoint = {
  timestamp: number;
  time: string;
  total: number;
  [eventType: string]: string | number;
};

// `/api/snapshot` 的完整响应，也是页面各状态卡片和图表的唯一基线。
export type Snapshot = {
  generatedAt: number;
  grpcAddress: string;
  grpc: {
    ok: boolean;
    errors: string[];
  };
  stream: {
    connected: boolean;
    error: string;
    startedAt: number;
  };
  ai: {
    configured: boolean;
    provider: string;
    generationProvider: string;
    baseUrl: string;
    model: string;
    bridgePath: string;
  };
  interfaces: string[];
  networkSnapshot: NetworkSnapshot | null;
  runtimeResources: RuntimeResources | null;
  requestFailures: RequestFailureSnapshot | null;
  health: HealthInfo;
  pings: PingResult[];
  latencySeries: Array<{
    timestamp: number;
    time: string;
    target: string;
    latencyMs: number | null;
    success: boolean;
  }>;
  events: NetworkEvent[];
  eventStats: {
    byType: Array<{ name: string; value: number }>;
    timeline: EventTimelinePoint[];
  };
};
