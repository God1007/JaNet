// Dashboard 前端数据契约：描述 Node BFF 返回的事件、探测、健康状态和完整快照。

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

export type TrafficObservationEvent = {
  type: string;
  reason: number;
  socketCookie: string;
  flowKey: string;
  description: string;
  timestampUnixMs: number;
  generation: number;
  anomalyType: string;
  severity: number;
};

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
  lruInsertAttempts: number;
  protectedInsertAttempts: number;
  interfaceInsertAttempts: number;
  eventsEmitted: number;
  userEventsTruncated: number;
  kernelCounters: number[];
  [key: string]: number | boolean | number[];
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
    baseUrl: string;
    model: string;
  };
  interfaces: string[];
  networkSnapshot: null | {
    observedAt: number;
    activeInterface: string;
    trafficObservation: {
      valid: boolean;
      generation: number;
      captureComplete: boolean;
      captureCompleteness: string;
      mapReadComplete: boolean;
      baselineOnly: boolean;
      mapObservability: TrafficMapObservability;
      recentEvents: TrafficObservationEvent[];
      [key: string]: unknown;
    };
    [key: string]: unknown;
  };
  health: HealthInfo;
  pings: PingResult[];
  latencySeries: Array<{
    time: string;
    target: string;
    latencyMs: number | null;
    success: boolean;
  }>;
  events: NetworkEvent[];
  eventStats: {
    byType: Array<{ name: string; value: number }>;
    timeline: Array<Record<string, string | number>>;
  };
};
