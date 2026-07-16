// JaNet Dashboard 主界面：把网络质量、流量采集可信度、Map 计数和诊断操作放进同一观测闭环。

import {
  Activity,
  Brain,
  Cpu,
  Database,
  Gauge,
  Globe2,
  Maximize2,
  Network,
  RefreshCw,
  Router,
  Search,
  Server,
  ShieldCheck,
  Sparkles,
  Moon,
  Sun,
  TerminalSquare,
  Wifi,
  X
} from "lucide-react";
import {
  Area,
  AreaChart,
  CartesianGrid,
  ComposedChart,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis
} from "recharts";
import { memo, startTransition, useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { CSSProperties, FormEvent, ReactNode } from "react";
import type {
  InterfaceSnapshot,
  EventTimelinePoint,
  NetworkEvent,
  PingResult,
  ProcessResourceMetrics,
  RequestFailureAlert,
  RequestFailureCategory,
  RequestFailureEvent,
  RequestFailureSnapshot,
  ResourceSample,
  Snapshot,
  TrafficMapObservability,
  TrafficSample
} from "./lib/types";
import { fetchJson, isAbortError } from "./lib/http_client.mjs";
import {
  createEventBatcher,
  mergeEventHistory,
  reconnectDelay
} from "./lib/realtime_lifecycle.mjs";
import {
  CHART_SAMPLE_LIMIT,
  CHART_WINDOW_LABEL,
  CHART_WINDOW_MS,
  trimChartWindow
} from "./lib/chart_window.mjs";
import {
  buildEventStats,
  EVENT_HISTORY_LIMIT,
  trimEventTimeline
} from "./lib/event_stats.mjs";
import { formatMilliseconds } from "./lib/rtt_format.mjs";
import {
  appendTrafficSample,
  capacityPercent,
  counterDelta,
  createTrafficSample,
  formatBytesPerSecond,
  formatCount,
  formatPacketsPerSecond,
  formatPercent
} from "./lib/traffic_metrics.mjs";
import {
  appendResourceSample,
  createResourceSample,
  formatResourceBytes,
  formatUptime
} from "./lib/resource_metrics.mjs";
import {
  PROBE_HISTORY_LIMIT,
  buildProbeRhythm,
  mergeProbeHistory
} from "./lib/latency_series.mjs";
import {
  reconcileSeriesSelection,
  toggleSeriesSelection
} from "./lib/series_selection.mjs";

const probeColors = ["var(--chart-1)", "var(--chart-2)", "var(--chart-3)", "var(--chart-4)", "var(--chart-5)"];
const trafficSeriesOptions = [
  { id: "bytesPerSecond", label: "Throughput B/s", color: "var(--chart-1)" },
  { id: "packetsPerSecond", label: "Packets/s", color: "var(--chart-2)" },
  { id: "activeFlows", label: "Active flows", color: "var(--chart-3)" }
];
const trafficSeriesIds = trafficSeriesOptions.map((option) => option.id);
const cpuSeriesOptions = [
  { id: "engineCpuPercent", label: "Engine CPU", color: "var(--chart-1)" },
  { id: "dashboardCpuPercent", label: "Dashboard CPU", color: "var(--chart-2)" }
];
const memorySeriesOptions = [
  { id: "engineResidentMemoryBytes", label: "Engine RSS", color: "var(--chart-1)" },
  { id: "dashboardResidentMemoryBytes", label: "Dashboard RSS", color: "var(--chart-2)" }
];
const cpuSeriesIds = cpuSeriesOptions.map((option) => option.id);
const memorySeriesIds = memorySeriesOptions.map((option) => option.id);
const chartRangeOptions = [
  { label: "30 min", value: 30 * 60 * 1000 },
  { label: "1 hour", value: 60 * 60 * 1000 },
  { label: "5 hours", value: CHART_WINDOW_MS }
] as const;
const requestFailureVisibleLimit = 50;
const requestAlertVisibleLimit = 12;
const chartTickOneDecimal = new Intl.NumberFormat("en-US", { maximumFractionDigits: 1 });
const chartTickTwoDecimals = new Intl.NumberFormat("en-US", { maximumFractionDigits: 2 });
const snapshotRefreshIntervalMs = 10_000;
const snapshotRequestTimeoutMs = 20_000;
const pingRequestTimeoutMs = 12_000;
const analysisRequestTimeoutMs = 35_000;
const manualPingResultLimit = 16;

// 所有趋势图共用一套紧凑 Tooltip 外观，避免 Recharts 默认的 16px 文本压过图表本身。
const chartTooltipContentStyle = {
  background: "var(--chart-tooltip-bg)",
  border: "1px solid var(--chart-tooltip-border)",
  borderRadius: 6,
  color: "var(--chart-tooltip-text)",
  padding: "7px 9px"
} satisfies CSSProperties;
const chartTooltipLabelStyle = {
  color: "var(--chart-tooltip-text)",
  marginBottom: 4
} satisfies CSSProperties;
const chartTooltipItemStyle = {
  color: "var(--chart-tooltip-text)",
  padding: "1px 0"
} satisfies CSSProperties;
const requestFailureFilters = [
  { id: "all", label: "All" },
  { id: "active", label: "Active alerts" },
  { id: "4xx", label: "4xx" },
  { id: "5xx", label: "5xx" },
  { id: "dns", label: "DNS" },
  { id: "connection", label: "Connection" },
  { id: "tls", label: "TLS" },
  { id: "network", label: "Other network" },
  { id: "cancelled-policy", label: "Cancelled / policy" }
] as const;
type RequestFailureFilter = typeof requestFailureFilters[number]["id"];
const apiBaseUrl = __API_BASE_URL__.replace(/\/$/, "");
const wsBaseUrl = __WS_BASE_URL__.replace(/\/$/, "");
type Theme = "light" | "dark";
type ExpandedChartId = "traffic" | "cpu" | "memory" | "probe" | "events";
const expandedChartTitles: Record<ExpandedChartId, string> = {
  traffic: "Live traffic",
  cpu: "CPU utilization",
  memory: "Resident memory",
  probe: "Probe rhythm",
  events: "Events per minute"
};
const expandedChartDescriptions: Record<ExpandedChartId, string> = {
  traffic: "Compare throughput, packet rate, and active flows on a real numeric time axis.",
  cpu: "Compare the network engine and Dashboard BFF CPU cost over the selected interval.",
  memory: "Inspect resident memory growth for both long-running processes.",
  probe: "Compare successful latency samples by target without converting failures into zero latency.",
  events: "Inspect continuous minute buckets; empty minutes remain zero instead of disappearing."
};

// 首屏脚本已经决定初始主题；React 直接复用，避免 hydration 后再闪一次颜色。
function initialTheme(): Theme {
  return document.documentElement.dataset.theme === "light" ? "light" : "dark";
}

// 时间戳只在展示层格式化，服务端和趋势历史始终保留毫秒精度。
function formatTime(value: number) {
  if (!Number.isFinite(value) || value <= 0) return "n/a";
  return new Date(value).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

function formatDateTime(value: number) {
  if (!Number.isFinite(value) || value <= 0) return "n/a";
  return new Date(value).toLocaleString();
}

// 图轴需要保留低占用 CPU 的差异，但不展示 0.055000% 一类无意义尾数。
function formatPercentTick(value: unknown) {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) return "n/a";
  return `${(Math.abs(numeric) < 1 ? chartTickTwoDecimals : chartTickOneDecimal).format(numeric)}%`;
}

function formatMillisecondsTick(value: unknown) {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) return "n/a";
  return `${(Math.abs(numeric) < 1 ? chartTickTwoDecimals : chartTickOneDecimal).format(numeric)}ms`;
}

function formatTrafficTooltip(value: unknown, name: unknown): [string, string] {
  const label = String(name);
  if (label === "Throughput B/s") return [formatBytesPerSecond(value), label];
  if (label === "Packets/s") return [formatPacketsPerSecond(value), label];
  return [formatCount(value), label];
}

function formatAge(value: number, now = Date.now()) {
  if (!Number.isFinite(value) || value <= 0) return "n/a";
  const seconds = Math.max(0, Math.floor((now - value) / 1000));
  if (seconds < 2) return "now";
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  return formatDateTime(value);
}

// 质量标签与服务端分值保持一一对应，同时仍单独展示 degraded 输入状态。
function scoreLabel(score: number | null) {
  if (score === null) return "No score";
  if (score >= 90) return "Excellent";
  if (score >= 75) return "Good";
  if (score >= 50) return "Fair";
  return "Poor";
}

function formatRssi(value: number | null, availability: string) {
  if (availability !== "AVAILABLE" || value === null || !Number.isFinite(value)) return "n/a";
  return `${Number.isInteger(value) ? value : value.toFixed(1)} dBm`;
}

function formatRtt(value: number | null, availability: string) {
  return availability === "AVAILABLE" ? formatMilliseconds(value) : "n/a";
}

function formatRttDelta(current: number | null, previous: number | null, availability: string) {
  if (availability !== "AVAILABLE" || current === null || previous === null) return "No previous sample";
  const delta = current - previous;
  const sign = delta > 0 ? "+" : "";
  return `${sign}${formatMilliseconds(delta)} vs previous`;
}

function availableMetric<T>(availability: string, value: T | null, formatter: (next: T) => string) {
  return availability === "AVAILABLE" && value !== null ? formatter(value) : "n/a";
}

function requestObserverState(snapshot: RequestFailureSnapshot | null) {
  if (!snapshot?.enabled) return { value: "setup", tone: "muted" as const };
  if (snapshot.connectedRecent) return { value: "live", tone: "ok" as const };
  if (snapshot && (snapshot.lastHeartbeatAt > 0 || snapshot.lastReceivedAt > 0)) {
    return { value: "offline", tone: "warn" as const };
  }
  return { value: "setup", tone: "muted" as const };
}

function requestFailureKey(host: string, failureCode: string) {
  return `${host}\u0000${failureCode}`;
}

function matchesRequestFailureFilter(
  item: Pick<RequestFailureEvent, "category" | "statusCode">,
  filter: RequestFailureFilter,
  active: boolean
) {
  if (filter === "all") return true;
  if (filter === "active") return active;
  if (filter === "4xx") return item.statusCode !== null && item.statusCode >= 400 && item.statusCode < 500;
  if (filter === "5xx") return item.statusCode !== null && item.statusCode >= 500 && item.statusCode < 600;
  if (filter === "cancelled-policy") return item.category === "cancelled" || item.category === "policy";
  return item.category === filter;
}

function requestOutcome(value: Pick<RequestFailureEvent, "statusCode" | "networkError" | "failureCode">) {
  return value.statusCode !== null
    ? `HTTP ${value.statusCode}`
    : value.networkError || value.failureCode || "Browser error";
}

function requestOutcomeTone(value: Pick<RequestFailureEvent, "statusCode" | "category">) {
  if (value.statusCode !== null && value.statusCode >= 500) return "danger";
  if (value.statusCode !== null) return "warning";
  return value.category === "cancelled" || value.category === "policy" ? "muted" : "danger";
}

function requestCategoryTone(category: RequestFailureCategory): "good" | "warning" | "danger" | "muted" {
  if (category === "http") return "warning";
  if (category === "cancelled" || category === "policy") return "muted";
  return "danger";
}

function formatWindowSeconds(seconds: number) {
  if (!Number.isFinite(seconds) || seconds <= 0) return "n/a";
  if (seconds % 60 === 0) return `${seconds / 60} min`;
  return `${seconds} sec`;
}

function formatChartSpan(items: readonly { timestamp: number }[]) {
  if (items.length < 2) return items.length === 1 ? "single sample" : "no samples";
  const first = Number(items[0]?.timestamp);
  const last = Number(items.at(-1)?.timestamp);
  const spanMs = Math.max(0, last - first);
  const minutes = Math.floor(spanMs / 60000);
  if (minutes < 1) return `${Math.max(1, Math.round(spanMs / 1000))} sec span`;
  if (minutes < 60) return `${minutes} min span`;
  const hours = Math.floor(minutes / 60);
  const remainder = minutes % 60;
  return remainder ? `${hours}h ${remainder}m span` : `${hours}h span`;
}

type EventStreamPhase = "connecting" | "live" | "recovering" | "reconnecting" | "paused" | "offline";

type EventStreamState = {
  transportConnected: boolean;
  sourceConnected: boolean;
  phase: EventStreamPhase;
  error: string;
  retryInMs: number | null;
};

// 管理浏览器到 BFF 的 WebSocket：区分传输层和上游 gRPC 状态，并在断线后自动恢复。
function useEventStream(onEvents: (events: NetworkEvent[]) => void) {
  const [state, setState] = useState<EventStreamState>({
    transportConnected: false,
    sourceConnected: false,
    phase: "connecting",
    error: "",
    retryInMs: null
  });

  useEffect(() => {
    let disposed = false;
    let socket: WebSocket | null = null;
    let retryTimer: number | null = null;
    let reconnectAttempt = 0;
    let connectionGeneration = 0;
    const eventBatcher = createEventBatcher<NetworkEvent>(onEvents, {
      delayMs: 100,
      maxBatchSize: 64
    });

    const patchState = (patch: Partial<EventStreamState>) => {
      if (!disposed) {
        setState((current) => {
          const changed = Object.entries(patch).some(([key, value]) => (
            current[key as keyof EventStreamState] !== value
          ));
          return changed ? { ...current, ...patch } : current;
        });
      }
    };

    const clearRetry = () => {
      if (retryTimer !== null) {
        window.clearTimeout(retryTimer);
        retryTimer = null;
      }
    };

    const scheduleReconnect = (message = "Event stream disconnected. Reconnecting automatically.") => {
      if (disposed || retryTimer !== null) return;
      const delay = reconnectDelay(reconnectAttempt, { jitterRatio: 0.2 });
      reconnectAttempt += 1;
      patchState({
        transportConnected: false,
        sourceConnected: false,
        phase: "reconnecting",
        error: message,
        retryInMs: delay
      });
      retryTimer = window.setTimeout(() => {
        retryTimer = null;
        connect();
      }, delay);
    };

    function connect() {
      if (disposed || socket || navigator.onLine === false || document.visibilityState === "hidden") return;
      clearRetry();
      const generation = ++connectionGeneration;
      patchState({
        transportConnected: false,
        sourceConnected: false,
        phase: "connecting",
        retryInMs: null
      });

      let nextSocket: WebSocket;
      try {
        nextSocket = new WebSocket(`${wsBaseUrl}/ws/events`);
      } catch {
        // 配置错误或 mixed-content 限制也进入同一有界退避，避免 effect 同步崩溃。
        scheduleReconnect("Dashboard cannot open the event socket. Retrying automatically.");
        return;
      }
      socket = nextSocket;

      nextSocket.onopen = () => {
        if (disposed || socket !== nextSocket || generation !== connectionGeneration) return;
        // WebSocket open 只证明页面连到 BFF；上游事件源必须等待 hello/stream 证据。
        patchState({ transportConnected: true, phase: "connecting", retryInMs: null });
      };

      nextSocket.onmessage = (message) => {
        if (disposed || socket !== nextSocket || generation !== connectionGeneration) return;
        try {
          const payload = JSON.parse(String(message.data));
          if (payload.type === "event" && payload.event) {
            eventBatcher.push(payload.event);
            // 收到真实事件本身就是上游恢复的强证据，避免状态停留在旧 offline。
            reconnectAttempt = 0;
            patchState({ sourceConnected: true, phase: "live", error: "", retryInMs: null });
          }
          if (payload.type === "hello") {
            if (Array.isArray(payload.recentEvents)) eventBatcher.pushMany(payload.recentEvents);
            const sourceConnected = Boolean(payload.stream?.connected);
            const sourceError = payload.stream?.error || "";
            reconnectAttempt = 0;
            patchState({
              transportConnected: true,
              sourceConnected,
              phase: sourceConnected ? "live" : sourceError ? "recovering" : "connecting",
              error: sourceError,
              retryInMs: null
            });
          }
          if (payload.type === "stream") {
            const sourceConnected = Boolean(payload.connected);
            patchState({
              sourceConnected,
              phase: sourceConnected ? "live" : "recovering",
              error: payload.error || "",
              retryInMs: null
            });
          }
        } catch {
          patchState({ error: "Dashboard received an invalid event payload" });
        }
      };

      nextSocket.onerror = () => {
        if (disposed || socket !== nextSocket) return;
        patchState({ error: "Dashboard event socket failed" });
        nextSocket.close();
      };

      nextSocket.onclose = () => {
        if (disposed || socket !== nextSocket || generation !== connectionGeneration) return;
        socket = null;
        if (navigator.onLine === false) {
          patchState({
            transportConnected: false,
            sourceConnected: false,
            phase: "offline",
            error: "Browser is offline. Live events will resume automatically.",
            retryInMs: null
          });
          return;
        }
        if (document.visibilityState === "hidden") {
          patchState({
            transportConnected: false,
            sourceConnected: false,
            phase: "paused",
            error: "",
            retryInMs: null
          });
          return;
        }

        scheduleReconnect();
      };
    }

    const reconnectNow = () => {
      if (disposed || navigator.onLine === false || document.visibilityState === "hidden") return;
      clearRetry();
      if (!socket || socket.readyState === WebSocket.CLOSED) {
        socket = null;
        connect();
      }
    };
    const handleOffline = () => {
      clearRetry();
      connectionGeneration += 1;
      const currentSocket = socket;
      socket = null;
      patchState({
        transportConnected: false,
        sourceConnected: false,
        phase: "offline",
        error: "Browser is offline. Live events will resume automatically.",
        retryInMs: null
      });
      currentSocket?.close();
    };
    const handleVisibility = () => {
      if (document.visibilityState === "visible") {
        reconnectNow();
        return;
      }
      clearRetry();
      eventBatcher.flush();
      connectionGeneration += 1;
      const currentSocket = socket;
      socket = null;
      patchState({
        transportConnected: false,
        sourceConnected: false,
        phase: "paused",
        error: "",
        retryInMs: null
      });
      // 隐藏标签页不消费实时事件；恢复时 hello + snapshot 会补回有界历史。
      currentSocket?.close();
    };

    window.addEventListener("online", reconnectNow);
    window.addEventListener("offline", handleOffline);
    document.addEventListener("visibilitychange", handleVisibility);
    connect();

    return () => {
      disposed = true;
      connectionGeneration += 1;
      clearRetry();
      window.removeEventListener("online", reconnectNow);
      window.removeEventListener("offline", handleOffline);
      document.removeEventListener("visibilitychange", handleVisibility);
      // effect cleanup 丢弃旧连接尚未提交的批次，避免 StrictMode/卸载阶段回写状态。
      eventBatcher.discard();
      if (socket) {
        socket.onopen = null;
        socket.onmessage = null;
        socket.onerror = null;
        socket.onclose = null;
        socket.close();
        socket = null;
      }
    };
  }, [onEvents]);

  return {
    ...state,
    connected: state.transportConnected && state.sourceConnected
  };
}

const chartCursor = {
  stroke: "var(--accent-border-strong)",
  strokeWidth: 1,
  strokeDasharray: "3 3"
};

function TrafficTrendChart({
  data,
  showThroughput,
  showPackets,
  showFlows,
  gradientId,
  expanded = false
}: {
  data: TrafficSample[];
  showThroughput: boolean;
  showPackets: boolean;
  showFlows: boolean;
  gradientId: string;
  expanded?: boolean;
}) {
  if (!data.length) return <EmptyLine text="Waiting for the first trusted traffic sample." />;
  const showCounts = showPackets || showFlows;
  return (
    <ResponsiveContainer width="100%" height="100%">
      <ComposedChart data={data} margin={{ top: 12, right: 8, bottom: 0, left: 0 }} accessibilityLayer>
        <defs>
          <linearGradient id={gradientId} x1="0" x2="0" y1="0" y2="1">
            <stop offset="4%" stopColor="var(--accent)" stopOpacity={0.28} />
            <stop offset="96%" stopColor="var(--accent)" stopOpacity={0.01} />
          </linearGradient>
        </defs>
        <CartesianGrid stroke="var(--chart-grid)" vertical={false} />
        <XAxis
          type="number"
          dataKey="timestamp"
          domain={["dataMin", "dataMax"]}
          tickFormatter={(value) => formatTime(Number(value))}
          stroke="var(--chart-axis)"
          tickLine={false}
          axisLine={false}
          minTickGap={30}
          interval="preserveStartEnd"
        />
        {showThroughput && <YAxis yAxisId="bytes" stroke="var(--chart-axis)" tickLine={false} axisLine={false} width={72} tickFormatter={(value) => formatBytesPerSecond(value)} />}
        {showCounts && <YAxis yAxisId="count" orientation="right" stroke="var(--chart-axis)" tickLine={false} axisLine={false} width={44} allowDecimals={false} />}
        <Tooltip
          formatter={formatTrafficTooltip}
          labelFormatter={(value) => formatDateTime(Number(value))}
          cursor={chartCursor}
          contentStyle={chartTooltipContentStyle}
          labelStyle={chartTooltipLabelStyle}
          itemStyle={chartTooltipItemStyle}
        />
        {showThroughput && <Area yAxisId="bytes" type="monotone" dataKey="bytesPerSecond" stroke="var(--chart-1)" fill={`url(#${gradientId})`} strokeWidth={2} activeDot={expanded ? { r: 3 } : false} name="Throughput B/s" isAnimationActive={false} />}
        {showPackets && <Line yAxisId="count" type="monotone" dataKey="packetsPerSecond" stroke="var(--chart-2)" strokeWidth={1.8} dot={false} activeDot={expanded ? { r: 3 } : false} name="Packets/s" isAnimationActive={false} />}
        {showFlows && <Line yAxisId="count" type="monotone" dataKey="activeFlows" stroke="var(--chart-3)" strokeWidth={1.8} dot={false} activeDot={expanded ? { r: 3 } : false} name="Active flows" isAnimationActive={false} />}
      </ComposedChart>
    </ResponsiveContainer>
  );
}

function CpuTrendChart({
  data,
  showEngine,
  showDashboard,
  expanded = false
}: {
  data: ResourceSample[];
  showEngine: boolean;
  showDashboard: boolean;
  expanded?: boolean;
}) {
  if (!data.length) return <EmptyLine text="Waiting for the first runtime resource sample." />;
  return (
    <ResponsiveContainer width="100%" height="100%">
      <LineChart data={data} margin={{ top: 10, right: 8, bottom: 0, left: 0 }} accessibilityLayer>
        <CartesianGrid stroke="var(--chart-grid)" vertical={false} />
        <XAxis type="number" dataKey="timestamp" domain={["dataMin", "dataMax"]} tickFormatter={(value) => formatTime(Number(value))} stroke="var(--chart-axis)" tickLine={false} axisLine={false} minTickGap={30} interval="preserveStartEnd" />
        <YAxis stroke="var(--chart-axis)" tickLine={false} axisLine={false} width={52} tickFormatter={formatPercentTick} />
        <Tooltip formatter={(value) => formatPercent(value)} labelFormatter={(value) => formatDateTime(Number(value))} cursor={chartCursor} contentStyle={chartTooltipContentStyle} labelStyle={chartTooltipLabelStyle} itemStyle={chartTooltipItemStyle} />
        {showEngine && <Line type="monotone" dataKey="engineCpuPercent" stroke="var(--chart-1)" strokeWidth={2} dot={false} activeDot={expanded ? { r: 3 } : false} name="Engine CPU" isAnimationActive={false} />}
        {showDashboard && <Line type="monotone" dataKey="dashboardCpuPercent" stroke="var(--chart-2)" strokeWidth={2} dot={false} activeDot={expanded ? { r: 3 } : false} name="Dashboard CPU" isAnimationActive={false} />}
      </LineChart>
    </ResponsiveContainer>
  );
}

function MemoryTrendChart({
  data,
  showEngine,
  showDashboard,
  expanded = false
}: {
  data: ResourceSample[];
  showEngine: boolean;
  showDashboard: boolean;
  expanded?: boolean;
}) {
  if (!data.length) return <EmptyLine text="Waiting for the first runtime resource sample." />;
  return (
    <ResponsiveContainer width="100%" height="100%">
      <LineChart data={data} margin={{ top: 10, right: 8, bottom: 0, left: 0 }} accessibilityLayer>
        <CartesianGrid stroke="var(--chart-grid)" vertical={false} />
        <XAxis type="number" dataKey="timestamp" domain={["dataMin", "dataMax"]} tickFormatter={(value) => formatTime(Number(value))} stroke="var(--chart-axis)" tickLine={false} axisLine={false} minTickGap={30} interval="preserveStartEnd" />
        <YAxis stroke="var(--chart-axis)" tickLine={false} axisLine={false} width={70} tickFormatter={(value) => formatResourceBytes(value)} />
        <Tooltip formatter={(value) => formatResourceBytes(value)} labelFormatter={(value) => formatDateTime(Number(value))} cursor={chartCursor} contentStyle={chartTooltipContentStyle} labelStyle={chartTooltipLabelStyle} itemStyle={chartTooltipItemStyle} />
        {showEngine && <Line type="monotone" dataKey="engineResidentMemoryBytes" stroke="var(--chart-1)" strokeWidth={2} dot={false} activeDot={expanded ? { r: 3 } : false} name="Engine RSS" isAnimationActive={false} />}
        {showDashboard && <Line type="monotone" dataKey="dashboardResidentMemoryBytes" stroke="var(--chart-2)" strokeWidth={2} dot={false} activeDot={expanded ? { r: 3 } : false} name="Dashboard RSS" isAnimationActive={false} />}
      </LineChart>
    </ResponsiveContainer>
  );
}

type ProbeRhythm = ReturnType<typeof buildProbeRhythm>;

function ProbeTrendChart({
  rhythm,
  selectedTargets,
  colorByTarget,
  expanded = false
}: {
  rhythm: ProbeRhythm;
  selectedTargets: readonly string[];
  colorByTarget: ReadonlyMap<string, string>;
  expanded?: boolean;
}) {
  if (!rhythm.points.length) return <EmptyLine text="Waiting for successful latency samples." />;
  return (
    <ResponsiveContainer width="100%" height="100%">
      <LineChart data={rhythm.points} margin={{ top: 0, right: 28, bottom: 0, left: 0 }} accessibilityLayer>
        <CartesianGrid stroke="var(--chart-grid)" vertical={false} />
        <XAxis type="number" dataKey="timestamp" domain={["dataMin", "dataMax"]} tickFormatter={(value) => formatTime(Number(value))} stroke="var(--chart-axis)" tickLine={false} axisLine={false} minTickGap={30} interval="preserveStartEnd" padding={{ left: 12, right: 12 }} />
        <YAxis stroke="var(--chart-axis)" tickLine={false} axisLine={false} width={52} tickFormatter={formatMillisecondsTick} />
        <Tooltip formatter={(value, name) => [formatMilliseconds(value), String(name)]} labelFormatter={(value) => formatDateTime(Number(value))} cursor={chartCursor} contentStyle={chartTooltipContentStyle} labelStyle={chartTooltipLabelStyle} itemStyle={chartTooltipItemStyle} />
        {rhythm.series.filter((series) => selectedTargets.includes(series.target)).map((series) => (
          <Line key={series.key} type="monotone" dataKey={series.key} connectNulls stroke={colorByTarget.get(series.target) || "var(--chart-5)"} strokeWidth={2} dot={false} activeDot={expanded ? { r: 3 } : false} name={series.target} isAnimationActive={false} />
        ))}
      </LineChart>
    </ResponsiveContainer>
  );
}

function EventCadenceChart({
  data,
  gradientId,
  expanded = false
}: {
  data: EventTimelinePoint[];
  gradientId: string;
  expanded?: boolean;
}) {
  if (!data.length) return <EmptyLine text="Waiting for the first event signal." />;
  return (
    <ResponsiveContainer width="100%" height="100%">
      <AreaChart data={data} margin={{ top: 0, right: 28, bottom: 0, left: 0 }} accessibilityLayer>
        <defs>
          <linearGradient id={gradientId} x1="0" x2="0" y1="0" y2="1">
            <stop offset="5%" stopColor="var(--chart-2)" stopOpacity={0.3} />
            <stop offset="95%" stopColor="var(--chart-2)" stopOpacity={0.01} />
          </linearGradient>
        </defs>
        <CartesianGrid stroke="var(--chart-grid-soft)" vertical={false} />
        <XAxis type="number" dataKey="timestamp" domain={["dataMin", "dataMax"]} tickFormatter={(value) => formatTime(Number(value))} stroke="var(--chart-axis)" tickLine={false} axisLine={false} minTickGap={30} interval="preserveStartEnd" padding={{ left: 12, right: 12 }} />
        <YAxis allowDecimals={false} stroke="var(--chart-axis)" tickLine={false} axisLine={false} width={34} />
        <Tooltip formatter={(value, name) => [formatCount(value), String(name)]} labelFormatter={(value) => formatDateTime(Number(value))} cursor={chartCursor} contentStyle={chartTooltipContentStyle} labelStyle={chartTooltipLabelStyle} itemStyle={chartTooltipItemStyle} />
        <Area type="monotone" dataKey="total" stroke="var(--chart-2)" fill={`url(#${gradientId})`} strokeWidth={2} activeDot={expanded ? { r: 3 } : false} name="Events" isAnimationActive={false} />
      </AreaChart>
    </ResponsiveContainer>
  );
}

// 实时事件只影响事件相关区域；稳定 props 的重图表跳过整页事件批次带来的无关重绘。
const MemoTrafficTrendChart = memo(TrafficTrendChart);
const MemoCpuTrendChart = memo(CpuTrendChart);
const MemoMemoryTrendChart = memo(MemoryTrendChart);
const MemoProbeTrendChart = memo(ProbeTrendChart);
const MemoEventCadenceChart = memo(EventCadenceChart);

function ChartExpandButton({ label, onClick }: { label: string; onClick: () => void }) {
  return (
    <button className="chart-expand-button" type="button" aria-haspopup="dialog" onClick={onClick}>
      <Maximize2 size={13} aria-hidden="true" />
      <span>Expand</span>
      <span className="sr-only"> {label}</span>
    </button>
  );
}

// Native dialog 会让背景失去交互，但 Recharts 的可访问图层位于最后一个 Tab 位时，
// 部分浏览器仍可能短暂把焦点落到 body；显式收口 Tab 顺序，保证键盘分析不中断。
function dialogFocusableElements(dialog: HTMLDialogElement) {
  return Array.from(
    dialog.querySelectorAll<HTMLElement>(
      'button:not(:disabled), [href], input:not(:disabled), select:not(:disabled), textarea:not(:disabled), [tabindex]:not([tabindex="-1"])'
    )
  ).filter((element) => element.getClientRects().length > 0 && element.getAttribute("aria-hidden") !== "true");
}

function ChartAnalysisDialog({
  title,
  description,
  sampleCount,
  span,
  rangeMs,
  onRangeChange,
  onClose,
  children
}: {
  title: string;
  description: string;
  sampleCount: number;
  span: string;
  rangeMs: number;
  onRangeChange: (value: number) => void;
  onClose: () => void;
  children: ReactNode;
}) {
  const dialogRef = useRef<HTMLDialogElement>(null);
  const closeButtonRef = useRef<HTMLButtonElement>(null);
  const previousFocusRef = useRef<HTMLElement | null>(null);
  const [chartReady, setChartReady] = useState(false);

  useEffect(() => {
    const dialog = dialogRef.current;
    if (!dialog) return;
    previousFocusRef.current = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    dialog.showModal();
    // ResponsiveContainer 只能在 dialog 获得真实布局尺寸后挂载，否则会产生 0x0 测量警告。
    setChartReady(true);
    closeButtonRef.current?.focus();
    return () => {
      if (dialog.open) dialog.close();
      document.body.style.overflow = previousOverflow;
      previousFocusRef.current?.focus();
    };
  }, []);

  return (
    <dialog
      ref={dialogRef}
      className="chart-analysis-dialog"
      aria-labelledby="chart-analysis-title"
      aria-describedby="chart-analysis-description"
      onCancel={(event) => {
        event.preventDefault();
        onClose();
      }}
      onKeyDown={(event) => {
        if (event.key !== "Tab") return;
        const focusable = dialogFocusableElements(event.currentTarget);
        if (!focusable.length) {
          event.preventDefault();
          closeButtonRef.current?.focus();
          return;
        }

        const first = focusable[0];
        const last = focusable[focusable.length - 1];
        const active = document.activeElement;
        if (event.shiftKey && (active === first || !event.currentTarget.contains(active))) {
          event.preventDefault();
          last.focus();
        } else if (!event.shiftKey && (active === last || !event.currentTarget.contains(active))) {
          event.preventDefault();
          first.focus();
        }
      }}
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) onClose();
      }}
    >
      <section className="chart-analysis-shell">
        <header className="chart-analysis-header">
          <div>
            <span className="quiet-label">Trend analysis</span>
            <h2 id="chart-analysis-title">{title}</h2>
            <p id="chart-analysis-description">{description}</p>
          </div>
          <button ref={closeButtonRef} className="chart-dialog-close" type="button" onClick={onClose} aria-label={`Close expanded ${title} chart`}>
            <X size={18} aria-hidden="true" />
          </button>
        </header>
        <div className="chart-analysis-toolbar">
          <div className="chart-range-picker" role="group" aria-label="Analysis time range">
            {chartRangeOptions.map((option) => (
              <button key={option.value} type="button" aria-pressed={rangeMs === option.value} onClick={() => onRangeChange(option.value)}>
                {option.label}
              </button>
            ))}
          </div>
          <p><strong>{sampleCount}</strong> plotted points <span>|</span> {span} <span>|</span> browser-local</p>
        </div>
        <div className="chart-analysis-content">
          {chartReady ? children : <EmptyLine text="Preparing expanded chart." />}
        </div>
        <footer>Hover or focus the plot to inspect exact values. Narrow the time range and visible series to isolate an anomaly.</footer>
      </section>
    </dialog>
  );
}

// REST snapshot、WebSocket 增量与前端环形历史共同驱动整个实时看板。
function App() {
  const [theme, setTheme] = useState<Theme>(initialTheme);
  const [snapshot, setSnapshot] = useState<Snapshot | null>(null);
  const [events, setEvents] = useState<NetworkEvent[]>([]);
  const [trafficHistory, setTrafficHistory] = useState<TrafficSample[]>([]);
  const [resourceHistory, setResourceHistory] = useState<ResourceSample[]>([]);
  const [probeHistory, setProbeHistory] = useState<Snapshot["latencySeries"]>([]);
  const [manualPingResults, setManualPingResults] = useState<PingResult[]>([]);
  const [selectedTrafficSeries, setSelectedTrafficSeries] = useState<string[]>(["bytesPerSecond"]);
  const [selectedCpuSeries, setSelectedCpuSeries] = useState<string[]>(cpuSeriesIds);
  const [selectedMemorySeries, setSelectedMemorySeries] = useState<string[]>(memorySeriesIds);
  const [selectedProbeTargets, setSelectedProbeTargets] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState("");
  const [lastUpdatedAt, setLastUpdatedAt] = useState(0);
  const [aiLoading, setAiLoading] = useState(false);
  const [aiError, setAiError] = useState("");
  const [analysis, setAnalysis] = useState("");
  const [pingHost, setPingHost] = useState("8.8.8.8");
  const [pingLoading, setPingLoading] = useState(false);
  const [pingError, setPingError] = useState("");
  const [expandedChart, setExpandedChart] = useState<ExpandedChartId | null>(null);
  const [expandedRangeMs, setExpandedRangeMs] = useState<number>(CHART_WINDOW_MS);
  const [chartNow, setChartNow] = useState(() => Date.now());
  const componentActiveRef = useRef(true);
  const snapshotAvailableRef = useRef(false);
  const snapshotRequestIdRef = useRef(0);
  const snapshotFinishedAtRef = useRef(0);
  const snapshotRequestRef = useRef<{
    id: number;
    controller: AbortController;
    promise: Promise<void>;
  } | null>(null);
  const analysisAbortRef = useRef<AbortController | null>(null);
  const pingAbortRef = useRef<AbortController | null>(null);

  // 用户选择持久化到浏览器，并同步原生控件和浏览器顶部主题色。
  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    document.documentElement.style.colorScheme = theme;
    document.querySelector('meta[name="theme-color"]')?.setAttribute(
      "content",
      theme === "light" ? "#f5f7fa" : "#080a0d"
    );
    try {
      localStorage.setItem("janet-color-theme", theme);
    } catch {
      // 受限存储环境仍可完成本次会话内的主题切换。
    }
  }, [theme]);

  // 页面隐藏时停止纯展示时钟，回到前台立即推进窗口，避免后台标签持续触发整页计算。
  useEffect(() => {
    const advanceChartClock = () => {
      if (document.visibilityState === "visible") setChartNow(Date.now());
    };
    const timer = window.setInterval(advanceChartClock, 60 * 1000);
    document.addEventListener("visibilitychange", advanceChartClock);
    return () => {
      window.clearInterval(timer);
      document.removeEventListener("visibilitychange", advanceChartClock);
    };
  }, []);

  // 一批事件只触发一次去重、排序和 React 提交；transition 保证突发事件不阻塞用户操作。
  const onEvents = useCallback((incoming: NetworkEvent[]) => {
    startTransition(() => {
      setEvents((current) => mergeEventHistory(current, incoming, {
        now: Date.now(),
        maxPoints: EVENT_HISTORY_LIMIT
      }));
    });
  }, []);

  const eventStream = useEventStream(onEvents);

  // 每次 snapshot 只追加一个可信 generation；请求有 deadline，旧/取消结果不能覆盖新状态。
  const loadSnapshot = useCallback((options: { interactive?: boolean } = {}) => {
    const interactive = options.interactive === true;
    if (interactive) setRefreshing(true);

    const activeRequest = snapshotRequestRef.current;
    if (activeRequest) {
      return interactive
        ? activeRequest.promise.finally(() => {
          if (componentActiveRef.current) setRefreshing(false);
        })
        : activeRequest.promise;
    }

    const id = ++snapshotRequestIdRef.current;
    const controller = new AbortController();
    const promise = (async () => {
      try {
        const next = await fetchJson<Snapshot>(
          `${apiBaseUrl}/api/snapshot${interactive ? "?fresh=1" : ""}`,
          { signal: controller.signal },
          { timeoutMs: snapshotRequestTimeoutMs, label: "Snapshot refresh" }
        );
        if (controller.signal.aborted || snapshotRequestRef.current?.id !== id) return;

        snapshotAvailableRef.current = true;
        setSnapshot(next);
        setError("");
        setLastUpdatedAt(Date.now());
        setChartNow(Date.now());
        const trafficSample = createTrafficSample(next.networkSnapshot);
        const resourceSample = createResourceSample(next.runtimeResources);
        // 趋势和事件是非阻塞派生视图；状态卡先更新，图表历史稍后完成同批提交。
        startTransition(() => {
          if (trafficSample) {
            setTrafficHistory((current) => appendTrafficSample(current, trafficSample));
          }
          if (resourceSample) {
            setResourceHistory((current) => appendResourceSample(current, resourceSample));
          }
          setProbeHistory((current) => mergeProbeHistory(current, next.latencySeries, {
            now: next.generatedAt,
            maxPoints: PROBE_HISTORY_LIMIT
          }));
          setEvents((current) => mergeEventHistory(current, next.events, {
            now: next.generatedAt,
            maxPoints: EVENT_HISTORY_LIMIT
          }));
        });
      } catch (caught) {
        if (!isAbortError(caught) && snapshotRequestRef.current?.id === id) {
          setError(caught instanceof Error ? caught.message : String(caught));
        }
      } finally {
        if (snapshotRequestRef.current?.id === id) {
          snapshotRequestRef.current = null;
          snapshotFinishedAtRef.current = Date.now();
          if (componentActiveRef.current) setLoading(false);
        }
      }
    })();
    snapshotRequestRef.current = { id, controller, promise };

    return interactive
      ? promise.finally(() => {
        if (componentActiveRef.current) setRefreshing(false);
      })
      : promise;
  }, []);

  // 组件卸载时终止全部浏览器请求；id 守卫阻止 StrictMode 旧 effect 回写新挂载。
  useEffect(() => {
    componentActiveRef.current = true;
    return () => {
      componentActiveRef.current = false;
      const snapshotRequest = snapshotRequestRef.current;
      snapshotRequest?.controller.abort();
      if (snapshotRequestRef.current?.id === snapshotRequest?.id) snapshotRequestRef.current = null;
      analysisAbortRef.current?.abort();
      analysisAbortRef.current = null;
      pingAbortRef.current?.abort();
      pingAbortRef.current = null;
    };
  }, []);

  // 请求完成后再等待 10 秒；隐藏或离线时暂停，回到前台后立即恢复一次采集。
  useEffect(() => {
    let disposed = false;
    let timer: number | null = null;

    const clearTimer = () => {
      if (timer !== null) {
        window.clearTimeout(timer);
        timer = null;
      }
    };
    const canPoll = () => document.visibilityState === "visible" && navigator.onLine !== false;
    const schedule = () => {
      clearTimer();
      if (disposed || !canPoll()) return;
      timer = window.setTimeout(runPoll, snapshotRefreshIntervalMs);
    };
    const runPoll = () => {
      if (disposed || !canPoll()) return;
      const elapsed = Date.now() - snapshotFinishedAtRef.current;
      if (snapshotFinishedAtRef.current > 0 && elapsed < snapshotRefreshIntervalMs) {
        clearTimer();
        timer = window.setTimeout(runPoll, snapshotRefreshIntervalMs - elapsed);
        return;
      }
      void loadSnapshot().finally(schedule);
    };
    const resume = () => {
      clearTimer();
      if (!canPoll()) {
        const activeRequest = snapshotRequestRef.current;
        activeRequest?.controller.abort();
        if (snapshotRequestRef.current?.id === activeRequest?.id) snapshotRequestRef.current = null;
        // 隐藏页保留首屏骨架；可见但离线时结束等待，避免页面看起来永久卡在加载中。
        if (navigator.onLine === false && componentActiveRef.current) setLoading(false);
        return;
      }
      // 离线恢复且尚无任何快照时重新进入首屏等待态；已有旧数据则持续显示旧数据。
      if (!snapshotAvailableRef.current && componentActiveRef.current) setLoading(true);
      void loadSnapshot().finally(schedule);
    };

    document.addEventListener("visibilitychange", resume);
    window.addEventListener("online", resume);
    window.addEventListener("offline", resume);
    resume();

    return () => {
      disposed = true;
      clearTimer();
      document.removeEventListener("visibilitychange", resume);
      window.removeEventListener("online", resume);
      window.removeEventListener("offline", resume);
      const activeRequest = snapshotRequestRef.current;
      activeRequest?.controller.abort();
      if (snapshotRequestRef.current?.id === activeRequest?.id) snapshotRequestRef.current = null;
    };
  }, [loadSnapshot]);

  // WebSocket 增量与 snapshot 种子在浏览器合并后统一聚合，避免类型构成和趋势口径分裂。
  const mergedSnapshot = useMemo(() => {
    if (!snapshot) return null;
    return {
      ...snapshot,
      events,
      eventStats: buildEventStats(events, { now: chartNow, maxEvents: EVENT_HISTORY_LIMIT })
    };
  }, [chartNow, events, snapshot]);

  // 手动 Ping 先用 POST 响应即时展示，再与后续 snapshot 的默认探测去重合并。
  const displayedPings = useMemo(() => {
    const unique = new Map<string, PingResult>();
    for (const item of [...(mergedSnapshot?.pings ?? []), ...manualPingResults]) {
      unique.set(`${item.target}\u0000${item.timestamp}`, item);
    }
    return Array.from(unique.values())
      .sort((left, right) => right.timestamp - left.timestamp)
      .slice(0, manualPingResultLimit);
  }, [manualPingResults, mergedSnapshot?.pings]);

  const visibleTrafficHistory = useMemo(
    () => trimChartWindow(trafficHistory, { now: chartNow, maxPoints: CHART_SAMPLE_LIMIT }),
    [chartNow, trafficHistory]
  );
  const visibleResourceHistory = useMemo(
    () => trimChartWindow(resourceHistory, { now: chartNow, maxPoints: CHART_SAMPLE_LIMIT }),
    [chartNow, resourceHistory]
  );
  const visibleProbeHistory = useMemo(
    () => trimChartWindow(probeHistory, { now: chartNow, maxPoints: PROBE_HISTORY_LIMIT }),
    [chartNow, probeHistory]
  );
  const visibleEventTimeline = useMemo(
    () => mergedSnapshot?.eventStats.timeline ?? [],
    [mergedSnapshot?.eventStats.timeline]
  );

  const expandedTrafficHistory = useMemo(
    () => {
      if (expandedChart !== "traffic") return [];
      if (expandedRangeMs === CHART_WINDOW_MS) return visibleTrafficHistory;
      return trimChartWindow(visibleTrafficHistory, { now: chartNow, windowMs: expandedRangeMs, maxPoints: CHART_SAMPLE_LIMIT });
    },
    [chartNow, expandedChart, expandedRangeMs, visibleTrafficHistory]
  );
  const expandedResourceHistory = useMemo(
    () => {
      if (expandedChart !== "cpu" && expandedChart !== "memory") return [];
      if (expandedRangeMs === CHART_WINDOW_MS) return visibleResourceHistory;
      return trimChartWindow(visibleResourceHistory, { now: chartNow, windowMs: expandedRangeMs, maxPoints: CHART_SAMPLE_LIMIT });
    },
    [chartNow, expandedChart, expandedRangeMs, visibleResourceHistory]
  );
  const expandedProbeHistory = useMemo(
    () => {
      if (expandedChart !== "probe") return [];
      if (expandedRangeMs === CHART_WINDOW_MS) return visibleProbeHistory;
      return trimChartWindow(visibleProbeHistory, { now: chartNow, windowMs: expandedRangeMs, maxPoints: PROBE_HISTORY_LIMIT });
    },
    [chartNow, expandedChart, expandedRangeMs, visibleProbeHistory]
  );
  const expandedEventTimeline = useMemo(
    () => {
      if (expandedChart !== "events") return [];
      if (expandedRangeMs === CHART_WINDOW_MS) return visibleEventTimeline;
      return trimEventTimeline(visibleEventTimeline, {
        now: chartNow,
        windowMs: expandedRangeMs,
        maxPoints: Math.ceil(CHART_WINDOW_MS / 60000) + 1
      });
    },
    [chartNow, expandedChart, expandedRangeMs, visibleEventTimeline]
  );

  // 每个 target 使用独立 dataKey；失败值保持 null，但不再切断其他 target 的曲线。
  const probeRhythm = useMemo(
    () => buildProbeRhythm(visibleProbeHistory),
    [visibleProbeHistory]
  );
  const expandedProbeRhythm = useMemo(
    () => expandedChart === "probe"
      ? buildProbeRhythm(expandedProbeHistory)
      : { points: [], series: [] },
    [expandedChart, expandedProbeHistory]
  );
  // Probe 的 probe_N 会随数据窗口重建；选择状态必须绑定稳定 target，而不是动态图表 key。
  const availableProbeTargets = useMemo(
    () => probeRhythm.series
      .filter((series) => series.successes > 0)
      .map((series) => series.target)
      .sort((left, right) => left.localeCompare(right)),
    [probeRhythm.series]
  );
  const probeColorByTarget = useMemo(
    () => new Map(
      probeRhythm.series
        .map((series) => series.target)
        .sort((left, right) => left.localeCompare(right))
        .map((target, index) => [target, probeColors[index % probeColors.length]])
    ),
    [probeRhythm.series]
  );
  const availableProbeTargetKey = availableProbeTargets.join("\u0000");

  // 新目标不会抢走用户选择；仅当旧目标消失时才回退到第一条可绘制曲线。
  useEffect(() => {
    setSelectedProbeTargets((current) => reconcileSeriesSelection(
      current,
      availableProbeTargets,
      availableProbeTargets[0]
    ));
  }, [availableProbeTargetKey]);

  function toggleTrafficSeries(seriesId: string) {
    setSelectedTrafficSeries((current) => toggleSeriesSelection(current, seriesId, trafficSeriesIds));
  }

  function toggleProbeTarget(target: string) {
    setSelectedProbeTargets((current) => toggleSeriesSelection(current, target, availableProbeTargets));
  }

  function toggleCpuSeries(seriesId: string) {
    setSelectedCpuSeries((current) => toggleSeriesSelection(current, seriesId, cpuSeriesIds));
  }

  function toggleMemorySeries(seriesId: string) {
    setSelectedMemorySeries((current) => toggleSeriesSelection(current, seriesId, memorySeriesIds));
  }

  function openExpandedChart(chart: ExpandedChartId) {
    setExpandedRangeMs(CHART_WINDOW_MS);
    setExpandedChart(chart);
  }

  async function runAnalysis() {
    if (aiLoading) return;
    const controller = new AbortController();
    analysisAbortRef.current?.abort();
    analysisAbortRef.current = controller;
    setAiLoading(true);
    setAiError("");
    try {
      const payload = await fetchJson<{ analysis: string }>(
        `${apiBaseUrl}/api/analyze`,
        { method: "POST", signal: controller.signal },
        { timeoutMs: analysisRequestTimeoutMs, label: "AI analysis" }
      );
      if (controller.signal.aborted || analysisAbortRef.current !== controller) return;
      setAnalysis(payload.analysis);
    } catch (caught) {
      if (!isAbortError(caught) && analysisAbortRef.current === controller) {
        setAiError(caught instanceof Error ? caught.message : String(caught));
      }
    } finally {
      if (analysisAbortRef.current === controller) {
        analysisAbortRef.current = null;
        if (componentActiveRef.current) setAiLoading(false);
      }
    }
  }

  async function runPing(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const hostname = pingHost.trim();
    if (!hostname || pingLoading) return;
    const controller = new AbortController();
    pingAbortRef.current?.abort();
    pingAbortRef.current = controller;
    setPingLoading(true);
    setPingError("");
    try {
      const payload = await fetchJson<PingResult>(
        `${apiBaseUrl}/api/ping`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ hostname }),
          signal: controller.signal
        },
        { timeoutMs: pingRequestTimeoutMs, label: "Ping probe" }
      );
      if (controller.signal.aborted || pingAbortRef.current !== controller) return;

      setManualPingResults((current) => {
        const unique = new Map(
          [payload, ...current].map((item) => [`${item.target}\u0000${item.timestamp}`, item])
        );
        return Array.from(unique.values()).slice(0, manualPingResultLimit);
      });
      startTransition(() => {
        setProbeHistory((current) => mergeProbeHistory(current, [{
          target: payload.target,
          timestamp: payload.timestamp,
          time: formatTime(payload.timestamp),
          latencyMs: payload.latencyMs,
          success: payload.success
        }], {
          now: payload.timestamp,
          maxPoints: PROBE_HISTORY_LIMIT
        }));
      });
      // POST 结果已经可见；完整 snapshot 只在后台同步其余状态，不再阻塞按钮反馈。
      void loadSnapshot();
    } catch (caught) {
      if (!isAbortError(caught) && pingAbortRef.current === controller) {
        setPingError(caught instanceof Error ? caught.message : String(caught));
      }
    } finally {
      if (pingAbortRef.current === controller) {
        pingAbortRef.current = null;
        if (componentActiveRef.current) setPingLoading(false);
      }
    }
  }

  const network = mergedSnapshot?.networkSnapshot ?? null;
  const runtimeResources = mergedSnapshot?.runtimeResources ?? null;
  const requestFailures = mergedSnapshot?.requestFailures ?? null;
  const browserRequestState = requestObserverState(requestFailures);
  const engineResources = runtimeResources?.engine ?? network?.engineResources ?? null;
  const dashboardResources = runtimeResources?.dashboard ?? null;
  // 无活动出口时绝不回退到 interfaces[0]，避免把残留指标误报成当前链路。
  const activeInterface = network?.hasActiveInterface
    ? network.interfaces.find((item) => item.interfaceName === network.activeInterface)
      || network.interfaces.find((item) => item.usingNow)
      || null
    : null;
  const quality = network?.quality ?? null;
  const observation = network?.trafficObservation ?? null;
  const map = observation?.mapObservability ?? null;
  const trafficTrusted = Boolean(
    observation?.availability === "AVAILABLE"
      && observation.valid
      && !observation.baselineOnly
      && observation.mapReadComplete
      && map?.readComplete
  );
  const score = quality?.score ?? mergedSnapshot?.health.score ?? null;
  const scoreOffset = 326 - ((score ?? 0) / 100) * 326;
  const previousTrafficSample = visibleTrafficHistory.length > 1 ? visibleTrafficHistory.at(-2) ?? null : null;
  const latestTrafficSample = visibleTrafficHistory.at(-1) ?? null;
  const packetDelta = latestTrafficSample && previousTrafficSample
    ? counterDelta(latestTrafficSample.packetsSeen, previousTrafficSample.packetsSeen)
    : null;
  const showTrafficThroughput = selectedTrafficSeries.includes("bytesPerSecond");
  const showTrafficPackets = selectedTrafficSeries.includes("packetsPerSecond");
  const showTrafficFlows = selectedTrafficSeries.includes("activeFlows");
  const showEngineCpu = selectedCpuSeries.includes("engineCpuPercent");
  const showDashboardCpu = selectedCpuSeries.includes("dashboardCpuPercent");
  const showEngineMemory = selectedMemorySeries.includes("engineResidentMemoryBytes");
  const showDashboardMemory = selectedMemorySeries.includes("dashboardResidentMemoryBytes");
  const expandedChartPoints: readonly { timestamp: number }[] = expandedChart === "traffic"
    ? expandedTrafficHistory
    : expandedChart === "cpu" || expandedChart === "memory"
      ? expandedResourceHistory
      : expandedChart === "probe"
        ? expandedProbeRhythm.points
        : expandedChart === "events"
          ? expandedEventTimeline
          : [];
  const eventStatusValue = eventStream.connected
    ? "live"
    : eventStream.phase === "recovering"
      ? "recovering"
      : eventStream.phase === "reconnecting"
        ? "reconnecting"
        : eventStream.phase;
  const eventStatusTone = eventStream.connected
    ? "ok" as const
    : eventStream.phase === "connecting" || eventStream.phase === "recovering" || eventStream.phase === "reconnecting"
      ? "warn" as const
      : "muted" as const;

  return (
    <main className="app-shell">
      <header className="command-header">
        <div className="brand-lockup">
          <span className="brand-icon" aria-hidden="true"><Activity size={19} /></span>
          <div>
            <strong>JaNet</strong>
            <span>Network Observatory</span>
          </div>
        </div>
        <div className="header-controls">
          <div className="status-cluster" aria-live="polite">
            <StatusPill ok={Boolean(mergedSnapshot?.grpc.ok)} label="gRPC" value={mergedSnapshot?.grpc.ok ? "online" : "offline"} />
            <StatusPill ok={eventStream.connected} tone={eventStatusTone} label="Events" value={eventStatusValue} />
            <StatusPill ok={browserRequestState.tone === "ok"} tone={browserRequestState.tone} label="Browser" value={browserRequestState.value} />
            <StatusPill ok={Boolean(mergedSnapshot?.ai.configured)} label="AI" value={mergedSnapshot?.ai.configured ? "ready" : "not configured"} />
            <StatusPill ok={Boolean(observation?.valid)} label="Capture" value={observation?.valid ? "trusted" : observation?.baselineOnly ? "warming" : "degraded"} />
          </div>
          <div className="header-actions">
            <button
              className="theme-switch"
              onClick={() => setTheme((current) => current === "dark" ? "light" : "dark")}
              role="switch"
              aria-checked={theme === "dark"}
              aria-label={`${theme === "dark" ? "Dark" : "Light"} theme. Switch to ${theme === "dark" ? "light" : "dark"} theme`}
              title={`Switch to ${theme === "dark" ? "light" : "dark"} theme`}
              type="button"
            >
              {theme === "dark" ? <Moon size={15} /> : <Sun size={15} />}
              <span>{theme === "dark" ? "Dark" : "Light"}</span>
            </button>
            <button
              className="icon-button"
              onClick={() => void loadSnapshot({ interactive: true })}
              disabled={refreshing}
              aria-busy={refreshing}
              aria-label="Refresh network snapshot"
              title="Refresh network snapshot"
              type="button"
            >
              <RefreshCw className={refreshing ? "spin" : ""} size={17} />
            </button>
          </div>
        </div>
      </header>

      <section className="context-bar" aria-label="Snapshot context">
        <span><strong>{network?.activeInterface || "No active route"}</strong> active interface</span>
        <span>gRPC {mergedSnapshot?.grpcAddress || "not resolved"}</span>
        <span>Observed {network ? formatAge(network.observedAt) : "n/a"}</span>
        <span>Dashboard updated {lastUpdatedAt ? formatAge(lastUpdatedAt) : "n/a"}</span>
      </section>

      {error && <div className="notice error" role="alert">Dashboard cannot collect the latest snapshot: {error}</div>}
      {eventStream.error && <div className="notice warning" role="status">Event stream: {eventStream.error}</div>}
      {mergedSnapshot && !mergedSnapshot.grpc.ok && (
        <div className="notice error" role="alert">
          gRPC server is not reachable at {mergedSnapshot.grpcAddress}. {mergedSnapshot.grpc.errors[0] || "No server response."}
        </div>
      )}
      {loading && <Skeleton />}

      {mergedSnapshot && (
        <>
          <section className="overview-grid" aria-label="Network overview">
            <article className="panel quality-panel">
              <PanelHeading eyebrow="Network posture" title={scoreLabel(score)} icon={<Gauge size={20} />} />
              <div className="quality-summary">
                <div className="quality-orbit">
                  <svg viewBox="0 0 120 120" role="img" aria-label={`Network quality score ${score ?? "unavailable"}`}>
                    <circle className="orbit-track" cx="60" cy="60" r="52" />
                    <circle className="orbit-value" cx="60" cy="60" r="52" strokeDashoffset={scoreOffset} />
                  </svg>
                  <div><strong>{score === null ? "n/a" : score.toFixed(0)}</strong><span>/100</span></div>
                </div>
                <div className="quality-copy">
                  <StatusTag tone={quality?.degraded ? "warning" : "good"}>
                    {quality?.degraded ? "Degraded inputs" : "Complete inputs"}
                  </StatusTag>
                  <p>{quality?.level || "UNKNOWN"} assessment</p>
                  <small>{quality?.missingMetrics.length ? `Missing: ${quality.missingMetrics.join(", ")}` : "No missing quality metrics"}</small>
                </div>
              </div>
              <div className="issue-list">
                {quality?.issues.length ? quality.issues.map((issue) => <span key={issue}>{issue}</span>) : <span>No quality issues reported.</span>}
              </div>
            </article>

            <article className="panel posture-panel">
              <PanelHeading
                eyebrow="Current link"
                title={activeInterface ? `${activeInterface.interfaceName} telemetry` : "No active interface"}
                icon={<Network size={20} />}
                meta={network ? `Sample ${formatTime(network.observedAt)}` : "Typed snapshot unavailable"}
              />
              <div className="kpi-grid">
                <Kpi label="RTT" value={activeInterface ? formatRtt(activeInterface.rttMs, activeInterface.rttAvailability) : "n/a"} meta={activeInterface ? formatRttDelta(activeInterface.rttMs, activeInterface.previousRttMs, activeInterface.rttAvailability) : "Unavailable"} />
                <Kpi label="TCP retrans. proxy" value={activeInterface ? availableMetric(activeInterface.tcpRetransmissionAvailability, activeInterface.tcpRetransmissionRatePercent, formatPercent) : "n/a"} meta={activeInterface?.tcpRetransmissionLevel || activeInterface?.tcpRetransmissionAvailability || "Unavailable"} />
                <Kpi label="RSSI" value={activeInterface ? formatRssi(activeInterface.rssiDbm, activeInterface.rssiAvailability) : "n/a"} meta={activeInterface?.rssiAvailability || "Unavailable on this platform"} />
                <Kpi label="Throughput" value={activeInterface && trafficTrusted ? availableMetric(activeInterface.trafficAvailability, activeInterface.trafficBytesPerSecond, formatBytesPerSecond) : "n/a"} meta={trafficTrusted ? activeInterface?.trafficAvailability || "Unavailable" : observation?.baselineOnly ? "Collector warming" : "Untrusted traffic sample"} />
                <Kpi label="Packet rate" value={activeInterface && trafficTrusted ? availableMetric(activeInterface.trafficAvailability, activeInterface.trafficPacketsPerSecond, formatPacketsPerSecond) : "n/a"} meta={trafficTrusted ? "Current sampled rate" : "Untrusted traffic sample"} />
                <Kpi label="Active flows" value={activeInterface && trafficTrusted ? availableMetric(activeInterface.trafficAvailability, activeInterface.activeFlows, formatCount) : "n/a"} meta={trafficTrusted ? activeInterface?.linkQuality || "Available" : "Untrusted traffic sample"} />
              </div>
              <div className="route-strip">
                <RouteFact label="Default route" value={network?.currentDefaultRouteInterface || "n/a"} />
                <RouteFact label="Route generation" value={network ? formatCount(network.routeGeneration) : "n/a"} />
                <RouteFact label="Previous interface" value={network?.previousActiveInterface || "None observed"} />
                <RouteFact label="Last route switch" value={network?.defaultRouteChanged ? formatDateTime(network.routeChangedAtUnixMs) : "No recent switch"} />
              </div>
            </article>
          </section>

          {network && observation && map ? (
            <>
              <section className="panel traffic-panel" data-testid="traffic-workspace">
                <PanelHeading
                  eyebrow="Traffic pulse"
                  title="Live traffic since this page opened"
                  icon={<Activity size={20} />}
                  meta={`${visibleTrafficHistory.length} trusted generations | ${CHART_WINDOW_LABEL}`}
                />
                <div className="traffic-layout">
                  <div className="chart-region">
                    <SeriesSelector
                      label="Visible traffic data"
                      options={trafficSeriesOptions}
                      selectedIds={selectedTrafficSeries}
                      controls="traffic-chart"
                      onToggle={toggleTrafficSeries}
                      action={<ChartExpandButton label="live traffic" onClick={() => openExpandedChart("traffic")} />}
                    />
                    {/* 桌面双栏时随右侧事实列表拉伸，充分利用该网格行原本空出的纵向空间。 */}
                    <div className="traffic-chart-canvas" id="traffic-chart">
                      <MemoTrafficTrendChart
                        data={visibleTrafficHistory}
                        showThroughput={showTrafficThroughput}
                        showPackets={showTrafficPackets}
                        showFlows={showTrafficFlows}
                        gradientId="traffic-gradient-inline"
                      />
                    </div>
                    <p className="chart-note">Up to 5 hours of browser-local history. Repeated generations replace the last point; a server restart starts a new series.</p>
                  </div>
                  <aside className="traffic-facts" aria-label="Latest traffic sample">
                    <DataFact label="Current throughput" value={activeInterface && trafficTrusted ? availableMetric(activeInterface.trafficAvailability, activeInterface.trafficBytesPerSecond, formatBytesPerSecond) : "n/a"} />
                    <DataFact label="Packet rate" value={activeInterface && trafficTrusted ? availableMetric(activeInterface.trafficAvailability, activeInterface.trafficPacketsPerSecond, formatPacketsPerSecond) : "n/a"} />
                    <DataFact label="Active flows" value={activeInterface && trafficTrusted ? availableMetric(activeInterface.trafficAvailability, activeInterface.activeFlows, formatCount) : "n/a"} />
                    <DataFact label="Packets seen" value={trafficTrusted ? formatCount(map.packetsSeen) : "n/a"} meta={!trafficTrusted ? "Partial or untrusted map read" : packetDelta === null ? "No comparable prior point" : `+${formatCount(packetDelta)} since prior sample`} />
                    <DataFact label="Generation" value={formatCount(observation.generation)} meta={`Bound ifindex ${formatCount(observation.boundIfindex)}`} />
                    <DataFact label="Sample age" value={formatAge(observation.sampledAt)} meta={formatDateTime(observation.sampledAt)} />
                  </aside>
                </div>
              </section>

              <section className="panel interface-panel">
                <PanelHeading eyebrow="Interfaces and route" title={`${network.interfaces.length} interfaces observed`} icon={<Router size={20} />} />
                <div className="table-scroll">
                  <table className="interface-table">
                    <thead>
                      <tr><th>Interface</th><th>Route and state</th><th>RTT</th><th>RSSI</th><th>TCP retrans.</th><th>Traffic</th><th>Flows</th></tr>
                    </thead>
                    <tbody>
                      {network.interfaces.map((item) => <InterfaceRow item={item} trafficTrusted={trafficTrusted} key={item.interfaceName} />)}
                    </tbody>
                  </table>
                </div>
                {network.interfaces.length === 0 && <EmptyLine text="No interfaces returned by gRPC." />}
              </section>

              <section className="panel capture-panel" data-testid="capture-health">
                <PanelHeading
                  eyebrow="Capture health"
                  title={observation.valid ? "Trusted traffic sample" : observation.baselineOnly ? "Collector warming up" : "Degraded traffic evidence"}
                  icon={<ShieldCheck size={20} />}
                  meta={`${observation.captureMode.toUpperCase()} · ${observation.captureCompleteness} · ${observation.availability}`}
                />
                <div className="capture-summary">
                  <DataFact label="Snapshot validity" value={observation.valid ? "Valid" : "Not valid"} meta={`Generation ${formatCount(observation.generation)}`} tone={observation.valid ? "good" : "warning"} />
                  <DataFact label="Capture coverage" value={observation.captureComplete ? "Complete" : "Partial"} meta={observation.captureCompleteness} tone={observation.captureComplete ? "good" : "warning"} />
                  <DataFact label="Map read" value={observation.mapReadComplete && map.readComplete ? "Complete" : "Partial"} meta={`Read error ${formatCount(map.readError)}`} tone={observation.mapReadComplete && map.readComplete ? "good" : "warning"} />
                  <DataFact label="Baseline" value={observation.baselineOnly ? "Warming" : "Established"} meta={`Sample ${formatAge(observation.sampledAt)}`} tone={observation.baselineOnly ? "warning" : "good"} />
                  <DataFact label="sock_diag" value={observation.sockDiagStatus} meta={observation.sockDiagAvailable ? "Available" : "Unavailable"} tone={observation.sockDiagAvailable ? "good" : "muted"} />
                </div>
                {(observation.degradedReason || observation.coverageLimitations) && (
                  <div className="limitation-callout">
                    {observation.degradedReason && <p><strong>Degraded reason</strong>{observation.degradedReason}</p>}
                    {observation.coverageLimitations && <p><strong>Coverage limits</strong>{observation.coverageLimitations}</p>}
                  </div>
                )}
                <div className="capability-grid">
                  <Capability label="libbpf" value={observation.libbpfAvailable} />
                  <Capability label="BPF loaded" value={observation.bpfLoaded} />
                  <Capability label="TC ingress" value={observation.tcIngressAttached} />
                  <Capability label="TC egress" value={observation.tcEgressAttached} />
                  <Capability label="TCP kprobe" value={observation.tcpKprobeAttached} falseLabel="Inactive" neutralWhenFalse />
                  <Capability label="UDP kprobe" value={observation.udpKprobeAttached} falseLabel="Inactive" neutralWhenFalse />
                  <Capability label="sock_diag IPv4" value={observation.sockDiagIpv4Available} />
                  <Capability label="sock_diag IPv6" value={observation.sockDiagIpv6Available} />
                  <Capability label="Process owner" value={observation.procOwnerResolution} />
                  <Capability label="IPv4" value={observation.ipv4Supported} />
                  <Capability label="IPv6" value={observation.ipv6Supported} />
                  <Capability label="IPv6 ext headers" value={observation.ipv6ExtensionHeadersSupported} falseLabel="Unsupported" neutralWhenFalse />
                  <Capability label="Bidirectional" value={observation.bidirectional} />
                  <Capability label="UDP interface" value={observation.udpInterfaceReliable} />
                </div>
              </section>

              <section className="panel map-panel" data-testid="map-observability">
                <PanelHeading
                  eyebrow="eBPF map observability"
                  title="Flow store and capture counters"
                  icon={<Database size={20} />}
                  meta={map.readComplete ? "Complete map read" : "Partial map read: zero values are not proof of absence"}
                />
                <div className="capacity-grid">
                  <CapacityBar label="LRU flow store" entries={map.lruEntries} capacity={map.lruCapacity} />
                  <CapacityBar label="Protected flow store" entries={map.protectedEntries} capacity={map.protectedCapacity} />
                </div>
                <div className="counter-groups">
                  <CounterGroup title="Packet path" items={[
                    ["Packets seen", map.packetsSeen],
                    ["Interface rejected", map.interfaceRejected],
                    ["Parse failures", map.parseFailures],
                    ["LRU lookup misses", map.lruLookupMisses]
                  ]} />
                  <CounterGroup title="LRU store" items={[
                    ["Current entries", map.lruEntries],
                    ["Insert attempts", map.lruInsertAttempts],
                    ["Insert successes", map.lruInsertSuccesses],
                    ["Insert failures", map.lruInsertFailures]
                  ]} />
                  <CounterGroup title="Protected store" items={[
                    ["Current entries", map.protectedEntries],
                    ["Hits", map.protectedHits],
                    ["Insert attempts", map.protectedInsertAttempts],
                    ["Insert successes", map.protectedInsertSuccesses],
                    ["Insert failures", map.protectedInsertFailures]
                  ]} />
                  <CounterGroup title="Continuity window" items={[
                    ["Disappeared", map.disappearedThisWindow],
                    ["Continuity lost", map.continuityLostThisWindow],
                    ["Counter resets", map.counterResetsThisWindow],
                    ["Lookup misses", map.lookupMisses],
                    ["Duplicate keys", map.duplicateKeys],
                    ["Read error", map.readError]
                  ]} />
                  <CounterGroup title="Interface and events" items={[
                    ["Interface inserts", map.interfaceInsertAttempts],
                    ["Interface failures", map.interfaceInsertFailures],
                    ["Events emitted", map.eventsEmitted],
                    ["Event drops", map.eventDrops],
                    ["User events truncated", map.userEventsTruncated]
                  ]} />
                  <CounterGroup title="Policy updates" items={[
                    ["Update attempts", map.policyUpdateAttempts],
                    ["Update failures", map.policyUpdateFailures]
                  ]} />
                </div>
                <details className="raw-counters">
                  <summary>Raw kernel counter vector ({map.kernelCounters.length})</summary>
                  <code>{map.kernelCounters.length ? map.kernelCounters.join(", ") : "No kernel counters returned"}</code>
                </details>
              </section>

              <section className="panel traffic-events-panel">
                <PanelHeading eyebrow="Traffic lifecycle" title="Collector anomaly events" icon={<Server size={20} />} meta={`${observation.recentEvents.length} recent events`} />
                <div className="traffic-event-list">
                  {observation.recentEvents.length === 0 && <EmptyLine text="No traffic collector anomalies in this snapshot." />}
                  {observation.recentEvents.map((event, index) => (
                    <article className="traffic-event" key={`${event.timestampUnixMs}-${event.generation}-${index}`}>
                      <div><StatusTag tone={event.severity > 1 ? "danger" : "warning"}>{event.type || "UNKNOWN"}</StatusTag><time>{formatDateTime(event.timestampUnixMs)}</time></div>
                      <strong>{event.description || event.anomalyType || "Traffic observation event"}</strong>
                      <p>Reason {event.reason} · severity {event.severity} · generation {event.generation}</p>
                      <code>{event.flowKey || "No flow key"} · socket {event.socketCookie}</code>
                    </article>
                  ))}
                </div>
              </section>
            </>
          ) : (
            <div className="notice warning" role="status">The server did not return a typed network snapshot. Detailed traffic evidence is unavailable.</div>
          )}

          <section className="panel resource-panel" data-testid="runtime-footprint">
            <PanelHeading
              eyebrow="Runtime footprint"
              title="Resource and scheduler statistics"
              icon={<Cpu size={20} />}
              meta={`${visibleResourceHistory.length} browser-local samples | ${runtimeResources ? `sampled ${formatAge(runtimeResources.sampledAt)}` : "runtime sampler unavailable"}`}
            />
            <div className="resource-semantics">
              <strong>CPU scale</strong>
              <span>One logical CPU core equals 100%; a multi-threaded process can exceed 100%.</span>
              {runtimeResources?.cpuSemantics && <code>{runtimeResources.cpuSemantics}</code>}
            </div>
            <div className="resource-summary-strip">
              <DataFact
                label="Combined resident memory"
                value={formatResourceBytes(runtimeResources?.combinedResidentMemoryBytes)}
                meta={runtimeResources?.combinedResidentMemoryComplete ? "Engine RSS + Dashboard RSS" : "Requires both process samples"}
              />
              <DataFact
                label="Engine sample window"
                value={processMetric(engineResources, engineResources?.sampleWindowMs, (value) => `${formatCount(value)} ms`)}
                meta={`${processMetric(engineResources, engineResources?.logicalCpuCount, (value) => formatCount(value))} logical CPUs`}
              />
              <DataFact
                label="Dashboard sample window"
                value={processMetric(dashboardResources, dashboardResources?.sampleWindowMs, (value) => `${formatCount(value)} ms`)}
                meta={`${processMetric(dashboardResources, dashboardResources?.logicalCpuCount, (value) => formatCount(value))} logical CPUs`}
              />
              <DataFact
                label="History retention"
                value={`${formatCount(visibleResourceHistory.length)} / ${formatCount(CHART_SAMPLE_LIMIT)}`}
                meta="5h TTL | current page session"
              />
            </div>

            <div className="resource-process-grid">
              <ProcessResourceCard label="Network engine" process={engineResources} />
              <ProcessResourceCard label="Dashboard BFF" process={dashboardResources} />
            </div>

            <div className="resource-chart-grid">
              <article className="resource-chart-card">
                <h3>CPU utilization trend</h3>
                <SeriesSelector
                  label="Visible CPU series"
                  options={cpuSeriesOptions.map((option) => ({
                    ...option,
                    detail: option.id === "engineCpuPercent"
                      ? processMetric(engineResources, engineResources?.cpuPercent, (value) => formatPercent(value))
                      : processMetric(dashboardResources, dashboardResources?.cpuPercent, (value) => formatPercent(value))
                  }))}
                  selectedIds={selectedCpuSeries}
                  controls="resource-cpu-chart"
                  onToggle={toggleCpuSeries}
                  action={<ChartExpandButton label="CPU utilization" onClick={() => openExpandedChart("cpu")} />}
                />
                <div className="resource-chart-canvas" id="resource-cpu-chart">
                  <MemoCpuTrendChart data={visibleResourceHistory} showEngine={showEngineCpu} showDashboard={showDashboardCpu} />
                </div>
                <p className="chart-note">Up to 5 hours of instantaneous process CPU; missing samples remain gaps.</p>
              </article>

              <article className="resource-chart-card">
                <h3>Resident memory trend</h3>
                <SeriesSelector
                  label="Visible RSS series"
                  options={memorySeriesOptions.map((option) => ({
                    ...option,
                    detail: option.id === "engineResidentMemoryBytes"
                      ? processMetric(engineResources, engineResources?.residentMemoryBytes, (value) => formatResourceBytes(value))
                      : processMetric(dashboardResources, dashboardResources?.residentMemoryBytes, (value) => formatResourceBytes(value))
                  }))}
                  selectedIds={selectedMemorySeries}
                  controls="resource-memory-chart"
                  onToggle={toggleMemorySeries}
                  action={<ChartExpandButton label="resident memory" onClick={() => openExpandedChart("memory")} />}
                />
                <div className="resource-chart-canvas" id="resource-memory-chart">
                  <MemoMemoryTrendChart data={visibleResourceHistory} showEngine={showEngineMemory} showDashboard={showDashboardMemory} />
                </div>
                <p className="chart-note">Up to 5 hours of current RSS, not cumulative allocation or virtual address space.</p>
              </article>
            </div>
          </section>

          <MemoRequestFailurePanel snapshot={requestFailures} />

          <section className="evidence-grid" id="diagnostic-evidence">
            <article className="panel chart-panel">
              <PanelHeading eyebrow="Latency trace" title="Probe rhythm" icon={<Wifi size={20} />} meta={`${visibleProbeHistory.length} browser-local results | ${probeRhythm.series.length} targets | 5h maximum`} />
              <SeriesSelector
                label="Visible probe targets"
                options={probeRhythm.series.map((series) => ({
                  id: series.target,
                  label: series.target,
                  color: probeColorByTarget.get(series.target) || "var(--chart-5)",
                  detail: `${series.successes} ok · ${series.failures} failed`,
                  disabled: series.successes === 0
                }))}
                selectedIds={selectedProbeTargets}
                controls="probe-rhythm-chart"
                onToggle={toggleProbeTarget}
                action={<ChartExpandButton label="probe rhythm" onClick={() => openExpandedChart("probe")} />}
              />
              <div className="probe-chart-canvas" id="probe-rhythm-chart">
                <MemoProbeTrendChart rhythm={probeRhythm} selectedTargets={selectedProbeTargets} colorByTarget={probeColorByTarget} />
              </div>
              <p className="chart-note">Up to 5 hours per browser session. Failed probes stay in the counters and are never converted to 0 ms or connected to another target.</p>
            </article>

            <article className="panel chart-panel event-signals">
              <PanelHeading eyebrow="Event signals" title="Composition and cadence" icon={<Activity size={20} />} meta={`${events.length} events in browser memory | cadence capped at 5h`} />
              <div className="event-chart-grid">
                <div>
                  <h3>Type composition</h3>
                  <EventTypeComposition items={mergedSnapshot.eventStats.byType} />
                </div>
                <div>
                  <div className="event-chart-heading">
                    <h3>Events per minute</h3>
                    <ChartExpandButton label="events per minute" onClick={() => openExpandedChart("events")} />
                  </div>
                  <div className="event-cadence-canvas">
                    <MemoEventCadenceChart data={visibleEventTimeline} gradientId="event-gradient-inline" />
                  </div>
                </div>
              </div>
            </article>
          </section>

          <section className="operations-grid">
            <article className="panel ops-panel">
              <PanelHeading eyebrow="Manual probe" title="Ping a host" icon={<TerminalSquare size={20} />} />
              <form className="probe-form" onSubmit={runPing}>
                <label htmlFor="ping-host">Hostname or IP</label>
                <div>
                  <input id="ping-host" value={pingHost} onChange={(event) => setPingHost(event.target.value)} placeholder="8.8.8.8" autoComplete="off" />
                  <button type="submit" disabled={pingLoading}>{pingLoading ? <RefreshCw className="spin" size={15} /> : <Activity size={15} />}{pingLoading ? "Running" : "Run probe"}</button>
                </div>
              </form>
              {pingError && <div className="notice error compact" role="alert">{pingError}</div>}
              <div className="probe-results">
                {displayedPings.map((item) => (
                  <article className={item.success ? "probe-result success" : "probe-result failed"} key={`${item.target}-${item.timestamp}`}>
                    <div><strong>{item.target}</strong><StatusTag tone={item.success ? "good" : "danger"}>{item.success ? "Success" : "Failed"}</StatusTag></div>
                    <p>{item.success ? formatMilliseconds(item.latencyMs) : item.error || item.result}</p>
                    <small>{item.interfaceName || "No interface"} · {formatDateTime(item.timestamp)}</small>
                  </article>
                ))}
              </div>
            </article>

            <article className="panel ai-panel">
              <PanelHeading eyebrow="Server-side AI" title="Diagnosis brief" icon={<Brain size={20} />} meta={mergedSnapshot.ai.configured ? `${mergedSnapshot.ai.generationProvider} · ${mergedSnapshot.ai.model}` : "Server key not configured"} />
              <p>The browser receives no provider key. The dashboard server sends only the current network evidence to the configured diagnosis bridge.</p>
              <div className="ai-metadata">
                <DataFact label="Bridge" value={mergedSnapshot.ai.provider || "n/a"} />
                <DataFact label="Generation" value={mergedSnapshot.ai.generationProvider || "n/a"} />
                <DataFact label="Model" value={mergedSnapshot.ai.model || "n/a"} />
              </div>
              <button className="analysis-button" type="button" onClick={runAnalysis} disabled={aiLoading || !mergedSnapshot.ai.configured}>
                {aiLoading ? <RefreshCw className="spin" size={15} /> : <Sparkles size={15} />}
                {aiLoading ? "Analyzing" : "Run AI analysis"}
              </button>
              {aiError && <div className="notice error compact" role="alert">{aiError}</div>}
              <pre className="analysis-output">{analysis || "AI analysis will appear here after the server key is configured."}</pre>
              <details className="bridge-details"><summary>Bridge details</summary><code>{mergedSnapshot.ai.baseUrl || "No base URL"}</code><code>{mergedSnapshot.ai.bridgePath || "No bridge path"}</code></details>
            </article>
          </section>

          <section className="panel timeline-panel">
            <PanelHeading eyebrow="Live event stream" title="What changed most recently" icon={<Server size={20} />} meta={`${events.length} deduplicated events`} />
            <div className="event-table">
              {events.length === 0 && <EmptyLine text="Waiting for JaNet events." />}
              {events.slice(-18).reverse().map((event) => (
                <article className="event-row" key={event.id}>
                  <time>{formatTime(event.timestamp)}</time>
                  <div><strong>{event.type}</strong><small>{event.source} · counter {event.counter} · priority {event.priority}</small></div>
                  <p>{event.message || "No event message"}</p>
                  {(event.details || event.trafficObservation) ? (
                    <details><summary>Evidence</summary><pre>{event.details || JSON.stringify(event.trafficObservation, null, 2)}</pre></details>
                  ) : <span className="no-details">No extra evidence</span>}
                </article>
              ))}
            </div>
          </section>

          {expandedChart && (
            <ChartAnalysisDialog
              title={expandedChartTitles[expandedChart]}
              description={expandedChartDescriptions[expandedChart]}
              sampleCount={expandedChartPoints.length}
              span={formatChartSpan(expandedChartPoints)}
              rangeMs={expandedRangeMs}
              onRangeChange={setExpandedRangeMs}
              onClose={() => setExpandedChart(null)}
            >
              {expandedChart === "traffic" && (
                <>
                  <SeriesSelector
                    label="Visible traffic data"
                    options={trafficSeriesOptions}
                    selectedIds={selectedTrafficSeries}
                    controls="expanded-traffic-chart"
                    onToggle={toggleTrafficSeries}
                  />
                  <div className="chart-analysis-canvas" id="expanded-traffic-chart">
                    <MemoTrafficTrendChart
                      data={expandedTrafficHistory}
                      showThroughput={showTrafficThroughput}
                      showPackets={showTrafficPackets}
                      showFlows={showTrafficFlows}
                      gradientId="traffic-gradient-expanded"
                      expanded
                    />
                  </div>
                </>
              )}
              {expandedChart === "cpu" && (
                <>
                  <SeriesSelector
                    label="Visible CPU series"
                    options={cpuSeriesOptions}
                    selectedIds={selectedCpuSeries}
                    controls="expanded-cpu-chart"
                    onToggle={toggleCpuSeries}
                  />
                  <div className="chart-analysis-canvas" id="expanded-cpu-chart">
                    <MemoCpuTrendChart data={expandedResourceHistory} showEngine={showEngineCpu} showDashboard={showDashboardCpu} expanded />
                  </div>
                </>
              )}
              {expandedChart === "memory" && (
                <>
                  <SeriesSelector
                    label="Visible RSS series"
                    options={memorySeriesOptions}
                    selectedIds={selectedMemorySeries}
                    controls="expanded-memory-chart"
                    onToggle={toggleMemorySeries}
                  />
                  <div className="chart-analysis-canvas" id="expanded-memory-chart">
                    <MemoMemoryTrendChart data={expandedResourceHistory} showEngine={showEngineMemory} showDashboard={showDashboardMemory} expanded />
                  </div>
                </>
              )}
              {expandedChart === "probe" && (
                <>
                  <SeriesSelector
                    label="Visible probe targets"
                    options={expandedProbeRhythm.series.map((series) => ({
                      id: series.target,
                      label: series.target,
                      color: probeColorByTarget.get(series.target) || "var(--chart-5)",
                      detail: `${series.successes} ok | ${series.failures} failed`,
                      disabled: series.successes === 0
                    }))}
                    selectedIds={selectedProbeTargets}
                    controls="expanded-probe-chart"
                    onToggle={toggleProbeTarget}
                  />
                  <div className="chart-analysis-canvas" id="expanded-probe-chart">
                    <MemoProbeTrendChart rhythm={expandedProbeRhythm} selectedTargets={selectedProbeTargets} colorByTarget={probeColorByTarget} expanded />
                  </div>
                </>
              )}
              {expandedChart === "events" && (
                <div className="chart-analysis-canvas chart-analysis-canvas-single" id="expanded-events-chart">
                  <MemoEventCadenceChart data={expandedEventTimeline} gradientId="event-gradient-expanded" expanded />
                </div>
              )}
            </ChartAnalysisDialog>
          )}
        </>
      )}
    </main>
  );
}

// Chrome 扩展只上报真实用户请求的失败终态；筛选只作用于服务端已有界结果，不复制长期历史。
function RequestFailurePanel({ snapshot }: { snapshot: RequestFailureSnapshot | null }) {
  const [hostFilter, setHostFilter] = useState("");
  const [failureFilter, setFailureFilter] = useState<RequestFailureFilter>("all");
  const observer = requestObserverState(snapshot);
  const hostNeedle = hostFilter.trim().toLowerCase();
  const activeKeys = useMemo(
    () => new Set((snapshot?.activeAlerts ?? []).map((alert) => requestFailureKey(alert.host, alert.failureCode))),
    [snapshot]
  );
  const filteredAlerts = useMemo(
    () => (snapshot?.activeAlerts ?? []).filter((alert) => {
      const matchesHost = !hostNeedle || alert.host.toLowerCase().includes(hostNeedle);
      return matchesHost && matchesRequestFailureFilter(alert, failureFilter, true);
    }),
    [failureFilter, hostNeedle, snapshot]
  );
  const filteredFailures = useMemo(
    () => (snapshot?.recentFailures ?? []).filter((failure) => {
      const matchesHost = !hostNeedle || failure.host.toLowerCase().includes(hostNeedle);
      const active = activeKeys.has(requestFailureKey(failure.host, failure.failureCode));
      return matchesHost && matchesRequestFailureFilter(failure, failureFilter, active);
    }),
    [activeKeys, failureFilter, hostNeedle, snapshot]
  );
  const visibleAlerts = filteredAlerts.slice(0, requestAlertVisibleLimit);
  const visibleFailures = filteredFailures.slice(0, requestFailureVisibleLimit);
  const contactAt = snapshot?.lastContactAt
    ?? Math.max(snapshot?.lastHeartbeatAt ?? 0, snapshot?.lastReceivedAt ?? 0);
  const contactMeta = contactAt
    ? `Last extension contact ${formatAge(contactAt)}`
    : "No extension contact received";
  const windowValue = snapshot
    ? `${snapshot.failuresInWindowCapped ? "≥" : ""}${formatCount(snapshot.failuresInWindow)}`
    : "n/a";

  return (
    <section className="panel request-failure-panel" data-testid="request-failure-watch">
      <PanelHeading
        eyebrow="Passive application layer"
        title="Real browser request failures"
        icon={<Globe2 size={20} />}
        meta={`${snapshot?.source || "chrome-mv3-webrequest"} | server-bounded recent failures`}
      />

      <div className="request-observer-explainer">
        <div>
          <strong>Chrome webRequest observes the user&apos;s real HTTP and HTTPS request terminal events.</strong>
          <p>JaNet does not create these requests, proxy browser traffic, or decrypt TLS.</p>
        </div>
        <div>
          <strong>HTTP response status and browser network errors are different evidence.</strong>
          <p>Received HTTP responses over HTTP or HTTPS show status codes such as 404, 429, or 500. DNS, TCP connection, and TLS handshake failures happen before an HTTP response, so Chrome reports a browser error instead.</p>
        </div>
      </div>

      <div className="request-failure-kpis">
        <DataFact
          label="Total failures"
          value={snapshot ? formatCount(snapshot.totalFailures) : "n/a"}
          meta="Cumulative accepted failures in this BFF process"
        />
        <DataFact
          label="Failures in window"
          value={windowValue}
          meta={snapshot?.failuresInWindowCapped
            ? "Lower bound because a bounded window was capped"
            : snapshot
              ? `${formatWindowSeconds(snapshot.windowSeconds)} sliding window`
              : "Window unavailable"}
          tone={snapshot?.failuresInWindow ? "warning" : "default"}
        />
        <DataFact
          label="Active alerts"
          value={snapshot ? formatCount(snapshot.activeAlerts.length) : "n/a"}
          meta={snapshot ? `${formatCount(snapshot.threshold)} matching failures per host and outcome` : "Threshold unavailable"}
          tone={snapshot?.activeAlerts.length ? "warning" : "default"}
        />
        <DataFact
          label="Extension contact"
          value={observer.value}
          meta={contactMeta}
          tone={observer.tone === "ok" ? "good" : observer.tone === "warn" ? "warning" : "muted"}
        />
      </div>

      <div className="request-failure-controls">
        <label className="request-host-filter" htmlFor="request-host-filter">
          <span>Host contains</span>
          <span className="request-host-input">
            <Search size={14} aria-hidden="true" />
            <input
              id="request-host-filter"
              type="search"
              value={hostFilter}
              onChange={(event) => setHostFilter(event.target.value)}
              placeholder="github.com"
              autoComplete="off"
            />
          </span>
        </label>
        <div className="request-class-filter">
          <span id="request-class-filter-label">Failure class</span>
          <div role="group" aria-labelledby="request-class-filter-label">
            {requestFailureFilters.map((option) => (
              <button
                key={option.id}
                type="button"
                aria-pressed={failureFilter === option.id}
                onClick={() => setFailureFilter(option.id)}
              >
                {option.label}
              </button>
            ))}
          </div>
        </div>
      </div>

      <div className="request-failure-layout">
        <section className="request-alert-region" aria-labelledby="request-alert-heading">
          <header>
            <div>
              <h3 id="request-alert-heading">Active threshold alerts</h3>
              <p>Same host and outcome within {snapshot ? formatWindowSeconds(snapshot.windowSeconds) : "the configured window"}.</p>
            </div>
            <span>{filteredAlerts.length} matching</span>
          </header>
          <div className="request-alert-list">
            {visibleAlerts.length === 0 && (
              <EmptyLine text={snapshot?.activeAlerts.length ? "No active alerts match the current filters." : "No request failure threshold is currently firing."} />
            )}
            {visibleAlerts.map((alert) => <RequestAlertRow alert={alert} key={alert.id} />)}
          </div>
          {filteredAlerts.length > visibleAlerts.length && (
            <p className="request-retention-note">Showing {visibleAlerts.length} of {filteredAlerts.length} matching active alerts.</p>
          )}
        </section>

        <section className="request-recent-region" aria-labelledby="request-recent-heading">
          <header>
            <div>
              <h3 id="request-recent-heading">Recent request failures</h3>
              <p>Newest first. URL path, query, fragment, credentials, headers, and bodies are not collected.</p>
            </div>
            <span>{filteredFailures.length} matching</span>
          </header>
          {visibleFailures.length === 0 ? (
            <EmptyLine text={snapshot?.recentFailures.length ? "No retained failures match the current host and failure-class filters." : "No real browser request failures have been received yet."} />
          ) : (
            <div className="request-failure-table-scroll">
              <table className="request-failure-table">
                <thead>
                  <tr>
                    <th>Time</th>
                    <th>Host</th>
                    <th>Method / type</th>
                    <th>Server IP</th>
                    <th>HTTP status / browser error</th>
                    <th>Category</th>
                  </tr>
                </thead>
                <tbody>
                  {visibleFailures.map((failure) => (
                    <tr key={failure.eventId}>
                      <td><time dateTime={new Date(failure.occurredAt).toISOString()}>{formatTime(failure.occurredAt)}</time><small>{formatAge(failure.occurredAt)}</small></td>
                      <td><strong title={failure.host}>{failure.host}</strong><small>Path omitted</small></td>
                      <td><strong>{failure.method}</strong><small>{failure.resourceType}{failure.fromCache ? " | cache" : ""}</small></td>
                      <td><code>{failure.serverIp || "n/a"}</code><small>{failure.scheme.toUpperCase()}:{failure.port}</small></td>
                      <td><strong className={`request-outcome ${requestOutcomeTone(failure)}`}>{requestOutcome(failure)}</strong><small>{failure.terminal === "completed" ? "HTTP response received" : "No HTTP response"}</small></td>
                      <td><StatusTag tone={requestCategoryTone(failure.category)}>{failure.category}</StatusTag></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          <p className="request-retention-note">
            Showing {visibleFailures.length} of {filteredFailures.length} matching failures. The BFF currently retains {formatCount(snapshot?.stats.recentSize ?? 0)} recent rows and bounds groups, IPs, dedupe keys, and alert transitions.
          </p>
        </section>
      </div>
    </section>
  );
}

const MemoRequestFailurePanel = memo(RequestFailurePanel);

function RequestAlertRow({ alert }: { alert: RequestFailureAlert }) {
  return (
    <article className="request-alert-row">
      <header>
        <div>
          <strong title={alert.host}>{alert.host}</strong>
          <small>{alert.resourceType || "other"} | last seen {formatAge(alert.lastSeenAt)}</small>
        </div>
        <StatusTag tone="danger">Firing</StatusTag>
      </header>
      <code className={`request-alert-code ${requestOutcomeTone(alert)}`}>{requestOutcome(alert)}</code>
      <dl>
        <div><dt>Window count</dt><dd>{formatCount(alert.countInWindow)} / {formatCount(alert.threshold)}</dd></div>
        <div><dt>Last server IP</dt><dd>{alert.lastIp || "n/a"}</dd></div>
      </dl>
    </article>
  );
}

type SeriesSelectorOption = {
  id: string;
  label: string;
  color: string;
  detail?: string;
  disabled?: boolean;
};

// 图例同时承担可键盘操作的多选控制；至少保留一条可绘序列，避免留下无解释的空图。
function SeriesSelector({
  label,
  options,
  selectedIds,
  controls,
  onToggle,
  action
}: {
  label: string;
  options: SeriesSelectorOption[];
  selectedIds: readonly string[];
  controls: string;
  onToggle: (id: string) => void;
  action?: ReactNode;
}) {
  const selectableCount = options.filter((option) => !option.disabled).length;
  const selectedCount = selectedIds.filter((id) => options.some((option) => option.id === id && !option.disabled)).length;
  return (
    <div className="series-picker">
      <div className="series-picker-heading">
        <div>
          <span>{label}</span>
          <small>{selectedCount} of {selectableCount} shown</small>
        </div>
        {action}
      </div>
      <div className="series-options" role="group" aria-label={label}>
        {options.map((option) => {
          const selected = selectedIds.includes(option.id);
          const lastVisible = selected && selectedCount === 1;
          const title = option.disabled
            ? `${option.label} has no successful samples to chart`
            : lastVisible
              ? `${option.label} is the last visible series`
              : `${selected ? "Hide" : "Show"} ${option.label}`;
          return (
            <button
              className={`series-option${option.detail ? " has-detail" : ""}`}
              key={option.id}
              type="button"
              data-series-id={option.id}
              aria-pressed={selected}
              aria-controls={controls}
              disabled={option.disabled}
              title={title}
              onClick={() => onToggle(option.id)}
            >
              <i className="legend-swatch" style={{ background: option.color }} aria-hidden="true" />
              <strong>{option.label}</strong>
              {option.detail && <small>{option.detail}</small>}
            </button>
          );
        })}
      </div>
    </div>
  );
}

function PanelHeading({ eyebrow, title, icon, meta }: { eyebrow: string; title: string; icon: ReactNode; meta?: string }) {
  return <div className="panel-heading"><div><span className="quiet-label">{eyebrow}</span><h2>{title}</h2>{meta && <p>{meta}</p>}</div><span className="heading-icon" aria-hidden="true">{icon}</span></div>;
}

function StatusPill({ ok, label, value, tone }: { ok: boolean; label: string; value: string; tone?: "ok" | "warn" | "muted" }) {
  return <span className={`status-pill ${tone || (ok ? "ok" : "warn")}`}><i />{label}<strong>{value}</strong></span>;
}

function StatusTag({ tone, children }: { tone: "good" | "warning" | "danger" | "muted"; children: ReactNode }) {
  return <span className={`status-tag ${tone}`}>{children}</span>;
}

function Kpi({ label, value, meta }: { label: string; value: string; meta: string }) {
  return <div className="kpi"><span>{label}</span><strong>{value}</strong><small>{meta}</small></div>;
}

function RouteFact({ label, value }: { label: string; value: string }) {
  return <div><span>{label}</span><strong>{value}</strong></div>;
}

function DataFact({ label, value, meta, tone = "default" }: { label: string; value: string; meta?: string; tone?: "default" | "good" | "warning" | "muted" }) {
  return <div className={`data-fact ${tone}`}><span>{label}</span><strong>{value}</strong>{meta && <small>{meta}</small>}</div>;
}

function processMetric(
  process: ProcessResourceMetrics | null,
  value: number | null | undefined,
  formatter: (next: number) => string
) {
  return process?.available && value !== null && value !== undefined && Number.isFinite(value)
    ? formatter(value)
    : "n/a";
}

function secondsWithPrecision(value: number) {
  return `${value.toFixed(value >= 100 ? 1 : 2).replace(/\.0+$/, "")} s`;
}

// 主视图保留可快速扫读的运行指标；完整内存、CPU 和调度计数放在同卡片的展开区。
function ProcessResourceCard({ label, process }: { label: string; process: ProcessResourceMetrics | null }) {
  const unavailableMetrics = process?.unavailableMetrics ?? [];
  const statusLabel = process?.available ? "Available" : "Unavailable";

  return (
    <article className="resource-process-card">
      <header>
        <div>
          <span className="quiet-label">{process?.component || label}</span>
          <h3>{label}</h3>
        </div>
        <div className="resource-process-status">
          <StatusTag tone={process?.available ? "good" : "muted"}>{statusLabel}</StatusTag>
          <small>{process ? `sampled ${formatAge(process.sampledAt)}` : "no process sample"}</small>
        </div>
      </header>
      <dl className="resource-primary-metrics">
        <ResourceMetric label="CPU" value={processMetric(process, process?.cpuPercent, (value) => formatPercent(value))} />
        <ResourceMetric label="Resident memory" value={processMetric(process, process?.residentMemoryBytes, (value) => formatResourceBytes(value))} />
        <ResourceMetric label="Threads" value={processMetric(process, process?.threadCount, (value) => formatCount(value))} />
        <ResourceMetric label="Open FDs" value={processMetric(process, process?.openFileDescriptors, (value) => formatCount(value))} />
        <ResourceMetric label="Uptime" value={processMetric(process, process?.uptimeSeconds, (value) => formatUptime(value))} />
        <ResourceMetric label="Voluntary ctx total" value={processMetric(process, process?.voluntaryContextSwitches, (value) => formatCount(value))} />
        <ResourceMetric label="Involuntary ctx total" value={processMetric(process, process?.involuntaryContextSwitches, (value) => formatCount(value))} />
        <ResourceMetric label="Active resources" value={processMetric(process, process?.activeResources, (value) => formatCount(value))} />
      </dl>
      <details className="resource-details">
        <summary>Extended process counters</summary>
        <dl>
          <ResourceMetric label="Peak RSS" value={processMetric(process, process?.peakResidentMemoryBytes, (value) => formatResourceBytes(value))} />
          <ResourceMetric label="Virtual memory" value={processMetric(process, process?.virtualMemoryBytes, (value) => formatResourceBytes(value))} />
          <ResourceMetric label="User CPU" value={processMetric(process, process?.userCpuSeconds, secondsWithPrecision)} />
          <ResourceMetric label="System CPU" value={processMetric(process, process?.systemCpuSeconds, secondsWithPrecision)} />
          <ResourceMetric label="Heap used" value={processMetric(process, process?.heapUsedBytes, (value) => formatResourceBytes(value))} />
          <ResourceMetric label="Heap total" value={processMetric(process, process?.heapTotalBytes, (value) => formatResourceBytes(value))} />
          <ResourceMetric label="External memory" value={processMetric(process, process?.externalMemoryBytes, (value) => formatResourceBytes(value))} />
          <ResourceMetric label="Array buffers" value={processMetric(process, process?.arrayBufferBytes, (value) => formatResourceBytes(value))} />
          <ResourceMetric label="Minor faults" value={processMetric(process, process?.minorPageFaults, (value) => formatCount(value))} />
          <ResourceMetric label="Major faults" value={processMetric(process, process?.majorPageFaults, (value) => formatCount(value))} />
        </dl>
      </details>
      {unavailableMetrics.length > 0 && (
        <p className="resource-unavailable"><strong>Unavailable metrics</strong>{unavailableMetrics.join(", ")}</p>
      )}
    </article>
  );
}

function ResourceMetric({ label, value }: { label: string; value: string }) {
  return <div><dt>{label}</dt><dd>{value}</dd></div>;
}

function Capability({ label, value, falseLabel = "Off", neutralWhenFalse = false }: { label: string; value: boolean; falseLabel?: string; neutralWhenFalse?: boolean }) {
  return <div className={`capability ${value ? "on" : neutralWhenFalse ? "neutral" : "off"}`}><span>{label}</span><strong>{value ? "On" : falseLabel}</strong></div>;
}

// SVG 固定轴宽会裁切长事件名；语义化排行条允许完整换行并展示全部类型。
function EventTypeComposition({ items }: { items: Array<{ name: string; value: number }> }) {
  const maxValue = Math.max(1, ...items.map((item) => item.value));
  if (items.length === 0) return <EmptyLine text="No event types have arrived yet." />;
  return (
    <div className="event-type-list" aria-label="Event type composition">
      {items.map((item) => (
        <div className="event-type-row" key={item.name}>
          <div className="event-type-heading">
            <strong title={item.name}>{item.name}</strong>
            <span>{formatCount(item.value)}</span>
          </div>
          <div className="event-type-meter" aria-hidden="true">
            <i style={{ width: `${Math.max(2, (item.value / maxValue) * 100)}%` }} />
          </div>
        </div>
      ))}
    </div>
  );
}

function CapacityBar({ label, entries, capacity }: { label: string; entries: number; capacity: number }) {
  const percent = capacityPercent(entries, capacity);
  return (
    <div className="capacity-bar">
      <div><span>{label}</span><strong>{formatCount(entries)} / {formatCount(capacity)} <small>{percent === null ? "n/a" : `${percent.toFixed(2)}%`}</small></strong></div>
      <div className="capacity-track" role="progressbar" aria-label={`${label} capacity`} aria-valuemin={0} aria-valuemax={100} aria-valuenow={percent ?? 0}><i style={{ width: `${percent ?? 0}%` }} /></div>
    </div>
  );
}

function CounterGroup({ title, items }: { title: string; items: Array<[string, number]> }) {
  return <div className="counter-group"><h3>{title}</h3><dl>{items.map(([label, value]) => <div key={label}><dt>{label}</dt><dd>{formatCount(value)}</dd></div>)}</dl></div>;
}

function InterfaceRow({ item, trafficTrusted }: { item: InterfaceSnapshot; trafficTrusted: boolean }) {
  const trafficAvailability = trafficTrusted ? item.trafficAvailability : "UNAVAILABLE";
  return (
    <tr>
      <td data-label="Interface"><strong>{item.interfaceName}</strong><small>{item.interfaceType}</small></td>
      <td data-label="Route and state"><div className="tag-row">{item.usingNow && <StatusTag tone="good">Active</StatusTag>}{item.isDefaultRoute && <StatusTag tone="muted">Default</StatusTag>}<StatusTag tone={item.state === "UP" ? "good" : "warning"}>{item.state}</StatusTag></div></td>
      <td data-label="RTT"><strong>{formatRtt(item.rttMs, item.rttAvailability)}</strong><small>{formatRttDelta(item.rttMs, item.previousRttMs, item.rttAvailability)} · {item.linkQuality}</small></td>
      <td data-label="RSSI"><strong>{formatRssi(item.rssiDbm, item.rssiAvailability)}</strong><small>{item.rssiAvailability}</small></td>
      <td data-label="TCP retrans."><strong>{availableMetric(item.tcpRetransmissionAvailability, item.tcpRetransmissionRatePercent, formatPercent)}</strong><small>{item.tcpRetransmissionLevel || item.tcpRetransmissionAvailability}</small></td>
      <td data-label="Traffic"><strong>{availableMetric(trafficAvailability, item.trafficBytesPerSecond, formatBytesPerSecond)}</strong><small>{availableMetric(trafficAvailability, item.trafficPacketsPerSecond, formatPacketsPerSecond)}</small></td>
      <td data-label="Flows"><strong>{availableMetric(trafficAvailability, item.activeFlows, formatCount)}</strong><small>{trafficAvailability}</small></td>
    </tr>
  );
}

function EmptyLine({ text }: { text: string }) {
  return <div className="empty-line">{text}</div>;
}

function Skeleton() {
  return <section className="skeleton-grid" aria-label="Loading dashboard"><div /><div /><div /></section>;
}

export default App;
