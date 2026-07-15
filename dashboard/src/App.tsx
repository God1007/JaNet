// JaNet Dashboard 主界面：把网络质量、流量采集可信度、Map 计数和诊断操作放进同一观测闭环。

import {
  Activity,
  Brain,
  Database,
  Gauge,
  Network,
  RefreshCw,
  Router,
  Server,
  ShieldCheck,
  Sparkles,
  Moon,
  Sun,
  TerminalSquare,
  Wifi
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
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { FormEvent, ReactNode } from "react";
import type {
  InterfaceSnapshot,
  NetworkEvent,
  Snapshot,
  TrafficMapObservability,
  TrafficSample
} from "./lib/types";
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
import { buildProbeRhythm } from "./lib/latency_series.mjs";
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
const apiBaseUrl = __API_BASE_URL__.replace(/\/$/, "");
const wsBaseUrl = __WS_BASE_URL__.replace(/\/$/, "");
type Theme = "light" | "dark";

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

// 管理浏览器到 BFF 的 WebSocket，并把首连历史和实时增量统一交给事件 reducer。
function useEventStream(onEvent: (event: NetworkEvent) => void) {
  const [connected, setConnected] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    const socket = new WebSocket(`${wsBaseUrl}/ws/events`);

    socket.onopen = () => {
      setConnected(true);
      setError("");
    };

    socket.onmessage = (message) => {
      try {
        const payload = JSON.parse(message.data);
        if (payload.type === "event") onEvent(payload.event);
        if (payload.type === "hello" && Array.isArray(payload.recentEvents)) {
          payload.recentEvents.forEach(onEvent);
        }
        if (payload.type === "stream") {
          setConnected(Boolean(payload.connected));
          setError(payload.error || "");
        }
      } catch {
        setError("Dashboard received an invalid event payload");
      }
    };

    socket.onerror = () => setError("Dashboard event socket failed");
    socket.onclose = () => setConnected(false);
    return () => socket.close();
  }, [onEvent]);

  return { connected, error };
}

// REST snapshot、WebSocket 增量与前端环形历史共同驱动整个实时看板。
function App() {
  const [theme, setTheme] = useState<Theme>(initialTheme);
  const [snapshot, setSnapshot] = useState<Snapshot | null>(null);
  const [events, setEvents] = useState<NetworkEvent[]>([]);
  const [trafficHistory, setTrafficHistory] = useState<TrafficSample[]>([]);
  const [selectedTrafficSeries, setSelectedTrafficSeries] = useState<string[]>(["bytesPerSecond"]);
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
  const requestInFlight = useRef(false);

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

  // 按事件 id 去重，只保留最近 120 条，避免长时间展示导致内存无界增长。
  const onEvent = useCallback((event: NetworkEvent) => {
    setEvents((current) => {
      if (current.some((item) => item.id === event.id)) return current;
      return [...current, event].sort((left, right) => left.timestamp - right.timestamp).slice(-120);
    });
  }, []);

  const eventStream = useEventStream(onEvent);

  // 每次 snapshot 只追加一个可信 generation；同代替换，服务重启时自动切断旧趋势。
  const loadSnapshot = useCallback(async () => {
    if (requestInFlight.current) return;
    requestInFlight.current = true;
    setRefreshing(true);
    try {
      setError("");
      const response = await fetch(`${apiBaseUrl}/api/snapshot`);
      if (!response.ok) throw new Error(await response.text());
      const next = (await response.json()) as Snapshot;
      setSnapshot(next);
      setLastUpdatedAt(Date.now());
      const trafficSample = createTrafficSample(next.networkSnapshot);
      if (trafficSample) {
        setTrafficHistory((current) => appendTrafficSample(current, trafficSample, 72));
      }
      setEvents((current) => {
        const merged = [...current, ...next.events];
        const unique = new Map(merged.map((event) => [event.id, event]));
        return Array.from(unique.values())
          .sort((left, right) => left.timestamp - right.timestamp)
          .slice(-120);
      });
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : String(caught));
    } finally {
      requestInFlight.current = false;
      setRefreshing(false);
      setLoading(false);
    }
  }, []);

  // 10 秒轮询与服务端流量分析周期对齐，前端历史明确只覆盖当前页面会话。
  useEffect(() => {
    loadSnapshot();
    const timer = window.setInterval(loadSnapshot, 10000);
    return () => window.clearInterval(timer);
  }, [loadSnapshot]);

  // WebSocket 事件覆盖 snapshot 的旧事件集合，图表聚合始终基于同一份去重数据。
  const mergedSnapshot = useMemo(() => {
    if (!snapshot) return null;
    return {
      ...snapshot,
      events,
      eventStats: {
        ...snapshot.eventStats,
        byType: Object.entries(
          events.reduce<Record<string, number>>((acc, event) => {
            acc[event.type] = (acc[event.type] || 0) + 1;
            return acc;
          }, {})
        )
          .map(([name, value]) => ({ name, value }))
          .sort((a, b) => b.value - a.value)
      }
    };
  }, [events, snapshot]);

  // 每个 target 使用独立 dataKey；失败值保持 null，但不再切断其他 target 的曲线。
  const probeRhythm = useMemo(
    () => buildProbeRhythm(mergedSnapshot?.latencySeries ?? []),
    [mergedSnapshot?.latencySeries]
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

  async function runAnalysis() {
    setAiLoading(true);
    setAiError("");
    try {
      const response = await fetch(`${apiBaseUrl}/api/analyze`, { method: "POST" });
      const payload = await response.json();
      if (!response.ok) throw new Error(payload.error || "AI analysis failed");
      setAnalysis(payload.analysis);
    } catch (caught) {
      setAiError(caught instanceof Error ? caught.message : String(caught));
    } finally {
      setAiLoading(false);
    }
  }

  async function runPing(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const hostname = pingHost.trim();
    if (!hostname || pingLoading) return;
    setPingLoading(true);
    setPingError("");
    try {
      const response = await fetch(`${apiBaseUrl}/api/ping`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ hostname })
      });
      const payload = await response.json();
      if (!response.ok) throw new Error(payload.error || "Ping probe failed");
      await loadSnapshot();
    } catch (caught) {
      setPingError(caught instanceof Error ? caught.message : String(caught));
    } finally {
      setPingLoading(false);
    }
  }

  const network = mergedSnapshot?.networkSnapshot ?? null;
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
  const previousTrafficSample = trafficHistory.length > 1 ? trafficHistory.at(-2) ?? null : null;
  const latestTrafficSample = trafficHistory.at(-1) ?? null;
  const packetDelta = latestTrafficSample && previousTrafficSample
    ? counterDelta(latestTrafficSample.packetsSeen, previousTrafficSample.packetsSeen)
    : null;
  const showTrafficThroughput = selectedTrafficSeries.includes("bytesPerSecond");
  const showTrafficPackets = selectedTrafficSeries.includes("packetsPerSecond");
  const showTrafficFlows = selectedTrafficSeries.includes("activeFlows");
  const showTrafficCounts = showTrafficPackets || showTrafficFlows;

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
            <StatusPill ok={eventStream.connected} label="Events" value={eventStream.connected ? "live" : "offline"} />
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
              onClick={loadSnapshot}
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
                  meta={`${trafficHistory.length} trusted generations retained`}
                />
                <div className="traffic-layout">
                  <div className="chart-region">
                    <SeriesSelector
                      label="Visible traffic data"
                      options={trafficSeriesOptions}
                      selectedIds={selectedTrafficSeries}
                      controls="traffic-chart"
                      onToggle={toggleTrafficSeries}
                    />
                    {/* 桌面双栏时随右侧事实列表拉伸，充分利用该网格行原本空出的纵向空间。 */}
                    <div className="traffic-chart-canvas" id="traffic-chart">
                      <ResponsiveContainer width="100%" height="100%">
                        <ComposedChart data={trafficHistory} margin={{ top: 12, right: 8, bottom: 0, left: 0 }}>
                          <defs>
                            <linearGradient id="trafficGradient" x1="0" x2="0" y1="0" y2="1">
                              <stop offset="4%" stopColor="var(--accent)" stopOpacity={0.28} />
                              <stop offset="96%" stopColor="var(--accent)" stopOpacity={0.01} />
                            </linearGradient>
                          </defs>
                          <CartesianGrid stroke="var(--chart-grid)" vertical={false} />
                          <XAxis dataKey="time" stroke="var(--chart-axis)" tickLine={false} axisLine={false} minTickGap={30} />
                          {showTrafficThroughput && <YAxis yAxisId="bytes" stroke="var(--chart-axis)" tickLine={false} axisLine={false} width={72} tickFormatter={(value) => formatBytesPerSecond(value)} />}
                          {showTrafficCounts && <YAxis yAxisId="count" orientation="right" stroke="var(--chart-axis)" tickLine={false} axisLine={false} width={44} allowDecimals={false} />}
                          <Tooltip contentStyle={{ background: "var(--chart-tooltip-bg)", border: "1px solid var(--chart-tooltip-border)", borderRadius: 6, color: "var(--chart-tooltip-text)" }} labelStyle={{ color: "var(--chart-tooltip-text)" }} itemStyle={{ color: "var(--chart-tooltip-text)" }} />
                          {showTrafficThroughput && <Area yAxisId="bytes" type="monotone" dataKey="bytesPerSecond" stroke="var(--chart-1)" fill="url(#trafficGradient)" strokeWidth={2} name="Throughput B/s" isAnimationActive={false} />}
                          {showTrafficPackets && <Line yAxisId="count" type="monotone" dataKey="packetsPerSecond" stroke="var(--chart-2)" strokeWidth={1.8} dot={false} name="Packets/s" isAnimationActive={false} />}
                          {showTrafficFlows && <Line yAxisId="count" type="monotone" dataKey="activeFlows" stroke="var(--chart-3)" strokeWidth={1.8} dot={false} name="Active flows" isAnimationActive={false} />}
                        </ComposedChart>
                      </ResponsiveContainer>
                    </div>
                    <p className="chart-note">Browser-local history. Repeated generations replace the last point; a server restart starts a new series.</p>
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

          <section className="evidence-grid" id="diagnostic-evidence">
            <article className="panel chart-panel">
              <PanelHeading eyebrow="Latency trace" title="Probe rhythm" icon={<Wifi size={20} />} meta={`${mergedSnapshot.latencySeries.length} retained results · ${probeRhythm.series.length} targets`} />
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
              />
              <div id="probe-rhythm-chart">
                <ResponsiveContainer width="100%" height={250}>
                  <LineChart data={probeRhythm.points}>
                  <CartesianGrid stroke="var(--chart-grid)" vertical={false} />
                  <XAxis type="number" dataKey="timestamp" domain={["dataMin", "dataMax"]} tickFormatter={(value) => formatTime(Number(value))} stroke="var(--chart-axis)" tickLine={false} axisLine={false} minTickGap={30} />
                  <YAxis stroke="var(--chart-axis)" tickLine={false} axisLine={false} width={52} tickFormatter={(value) => `${value} ms`} />
                  <Tooltip labelFormatter={(value) => formatDateTime(Number(value))} contentStyle={{ background: "var(--chart-tooltip-bg)", border: "1px solid var(--chart-tooltip-border)", borderRadius: 6, color: "var(--chart-tooltip-text)" }} labelStyle={{ color: "var(--chart-tooltip-text)" }} itemStyle={{ color: "var(--chart-tooltip-text)" }} />
                  {probeRhythm.series.filter((series) => selectedProbeTargets.includes(series.target)).map((series) => (
                    <Line key={series.key} type="monotone" dataKey={series.key} connectNulls stroke={probeColorByTarget.get(series.target) || "var(--chart-5)"} strokeWidth={2} dot={false} name={series.target} isAnimationActive={false} />
                  ))}
                  </LineChart>
                </ResponsiveContainer>
              </div>
              <p className="chart-note">Each target owns one continuous line. Failed probes stay in the counters and are never converted to 0 ms or connected to another target.</p>
            </article>

            <article className="panel chart-panel event-signals">
              <PanelHeading eyebrow="Event signals" title="Composition and cadence" icon={<Activity size={20} />} meta={`${events.length} events in browser memory`} />
              <div className="event-chart-grid">
                <div>
                  <h3>Type composition</h3>
                  <EventTypeComposition items={mergedSnapshot.eventStats.byType} />
                </div>
                <div>
                  <h3>Events per minute</h3>
                  <ResponsiveContainer width="100%" height={215}>
                    <AreaChart data={mergedSnapshot.eventStats.timeline}>
                      <defs><linearGradient id="eventGradient" x1="0" x2="0" y1="0" y2="1"><stop offset="5%" stopColor="var(--chart-2)" stopOpacity={0.3} /><stop offset="95%" stopColor="var(--chart-2)" stopOpacity={0.01} /></linearGradient></defs>
                      <CartesianGrid stroke="var(--chart-grid-soft)" vertical={false} />
                      <XAxis dataKey="time" stroke="var(--chart-axis)" tickLine={false} axisLine={false} minTickGap={30} />
                      <YAxis allowDecimals={false} stroke="var(--chart-axis)" tickLine={false} axisLine={false} width={34} />
                      <Tooltip contentStyle={{ background: "var(--chart-tooltip-bg)", border: "1px solid var(--chart-tooltip-border)", borderRadius: 6, color: "var(--chart-tooltip-text)" }} labelStyle={{ color: "var(--chart-tooltip-text)" }} itemStyle={{ color: "var(--chart-tooltip-text)" }} />
                      <Area type="monotone" dataKey="total" stroke="var(--chart-2)" fill="url(#eventGradient)" strokeWidth={2} name="Events" isAnimationActive={false} />
                    </AreaChart>
                  </ResponsiveContainer>
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
                {mergedSnapshot.pings.map((item) => (
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
        </>
      )}
    </main>
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
  onToggle
}: {
  label: string;
  options: SeriesSelectorOption[];
  selectedIds: readonly string[];
  controls: string;
  onToggle: (id: string) => void;
}) {
  const selectableCount = options.filter((option) => !option.disabled).length;
  const selectedCount = selectedIds.filter((id) => options.some((option) => option.id === id && !option.disabled)).length;
  return (
    <div className="series-picker">
      <div className="series-picker-heading">
        <span>{label}</span>
        <small>{selectedCount} of {selectableCount} shown</small>
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

function StatusPill({ ok, label, value }: { ok: boolean; label: string; value: string }) {
  return <span className={ok ? "status-pill ok" : "status-pill warn"}><i />{label}<strong>{value}</strong></span>;
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
