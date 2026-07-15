// Dashboard 主界面：轮询 snapshot、接收实时事件，并呈现质量、探测与 AI 诊断状态。

import {
  Activity,
  Brain,
  Gauge,
  Network,
  RefreshCw,
  Router,
  Server,
  ShieldCheck,
  Sparkles,
  TerminalSquare,
  Wifi
} from "lucide-react";
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Line,
  LineChart,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis
} from "recharts";
import { useCallback, useEffect, useMemo, useState } from "react";
import type { NetworkEvent, Snapshot } from "./lib/types";
import { formatMilliseconds } from "./lib/rtt_format.mjs";

const chartColors = ["#63d471", "#48b8d0", "#f0b35a", "#f07167", "#b9c0c8", "#8fd0a6"];
const apiBaseUrl = __API_BASE_URL__.replace(/\/$/, "");
const wsBaseUrl = __WS_BASE_URL__.replace(/\/$/, "");

// 将毫秒时间戳格式化为用户本地时间。
function formatTime(value: number) {
  return new Date(value).toLocaleTimeString();
}

// 把服务端质量分数映射为面向用户的等级文案。
function scoreLabel(score: number | null) {
  if (score === null) return "No score";
  if (score >= 90) return "Excellent";
  if (score >= 75) return "Good";
  if (score >= 50) return "Fair";
  return "Poor";
}

// 统一处理空指标，避免卡片渲染 undefined 或空字符串。
function metricValue(value: unknown, fallback = "n/a") {
  if (value === null || value === undefined || value === "") return fallback;
  return String(value);
}

// 管理浏览器 WebSocket 生命周期，并把服务端事件交给调用方去重入库。
function useEventStream(onEvent: (event: NetworkEvent) => void) {
  const [connected, setConnected] = useState(false);
  const [error, setError] = useState("");

  // Hook 创建或 onEvent 变化时重建唯一 WebSocket，并在清理函数中关闭。
  useEffect(() => {
    const socket = new WebSocket(`${wsBaseUrl}/ws/events`);

    // 浏览器到 BFF 的 WebSocket 建立后清除旧错误。
    socket.onopen = () => {
      setConnected(true);
      setError("");
    };

    // 分流增量事件、首连历史事件和服务端 stream 状态消息。
    socket.onmessage = (message) => {
      const payload = JSON.parse(message.data);
      if (payload.type === "event") {
        onEvent(payload.event);
      }
      if (payload.type === "hello" && Array.isArray(payload.recentEvents)) {
        payload.recentEvents.forEach(onEvent);
      }
      if (payload.type === "stream") {
        setConnected(Boolean(payload.connected));
        setError(payload.error || "");
      }
    };

    // 记录浏览器侧 socket 建连或传输失败。
    socket.onerror = () => {
      setError("Dashboard event socket failed");
    };

    // 关闭时只更新连接状态，组件卸载清理也走该分支。
    socket.onclose = () => {
      setConnected(false);
    };

    // Hook 重建或组件卸载时主动关闭旧连接，避免重复订阅。
    return () => socket.close();
  }, [onEvent]);

  return { connected, error };
}

// 组合 REST snapshot、WebSocket 增量事件和用户操作，驱动整个看板页面。
function App() {
  const [snapshot, setSnapshot] = useState<Snapshot | null>(null);
  const [events, setEvents] = useState<NetworkEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [aiLoading, setAiLoading] = useState(false);
  const [aiError, setAiError] = useState("");
  const [analysis, setAnalysis] = useState("");
  const [pingHost, setPingHost] = useState("8.8.8.8");

  // 按事件 id 去重，并只保留最近 120 条用于图表和时间线。
  const onEvent = useCallback((event: NetworkEvent) => {
    setEvents((current) => {
      if (current.some((item) => item.id === event.id)) return current;
      return [...current.slice(-119), event];
    });
  }, []);

  useEventStream(onEvent);

  // 拉取最新 snapshot，并与 WebSocket 已收到的事件合并，避免轮询覆盖实时增量。
  const loadSnapshot = useCallback(async () => {
    try {
      setError("");
      const response = await fetch(`${apiBaseUrl}/api/snapshot`);
      if (!response.ok) throw new Error(await response.text());
      const next = (await response.json()) as Snapshot;
      setSnapshot(next);
      setEvents((current) => {
        const merged = [...current, ...next.events];
        const unique = new Map(merged.map((event) => [event.id, event]));
        return Array.from(unique.values()).slice(-120);
      });
    } catch (caught) {
      // REST 错误只更新提示，保留上一份 snapshot 避免页面整体清空。
      setError(caught instanceof Error ? caught.message : String(caught));
    } finally {
      setLoading(false);
    }
  }, []);

  // 首次立即加载，随后每 15 秒刷新一次服务端状态和主动探测数据。
  useEffect(() => {
    loadSnapshot();
    const timer = window.setInterval(loadSnapshot, 15000);
    return () => window.clearInterval(timer);
  }, [loadSnapshot]);

  // 用实时事件重算类型分布，同时保留 snapshot 中的其他聚合结果。
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

  // 请求服务端基于最新 snapshot 执行 AI 分析，并维护独立加载/错误状态。
  async function runAnalysis() {
    setAiLoading(true);
    setAiError("");
    try {
      const response = await fetch(`${apiBaseUrl}/api/analyze`, { method: "POST" });
      const payload = await response.json();
      if (!response.ok) throw new Error(payload.error || "AI analysis failed");
      setAnalysis(payload.analysis);
    } catch (caught) {
      // AI 请求失败独立展示，不影响其他实时指标和手动探测。
      setAiError(caught instanceof Error ? caught.message : String(caught));
    } finally {
      setAiLoading(false);
    }
  }

  // 提交用户指定的 Ping 目标，成功后刷新 snapshot 和延迟图。
  async function runPing() {
    const hostname = pingHost.trim();
    if (!hostname) return;
    const response = await fetch(`${apiBaseUrl}/api/ping`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ hostname })
    });
    if (response.ok) {
      loadSnapshot();
    }
  }

  const healthParsed = mergedSnapshot?.health.parsed ?? {};
  const score = mergedSnapshot?.health.score ?? null;
  const scoreOffset = 326 - ((score ?? 0) / 100) * 326;

  return (
    <main className="app-shell">
      <section className="topbar">
        <div>
          <div className="product-mark">
            <span className="mark-icon">
              <Activity size={18} />
            </span>
            WeakNet Observatory
          </div>
          <h1>Live diagnosis.</h1>
          <p>
            A local gRPC dashboard for events, quality, ping probes and server-side AI analysis.
          </p>
        </div>
        <div className="status-cluster" aria-live="polite">
          <StatusPill ok={Boolean(mergedSnapshot?.grpc.ok)} label="gRPC" />
          <StatusPill ok={Boolean(mergedSnapshot?.stream.connected)} label="Events" />
          <StatusPill ok={Boolean(mergedSnapshot?.ai.configured)} label="AI server key" />
          <button className="icon-button" onClick={loadSnapshot} title="Refresh snapshot" type="button">
            <RefreshCw size={18} />
          </button>
        </div>
      </section>

      {/* REST 采集失败与 gRPC 不可达分开呈现，便于定位 BFF 和后端边界。 */}
      {error && <div className="notice error">Dashboard cannot collect the latest snapshot: {error}</div>}
      {mergedSnapshot && !mergedSnapshot.grpc.ok && (
        <div className="notice error">
          gRPC server is not reachable at {mergedSnapshot.grpcAddress}. {mergedSnapshot.grpc.errors[0] || "No server response."}
        </div>
      )}
      {/* 首次 snapshot 返回前使用骨架屏，后续轮询不打断现有内容。 */}
      {loading && <Skeleton />}

      {/* 只有存在可用 snapshot 时才渲染指标、图表和操作区域。 */}
      {mergedSnapshot && (
        <>
          <section className="story-grid">
            <div className="quality-panel">
              <div className="panel-heading">
                <div>
                  <span className="quiet-label">Quality index</span>
                  <h2>{scoreLabel(score)}</h2>
                </div>
                <Gauge size={24} />
              </div>
              <div className="quality-orbit">
                <svg viewBox="0 0 120 120" role="img" aria-label="Network quality score">
                  <circle className="orbit-track" cx="60" cy="60" r="52" />
                  <circle className="orbit-value" cx="60" cy="60" r="52" strokeDashoffset={scoreOffset} />
                </svg>
                <div>
                  <strong>{score === null ? "--" : score.toFixed(1)}</strong>
                  <span>/ 100</span>
                </div>
              </div>
              <div className="metric-rail">
                <Metric label="Interface" value={metricValue(healthParsed.interface)} />
                <Metric label="RTT" value={formatMilliseconds(healthParsed.rtt_ms)} />
                <Metric label="TCP loss" value={`${metricValue(healthParsed.tcp_loss_rate)}%`} />
                <Metric label="RSSI" value={`${metricValue(healthParsed.rssi_dbm)} dBm`} />
              </div>
            </div>

            <div className="chart-panel wide">
              <div className="panel-heading">
                <div>
                  <span className="quiet-label">Latency trace</span>
                  <h2>Probe rhythm</h2>
                </div>
                <Wifi size={24} />
              </div>
              <ResponsiveContainer width="100%" height={245}>
                <LineChart data={mergedSnapshot.latencySeries.filter((item) => item.latencyMs !== null)}>
                  <CartesianGrid stroke="rgba(255,255,255,0.07)" vertical={false} />
                  <XAxis dataKey="time" stroke="#7b858f" tickLine={false} axisLine={false} minTickGap={28} />
                  <YAxis stroke="#7b858f" tickLine={false} axisLine={false} width={42} />
                  <Tooltip contentStyle={{ background: "#11161c", border: "1px solid #27313b", borderRadius: 8 }} />
                  <Line type="monotone" dataKey="latencyMs" stroke="#63d471" strokeWidth={2.5} dot={false} name="Latency ms" />
                </LineChart>
              </ResponsiveContainer>
            </div>

            <div className="interface-panel">
              <div className="panel-heading">
                <div>
                  <span className="quiet-label">Interfaces</span>
                  <h2>{mergedSnapshot.interfaces.length || 0} observed</h2>
                </div>
                <Router size={24} />
              </div>
              <div className="interface-list">
                {mergedSnapshot.interfaces.length === 0 && <EmptyLine text="No interfaces returned by gRPC." />}
                {mergedSnapshot.interfaces.map((name) => (
                  <div className="interface-row" key={name}>
                    <Network size={18} />
                    <span>{name}</span>
                  </div>
                ))}
              </div>
            </div>
          </section>

          <section className="grid-two">
            <div className="chart-panel">
              <div className="panel-heading">
                <div>
                  <span className="quiet-label">Event composition</span>
                  <h2>Signal mix</h2>
                </div>
                <ShieldCheck size={24} />
              </div>
              <ResponsiveContainer width="100%" height={260}>
                <PieChart>
                  <Pie data={mergedSnapshot.eventStats.byType} innerRadius={64} outerRadius={96} paddingAngle={4} dataKey="value" nameKey="name">
                    {mergedSnapshot.eventStats.byType.map((entry, index) => (
                      <Cell key={entry.name} fill={chartColors[index % chartColors.length]} />
                    ))}
                  </Pie>
                  <Tooltip contentStyle={{ background: "#11161c", border: "1px solid #27313b", borderRadius: 8 }} />
                </PieChart>
              </ResponsiveContainer>
              <div className="legend-list">
                {mergedSnapshot.eventStats.byType.length === 0 && <EmptyLine text="No events have arrived yet." />}
                {mergedSnapshot.eventStats.byType.slice(0, 5).map((item, index) => (
                  <span key={item.name}>
                    <i style={{ background: chartColors[index % chartColors.length] }} />
                    {item.name} ({item.value})
                  </span>
                ))}
              </div>
            </div>

            <div className="chart-panel">
              <div className="panel-heading">
                <div>
                  <span className="quiet-label">Event cadence</span>
                  <h2>Changes over time</h2>
                </div>
                <Activity size={24} />
              </div>
              <ResponsiveContainer width="100%" height={260}>
                <AreaChart data={mergedSnapshot.eventStats.timeline}>
                  <defs>
                    <linearGradient id="eventGradient" x1="0" x2="0" y1="0" y2="1">
                      <stop offset="5%" stopColor="#63d471" stopOpacity={0.55} />
                      <stop offset="95%" stopColor="#63d471" stopOpacity={0.02} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid stroke="rgba(255,255,255,0.07)" vertical={false} />
                  <XAxis dataKey="time" stroke="#7b858f" tickLine={false} axisLine={false} minTickGap={28} />
                  <YAxis allowDecimals={false} stroke="#7b858f" tickLine={false} axisLine={false} width={34} />
                  <Tooltip contentStyle={{ background: "#11161c", border: "1px solid #27313b", borderRadius: 8 }} />
                  <Area type="monotone" dataKey="total" stroke="#63d471" fill="url(#eventGradient)" strokeWidth={2} />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </section>

          <section className="grid-two">
            <div className="ops-panel">
              <div className="panel-heading">
                <div>
                  <span className="quiet-label">Manual probe</span>
                  <h2>Ping a host</h2>
                </div>
                <TerminalSquare size={24} />
              </div>
              <div className="probe-form">
                <label htmlFor="ping-host">Hostname or IP</label>
                <div>
                  <input id="ping-host" value={pingHost} onChange={(event) => setPingHost(event.target.value)} placeholder="8.8.8.8" />
                  <button type="button" onClick={runPing}>
                    <RefreshCw size={16} />
                    Run
                  </button>
                </div>
              </div>
              <ResponsiveContainer width="100%" height={220}>
                <BarChart data={mergedSnapshot.pings}>
                  <CartesianGrid stroke="rgba(255,255,255,0.07)" vertical={false} />
                  <XAxis dataKey="target" stroke="#7b858f" tickLine={false} axisLine={false} />
                  <YAxis stroke="#7b858f" tickLine={false} axisLine={false} width={42} />
                  <Tooltip contentStyle={{ background: "#11161c", border: "1px solid #27313b", borderRadius: 8 }} />
                  <Bar dataKey="latencyMs" radius={[6, 6, 0, 0]} name="Latency ms">
                    {mergedSnapshot.pings.map((item, index) => (
                      <Cell key={item.target} fill={item.success ? chartColors[index % chartColors.length] : "#f07167"} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>

            <div className="ai-panel">
              <div className="panel-heading">
                <div>
                  <span className="quiet-label">Server-side AI</span>
                  <h2>Diagnosis brief</h2>
                </div>
                <Brain size={24} />
              </div>
              <p>
                The browser never receives an API key. The dashboard server reads it from the terminal or environment and sends only network evidence.
              </p>
              {/* AI Key 仅保存在 Node 服务端；前端只提交无敏感参数的分析请求。 */}
              <button className="analysis-button" type="button" onClick={runAnalysis} disabled={aiLoading}>
                {aiLoading ? <RefreshCw className="spin" size={16} /> : <Sparkles size={16} />}
                {aiLoading ? "Analyzing" : "Run AI analysis"}
              </button>
              {aiError && <div className="notice error compact">{aiError}</div>}
              <pre className="analysis-output">{analysis || "AI analysis will appear here after the server key is configured."}</pre>
            </div>
          </section>

          <section className="timeline-panel">
            <div className="panel-heading">
              <div>
                <span className="quiet-label">Live event stream</span>
                <h2>What changed most recently</h2>
              </div>
              <Server size={24} />
            </div>
            <div className="event-table">
              {events.length === 0 && <EmptyLine text="Waiting for WeakNet events." />}
              {events.slice(-12).reverse().map((event) => (
                <div className="event-row" key={event.id}>
                  <span>{formatTime(event.timestamp)}</span>
                  <strong>{event.type}</strong>
                  <p>{event.message || event.details || "No message"}</p>
                  <em>{event.source}</em>
                </div>
              ))}
            </div>
          </section>
        </>
      )}
    </main>
  );
}

// 用统一视觉语义展示 gRPC、事件流和 AI 配置是否就绪。
function StatusPill({ ok, label }: { ok: boolean; label: string }) {
  return (
    <span className={ok ? "status-pill ok" : "status-pill warn"}>
      <i />
      {label}
    </span>
  );
}

// 渲染质量卡片中的单个标签和值。
function Metric({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

// 在列表或图表没有数据时提供一致的空状态提示。
function EmptyLine({ text }: { text: string }) {
  return <div className="empty-line">{text}</div>;
}

// 首屏加载期间展示固定布局骨架，减少内容跳动。
function Skeleton() {
  return (
    <section className="skeleton-grid" aria-label="Loading dashboard">
      <div />
      <div />
      <div />
    </section>
  );
}

export default App;
