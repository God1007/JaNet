// Dashboard 诊断契约层：把 Python RAG bridge 输出规范化为稳定 API schema，并在 bridge
// 不可用时生成显式 typed-snapshot fallback。HTTP/JSON/schema 成功只表示传输契约成立；
// degraded、provider 与 error 才说明业务是否降级以及是否走了 bridge fallback。

export const DIAGNOSIS_SCHEMA_VERSION = "weaknet.diagnosis.v1";

// 把数值字段收敛为有限数；NaN/Infinity 或非法文本使用调用方给出的安全默认值。
function finiteNumber(value, fallback) {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : fallback;
}

// 规范化字符串集合并去重，避免 evidence/action 在跨语言桥接后重复展示。
function uniqueStrings(values) {
  return Array.from(new Set((Array.isArray(values) ? values : []).map(String).filter(Boolean)));
}

// 将 Python bridge 的证据项转换成前端稳定字段；来源 revision/anchor/excerpt/checksum
// 原样进入 API，供调用方追溯证据，而不把跨语言对象的额外字段泄漏成隐式契约。
function normalizeEvidence(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return null;
  }
  return {
    kind: String(value.kind || "observation"),
    source: String(value.source || "typed_network_snapshot"),
    summary: String(value.summary || ""),
    ...(value.metric ? { metric: String(value.metric) } : {}),
    ...(value.value !== undefined ? { value: value.value } : {}),
    ...(value.knowledge_entry_id ? { knowledge_entry_id: String(value.knowledge_entry_id) } : {}),
    ...(value.chunk_id ? { chunk_id: String(value.chunk_id) } : {}),
    ...(value.content_hash ? { content_hash: String(value.content_hash) } : {}),
    ...(value.knowledge_store ? { knowledge_store: String(value.knowledge_store) } : {}),
    ...(value.artifact_version ? { artifact_version: String(value.artifact_version) } : {}),
    ...(value.source_revision ? { source_revision: String(value.source_revision) } : {}),
    ...(value.source_sha256 ? { source_sha256: String(value.source_sha256) } : {}),
    ...(value.source_anchor && typeof value.source_anchor === "object"
      ? { source_anchor: { ...value.source_anchor } }
      : {}),
    ...(value.source_excerpt ? { source_excerpt: String(value.source_excerpt) } : {}),
    ...(Number.isFinite(Number(value.score)) ? { score: Number(value.score) } : {})
  };
}

// 把任意 bridge 响应收敛为前端和调用方可依赖的固定字段集合。
// 校验并规范化一份 bridge 诊断；返回值始终符合 Dashboard 对外 schema。
export function normalizeDiagnosis(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError("RAG bridge must return a JSON object");
  }

  // status 描述网络诊断结果，不描述 HTTP 是否成功；unknown 是非法业务状态的安全收敛值。
  const allowedStatuses = new Set([
    "healthy", "degraded", "unhealthy", "unknown", "insufficient_evidence", "unavailable"
  ]);
  const status = String(value.status || "unknown").toLowerCase();
  const evidence = (Array.isArray(value.evidence) ? value.evidence : [])
    .map(normalizeEvidence)
    .filter(Boolean);
  // bridge 可能只在 evidence 中返回知识 ID；合并两处并去重，保证引用集合完整且稳定。
  const knowledgeEntryIds = uniqueStrings([
    ...(Array.isArray(value.knowledge_entry_ids) ? value.knowledge_entry_ids : []),
    ...evidence.map((item) => item.knowledge_entry_id).filter(Boolean)
  ]);

  // normalize 只建立 schema，不把 degraded/fallback 偷换成成功；业务层仍需检查这些字段。
  return {
    schema_version: DIAGNOSIS_SCHEMA_VERSION,
    status: allowedStatuses.has(status) ? status : "unknown",
    evidence,
    knowledge_entry_ids: knowledgeEntryIds,
    confidence: Math.max(0, Math.min(1, finiteNumber(value.confidence, 0))),
    actions: uniqueStrings(value.actions),
    degraded: Boolean(value.degraded),
    provider: String(value.provider || "unknown"),
    artifact_version: String(value.artifact_version || "unavailable"),
    top_k: Math.max(1, Math.trunc(finiteNumber(value.top_k, 4))),
    similarity_threshold: finiteNumber(value.similarity_threshold, 0.08),
    error: String(value.error || "")
  };
}

// 当 bridge、索引或 RAG 依赖不可用时，只基于 typed snapshot 给出保守结论并显式降级。
// 当 Python/RAG 不可用时，从 typed snapshot 构造显式 degraded 结果。
// 该路径必须携带 provider/reason，不能伪装成在线 RAG 成功。
export function buildDegradedDiagnosis(networkSnapshot, reason) {
  const quality = networkSnapshot?.quality || {};
  const explicitlyNoActive = networkSnapshot?.hasActiveInterface === false;
  // hasActiveInterface=false 是 typed snapshot 的权威状态；即使列表残留旧指标也必须丢弃。
  const active = explicitlyNoActive
    ? null
    : networkSnapshot?.interfaces?.find((item) => item.usingNow)
      || networkSnapshot?.interfaces?.[0]
      || null;
  const evidence = [];
  const actions = ["检查 RAG bridge 与知识库 artifact 后重新运行诊断。"];

  if (!active) {
    evidence.push({
      kind: "state",
      source: "typed_network_snapshot",
      summary: "快照中没有可诊断的网络接口。"
    });
    actions.push("确认接口发现与默认路由监控线程正在运行。");
  } else {
    for (const [metric, value, unit] of [
      ["rtt_ms", active.rttMs, "ms"],
      ["tcp_retransmission_rate_percent", active.tcpRetransmissionRatePercent, "%"],
      ["rssi_dbm", active.rssiDbm, "dBm"]
    ]) {
      if (value !== null && value !== undefined) {
        evidence.push({
          kind: "metric",
          source: active.interfaceName || "typed_network_snapshot",
          metric,
          value,
          summary: `${metric}=${value}${unit}`
        });
      }
    }
  }

  const score = finiteNumber(quality.score, null);
  const unhealthy = !explicitlyNoActive && score !== null && score < 50;
  if (Array.isArray(quality.missingMetrics) && quality.missingMetrics.length > 0) {
    actions.push(`补齐缺失指标：${quality.missingMetrics.join(", ")}。`);
  }

  // fallback 不生成 knowledge_entry_ids，也固定 provider=typed-rule-fallback，防止规则兜底
  // 被 HTTP 200 + 合法 schema 包装成一次成功的在线 RAG 检索。
  return normalizeDiagnosis({
    status: explicitlyNoActive ? "insufficient_evidence" : unhealthy ? "unhealthy" : "degraded",
    evidence,
    knowledge_entry_ids: [],
    confidence: evidence.length > 0 ? 0.35 : 0.1,
    actions,
    degraded: true,
    provider: "typed-rule-fallback",
    top_k: finiteNumber(networkSnapshot?.diagnosisConfig?.topK, 4),
    similarity_threshold: finiteNumber(
      networkSnapshot?.diagnosisConfig?.similarityThreshold,
      0.08
    ),
    error: reason || "RAG retrieval unavailable"
  });
}

// 为仍显示纯文本的现有 Dashboard UI 生成可读摘要，同时 API 保留全部结构化字段。
// 把结构化诊断渲染为简短的人类可读文本；原始结构仍由 API 单独返回。
export function formatDiagnosis(diagnosis) {
  // 该文本仅用于 UI 展示；业务判断必须读取原结构的 status/degraded/provider/error。
  const evidence = diagnosis.evidence.length > 0
    ? diagnosis.evidence.map((item) => `- ${item.summary || item.metric || item.kind}`).join("\n")
    : "- 暂无可用证据";
  const actions = diagnosis.actions.length > 0
    ? diagnosis.actions.map((item) => `- ${item}`).join("\n")
    : "- 继续采样后重试";
  const degraded = diagnosis.degraded ? "（降级）" : "";

  return [
    `status: ${diagnosis.status}${degraded}`,
    `confidence: ${diagnosis.confidence.toFixed(2)}`,
    "evidence:",
    evidence,
    `knowledge_entry_ids: ${diagnosis.knowledge_entry_ids.join(", ") || "none"}`,
    "actions:",
    actions,
    diagnosis.error ? `error: ${diagnosis.error}` : ""
  ].filter(Boolean).join("\n");
}
