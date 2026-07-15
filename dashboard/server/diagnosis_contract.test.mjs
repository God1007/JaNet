// Node 内建测试：锁定 /api/analyze 对外的结构化诊断字段和显式降级语义。

import assert from "node:assert/strict";
import test from "node:test";

import {
  DIAGNOSIS_SCHEMA_VERSION,
  buildDegradedDiagnosis,
  formatDiagnosis,
  normalizeDiagnosis
} from "./diagnosis_contract.mjs";

// 模拟在线 bridge 的完整成功响应：验证字段规范化、去重、置信度截断和来源证据保真。
test("normalizes bridge output into the stable diagnosis contract", () => {
  // fixture 同时携带知识 ID 与 source anchor，覆盖 Python→BFF 跨语言后的证据追溯字段。
  const result = normalizeDiagnosis({
    status: "unhealthy",
    evidence: [
      {
        kind: "knowledge",
        source: "versioned_knowledge_store",
        summary: "High RTT guidance",
        knowledge_entry_id: "kb-rtt-001",
        chunk_id: "kb-rtt-001#0",
        content_hash: "content-sha",
        artifact_version: "artifact-v1",
        knowledge_store: "versioned_knowledge_store:artifact-v1",
        source_revision: "sha256:file-sha",
        source_sha256: "file-sha",
        source_anchor: { line_start: 7, line_end: 9, excerpt_sha256: "excerpt-sha" },
        source_excerpt: "claim: metric=rtt; threshold=gt 50 ms\n",
        score: 0.91
      }
    ],
    knowledge_entry_ids: ["kb-rtt-001", "kb-rtt-001"],
    confidence: 1.4,
    actions: ["Check route", "Check route"],
    degraded: false,
    provider: "versioned-local-rag",
    artifact_version: "artifact-v1",
    top_k: 7,
    similarity_threshold: 0.12
  });

  // schema 合法只是第一层；这里还要求业务 unhealthy、非 degraded 且真实知识证据未丢失。
  assert.equal(result.schema_version, DIAGNOSIS_SCHEMA_VERSION);
  assert.equal(result.status, "unhealthy");
  assert.equal(result.confidence, 1);
  assert.deepEqual(result.knowledge_entry_ids, ["kb-rtt-001"]);
  assert.deepEqual(result.actions, ["Check route"]);
  assert.equal(result.degraded, false);
  assert.equal(result.artifact_version, "artifact-v1");
  assert.equal(result.top_k, 7);
  assert.equal(result.similarity_threshold, 0.12);
  assert.equal(result.evidence[0].content_hash, "content-sha");
  assert.equal(result.evidence[0].source_revision, "sha256:file-sha");
  assert.equal(result.evidence[0].source_anchor.line_start, 7);
});

// 模拟 bridge/artifact 不可用：HTTP 层仍可返回统一 schema，但业务必须显式 degraded/fallback。
test("marks typed rule fallback as degraded and never invents knowledge ids", () => {
  const result = buildDegradedDiagnosis(
    {
      interfaces: [
        {
          interfaceName: "eth0",
          usingNow: true,
          rttMs: 260,
          tcpRetransmissionRatePercent: 2.8,
          rssiDbm: null
        }
      ],
      quality: { score: 42, missingMetrics: ["rssi_dbm"] }
    },
    "knowledge artifact unavailable"
  );

  // unhealthy 来自 typed 指标规则；provider/degraded/空知识 ID 证明它不是在线 RAG 成功。
  assert.equal(result.status, "unhealthy");
  assert.equal(result.degraded, true);
  assert.equal(result.provider, "typed-rule-fallback");
  assert.deepEqual(result.knowledge_entry_ids, []);
  assert.match(formatDiagnosis(result), /knowledge_entry_ids: none/);
  assert.match(result.error, /artifact unavailable/);
});

// 非对象 bridge 输出连 schema 层都不成立，必须拒绝而不是静默包装成 unknown。
test("rejects non-object bridge output", () => {
  assert.throws(() => normalizeDiagnosis("not-json-object"), /JSON object/);
});

// typed snapshot 明确无活动接口时，验证 fallback 不消费 interfaces 中可能残留的旧指标。
test("explicit no-active fallback discards stale interface metrics and cannot claim unhealthy", () => {
  const result = buildDegradedDiagnosis(
    {
      hasActiveInterface: false,
      interfaces: [{ interfaceName: "eth0", usingNow: true, rttMs: 900 }],
      quality: { score: 1, missingMetrics: [] }
    },
    "bridge unavailable"
  );

  // 此时只能声称证据不足；若返回 unhealthy，会把陈旧指标误当成当前网络事实。
  assert.equal(result.status, "insufficient_evidence");
  assert.equal(result.degraded, true);
  assert.equal(result.evidence.some((item) => item.kind === "metric"), false);
});
