#!/usr/bin/env python3
"""Bridge contract tests: typed canonical mapping, RAG evidence IDs and explicit fallback."""

# 文件职责：验证 Dashboard typed snapshot 到知识管线的桥接契约，尤其是可用性语义、
# 知识证据 ID、检索参数回显，以及 RAG 失败时可见且可机器解析的降级响应。

import contextlib
import io
import json
import unittest
from unittest import mock

import rag_diagnosis_bridge as bridge


def typed_fixture():
    """返回字段完整且采集可用的 camelCase typed snapshot 基准样本。"""

    return {
        "observedAt": 1720000000000,
        "hasActiveInterface": True,
        "activeInterface": "eth0",
        "previousActiveInterface": "",
        "defaultRouteChanged": False,
        "routeGeneration": 1,
        "routeChangedAtUnixMs": 0,
        "interfaces": [
            {
                "interfaceName": "eth0",
                "state": "UP",
                "usingNow": True,
                "rttMs": 88,
                "tcpRetransmissionRatePercent": 1.4,
                "rssiDbm": -58,
                "trafficBytesPerSecond": 1048576,
                "trafficPacketsPerSecond": 900,
                "activeFlows": 12,
            }
        ],
        "quality": {
            "level": "GOOD",
            "score": 81,
            "issues": [],
            "degraded": False,
            "missingMetrics": [],
        },
        "trafficObservation": {
            "availability": "AVAILABLE",
            "valid": True,
            "captureComplete": True,
            "mapReadComplete": True,
            "baselineOnly": False,
            "generation": 9,
            "boundIfindex": 2,
            "captureMode": "tc",
            "degradedReason": "",
            "libbpfAvailable": True,
            "bpfLoaded": True,
            "bidirectional": True,
            "ipv4Supported": True,
            "ipv6Supported": True,
            "udpInterfaceReliable": True,
        },
    }


class RagDiagnosisBridgeTest(unittest.TestCase):
    """覆盖 bridge 规范化、证据传递、阈值归属与显式降级的契约测试。"""

    def test_camel_snapshot_maps_to_pipeline_canonical_schema(self):
        """验证 camelCase typed snapshot 无损映射为 pipeline canonical schema。"""

        facts = bridge._snapshot_facts(typed_fixture())
        canonical = bridge._canonical_snapshot(facts)

        self.assertEqual(canonical["interface_name"], "eth0")
        self.assertEqual(canonical["interface_state"], "UP")
        self.assertEqual(canonical["rtt_ms"], 88.0)
        self.assertEqual(canonical["tcp_retransmission_rate"], 1.4)
        self.assertEqual(canonical["traffic_mbps"], 1.0)
        self.assertEqual(canonical["collector_status"], "available")
        self.assertIs(canonical["ebpf_available"], True)
        self.assertEqual(canonical["traffic_generation"], 9)
        self.assertFalse(canonical["default_route_changed"])
        self.assertNotIn("tcpRetransmissionRatePercent", canonical)

    def test_diagnosis_preserves_real_knowledge_ids(self):
        """验证诊断保留检索返回的真实知识 ID、动作和检索配置。"""

        knowledge = {
            "kind": "knowledge",
            "source": "versioned_knowledge_store:test-v1",
            "summary": "TCP retransmission guidance",
            "knowledge_entry_id": "net.tcp.retransmission_elevated",
            "chunk_id": "net.tcp.retransmission_elevated::main",
            "score": 0.8,
        }
        with mock.patch.object(
            bridge,
            "_retrieve",
            return_value=(
                [knowledge], False, "", ["检查拥塞窗口。"], "test-rag", "unhealthy", "test-v1",
                7, 0.12,
            ),
        ):
            result = bridge.diagnose(typed_fixture())

        # Dashboard 必须引用真实 entry_id，而不是 bridge 临时生成的展示 ID；否则
        # evidence 无法回溯到被版本化、评测过的知识条目。
        self.assertEqual(result["provider"], "test-rag")
        self.assertEqual(result["knowledge_entry_ids"], ["net.tcp.retransmission_elevated"])
        self.assertFalse(result["degraded"])
        self.assertEqual(result["top_k"], 7)
        self.assertEqual(result["similarity_threshold"], 0.12)
        self.assertIn("检查拥塞窗口。", result["actions"])

    def test_retrieval_failure_is_explicit_degraded_jsonl(self):
        """验证检索失败输出单行、合法且显式 degraded 的 JSONL。"""

        with mock.patch.object(
            bridge,
            "_retrieve",
            return_value=(
                [], True, "knowledge artifact unavailable", [], "typed-rule-fallback",
                "unavailable", "unavailable", 4, 0.08
            ),
        ):
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                bridge._serve([json.dumps(typed_fixture())])

        lines = output.getvalue().splitlines()
        self.assertEqual(len(lines), 1)
        payload = json.loads(lines[0])
        self.assertEqual(payload["status"], "unavailable")
        self.assertTrue(payload["degraded"])
        self.assertEqual(payload["knowledge_entry_ids"], [])
        self.assertEqual(payload["provider"], "typed-rule-fallback")
        self.assertIn("artifact unavailable", payload["error"])

    def test_unavailable_collector_does_not_turn_zero_into_traffic_evidence(self):
        """验证采集不可用时数值 0 表示未知，不能伪装成真实零流量证据。"""

        fixture = typed_fixture()
        fixture["interfaces"][0]["trafficBytesPerSecond"] = 0
        fixture["interfaces"][0]["trafficPacketsPerSecond"] = 0
        fixture["interfaces"][0]["activeFlows"] = 0
        fixture["trafficObservation"].update(
            {
                "availability": "UNAVAILABLE",
                "valid": False,
                "generation": 1,
                "captureMode": "unavailable",
                "degradedReason": "libbpf is unavailable",
                "libbpfAvailable": False,
                "bpfLoaded": False,
            }
        )
        with mock.patch.object(
            bridge,
            "_retrieve",
            return_value=(
                [], True, "collector unavailable", [], "typed-rule-fallback",
                "unavailable", "unavailable", 4, 0.08
            ),
        ):
            result = bridge.diagnose(fixture)

        # availability/valid 比数值本身更权威：探针失败后的默认 0 不能触发“空闲”或
        # “零流量”知识，否则观测缺失会被误诊成业务事实。
        metrics = {item.get("metric") for item in result["evidence"]}
        self.assertNotIn("traffic_bytes_per_second", metrics)
        self.assertNotIn("traffic_packets_per_second", metrics)
        self.assertNotIn("active_flows", metrics)
        self.assertTrue(result["degraded"])
        self.assertTrue(any("libbpf is unavailable" in action for action in result["actions"]))

    def test_unavailable_collector_retrieves_the_ebpf_golden_entry(self):
        """验证 eBPF 采集不可用会命中对应 golden 知识并标记降级。"""

        fixture = typed_fixture()
        fixture["interfaces"][0].update(
            {
                "rttMs": 20,
                "tcpRetransmissionRatePercent": 0.0,
                "rssiDbm": -50,
                "trafficBytesPerSecond": 0,
                "trafficPacketsPerSecond": 0,
                "activeFlows": 0,
            }
        )
        fixture["quality"].update({"score": 80, "degraded": True, "missingMetrics": ["traffic"]})
        fixture["trafficObservation"].update(
            {
                "availability": "UNAVAILABLE",
                "valid": False,
                "generation": 1,
                "captureMode": "unavailable",
                "degradedReason": "libbpf is unavailable",
                "libbpfAvailable": False,
                "bpfLoaded": False,
                "bidirectional": False,
            }
        )

        result = bridge.diagnose(fixture)

        self.assertIn("net.ebpf.collector_unavailable", result["knowledge_entry_ids"])
        self.assertTrue(result["degraded"])

    def test_pipeline_threshold_is_authoritative_for_dashboard_status(self):
        """验证知识管线阈值决定最终状态，bridge 不自行重算或降级严重度。"""

        fixture = typed_fixture()
        fixture["interfaces"][0].update(
            {
                "rttMs": 80,
                "tcpRetransmissionRatePercent": 0.0,
                "rssiDbm": -50,
            }
        )
        fixture["quality"].update({"score": 90, "degraded": False, "missingMetrics": []})

        result = bridge.diagnose(fixture)

        # 阈值属于已审核、已评测的知识 artifact；若 Dashboard/bridge 再维护一份阈值，
        # 同一 RTT 会因版本漂移得到不同状态。
        self.assertEqual(result["status"], "unhealthy")
        self.assertIn("net.rtt.high", result["knowledge_entry_ids"])

    def test_route_transition_fields_reach_the_pipeline(self):
        """验证默认路由切换字段进入管线并形成 route_transition 证据。"""

        fixture = typed_fixture()
        fixture.update(
            {
                "previousActiveInterface": "wlan0",
                "currentDefaultRouteInterface": "eth0",
                "defaultRouteChanged": True,
                "routeGeneration": 2,
                "routeChangedAtUnixMs": 1720000000000,
            }
        )
        fixture["interfaces"][0].update({"rttMs": 20, "tcpRetransmissionRatePercent": 0.0})

        result = bridge.diagnose(fixture)

        self.assertEqual(result["status"], "degraded")
        self.assertIn("net.interface.default_route_switched", result["knowledge_entry_ids"])
        self.assertTrue(any(item["kind"] == "route_transition" for item in result["evidence"]))

    def test_no_active_interface_cannot_be_overridden_to_healthy_by_stale_interface(self):
        """验证无活动接口时旧接口指标不能把状态覆盖成 healthy。"""

        fixture = typed_fixture()
        fixture["hasActiveInterface"] = False
        fixture["activeInterface"] = ""

        result = bridge.diagnose(fixture)

        self.assertEqual(result["status"], "insufficient_evidence")
        self.assertTrue(result["degraded"])
        self.assertFalse(any(item.get("kind") == "metric" for item in result["evidence"]))

    def test_request_retrieval_config_overrides_environment_and_is_echoed(self):
        """验证请求级 topK/threshold 优先于环境变量，并在响应中原样回显。"""

        fixture = typed_fixture()
        fixture["diagnosisConfig"] = {"topK": 7, "similarityThreshold": 0.12}
        with mock.patch.object(
            bridge,
            "_retrieve",
            return_value=([], False, "", [], "test-rag", "healthy", "test-v1", 7, 0.12),
        ) as retrieve:
            with mock.patch.dict(
                "os.environ",
                {"RAG_TOP_K": "2", "RAG_SIMILARITY_THRESHOLD": "0.5"},
                clear=False,
            ):
                result = bridge.diagnose(fixture)

        self.assertEqual(retrieve.call_args.args[-2:], (7, 0.12))
        # 回显实际生效参数，保证结果中的 evidence 可按同一检索口径复现。
        self.assertEqual(result["top_k"], 7)
        self.assertEqual(result["similarity_threshold"], 0.12)

    def test_partial_capture_is_unavailable_and_never_emits_zero_traffic_facts(self):
        """验证采集未完成即视为不可用，并清空可能误导诊断的流量事实。"""

        fixture = typed_fixture()
        fixture["interfaces"][0].update(
            {"trafficBytesPerSecond": 0, "trafficPacketsPerSecond": 0, "activeFlows": 3}
        )
        fixture["trafficObservation"].update(
            {"valid": True, "captureComplete": False, "mapReadComplete": True, "baselineOnly": False}
        )
        facts = bridge._snapshot_facts(fixture)

        self.assertEqual(facts["collector_status"], "unavailable")
        self.assertIsNone(facts["traffic_bytes_per_second"])
        self.assertIsNone(facts["active_flows"])


if __name__ == "__main__":
    unittest.main()
