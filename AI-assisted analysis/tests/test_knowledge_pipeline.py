#!/usr/bin/env python3
"""
文件职责：验证知识库跨进程确定性、评测门禁、制品完整性、发布/回滚与 typed snapshot 诊断。
"""

import contextlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ANALYSIS_DIR = Path(__file__).resolve().parents[1]
if str(ANALYSIS_DIR) not in sys.path:
    sys.path.insert(0, str(ANALYSIS_DIR))

import knowledge_pipeline as pipeline  # noqa: E402

from knowledge_pipeline import (  # noqa: E402
    DEFAULT_GOLDEN_PATH,
    DEFAULT_RAW_PATH,
    DEFAULT_SCHEMA_PATH,
    ArtifactIntegrityError,
    EvaluationGateError,
    IncompatibleArtifactError,
    KnowledgeConflictError,
    KnowledgeLifecycle,
    KnowledgeValidationError,
    StableHashEmbeddings,
    StaleSourceError,
    VersionedKnowledgeStore,
    atomic_write_json,
    diagnose_snapshot,
    migrate_artifact_only,
    promote_candidates,
    read_json,
    validate_artifact_directory,
)


def approved_entry(entry_id="net.test.alpha", metric="rtt", condition="alpha latency condition",
                   threshold=None, actions=None):
    """构造带真实来源锚点和人工审批字段的最小合法知识条目。"""

    selected_threshold = threshold or {"operator": "gt", "value": 50}
    unit = "ms" if metric == "rtt" else "unit"
    claim = "metric=%s; threshold=%s %s %s" % (
        metric, selected_threshold["operator"], selected_threshold.get("value"), unit
    )
    entry = {
        "entry_id": entry_id,
        "metric": metric,
        "condition": condition,
        "threshold": selected_threshold,
        "unit": unit,
        "symptoms": ["alpha observable symptom"],
        "root_causes": ["alpha verified root cause"],
        "actions": actions or ["alpha remediation action"],
        "severity": "high",
        "tags": ["alpha", "deterministic"],
        "source": "AI-assisted analysis/knowledge/source_policy.md",
        "source_revision": "sha256:18f5c197c3b36eba02d7f6457a7d39bc7fcdf89469fb16c6d01303d2f3cb25ce",
        "source_anchor": {
            "symbol": "net.test.fixture",
            "line_start": 79,
            "line_end": 82,
            "claim": claim,
            "excerpt_sha256": "46fcc3c4da6133667838c8bc516b3bb09972d26fc815da1cff2c351c22e86379",
            "semantic_sha256": {},
        },
        "updated_at": "2026-07-14T00:00:00Z",
        "review_status": "approved",
        "reviewed_by": "weaknet-maintainer",
        "reviewed_at": "2026-07-14T00:00:00Z",
        "reviewed_by_human": True,
    }
    entry["source_anchor"]["semantic_sha256"] = pipeline._entry_semantic_sha256(entry)
    return entry


def knowledge_document(entries, version="1.0.0"):
    """把条目列表包装为指定版本的 schema v2 测试知识文档。"""

    return {
        "schema_version": "2.0.0",
        "kb_version": version,
        "description": "test knowledge",
        "entries": entries,
    }


def golden_document(expected="net.test.alpha", query="alpha latency symptom", snapshot=None):
    """构造一条检索、引用和诊断门禁均为满分的 golden 文档。"""

    typed_snapshot = snapshot or {
        "hasActiveInterface": True,
        "activeInterface": "eth0",
        "interfaces": [{"interfaceName": "eth0", "state": "UP", "usingNow": True, "rttMs": 75}],
    }
    return {
        "schema_version": "1.0.0",
        "top_k": 4,
        "min_score": 0.0,
        "gates": {
            "recall_at_4": 1.0,
            "mrr_at_4": 1.0,
            "citation_support_rate": 1.0,
            "diagnosis_accuracy": 1.0,
        },
        "cases": [
            {
                "case_id": "alpha",
                "query": query,
                "expected_entry_ids": [expected],
                "snapshot": typed_snapshot,
                "expected_status": "unhealthy",
                "expected_diagnosis_entry_ids": [expected],
                "expected_evidence_entry_ids": [expected],
            }
        ],
    }


class TemporaryKnowledgeLayout:
    """在临时目录中布置 raw、golden 与 artifact，并提供统一工厂方法。"""

    def __init__(self, root: Path, raw=None, golden=None):
        """写入测试知识和 golden 初始文件，但尚不发布 artifact。"""

        self.root = root
        self.raw = root / "raw.json"
        self.golden = root / "golden.json"
        self.artifacts = root / "artifacts"
        atomic_write_json(self.raw, raw or knowledge_document([approved_entry()]))
        atomic_write_json(self.golden, golden or golden_document())

    def lifecycle(self, embeddings=None):
        """返回绑定当前临时布局的 ``KnowledgeLifecycle``。"""

        return KnowledgeLifecycle(
            raw_path=self.raw,
            schema_path=DEFAULT_SCHEMA_PATH,
            golden_path=self.golden,
            artifact_root=self.artifacts,
            embeddings=embeddings,
            enforce_release_golden_contract=False,
        )

    def store(self, embeddings=None):
        """返回绑定当前 artifact/raw/schema 的只读版本化 store。"""

        return VersionedKnowledgeStore(
            artifact_root=self.artifacts,
            raw_path=self.raw,
            schema_path=DEFAULT_SCHEMA_PATH,
            embeddings=embeddings,
        )


def rewrite_outer_artifact_checksums(artifact_root: Path, changed_name: str) -> Path:
    """重算外层 SHA/current 指针，并返回版本目录以模拟有限能力攻击者。

    这样后续失败不能归因于“忘记更新普通 checksum”，而必须来自 canonical
    raw→chunk→vector 派生关系的深层防篡改校验。
    """
    pointer_path = artifact_root / "current.json"
    pointer = read_json(pointer_path)
    version_dir = artifact_root / "versions" / pointer["artifact_version"]
    manifest_path = version_dir / "manifest.json"
    manifest = read_json(manifest_path)
    manifest["artifact_checksums"][changed_name] = pipeline.sha256_file(version_dir / changed_name)
    manifest["artifact_checksum"] = pipeline.sha256_bytes(
        pipeline.canonical_json_bytes(manifest["artifact_checksums"])
    )
    atomic_write_json(manifest_path, manifest)
    pointer["manifest_sha256"] = pipeline.sha256_file(manifest_path)
    atomic_write_json(pointer_path, pointer)
    return version_dir


class KnowledgePipelineTest(unittest.TestCase):
    """覆盖知识构建、评测、发布、恢复、完整性和确定性契约的端到端测试。"""

    def test_embedding_is_deterministic_across_process_hash_seeds(self):
        """验证 embedding 不受不同进程 ``PYTHONHASHSEED`` 影响。"""

        code = (
            "import json; from knowledge_pipeline import StableHashEmbeddings; "
            "print(json.dumps(StableHashEmbeddings().embed_query('RTT 延迟 tcp_retransmission 弱网')))"
        )
        outputs = []
        for seed in ("1", "998244353", "random"):
            environment = dict(os.environ)
            environment["PYTHONPATH"] = str(ANALYSIS_DIR)
            environment["PYTHONHASHSEED"] = seed
            outputs.append(subprocess.check_output([sys.executable, "-c", code], env=environment))
        # 跨进程字节级一致才能保证向量、排序和 artifact identity 可重放；仅在同一
        # Python 进程重复调用无法发现内建 hash 随机种子泄漏。
        self.assertEqual(outputs[0], outputs[1])
        self.assertEqual(outputs[1], outputs[2])

    def test_source_change_rejects_stale_current_index(self):
        """验证 raw 内容变化后，带 source 校验的旧 current artifact 被拒绝。"""

        with tempfile.TemporaryDirectory() as directory:
            layout = TemporaryKnowledgeLayout(Path(directory))
            layout.lifecycle().release()
            layout.store().load_current(validate_source=True)
            changed = read_json(layout.raw)
            changed["entries"][0]["actions"] = ["changed remediation"]
            atomic_write_json(layout.raw, changed)
            with self.assertRaises(StaleSourceError):
                layout.store().load_current(validate_source=True)

    def test_publish_retains_previous_and_rollback_restores_source_and_current(self):
        """验证连续发布保留 previous，回滚同时恢复 raw 与 current 指针。"""

        with tempfile.TemporaryDirectory() as directory:
            layout = TemporaryKnowledgeLayout(Path(directory))
            first = layout.lifecycle().release()
            second_raw = read_json(layout.raw)
            second_raw["kb_version"] = "1.0.1"
            atomic_write_json(layout.raw, second_raw)
            second = layout.lifecycle().release()
            self.assertNotEqual(first["artifact_version"], second["artifact_version"])
            self.assertEqual(read_json(layout.artifacts / "previous.json")["artifact_version"], first["artifact_version"])

            # 回滚不是只切换索引指针；raw 与 current 必须回到同一版本，否则下一次
            # validate_source 会面对“旧 artifact + 新 source”的撕裂状态。
            rolled_back = layout.lifecycle().rollback()
            self.assertEqual(rolled_back["artifact_version"], first["artifact_version"])
            store = layout.store().load_current(validate_source=True)
            self.assertEqual(store.artifact_version, first["artifact_version"])
            self.assertEqual(read_json(layout.raw)["kb_version"], "1.0.0")

    def test_draft_candidate_and_failed_eval_never_change_raw_or_current(self):
        """验证未审批候选和评测失败均不能修改 raw 或 current。"""

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            layout = TemporaryKnowledgeLayout(root)
            layout.lifecycle().release()
            original_raw = layout.raw.read_bytes()
            original_current = (layout.artifacts / "current.json").read_bytes()

            draft = knowledge_document([approved_entry("net.test.beta", "beta", "beta candidate")], "1.0.1")
            draft["entries"][0].update({"review_status": "draft", "reviewed_by": None, "reviewed_at": None})
            draft_path = root / "draft.json"
            atomic_write_json(draft_path, draft)
            with self.assertRaises(KnowledgeValidationError):
                promote_candidates(
                    draft_path, layout.raw, DEFAULT_SCHEMA_PATH, layout.golden, layout.artifacts, "1.0.1", False
                )
            self.assertEqual(layout.raw.read_bytes(), original_raw)
            self.assertEqual((layout.artifacts / "current.json").read_bytes(), original_current)

            # 即使条目已经人工 approved，golden 门禁失败也必须停留在 staging；发布
            # 前后的 raw/current 字节一致是“评测先于提交”的硬证据。
            approved = knowledge_document(
                [
                    approved_entry(
                        "net.test.beta",
                        "interface_state",
                        "beta candidate",
                        {"operator": "eq", "value": "bad"},
                    )
                ],
                "1.0.1",
            )
            approved_path = root / "approved.json"
            atomic_write_json(approved_path, approved)
            failing_golden = root / "failing-golden.json"
            atomic_write_json(failing_golden, golden_document("net.missing.entry", "unrelated missing evidence"))
            with self.assertRaises(EvaluationGateError):
                promote_candidates(
                    approved_path,
                    layout.raw,
                    DEFAULT_SCHEMA_PATH,
                    failing_golden,
                    layout.artifacts,
                    "1.0.1",
                    False,
                )
            self.assertEqual(layout.raw.read_bytes(), original_raw)
            self.assertEqual((layout.artifacts / "current.json").read_bytes(), original_current)

    def test_approved_candidate_is_evaluated_then_committed_as_one_recoverable_transaction(self):
        """验证 approved 候选经评测后以单个可恢复事务提交。"""

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            layout = TemporaryKnowledgeLayout(root)
            first = layout.lifecycle().release()
            beta = approved_entry(
                "net.test.beta",
                "interface_state",
                "beta unique collector condition",
                {"operator": "eq", "value": "bad"},
                ["beta remediation action"],
            )
            candidate_path = root / "approved-beta.json"
            atomic_write_json(candidate_path, knowledge_document([beta], "1.0.1"))
            beta_golden = root / "beta-golden.json"
            atomic_write_json(
                beta_golden,
                golden_document(
                    "net.test.beta",
                    "beta unique collector condition",
                    {
                        "hasActiveInterface": True,
                        "activeInterface": "eth0",
                        "interfaces": [
                            {"interfaceName": "eth0", "state": "bad", "usingNow": True}
                        ],
                    },
                ),
            )

            release = promote_candidates(
                candidate_path,
                layout.raw,
                DEFAULT_SCHEMA_PATH,
                beta_golden,
                layout.artifacts,
                "1.0.1",
                False,
            )
            self.assertNotEqual(release["pointer"]["artifact_version"], first["artifact_version"])
            self.assertIn("net.test.beta", {entry["entry_id"] for entry in read_json(layout.raw)["entries"]})
            store = layout.store().load_current(validate_source=True)
            self.assertEqual(store.artifact_version, release["pointer"]["artifact_version"])
            marker = read_json(
                layout.artifacts / "transactions" / release["transaction_id"] / "transaction.json"
            )
            # committed marker 同时记录 evaluation，证明 artifact/raw/pointer 发布不是
            # 若干无关联写操作，故障恢复能够判断事务是否完整完成。
            self.assertEqual(marker["status"], "committed")
            self.assertTrue(marker["evaluation"])

    def test_deduplication_and_conflict_detection_are_enforced(self):
        """验证完全重复条目会去重，而内容、阈值和单位冲突会被拒绝。"""

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            duplicate = approved_entry()
            layout = TemporaryKnowledgeLayout(
                root,
                raw=knowledge_document([duplicate, dict(duplicate)]),
            )
            build = layout.lifecycle().build_staging(enforce_evaluation=True)
            self.assertEqual(build.manifest["source"]["entry_count"], 1)
            self.assertEqual(build.manifest["source"]["deduplicated_entry_count"], 1)

            conflict = approved_entry()
            conflict["severity"] = "critical"
            atomic_write_json(layout.raw, knowledge_document([duplicate, conflict]))
            with self.assertRaisesRegex(KnowledgeConflictError, "conflicting content for entry_id"):
                layout.lifecycle().build_staging(enforce_evaluation=True)

            threshold_conflict = approved_entry("net.test.beta")
            threshold_conflict["threshold"] = {"operator": "gt", "value": 80}
            # 两项 source anchor 均独立有效，随后才精确命中 trigger threshold 冲突分支。
            pipeline._source_provenance(duplicate)
            pipeline._source_provenance(threshold_conflict)
            with self.assertRaisesRegex(KnowledgeConflictError, "conflicting thresholds"):
                pipeline.deduplicate_entries([duplicate, threshold_conflict])

            unit_conflict = approved_entry("net.test.gamma")
            unit_conflict["unit"] = "seconds"
            with self.assertRaisesRegex(KnowledgeConflictError, "conflicting units"):
                pipeline.deduplicate_entries([duplicate, unit_conflict])

    def test_approved_entry_requires_real_source_and_allowlisted_human(self):
        """验证 approved 条目必须引用真实来源并由允许的人类审核者批准。"""

        with tempfile.TemporaryDirectory() as directory:
            layout = TemporaryKnowledgeLayout(Path(directory))
            invalid = read_json(layout.raw)
            invalid["entries"][0]["source"] = "server/src/does-not-exist.cpp"
            atomic_write_json(layout.raw, invalid)
            with self.assertRaises(KnowledgeValidationError):
                layout.lifecycle().build_staging()

            invalid = knowledge_document([approved_entry()])
            invalid["entries"][0].update({"reviewed_by": "deepseek", "reviewed_by_human": True})
            atomic_write_json(layout.raw, invalid)
            with mock.patch.dict(os.environ, {"RAG_APPROVED_REVIEWERS": "deepseek"}, clear=False):
                with self.assertRaises(KnowledgeValidationError):
                    layout.lifecycle().build_staging()

            invalid["entries"][0].update(
                {"reviewed_by": "weaknet-maintainer", "reviewed_by_human": False}
            )
            atomic_write_json(layout.raw, invalid)
            with self.assertRaises(KnowledgeValidationError):
                layout.lifecycle().build_staging()

    def test_incompatible_embedding_is_rebuilt_from_raw(self):
        """验证 embedding 维度不兼容时拒绝旧 artifact，并从 raw 全量重建。"""

        with tempfile.TemporaryDirectory() as directory:
            layout = TemporaryKnowledgeLayout(Path(directory))
            first = layout.lifecycle(StableHashEmbeddings(384)).release()
            with self.assertRaises(IncompatibleArtifactError):
                layout.store(StableHashEmbeddings(256)).load_current(validate_source=True)
            migrated = layout.lifecycle(StableHashEmbeddings(256)).ensure_current(rebuild_on_incompatible=True)
            self.assertNotEqual(migrated.artifact_version, first["artifact_version"])
            self.assertEqual(migrated.manifest["embedding"]["dimension"], 256)
            self.assertEqual(migrated.manifest["build"]["mode"], "versioned-full-rebuild")

    def test_manifest_requires_all_artifacts_and_dependency_fingerprint(self):
        """验证 manifest 必须覆盖全部制品并携带依赖指纹。"""

        with tempfile.TemporaryDirectory() as directory:
            layout = TemporaryKnowledgeLayout(Path(directory))
            pointer = layout.lifecycle().release()
            version_dir = layout.artifacts / "versions" / pointer["artifact_version"]
            manifest = read_json(version_dir / "manifest.json")
            self.assertIn("dependencies", manifest)
            self.assertIn("fingerprint_sha256", manifest["dependencies"])
            if manifest["faiss"]["index_file"]:
                self.assertIn(manifest["faiss"]["index_file"], manifest["artifact_checksums"])
            del manifest["artifact_checksums"]["raw_source.json"]
            atomic_write_json(version_dir / "manifest.json", manifest)
            with self.assertRaises(ArtifactIntegrityError):
                validate_artifact_directory(version_dir, DEFAULT_SCHEMA_PATH, StableHashEmbeddings(), None)

    def test_runtime_dependency_mismatch_rejects_but_optional_package_drift_does_not(self):
        """验证核心运行时漂移会拒绝 artifact，而未使用的可选包漂移不会。"""

        with tempfile.TemporaryDirectory() as directory:
            layout = TemporaryKnowledgeLayout(Path(directory))
            pointer = layout.lifecycle().release()
            version_dir = layout.artifacts / "versions" / pointer["artifact_version"]
            manifest_path = version_dir / "manifest.json"
            manifest = read_json(manifest_path)

            manifest["dependencies"]["packages"]["langchain"]["version"] = "optional-drift"
            inventory = dict(manifest["dependencies"])
            inventory.pop("fingerprint_sha256")
            manifest["dependencies"]["fingerprint_sha256"] = pipeline.sha256_bytes(
                pipeline.canonical_json_bytes(inventory)
            )
            atomic_write_json(manifest_path, manifest)
            validate_artifact_directory(version_dir, DEFAULT_SCHEMA_PATH, StableHashEmbeddings(), None)

            manifest["dependencies"]["python"]["version"] = "0.0.0"
            inventory = dict(manifest["dependencies"])
            inventory.pop("fingerprint_sha256")
            manifest["dependencies"]["fingerprint_sha256"] = pipeline.sha256_bytes(
                pipeline.canonical_json_bytes(inventory)
            )
            atomic_write_json(manifest_path, manifest)
            with self.assertRaises(IncompatibleArtifactError):
                validate_artifact_directory(version_dir, DEFAULT_SCHEMA_PATH, StableHashEmbeddings(), None)

    def test_golden_and_gate_hashes_are_part_of_artifact_identity(self):
        """验证 golden 内容和门禁参数变化都会改变 artifact identity。"""

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = TemporaryKnowledgeLayout(root / "first")
            second_golden = golden_document()
            second_golden["gates"]["mrr_at_4"] = 0.99
            second = TemporaryKnowledgeLayout(root / "second", golden=second_golden)
            first_version = first.lifecycle().build_staging().manifest["artifact_version"]
            second_version = second.lifecycle().build_staging().manifest["artifact_version"]
            self.assertNotEqual(first_version, second_version)

    def test_golden_minimum_gates_and_required_release_cases_cannot_be_removed(self):
        """验证最低 golden 门槛、必需用例及 typed 输入均不可被弱化或删除。"""

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            weak_gates = golden_document()
            weak_gates["gates"]["diagnosis_accuracy"] = 0.0
            layout = TemporaryKnowledgeLayout(root / "weak", golden=weak_gates)
            with self.assertRaises(KnowledgeValidationError):
                layout.lifecycle().build_staging()

            missing_release_cases = TemporaryKnowledgeLayout(root / "missing")
            lifecycle = KnowledgeLifecycle(
                raw_path=missing_release_cases.raw,
                schema_path=DEFAULT_SCHEMA_PATH,
                golden_path=missing_release_cases.golden,
                artifact_root=missing_release_cases.artifacts,
                enforce_release_golden_contract=True,
            )
            with self.assertRaises(KnowledgeValidationError):
                lifecycle.build_staging()

            production_raw = root / "production-raw.json"
            production_golden = read_json(DEFAULT_GOLDEN_PATH)
            high_case = next(
                case for case in production_golden["cases"] if case["case_id"] == "high-rtt"
            )
            high_case["snapshot"]["interfaces"][0]["rttMs"] = 20
            tampered_golden = root / "tampered-golden.json"
            atomic_write_json(production_raw, read_json(DEFAULT_RAW_PATH))
            atomic_write_json(tampered_golden, production_golden)
            tampered = KnowledgeLifecycle(
                raw_path=production_raw,
                schema_path=DEFAULT_SCHEMA_PATH,
                golden_path=tampered_golden,
                artifact_root=root / "tampered-artifacts",
                enforce_release_golden_contract=True,
            )
            with self.assertRaises(KnowledgeValidationError):
                tampered.build_staging()

    def test_golden_report_has_real_citation_support_and_diagnosis_accuracy(self):
        """验证评测报告真实计算引用支持率和诊断准确率，而非只写 passed。"""

        with tempfile.TemporaryDirectory() as directory:
            layout = TemporaryKnowledgeLayout(Path(directory))
            build = layout.lifecycle().build_staging(enforce_evaluation=True)
            report = build.evaluation
            self.assertTrue(report["passed"])
            self.assertEqual(report["metrics"]["citation_support_rate"], 1.0)
            self.assertEqual(report["metrics"]["diagnosis_accuracy"], 1.0)
            case = report["cases"][0]
            self.assertEqual(case["valid_supporting_citation_ids"], ["net.test.alpha"])
            self.assertEqual(case["citation_support_ratio"], 1.0)

    def test_typed_camel_case_snapshot_supports_availability_and_multiple_interfaces(self):
        """验证 typed camelCase snapshot 的可用性、多接口和路由语义进入诊断。"""

        with tempfile.TemporaryDirectory() as directory:
            artifacts = Path(directory) / "artifacts"
            environment = {
                "RAG_ARTIFACT_ROOT": str(artifacts),
                "RAG_RAW_PATH": str(DEFAULT_RAW_PATH),
                "RAG_SCHEMA_PATH": str(DEFAULT_SCHEMA_PATH),
                "RAG_GOLDEN_PATH": str(DEFAULT_GOLDEN_PATH),
            }
            snapshot = {
                "observedAt": 1784000000000,
                "hasActiveInterface": True,
                "activeInterface": "wlan0",
                "defaultRouteChanged": True,
                "interfaces": [
                    {
                        "interfaceName": "wlan0",
                        "isDefaultRoute": True,
                        "state": "UP",
                        "usingNow": True,
                        "rttMs": 120,
                        "rttAvailability": "AVAILABLE",
                        "rssiDbm": -82,
                        "rssiAvailability": "AVAILABLE",
                        "tcpRetransmissionRatePercent": 4.0,
                        "tcpRetransmissionAvailability": "AVAILABLE",
                        "trafficBytesPerSecond": 0,
                        "trafficAvailability": "UNAVAILABLE",
                    },
                    {
                        "interfaceName": "eth0",
                        "isDefaultRoute": False,
                        "state": "DOWN",
                        "usingNow": False,
                        "rttMs": 10,
                        "rttAvailability": "AVAILABLE",
                    },
                ],
                "quality": {"score": 45, "degraded": True, "missingMetrics": ["traffic"]},
                "trafficObservation": {
                    "availability": "UNAVAILABLE",
                    "valid": False,
                    "libbpfAvailable": True,
                    "bpfLoaded": False,
                    "degradedReason": "attach failed",
                },
            }
            output = io.StringIO()
            with mock.patch.dict(os.environ, environment, clear=False), contextlib.redirect_stdout(output):
                diagnosis = diagnose_snapshot(snapshot, top_k=12, min_score=0.0)
            self.assertEqual(output.getvalue(), "")
            self.assertEqual(diagnosis["status"], "unhealthy")
            self.assertTrue(diagnosis["degraded"])
            self.assertTrue(diagnosis["observation_degraded"])
            self.assertFalse(diagnosis["retrieval_degraded"])
            expected = {
                "net.rtt.critical",
                "net.tcp.retransmission_critical",
                "net.wifi.rssi_critical",
                "net.ebpf.collector_unavailable",
                "net.interface.default_route_switched",
            }
            # 只有活动/默认接口且 availability=AVAILABLE 的观测才能形成指标证据；
            # DOWN 的备用 eth0 和采集失败后的 traffic=0 都不能制造错误知识命中。
            self.assertTrue(expected.issubset(set(diagnosis["knowledge_entry_ids"])))
            self.assertNotIn("net.interface.down", diagnosis["knowledge_entry_ids"])
            self.assertNotIn("net.traffic.zero", diagnosis["knowledge_entry_ids"])
            self.assertTrue(diagnosis["actions"])

            normal_snapshot = {
                "interfaces": [
                    {
                        "interfaceName": "eth0",
                        "state": "UP",
                        "usingNow": True,
                        "rttMs": 20,
                        "rssiDbm": -50,
                        "tcpRetransmissionRatePercent": 0.0,
                        "trafficBytesPerSecond": 1024,
                    }
                ],
                "quality": {"score": 90},
                "trafficObservation": {
                    "availability": "AVAILABLE",
                    "valid": True,
                    "libbpfAvailable": True,
                    "bpfLoaded": True,
                },
            }
            with mock.patch.dict(os.environ, environment, clear=False), contextlib.redirect_stdout(output):
                healthy = diagnose_snapshot(normal_snapshot, top_k=12, min_score=0.0)
            self.assertEqual(healthy["status"], "healthy")
            self.assertFalse(healthy["degraded"])
            self.assertEqual(healthy["evidence"], [])

            idle_snapshot = {
                "hasActiveInterface": True,
                "activeInterface": "eth0",
                "interfaces": [
                    {
                        "interfaceName": "eth0",
                        "state": "UP",
                        "usingNow": True,
                        "trafficBytesPerSecond": 0,
                        "activeFlows": 0,
                        "trafficAvailability": "AVAILABLE",
                    }
                ],
                "trafficObservation": {"availability": "AVAILABLE", "valid": True},
            }
            with mock.patch.dict(os.environ, environment, clear=False):
                idle = diagnose_snapshot(idle_snapshot, top_k=12, min_score=0.0)
            # “可用且 0 流量 + 0 active flow”是正常空闲，与 collector unavailable
            # 返回的默认 0 完全不同，因此也不能命中 net.traffic.zero 异常条目。
            self.assertEqual(idle["status"], "healthy")
            self.assertNotIn("net.traffic.zero", idle["knowledge_entry_ids"])

    def test_promotion_crash_after_raw_replace_is_recovered_before_load(self):
        """验证发布在替换 raw 后崩溃，会在下一次加载前自动恢复旧一致状态。"""

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            layout = TemporaryKnowledgeLayout(root)
            layout.lifecycle().release()
            original_raw = layout.raw.read_bytes()
            original_current = (layout.artifacts / "current.json").read_bytes()
            beta = approved_entry(
                "net.test.beta",
                "interface_state",
                "beta unique collector condition",
                {"operator": "eq", "value": "bad"},
            )
            candidate = root / "candidate.json"
            atomic_write_json(candidate, knowledge_document([beta], "1.0.1"))
            beta_golden = root / "beta-golden.json"
            atomic_write_json(
                beta_golden,
                golden_document(
                    "net.test.beta",
                    "beta unique collector condition",
                    {
                        "hasActiveInterface": True,
                        "activeInterface": "eth0",
                        "interfaces": [{"interfaceName": "eth0", "state": "bad", "usingNow": True}],
                    },
                ),
            )
            code = (
                "import sys; from pathlib import Path; from knowledge_pipeline import promote_candidates; "
                "promote_candidates(Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3]), "
                "Path(sys.argv[4]), Path(sys.argv[5]), '1.0.1', False)"
            )
            environment = dict(os.environ)
            environment.update(
                {"PYTHONPATH": str(ANALYSIS_DIR), "RAG_PROMOTION_FAILPOINT": "after_raw_replace"}
            )
            crashed = subprocess.run(
                [
                    sys.executable,
                    "-c",
                    code,
                    str(candidate),
                    str(layout.raw),
                    str(DEFAULT_SCHEMA_PATH),
                    str(beta_golden),
                    str(layout.artifacts),
                ],
                env=environment,
                check=False,
            )
            self.assertEqual(crashed.returncode, 86)
            self.assertNotEqual(layout.raw.read_bytes(), original_raw)

            # failpoint 刻意制造“raw 已换、current 未换”的半提交；ensure_current 必须
            # 先读取事务日志回滚，再允许任何 store 暴露给调用方。
            layout.lifecycle().ensure_current(rebuild_on_incompatible=True)
            self.assertEqual(layout.raw.read_bytes(), original_raw)
            self.assertEqual((layout.artifacts / "current.json").read_bytes(), original_current)
            markers = list((layout.artifacts / "transactions").glob("*/transaction.json"))
            self.assertEqual(len(markers), 1)
            self.assertEqual(read_json(markers[0])["status"], "aborted_and_raw_restored")

    def test_concurrent_first_load_is_serialized_by_artifact_lock(self):
        """验证两个进程首次构建由 artifact lock 串行化，且最终 current 可加载。"""

        with tempfile.TemporaryDirectory() as directory:
            layout = TemporaryKnowledgeLayout(Path(directory))
            code = (
                "import sys; from pathlib import Path; from knowledge_pipeline import KnowledgeLifecycle; "
                "KnowledgeLifecycle(Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3]), "
                "Path(sys.argv[4]), enforce_release_golden_contract=False).ensure_current()"
            )
            environment = dict(os.environ)
            environment["PYTHONPATH"] = str(ANALYSIS_DIR)
            command = [
                sys.executable,
                "-c",
                code,
                str(layout.raw),
                str(DEFAULT_SCHEMA_PATH),
                str(layout.golden),
                str(layout.artifacts),
            ]
            processes = [subprocess.Popen(command, env=environment) for _ in range(2)]
            # 使用独立进程而非线程，才能覆盖真实文件锁、原子 rename 与指针发布竞态。
            self.assertEqual([process.wait(timeout=30) for process in processes], [0, 0])
            layout.store().load_current(validate_source=True)

    def test_schema_1_document_and_falsified_source_semantics_are_rejected(self):
        """验证旧 schema 与伪造 actions/root-causes 都无法通过来源语义校验。"""

        with tempfile.TemporaryDirectory() as directory:
            layout = TemporaryKnowledgeLayout(Path(directory))
            old_schema = read_json(layout.raw)
            old_schema["schema_version"] = "1.0.0"
            atomic_write_json(layout.raw, old_schema)
            with self.assertRaisesRegex(KnowledgeValidationError, "JSON Schema validation failed"):
                layout.lifecycle().build_staging()

            falsified = knowledge_document([approved_entry()])
            falsified["entries"][0]["actions"] = ["invented unsafe action"]
            atomic_write_json(layout.raw, falsified)
            with self.assertRaisesRegex(KnowledgeValidationError, "reviewed source semantics"):
                layout.lifecycle().build_staging()

            falsified = knowledge_document([approved_entry()])
            falsified["entries"][0]["root_causes"] = ["invented root cause"]
            atomic_write_json(layout.raw, falsified)
            with self.assertRaisesRegex(KnowledgeValidationError, "reviewed source semantics"):
                layout.lifecycle().build_staging()

    def test_live_source_mutation_is_rejected_but_portable_artifact_loads_offline(self):
        """验证在线来源被篡改会拒绝加载，而自包含 artifact 可在离线模式迁移使用。"""

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository = root / "repository"
            cited_source = repository / "AI-assisted analysis/knowledge/source_policy.md"
            cited_source.parent.mkdir(parents=True)
            shutil.copy2(pipeline.REPOSITORY_ROOT / "AI-assisted analysis/knowledge/source_policy.md", cited_source)
            layout = TemporaryKnowledgeLayout(root / "layout")
            with mock.patch.object(pipeline, "REPOSITORY_ROOT", repository):
                layout.lifecycle().release()
                layout.store().load_current(validate_source=True)
                cited_source.write_bytes(cited_source.read_bytes() + b"\nmutated\n")
                with self.assertRaises(StaleSourceError):
                    layout.store().load_current(validate_source=True)

            portable = root / "portable-artifacts"
            shutil.copytree(layout.artifacts, portable)
            # validate_source=False 只跳过“现场仓库是否仍存在/一致”，不会跳过 artifact
            # 内部 checksum、canonical provenance 与向量派生校验。
            with mock.patch.object(pipeline, "REPOSITORY_ROOT", root / "no-source-tree"):
                store = VersionedKnowledgeStore(
                    artifact_root=portable,
                    raw_path=root / "missing-raw.json",
                    schema_path=root / "missing-schema.json",
                ).load_current(validate_source=False)
            self.assertEqual(len(store.chunks), 1)

    def test_two_independent_processes_return_identical_ids_scores_and_artifact(self):
        """验证两个独立进程返回完全一致的 artifact、知识 ID 与检索分数。"""

        with tempfile.TemporaryDirectory() as directory:
            layout = TemporaryKnowledgeLayout(Path(directory))
            layout.lifecycle().release()
            code = (
                "import json,sys; from pathlib import Path; "
                "from knowledge_pipeline import VersionedKnowledgeStore; "
                "s=VersionedKnowledgeStore(Path(sys.argv[1]),Path(sys.argv[2]),Path(sys.argv[3])).load_current(); "
                "r=s.retrieve('alpha latency symptom',top_k=4,similarity_threshold=0.0); "
                "print(json.dumps({'artifact':r.artifact_version,'ids':[e.entry_id for e in r.evidence],"
                "'scores':[e.score for e in r.evidence]},sort_keys=True,separators=(',',':')))"
            )
            environment = dict(os.environ)
            environment["PYTHONPATH"] = str(ANALYSIS_DIR)
            command = [
                sys.executable, "-c", code, str(layout.artifacts), str(layout.raw),
                str(DEFAULT_SCHEMA_PATH),
            ]
            outputs = [subprocess.check_output(command, env=environment) for _ in range(2)]
            # 比较规范 JSON 字节可同时覆盖排序、浮点分数、ID 和 artifact 版本；仅比较
            # top-1 ID 会漏掉次序或分数在进程间漂移的问题。
            self.assertEqual(outputs[0], outputs[1])
            self.assertEqual(json.loads(outputs[0])["ids"], ["net.test.alpha"])

    def test_production_candidate_promote_then_rollback_with_full_contract(self):
        """验证 production 完整门禁下候选可发布，并可原子回滚到上一版本。"""

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            raw_path = root / "production-raw.json"
            golden_path = root / "production-golden.json"
            atomic_write_json(raw_path, read_json(DEFAULT_RAW_PATH))
            atomic_write_json(golden_path, read_json(DEFAULT_GOLDEN_PATH))
            artifacts = root / "artifacts"
            lifecycle = KnowledgeLifecycle(
                raw_path, DEFAULT_SCHEMA_PATH, golden_path, artifacts,
                enforce_release_golden_contract=True,
            )
            first = lifecycle.release()
            duplicate = next(
                entry for entry in read_json(DEFAULT_RAW_PATH)["entries"]
                if entry["entry_id"] == "net.rtt.high"
            )
            candidate_path = root / "candidate.json"
            atomic_write_json(candidate_path, knowledge_document([duplicate], "1.0.1"))
            promoted = promote_candidates(
                candidate_path, raw_path, DEFAULT_SCHEMA_PATH, golden_path, artifacts,
                "1.0.1", True,
            )
            self.assertEqual(promoted["evaluation"]["failures"], {})
            self.assertEqual(read_json(raw_path)["kb_version"], "1.0.1")
            rolled_back = lifecycle.rollback()
            self.assertEqual(rolled_back["artifact_version"], first["artifact_version"])
            self.assertEqual(read_json(raw_path)["kb_version"], "1.0.0")

    def test_supporting_ids_cannot_bypass_candidate_golden_coverage(self):
        """验证 supporting IDs 不能冒充候选条目的直接 golden 覆盖。"""

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            layout = TemporaryKnowledgeLayout(root)
            layout.lifecycle().release()
            beta = approved_entry("net.test.beta", condition="beta unique collector condition")
            candidate = root / "candidate.json"
            atomic_write_json(candidate, knowledge_document([beta], "1.0.1"))
            bypass = golden_document()
            bypass["cases"][0]["supporting_entry_ids"] = ["net.test.beta"]
            bypass_path = root / "bypass-golden.json"
            atomic_write_json(bypass_path, bypass)
            with self.assertRaisesRegex(EvaluationGateError, "require golden coverage"):
                promote_candidates(
                    candidate, layout.raw, DEFAULT_SCHEMA_PATH, bypass_path, layout.artifacts,
                    "1.0.1", False,
                )

    def test_required_golden_query_identity_cannot_be_gamed(self):
        """验证必需 golden query/typed snapshot 身份不可改成直接泄露答案的文本。"""

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            raw_path = root / "raw.json"
            golden = read_json(DEFAULT_GOLDEN_PATH)
            golden["cases"][0]["query"] = "net.rtt.high"
            golden_path = root / "golden.json"
            atomic_write_json(raw_path, read_json(DEFAULT_RAW_PATH))
            atomic_write_json(golden_path, golden)
            lifecycle = KnowledgeLifecycle(
                raw_path, DEFAULT_SCHEMA_PATH, golden_path, root / "artifacts",
                enforce_release_golden_contract=True,
            )
            with self.assertRaisesRegex(KnowledgeValidationError, "immutable query/typed-snapshot"):
                lifecycle.build_staging()

    def test_merge_uses_explicit_custom_schema_path(self):
        """验证 merge 全程使用调用方显式传入的 schema，而不回落到默认路径。"""

        with tempfile.TemporaryDirectory() as directory:
            custom_schema = Path(directory) / "schema.json"
            shutil.copy2(DEFAULT_SCHEMA_PATH, custom_schema)
            base = knowledge_document([approved_entry()])
            candidate = knowledge_document([approved_entry()], "1.0.1")
            real_validate = pipeline.validate_knowledge_document
            seen = []

            def guarded(document, schema_path=Path("forbidden"), **kwargs):
                """记录每次 schema 实参，并在 merge 偷用默认路径时立即失败。"""

                seen.append(Path(schema_path))
                if Path(schema_path) != custom_schema:
                    raise AssertionError("merge used implicit default schema")
                return real_validate(document, schema_path, **kwargs)

            with mock.patch.object(pipeline, "validate_knowledge_document", side_effect=guarded):
                pipeline.merge_approved_documents(
                    base, [candidate], kb_version="1.0.1", schema_path=custom_schema
                )
            self.assertEqual(seen, [custom_schema, custom_schema])

    def test_optional_faiss_output_changes_artifact_identity(self):
        """验证有无可选 FAISS 索引输出会产生不同 artifact identity。"""

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            def vectors_only(_path, _vectors):
                """模拟未安装 FAISS，仅保留基础向量制品。"""

                return {
                    "available_at_build": False,
                    "version": "not-installed",
                    "numpy_version": "test",
                    "index_type": None,
                    "metric": "cosine-via-normalized-inner-product",
                    "index_file": None,
                }

            def with_index(path, _vectors):
                """模拟生成确定性 FAISS 索引文件并返回构建元数据。"""

                path.write_bytes(b"deterministic-test-faiss-index")
                return {
                    "available_at_build": True,
                    "version": "test-faiss",
                    "numpy_version": "test-numpy",
                    "index_type": "IndexFlatIP",
                    "metric": "cosine-via-normalized-inner-product",
                    "index_file": path.name,
                }

            first = TemporaryKnowledgeLayout(root / "first")
            second = TemporaryKnowledgeLayout(root / "second")
            with mock.patch.object(pipeline, "_optional_faiss_index", side_effect=vectors_only):
                vectors_version = first.lifecycle().build_staging().manifest["artifact_version"]
            with mock.patch.object(pipeline, "_optional_faiss_index", side_effect=with_index):
                faiss_version = second.lifecycle().build_staging().manifest["artifact_version"]
            self.assertNotEqual(vectors_version, faiss_version)

    def test_offline_validation_links_raw_semantics_to_bundled_provenance(self):
        """验证离线校验仍把 raw 语义绑定到 artifact 内置 provenance。"""

        with tempfile.TemporaryDirectory() as directory:
            layout = TemporaryKnowledgeLayout(Path(directory))
            build = layout.lifecycle().build_staging()
            snapshot_path = build.staging_dir / "raw_snapshot.json"
            manifest_path = build.staging_dir / "manifest.json"
            snapshot = read_json(snapshot_path)
            snapshot["entries"][0]["actions"] = ["artifact-only forged action"]
            atomic_write_json(snapshot_path, snapshot)
            # 攻击者同步重算 snapshot、manifest 和外层 checksum，测试必须继续依靠
            # canonical provenance 派生关系识别“有完整哈希但语义被伪造”的 artifact。
            manifest = read_json(manifest_path)
            manifest["source"]["aggregate_sha256"] = pipeline.sha256_bytes(
                pipeline.canonical_json_bytes(snapshot)
            )
            manifest["artifact_checksums"]["raw_snapshot.json"] = pipeline.sha256_file(snapshot_path)
            manifest["artifact_checksum"] = pipeline.sha256_bytes(
                pipeline.canonical_json_bytes(manifest["artifact_checksums"])
            )
            atomic_write_json(manifest_path, manifest)
            with self.assertRaisesRegex(ArtifactIntegrityError, "does not support raw snapshot semantics"):
                validate_artifact_directory(
                    build.staging_dir, DEFAULT_SCHEMA_PATH, StableHashEmbeddings(), None
                )

    def test_artifact_only_migration_works_without_live_source_or_external_inputs(self):
        """验证 artifact-only 迁移不依赖现场源码或外部知识输入。"""

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            layout = TemporaryKnowledgeLayout(root / "source-layout")
            layout.lifecycle().release()
            copied = root / "copied-artifact"
            shutil.copytree(layout.artifacts, copied)
            target = root / "migrated-artifact"
            code = (
                "import sys; from pathlib import Path; import knowledge_pipeline as p; "
                "p.REPOSITORY_ROOT=Path('/definitely/no/source/tree'); "
                "p.migrate_artifact_only(Path(sys.argv[1]),Path(sys.argv[2]),p.StableHashEmbeddings(256))"
            )
            environment = dict(os.environ)
            environment["PYTHONPATH"] = str(ANALYSIS_DIR)
            subprocess.check_call([sys.executable, "-c", code, str(copied), str(target)], env=environment)
            store = VersionedKnowledgeStore(
                target,
                root / "missing-raw.json",
                root / "missing-schema.json",
                StableHashEmbeddings(256),
            ).load_current(validate_source=False)
            self.assertEqual(store.manifest["build"]["mode"], "artifact-only-full-rebuild")
            self.assertEqual(store.manifest["embedding"]["dimension"], 256)
            self.assertEqual(store.retrieve("alpha latency", 1, 0.0).evidence[0].entry_id, "net.test.alpha")

    def test_forged_chunk_threshold_and_actions_fail_after_outer_checksums_are_recomputed(self):
        """验证伪造 chunk 阈值/动作即使重算外层 checksum 仍会被拒绝。"""

        with tempfile.TemporaryDirectory() as directory:
            layout = TemporaryKnowledgeLayout(Path(directory))
            pointer = layout.lifecycle().release()
            version_dir = layout.artifacts / "versions" / pointer["artifact_version"]
            chunks_path = version_dir / "chunks.json"
            chunks = read_json(chunks_path)
            chunks[0]["metadata"]["threshold"] = {"operator": "gt", "value": 0}
            chunks[0]["metadata"]["actions"] = ["FORGED_UNSUPPORTED_ACTION"]
            atomic_write_json(chunks_path, chunks)
            rewrite_outer_artifact_checksums(layout.artifacts, "chunks.json")

            with self.assertRaisesRegex(
                ArtifactIntegrityError, "chunks differ from canonical raw/provenance derivation"
            ):
                layout.store().load_current(validate_source=False)

    def test_forged_vector_fails_after_outer_checksums_are_recomputed(self):
        """验证伪造向量即使重算外层 checksum 仍违反 canonical embedding 派生关系。"""

        with tempfile.TemporaryDirectory() as directory:
            layout = TemporaryKnowledgeLayout(Path(directory))
            pointer = layout.lifecycle().release()
            version_dir = layout.artifacts / "versions" / pointer["artifact_version"]
            vectors_path = version_dir / "vectors.json"
            vectors = read_json(vectors_path)
            vectors[0][0] += 0.25
            atomic_write_json(vectors_path, vectors)
            rewrite_outer_artifact_checksums(layout.artifacts, "vectors.json")

            with self.assertRaisesRegex(
                ArtifactIntegrityError, "vectors differ from canonical chunk embedding derivation"
            ):
                layout.store().load_current(validate_source=False)


if __name__ == "__main__":
    unittest.main()
