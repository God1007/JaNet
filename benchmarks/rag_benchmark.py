#!/usr/bin/env python3
"""WeakNet RAG artifact/load/retrieve/typed-diagnosis correctness performance benchmark."""

# 文件职责：以 production 只读 artifact 或确定性 synthetic corpus 运行 RAG 的
# load/retrieve/diagnose 矩阵，同时校验响应契约、确定性、并发、内存与文件零变更。

from __future__ import annotations

import argparse
import gc
import hashlib
import json
import math
import os
import platform
import resource
import sys
import tempfile
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Mapping, Sequence, Tuple


SCHEMA_VERSION = "weaknet.benchmark.v1"
PROJECT_ROOT = Path(__file__).resolve().parents[1]
ANALYSIS_DIR = PROJECT_ROOT / "AI-assisted analysis"
if str(ANALYSIS_DIR) not in sys.path:
    sys.path.insert(0, str(ANALYSIS_DIR))


PROFILES = {
    "smoke": {"concurrency": [1, 4], "requests": [8], "warmup": 2},
    "standard": {"concurrency": [1, 4, 8, 16], "requests": [64, 256], "warmup": 8},
    "stress": {"concurrency": [1, 4, 8, 16], "requests": [1000, 5000], "warmup": 32},
}
SYNTHETIC_ENTRY_DEFAULTS = {"smoke": 128, "standard": 1_000, "stress": 10_000}
SYNTHETIC_REQUEST_LEVELS = {"smoke": [8], "standard": [8, 32], "stress": [4, 16]}
SYNTHETIC_WARMUPS = {"smoke": 2, "standard": 4, "stress": 4}
FEATURE_HASH_DIMENSION = 384
ALLOWED_DIAGNOSIS_STATUSES = {
    "healthy", "degraded", "unhealthy", "unknown", "insufficient_evidence", "unavailable"
}


def utc_now() -> str:
    """返回 RFC3339 UTC 时间戳，写入统一报告信封。"""
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def parse_positive_ints(value: str) -> List[int]:
    """解析 ``1,4,8,16`` 形式的正整数覆盖项；非法输入抛 argparse 错误。"""
    result = [int(item.strip()) for item in value.split(",") if item.strip()]
    if not result or any(item <= 0 for item in result):
        raise argparse.ArgumentTypeError("expected comma-separated positive integers")
    return result


def parse_operations(value: str) -> List[str]:
    """解析并校验 RAG 操作子集；空集合或未知操作抛 argparse 错误。"""
    operations = [item.strip() for item in value.split(",") if item.strip()]
    invalid = sorted(set(operations) - {"load", "retrieve", "diagnose"})
    if not operations or invalid:
        raise argparse.ArgumentTypeError("invalid operations: %s" % ", ".join(invalid))
    return operations


def canonical_digest(value: Any) -> str:
    """将 JSON 规范化后计算 SHA-256，返回用于响应确定性比较的摘要。"""
    encoded = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def percentile(values: Sequence[float], quantile: float) -> float:
    """用线性插值计算分位数；空输入返回 0，且不依赖外部统计库。"""
    if not values:
        return 0.0
    ordered = sorted(values)
    position = (len(ordered) - 1) * quantile
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)


def latency_summary(values: Sequence[float]) -> Dict[str, float]:
    """把延迟样本归纳为统一的 p50/p95/p99/max 结构。"""
    return {
        "p50": round(percentile(values, 0.50), 6),
        "p95": round(percentile(values, 0.95), 6),
        "p99": round(percentile(values, 0.99), 6),
        "max": round(max(values), 6) if values else 0.0,
    }


def current_rss_bytes() -> int:
    """优先读取当前驻留内存字节数，不支持时退化为进程峰值 RSS。"""
    statm = Path("/proc/self/statm")
    if statm.exists():
        try:
            resident_pages = int(statm.read_text(encoding="utf-8").split()[1])
            return resident_pages * int(os.sysconf("SC_PAGE_SIZE"))
        except (OSError, ValueError, IndexError):
            pass
    peak = int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
    return peak if sys.platform == "darwin" else peak * 1024


def peak_rss_bytes() -> int:
    """把 macOS/Linux 单位不同的 ``ru_maxrss`` 统一换算为字节。"""
    peak = int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
    return peak if sys.platform == "darwin" else peak * 1024


def sha256_file(path: Path) -> str:
    """以 1 MiB 分块计算受保护文件 SHA-256，避免一次性读入大 artifact。"""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def path_state(path: Path) -> Dict[str, Any]:
    """采集路径类型、mtime、内容摘要或链接目标，供只读零变更证明使用。"""
    try:
        stat = path.lstat()
    except FileNotFoundError:
        return {"exists": False}
    state: Dict[str, Any] = {
        "exists": True,
        "size": stat.st_size,
        "mtime_ns": stat.st_mtime_ns,
        "kind": "symlink" if path.is_symlink() else "directory" if path.is_dir() else "file",
    }
    if path.is_symlink():
        state["target"] = os.readlink(path)
    elif path.is_file():
        state["sha256"] = sha256_file(path)
    return state


def mutation_guard_snapshot(args: argparse.Namespace, fixture_root: Path | None) -> Dict[str, Any]:
    """快照受保护范围，返回路径到状态的映射。

    fixture 只保护本轮临时树；production 同时保护 raw/schema/golden、artifact 树
    及 current/previous 指针。显式限定范围既能发现自动 rebuild/换链等副作用，
    又避免把无关仓库变更误算成 RAG benchmark mutation。
    """
    result: Dict[str, Any] = {}
    if fixture_root is not None:
        roots = [("fixture", fixture_root)]
        explicit: List[Tuple[str, Path]] = []
    else:
        roots = [("artifact", args.artifact_root.resolve())]
        explicit = [
            ("source/raw", args.raw.resolve()),
            ("source/schema", args.schema.resolve()),
            ("source/golden", args.golden.resolve()),
            ("artifact/current.json", args.artifact_root.resolve() / "current.json"),
            ("artifact/previous.json", args.artifact_root.resolve() / "previous.json"),
        ]
    for label, path in explicit:
        result[label] = path_state(path)
    for label, root in roots:
        result[label] = path_state(root)
        if root.exists():
            for child in sorted(root.rglob("*")):
                result["%s/%s" % (label, child.relative_to(root))] = path_state(child)
    return result


def mutation_changes(before: Mapping[str, Any], after: Mapping[str, Any]) -> List[Dict[str, Any]]:
    """返回所有存在性、类型、链接目标、mtime 或内容发生变化的受保护路径。"""
    changes: List[Dict[str, Any]] = []
    for key in sorted(set(before) | set(after)):
        if before.get(key) != after.get(key):
            changes.append({"path": key, "before": before.get(key), "after": after.get(key)})
    return changes


def require(condition: bool, message: str) -> None:
    """条件不满足时抛 ``ValueError``；调用层会把契约错误记录为正确性数据。"""
    if not condition:
        raise ValueError(message)


def validate_load(value: Mapping[str, Any]) -> None:
    """校验 artifact load 的最小完整性契约；不满足时抛 ``ValueError``。"""
    require(isinstance(value, Mapping), "artifact load result must be an object")
    require(isinstance(value.get("artifact_version"), str) and bool(value["artifact_version"]),
            "artifact_version must be non-empty")
    require(isinstance(value.get("chunk_count"), int) and value["chunk_count"] > 0,
            "chunk_count must be positive")
    require(value.get("chunk_count") == value.get("vector_count"),
            "chunk/vector count mismatch")
    require(value.get("evaluation_passed") is True, "artifact evaluation gate is not passed")


def validate_retrieve(value: Mapping[str, Any]) -> None:
    """校验检索元数据及每条 evidence 的字段、数量和有限分数。"""
    require(isinstance(value, Mapping), "retrieval result must be an object")
    require(isinstance(value.get("query"), str) and bool(value["query"]), "query is missing")
    require(isinstance(value.get("top_k"), int) and value["top_k"] > 0, "top_k is invalid")
    require(isinstance(value.get("similarity_threshold"), (int, float)),
            "similarity_threshold is invalid")
    require(isinstance(value.get("artifact_version"), str) and bool(value["artifact_version"]),
            "artifact_version is missing")
    evidence = value.get("evidence")
    require(isinstance(evidence, list), "evidence must be an array")
    require(len(evidence) <= value["top_k"], "evidence exceeds top_k")
    require(isinstance(value.get("insufficient_evidence"), bool),
            "insufficient_evidence must be boolean")
    require(value["insufficient_evidence"] == (len(evidence) == 0),
            "insufficient_evidence is inconsistent with evidence")
    for item in evidence:
        require(isinstance(item, Mapping), "retrieval evidence must be an object")
        for field in ("entry_id", "chunk_id", "content_hash"):
            require(isinstance(item.get(field), str) and bool(item[field]),
                    "retrieval evidence.%s is invalid" % field)
        score = item.get("score")
        require(isinstance(score, (int, float)) and math.isfinite(float(score)),
                "retrieval score must be finite")
        require(isinstance(item.get("metadata"), Mapping), "retrieval metadata must be an object")


def validate_diagnosis(value: Mapping[str, Any]) -> None:
    """校验 Dashboard 消费的 typed diagnosis 完整结构；失败时抛契约异常。"""
    require(isinstance(value, Mapping), "diagnosis must be an object")
    require(value.get("status") in ALLOWED_DIAGNOSIS_STATUSES, "diagnosis status is invalid")
    for field in ("evidence", "knowledge_entry_ids", "actions"):
        require(isinstance(value.get(field), list), "diagnosis.%s must be an array" % field)
    confidence = value.get("confidence")
    require(isinstance(confidence, (int, float)) and math.isfinite(float(confidence)),
            "diagnosis confidence must be finite")
    require(0.0 <= float(confidence) <= 1.0, "diagnosis confidence must be within [0, 1]")
    require(isinstance(value.get("degraded"), bool), "diagnosis.degraded must be boolean")
    require(isinstance(value.get("provider"), str) and bool(value["provider"]),
            "diagnosis.provider is missing")
    require(isinstance(value.get("artifact_version"), str) and bool(value["artifact_version"]),
            "diagnosis.artifact_version is missing")
    require(isinstance(value.get("top_k"), int) and value["top_k"] > 0,
            "diagnosis.top_k is invalid")
    threshold = value.get("similarity_threshold")
    require(isinstance(threshold, (int, float)) and math.isfinite(float(threshold)),
            "diagnosis.similarity_threshold is invalid")
    require(all(isinstance(item, str) and item for item in value["knowledge_entry_ids"]),
            "diagnosis knowledge_entry_ids must contain non-empty strings")
    require(len(set(value["knowledge_entry_ids"])) == len(value["knowledge_entry_ids"]),
            "diagnosis knowledge_entry_ids must be unique")
    require(all(isinstance(item, str) and item for item in value["actions"]),
            "diagnosis actions must contain non-empty strings")
    for item in value["evidence"]:
        require(isinstance(item, Mapping), "diagnosis evidence must be an object")
        for field in ("entry_id", "chunk_id", "content_hash"):
            require(isinstance(item.get(field), str) and bool(item[field]),
                    "diagnosis evidence.%s is invalid" % field)
        require(isinstance(item.get("score"), (int, float))
                and math.isfinite(float(item["score"])),
                "diagnosis evidence score must be finite")
        require(isinstance(item.get("metadata"), Mapping),
                "diagnosis evidence metadata must be an object")


def load_fingerprint(value: Mapping[str, Any]) -> str:
    """对完整稳定 load 描述计算指纹，返回确定性比较摘要。"""
    return canonical_digest(value)


def retrieve_fingerprint(value: Mapping[str, Any]) -> str:
    """对影响检索排序的字段计算指纹，排除仅展示且不影响语义的正文。"""
    return canonical_digest({
        "artifact_version": value["artifact_version"],
        "top_k": value["top_k"],
        "similarity_threshold": value["similarity_threshold"],
        "insufficient_evidence": value["insufficient_evidence"],
        "evidence": [
            {
                "entry_id": item["entry_id"],
                "chunk_id": item["chunk_id"],
                "content_hash": item["content_hash"],
                "score": item["score"],
            }
            for item in value["evidence"]
        ],
    })


def diagnosis_fingerprint(value: Mapping[str, Any]) -> str:
    """对所有影响用户可见诊断语义的字段计算确定性指纹。"""
    return canonical_digest({
        "status": value["status"],
        "knowledge_entry_ids": value["knowledge_entry_ids"],
        "confidence": value["confidence"],
        "actions": value["actions"],
        "degraded": value["degraded"],
        "provider": value["provider"],
        "artifact_version": value["artifact_version"],
        "top_k": value["top_k"],
        "similarity_threshold": value["similarity_threshold"],
        "evidence": value["evidence"],
    })


QUERIES = [
    "RTT 75ms 页面响应慢，如何排查链路拥塞",
    "TCP 重传代理比率 2%，如何验证拥塞和丢包",
    "WiFi RSSI -75dBm 信号弱，如何处理无线干扰",
    "默认路由从 wlan0 切换到 eth0，如何重绑流量采集",
]
SNAPSHOTS = [
    {
        "hasActiveInterface": True,
        "activeInterface": "eth0",
        "interfaces": [{"interfaceName": "eth0", "state": "UP", "usingNow": True,
                        "rttMs": 75, "rttAvailability": "AVAILABLE"}],
    },
    {
        "hasActiveInterface": True,
        "activeInterface": "wlan0",
        "interfaces": [{"interfaceName": "wlan0", "state": "UP", "usingNow": True,
                        "rssiDbm": -75, "rssiAvailability": "AVAILABLE"}],
    },
    {
        "hasActiveInterface": True,
        "activeInterface": "eth0",
        "defaultRouteChanged": True,
        "previousActiveInterface": "wlan0",
        "currentDefaultRouteInterface": "eth0",
        "routeGeneration": 2,
        "interfaces": [{"interfaceName": "eth0", "state": "UP", "usingNow": True}],
    },
    {
        "hasActiveInterface": True,
        "activeInterface": "eth0",
        "interfaces": [{"interfaceName": "eth0", "state": "UP", "usingNow": True}],
        "trafficObservation": {
            "availability": "UNAVAILABLE", "valid": False, "captureComplete": False,
            "mapReadComplete": False, "baselineOnly": False, "bpfLoaded": False,
        },
    },
]


def feature_hash_metrics(tokens: Iterable[str], dimension: int) -> Dict[str, Any]:
    """统计 feature-hashing 坐标占用，并返回碰撞指标和生日模型概率。

    这里的“碰撞”是不同 token 被压到有限 ``dimension`` 坐标，不是 SHA-256
    全摘要相同。若 token 数超过维度，抽屉原理使坐标碰撞概率为 1；否则使用
    ``1 - Π((dimension-i)/dimension)`` 计算至少一次坐标碰撞的理论概率。实际
    ``coordinate_collisions`` 与理论概率同时报告，避免把降维碰撞误说成密码学
    hash 失效；``sha256_digest_collisions`` 则单独统计全摘要重复。
    """
    unique = sorted(set(tokens))
    bucket_loads: Counter[int] = Counter()
    full_digests = set()
    for token in unique:
        digest = hashlib.sha256(token.encode("utf-8")).digest()
        full_digests.add(digest)
        bucket_loads[int.from_bytes(digest[:8], "big") % dimension] += 1
    count = len(unique)
    if count > dimension:
        birthday_probability = 1.0
    else:
        no_collision = 1.0
        for index in range(count):
            no_collision *= max(0.0, (dimension - index) / dimension)
        birthday_probability = 1.0 - no_collision
    return {
        "feature_hash_dimension": dimension,
        "unique_tokens": count,
        "occupied_buckets": len(bucket_loads),
        "coordinate_collisions": count - len(bucket_loads),
        "max_bucket_load": max(bucket_loads.values(), default=0),
        "birthday_probability": round(birthday_probability, 12),
        "signed_feature_hashing": True,
        "hash_function": "sha256",
        "sha256_digest_collisions": count - len(full_digests),
        "collision_semantics": (
            "coordinate collisions in signed feature hashing; not SHA-256 digest collisions"
        ),
    }


def synthetic_store(pipeline: Any, corpus_size: int) -> Tuple[Any, Dict[str, Any]]:
    """构造合法内存 store，并返回 ``(store, feature_hash_metrics)``。

    语料虽为可重复 fixture，但 tokenizer、StableHashEmbeddings、向量和检索实现
    都走真实运行时代码；语料小于批准的种子条目数时抛契约异常。
    """
    raw_payload = json.loads(
        (ANALYSIS_DIR / "knowledge" / "raw" / "network_knowledge.json").read_text(encoding="utf-8")
    )
    source_entries = raw_payload["entries"]
    require(corpus_size >= len(source_entries),
            "synthetic corpus must fit all approved semantic seed entries")
    chunks: List[Dict[str, Any]] = []
    contents: List[str] = []
    for index in range(corpus_size):
        if index < len(source_entries):
            entry = source_entries[index]
            entry_id = entry["entry_id"]
            content = pipeline.render_entry(entry)
            metadata = {
                "metric": entry["metric"],
                "condition": entry["condition"],
                "threshold": entry["threshold"],
                "unit": entry["unit"],
                "severity": entry["severity"],
                "actions": entry["actions"],
                "tags": entry["tags"],
                "synthetic": False,
            }
        else:
            entry_id = "synthetic.fixture.%06d" % index
            content = (
                "synthetic fixture corpus entry_%06d shard_%03d feature_%05d "
                "deterministic vector load benchmark"
                % (index, index % 257, (index * 17) % 65_521)
            )
            metadata = {
                "metric": "synthetic_fixture_metric",
                "condition": "benchmark-only non-runtime metric",
                "threshold": {"operator": "gt", "value": 1_000_000_000},
                "unit": "synthetic",
                "severity": "info",
                "actions": [],
                "tags": ["synthetic", "benchmark"],
                "synthetic": True,
            }
        contents.append(content)
        chunks.append({
            "entry_id": entry_id,
            "chunk_id": entry_id + "::main",
            "content_hash": hashlib.sha256(content.encode("utf-8")).hexdigest(),
            "content": content,
            "metadata": metadata,
        })
    embeddings = pipeline.StableHashEmbeddings(FEATURE_HASH_DIMENSION)
    tokens = {
        token
        for content in contents
        for token in embeddings.tokenizer.tokenize(content)
    }
    vectors = embeddings.embed_documents(contents)
    store = pipeline._VectorKnowledgeStore(
        chunks, vectors, embeddings,
        "fixture-synthetic-%d-d%d-v1" % (corpus_size, FEATURE_HASH_DIMENSION),
    )
    return store, feature_hash_metrics(tokens, FEATURE_HASH_DIMENSION)


def fixture_operations(args: argparse.Namespace, fixture_root: Path) -> Tuple[
        Dict[str, Dict[str, Any]], Dict[str, Any]]:
    """构造真实 synthetic RAG runtime，返回三个 operation 和环境指标。

    冷加载口径包含语料、tokenizer、embedding 与 store 物化；热加载只扫描已驻留
    store 的维度和完整性，因此两者不能直接当作同一操作的冷热缓存倍数。
    """
    import knowledge_pipeline as pipeline

    # 冷启动包含语料构造、真实 tokenizer/embedding 和 in-memory store materialization。
    cold_rss_before = current_rss_bytes()
    cold_started = time.perf_counter()
    store, hash_metrics = synthetic_store(pipeline, args.synthetic_entries)
    cold_duration_ms = (time.perf_counter() - cold_started) * 1000.0
    cold_rss_after = current_rss_bytes()
    cold_rss_peak = peak_rss_bytes()
    warm_rss_before = cold_rss_after
    warm_started = time.perf_counter()
    vector_cells = sum(len(vector) for vector in store.vectors)
    require(len(store.chunks) == len(store.vectors), "synthetic chunk/vector count mismatch")
    require(vector_cells == len(store.vectors) * FEATURE_HASH_DIMENSION,
            "synthetic vector dimension mismatch")
    warm_duration_ms = (time.perf_counter() - warm_started) * 1000.0
    warm_rss_after = current_rss_bytes()
    warm_rss_peak = peak_rss_bytes()
    corpus_metrics = {
        "corpus_size": len(store.chunks),
        "vector_dim": FEATURE_HASH_DIMENSION,
        "cold_load": {
            "duration_ms": round(cold_duration_ms, 6),
            "rss_before": cold_rss_before,
            "rss_after": cold_rss_after,
            "rss_delta": cold_rss_after - cold_rss_before,
            "rss_peak": cold_rss_peak,
            "mode": "synthetic materialization with StableHashEmbeddings",
        },
        "warm_load": {
            "duration_ms": round(warm_duration_ms, 6),
            "rss_before": warm_rss_before,
            "rss_after": warm_rss_after,
            "rss_delta": warm_rss_after - warm_rss_before,
            "rss_peak": warm_rss_peak,
            "mode": "resident store dimension/integrity scan",
        },
        **hash_metrics,
    }
    fixture_manifest = fixture_root / "synthetic_manifest.json"
    fixture_manifest.write_text(
        json.dumps(corpus_metrics, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )

    def load(index: int) -> Tuple[str, Dict[str, Any]]:
        """读取已驻留 synthetic store 元数据，返回固定 workload key 与结果。"""
        del index
        return "artifact", {
            "artifact_version": store.artifact_version,
            "chunk_count": len(store.chunks),
            "vector_count": len(store.vectors),
            "evaluation_passed": True,
        }

    def retrieve(index: int) -> Tuple[str, Dict[str, Any]]:
        """循环四个固定查询执行真实向量检索，返回 query key 与结果。"""
        query = QUERIES[index % len(QUERIES)]
        return query, store.retrieve(
            query, top_k=args.top_k, similarity_threshold=args.similarity_threshold
        ).to_dict()

    def diagnose(index: int) -> Tuple[str, Dict[str, Any]]:
        """让固定 typed snapshot 走线上同一 diagnosis core，返回 workload key 与结果。"""
        fixture_index = index % len(SNAPSHOTS)
        return "snapshot-%d" % fixture_index, pipeline._diagnose_snapshot_with_store(
            SNAPSHOTS[fixture_index], store,
            top_k=args.top_k, min_score=args.similarity_threshold,
        )

    common_metrics = {
        "engine": "synthetic-real-runtime",
        "corpus_size": len(store.chunks),
        "vector_dim": FEATURE_HASH_DIMENSION,
    }
    operations = {
        "load": {"name": "rag.artifact_load", "endpoint": "in-memory synthetic store warm access",
                 "call": load, "validate": validate_load, "fingerprint": load_fingerprint,
                 "workloads": 1, "operation_metrics": {**common_metrics, **corpus_metrics}},
        "retrieve": {"name": "rag.retrieve", "endpoint": "_VectorKnowledgeStore.retrieve",
                     "call": retrieve, "validate": validate_retrieve,
                     "fingerprint": retrieve_fingerprint, "workloads": len(QUERIES),
                     "operation_metrics": common_metrics},
        "diagnose": {"name": "rag.typed_diagnose",
                     "endpoint": "_diagnose_snapshot_with_store(readonly in-memory store)",
                     "call": diagnose, "validate": validate_diagnosis,
                     "fingerprint": diagnosis_fingerprint, "workloads": len(SNAPSHOTS),
                     "operation_metrics": common_metrics},
    }
    environment = {
        "fixture": True,
        "engine": "synthetic-real-runtime",
        "fixture_qps_semantics": "real local RAG runtime over synthetic corpus",
        "fixture_root": str(fixture_root),
        **corpus_metrics,
    }
    return operations, environment


def real_operations(args: argparse.Namespace) -> Tuple[Dict[str, Dict[str, Any]], Dict[str, Any]]:
    """只读加载 production artifact，返回 operation 表与环境指标。

    函数刻意不调用带 auto-rebuild 的公共诊断入口；任何 artifact 源不一致应由
    ``load_current`` 抛错，而不能在性能测试期间偷偷重建、改变输入再继续测量。
    所谓 cold/warm 是同一进程连续两次只读加载，主要反映文件缓存差异，不等价
    于重启机器后的绝对冷盘基准。
    """
    import knowledge_pipeline as pipeline

    artifact_root = args.artifact_root.resolve()
    raw_path = args.raw.resolve()
    schema_path = args.schema.resolve()
    golden_path = args.golden.resolve()

    # 连续两次只读加载分别近似冷/热文件缓存路径，并单独记录 RSS。
    cold_rss_before = current_rss_bytes()
    cold_started = time.perf_counter()
    cold_store = pipeline.VersionedKnowledgeStore(
        artifact_root=artifact_root, raw_path=raw_path, schema_path=schema_path
    ).load_current(validate_source=not args.offline_artifact)
    cold_duration_ms = (time.perf_counter() - cold_started) * 1000.0
    cold_rss_after = current_rss_bytes()
    cold_rss_peak = peak_rss_bytes()
    warm_rss_before = cold_rss_after
    warm_started = time.perf_counter()
    base_store = pipeline.VersionedKnowledgeStore(
        artifact_root=artifact_root, raw_path=raw_path, schema_path=schema_path
    ).load_current(validate_source=not args.offline_artifact)
    warm_duration_ms = (time.perf_counter() - warm_started) * 1000.0
    warm_rss_after = current_rss_bytes()
    warm_rss_peak = peak_rss_bytes()
    del cold_store
    gc.collect()

    vector_dim = int(getattr(base_store.embeddings, "dimension", 0))
    require(vector_dim > 0, "loaded artifact embedding dimension must be positive")
    tokens = {
        token
        for chunk in base_store.chunks
        for token in base_store.embeddings.tokenizer.tokenize(chunk["content"])
    }
    corpus_metrics = {
        "corpus_size": len(base_store.chunks),
        "vector_dim": vector_dim,
        "cold_load": {
            "duration_ms": round(cold_duration_ms, 6),
            "rss_before": cold_rss_before,
            "rss_after": cold_rss_after,
            "rss_delta": cold_rss_after - cold_rss_before,
            "rss_peak": cold_rss_peak,
            "mode": "first read-only VersionedKnowledgeStore.load_current",
        },
        "warm_load": {
            "duration_ms": round(warm_duration_ms, 6),
            "rss_before": warm_rss_before,
            "rss_after": warm_rss_after,
            "rss_delta": warm_rss_after - warm_rss_before,
            "rss_peak": warm_rss_peak,
            "mode": "second read-only load with warm filesystem cache",
        },
        **feature_hash_metrics(tokens, vector_dim),
    }

    def load(_index: int) -> Tuple[str, Dict[str, Any]]:
        """每次创建新 store 并只读校验 current artifact，返回稳定 workload key。"""
        store = pipeline.VersionedKnowledgeStore(
            artifact_root=artifact_root, raw_path=raw_path, schema_path=schema_path
        ).load_current(validate_source=not args.offline_artifact)
        return "artifact", {
            "artifact_version": store.artifact_version,
            "chunk_count": len(store.chunks),
            "vector_count": len(store.vectors),
            "evaluation_passed": store.manifest.get("evaluation", {}).get("passed") is True,
        }

    def retrieve(index: int) -> Tuple[str, Dict[str, Any]]:
        """复用已加载 store 测量 production retrieval 热路径并返回固定 query key。"""
        query = QUERIES[index % len(QUERIES)]
        result = base_store.retrieve(
            query, top_k=args.top_k, similarity_threshold=args.similarity_threshold
        ).to_dict()
        return query, result

    def diagnose(index: int) -> Tuple[str, Dict[str, Any]]:
        """直接注入只读 store 运行诊断，避开 ``diagnose_snapshot`` 的自动重建分支。"""
        fixture_index = index % len(SNAPSHOTS)
        return "snapshot-%d" % fixture_index, pipeline._diagnose_snapshot_with_store(
            SNAPSHOTS[fixture_index], base_store,
            top_k=args.top_k, min_score=args.similarity_threshold,
        )

    common_metrics = {
        "engine": "production-readonly-runtime",
        "corpus_size": len(base_store.chunks),
        "vector_dim": vector_dim,
    }
    operations = {
        "load": {"name": "rag.artifact_load", "endpoint": "VersionedKnowledgeStore.load_current",
                 "call": load, "validate": validate_load, "fingerprint": load_fingerprint,
                 "workloads": 1, "operation_metrics": {**common_metrics, **corpus_metrics}},
        "retrieve": {"name": "rag.retrieve", "endpoint": "VersionedKnowledgeStore.retrieve",
                     "call": retrieve, "validate": validate_retrieve,
                     "fingerprint": retrieve_fingerprint, "workloads": len(QUERIES),
                     "operation_metrics": common_metrics},
        "diagnose": {"name": "rag.typed_diagnose",
                     "endpoint": "_diagnose_snapshot_with_store(readonly loaded artifact)",
                     "call": diagnose, "validate": validate_diagnosis,
                     "fingerprint": diagnosis_fingerprint, "workloads": len(SNAPSHOTS),
                     "operation_metrics": common_metrics},
    }
    environment = {
        "fixture": False,
        "engine": "production-readonly-runtime",
        "artifact_root": str(artifact_root),
        "artifact_version": base_store.artifact_version,
        "embedding": base_store.manifest.get("embedding", {}),
        "offline_artifact": args.offline_artifact,
        "raw_path": str(raw_path),
        "schema_path": str(schema_path),
        "golden_path": str(golden_path),
        **corpus_metrics,
    }
    return operations, environment


def run_one(operation: Mapping[str, Any], concurrency: int, request_count: int,
            warmup: int) -> Dict[str, Any]:
    """运行一格 operation×request×concurrency，返回性能与正确性指标。

    warmup 至少覆盖每个固定 workload，并建立响应指纹基线；测量阶段用共享 store
    的线程池制造调用侧并发，以同时验证只读线程安全。QPS 口径是“提交请求数 / 
    整格墙钟时间”，延迟包含成功和失败调用；因此必须与 success/error/mismatch
    一起解读，不能用高 QPS 掩盖失败。该数字代表单 Python 进程线程并发，不等同
    于多进程或多机容量，且会受 GIL 与底层实现是否释放 GIL 影响。
    """
    call: Callable[[int], Tuple[str, Mapping[str, Any]]] = operation["call"]
    validate: Callable[[Mapping[str, Any]], None] = operation["validate"]
    fingerprint: Callable[[Mapping[str, Any]], str] = operation["fingerprint"]
    warmup_count = max(warmup, int(operation["workloads"]))
    baselines: Dict[str, str] = {}
    warmup_errors: List[Dict[str, Any]] = []
    # Warmup 同时建立每个固定 workload 的确定性基线，未覆盖 workload 不能混入测量。
    for index in range(warmup_count):
        try:
            key, payload = call(index)
            validate(payload)
            digest = fingerprint(payload)
            if key in baselines and baselines[key] != digest:
                raise ValueError("warmup determinism mismatch for %s" % key)
            baselines[key] = digest
        except Exception as error:  # benchmark must report contract failures as data
            warmup_errors.append({"phase": "warmup", "index": index,
                                  "type": type(error).__name__, "message": str(error)[:500]})

    rss_before = current_rss_bytes()
    peak_before = peak_rss_bytes()

    def invoke(index: int) -> Dict[str, Any]:
        """执行一次请求并返回延迟/状态；异常转成数据而非中断整轮。"""
        started = time.perf_counter_ns()
        try:
            key, payload = call(index)
            validate(payload)
            digest = fingerprint(payload)
            mismatch = key not in baselines or baselines[key] != digest
            return {"latency_ms": (time.perf_counter_ns() - started) / 1_000_000.0,
                    "ok": True, "mismatch": mismatch}
        except Exception as error:
            return {"latency_ms": (time.perf_counter_ns() - started) / 1_000_000.0,
                    "ok": False, "mismatch": False, "type": type(error).__name__,
                    "message": str(error)[:500], "index": index}

    measured_started = time.perf_counter()
    # 线程池覆盖调用侧并发和共享 store 的只读线程安全；所有结果按请求序号收集。
    with ThreadPoolExecutor(max_workers=concurrency, thread_name_prefix="rag-bench") as executor:
        outcomes = list(executor.map(invoke, range(request_count)))
    duration_seconds = max(time.perf_counter() - measured_started, 1e-12)
    rss_after = current_rss_bytes()
    peak_after = max(peak_before, peak_rss_bytes(), rss_after)
    latencies = [float(item["latency_ms"]) for item in outcomes]
    runtime_errors = [
        {"phase": "measure", "index": item["index"], "type": item["type"],
         "message": item["message"]}
        for item in outcomes if not item["ok"]
    ]
    errors = warmup_errors + runtime_errors
    mismatches = sum(1 for item in outcomes if item["mismatch"])
    success_count = sum(1 for item in outcomes if item["ok"])
    return {
        "name": operation["name"],
        "transport": "python",
        "endpoint": operation["endpoint"],
        "concurrency": concurrency,
        "requests": request_count,
        "warmup_requests": warmup_count,
        "duration_ms": round(duration_seconds * 1000.0, 6),
        "latency_ms": latency_summary(latencies),
        "qps": round(request_count / duration_seconds, 6),
        "success_count": success_count,
        "error_count": len(errors),
        "errors": errors[:10],
        "determinism_mismatch_count": mismatches,
        "determinism_mode": "exact_response_by_fixed_workload",
        "operation_metrics": dict(operation.get("operation_metrics", {})),
        "rss_bytes": {
            "before": rss_before,
            "after": rss_after,
            "delta": rss_after - rss_before,
            "peak": peak_after,
        },
        "correctness_pass": not errors and mismatches == 0 and success_count == request_count,
    }


def summarize(results: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    """汇总所有网格的请求、错误和确定性计数，且不隐藏 warmup 异常。"""
    return {
        "benchmark_count": len(results),
        "request_count": sum(int(item["requests"]) for item in results),
        "success_count": sum(int(item["success_count"]) for item in results),
        "error_count": sum(int(item["error_count"]) for item in results),
        "determinism_mismatch_count": sum(
            int(item["determinism_mismatch_count"]) for item in results
        ),
        "correctness_pass": bool(results) and all(bool(item["correctness_pass"]) for item in results),
    }


def build_parser() -> argparse.ArgumentParser:
    """定义直接运行和总套件共用的独立命令行参数。"""
    parser = argparse.ArgumentParser(description="WeakNet RAG correctness/performance benchmark")
    parser.add_argument("--profile", choices=sorted(PROFILES), default="smoke")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--fixture", action="store_true",
                        help="run the real local RAG runtime over a deterministic synthetic corpus")
    parser.add_argument("--synthetic-entries", type=int,
                        help="fixture corpus size; defaults: smoke=128, standard=1000, stress=10000")
    parser.add_argument("--operations", type=parse_operations, default=["load", "retrieve", "diagnose"])
    parser.add_argument("--concurrency", type=parse_positive_ints)
    parser.add_argument("--requests", type=parse_positive_ints)
    parser.add_argument("--warmup", type=int)
    parser.add_argument("--top-k", type=int, default=4)
    parser.add_argument("--similarity-threshold", type=float, default=0.08)
    parser.add_argument("--offline-artifact", action="store_true")
    parser.add_argument("--artifact-root", type=Path,
                        default=ANALYSIS_DIR / "knowledge" / "artifacts")
    parser.add_argument("--raw", type=Path,
                        default=ANALYSIS_DIR / "knowledge" / "raw" / "network_knowledge.json")
    parser.add_argument("--schema", type=Path,
                        default=ANALYSIS_DIR / "knowledge" / "schema" / "knowledge_entry.schema.json")
    parser.add_argument("--golden", type=Path,
                        default=ANALYSIS_DIR / "knowledge" / "golden_set.json")
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    """构建 runtime、执行 mutation guard 与并发矩阵，并写出最终 JSON。

    production 输出被强制放在受保护源码/artifact 树外；运行前后比较文件集合、
    内容、mtime 和 symlink target，任一变化都会覆盖单项成功并使总状态失败。
    返回 0 仅表示所有响应契约、确定性和零变更门禁同时通过，否则返回 2。
    """
    args = build_parser().parse_args(argv)
    if args.warmup is not None and args.warmup < 0:
        raise SystemExit("--warmup must be non-negative")
    if args.top_k <= 0 or not math.isfinite(args.similarity_threshold):
        raise SystemExit("invalid top-k/similarity-threshold")
    if args.synthetic_entries is not None and not args.fixture:
        raise SystemExit("--synthetic-entries requires --fixture")
    # Production guard 必须先于任何 artifact load；fixture 则只保护自己的临时目录。
    if args.fixture:
        args.synthetic_entries = args.synthetic_entries or SYNTHETIC_ENTRY_DEFAULTS[args.profile]
        if args.synthetic_entries < 12:
            raise SystemExit("--synthetic-entries must be at least 12")
    output = args.output.expanduser().resolve()
    if not args.fixture:
        protected_files = {args.raw.resolve(), args.schema.resolve(), args.golden.resolve()}
        artifact_root = args.artifact_root.resolve()
        if output in protected_files or output == artifact_root or artifact_root in output.parents:
            raise SystemExit("--output must be outside protected RAG source/artifact paths")
    profile = PROFILES[args.profile]
    concurrencies = args.concurrency or list(profile["concurrency"])
    request_levels = args.requests or list(
        SYNTHETIC_REQUEST_LEVELS[args.profile] if args.fixture else profile["requests"]
    )
    warmup = args.warmup if args.warmup is not None else int(
        SYNTHETIC_WARMUPS[args.profile] if args.fixture else profile["warmup"]
    )
    started_at = utc_now()
    overall_started = time.perf_counter()
    temporary_fixture: tempfile.TemporaryDirectory[str] | None = None
    if args.fixture:
        temporary_fixture = tempfile.TemporaryDirectory(prefix="weaknet-rag-benchmark-")
        fixture_root = Path(temporary_fixture.name)
        operations, extra_environment = fixture_operations(args, fixture_root)
        guard_before = mutation_guard_snapshot(args, fixture_root)
    else:
        guard_before = mutation_guard_snapshot(args, None)
        operations, extra_environment = real_operations(args)
    results = [
        run_one(operations[name], concurrency, request_count, warmup)
        for name in args.operations
        for request_count in request_levels
        for concurrency in concurrencies
    ]
    # 任何内容、mtime、symlink target 或文件集合变化都会覆盖单项通过结果，使总门禁失败。
    guard_after = mutation_guard_snapshot(args, Path(temporary_fixture.name) if temporary_fixture else None)
    guard_changes = mutation_changes(guard_before, guard_after)
    extra_environment["mutation_guard"] = {
        "scope": "ephemeral_fixture_tree" if args.fixture else "production_sources_and_artifact_tree",
        "protected_entry_count": len(guard_before),
        "passed": not guard_changes,
        "change_count": len(guard_changes),
        "changes": guard_changes[:50],
    }
    summary = summarize(results)
    summary["mutation_guard_pass"] = not guard_changes
    if guard_changes:
        summary["correctness_pass"] = False
        summary["error_count"] += len(guard_changes)
    for field in (
        "corpus_size", "vector_dim", "feature_hash_dimension", "unique_tokens",
        "occupied_buckets", "coordinate_collisions", "max_bucket_load", "birthday_probability",
    ):
        summary[field] = extra_environment[field]
    summary["status"] = "passed" if summary["correctness_pass"] else "failed"
    document = {
        "schema_version": SCHEMA_VERSION,
        "component": "rag",
        "profile": args.profile,
        "environment": {
            "python": platform.python_version(),
            "platform": platform.platform(),
            "pid": os.getpid(),
            "concurrency": concurrencies,
            "request_levels": request_levels,
            "top_k": args.top_k,
            "similarity_threshold": args.similarity_threshold,
            **extra_environment,
        },
        "started_at": started_at,
        "duration_ms": round((time.perf_counter() - overall_started) * 1000.0, 6),
        "benchmarks": results,
        "summary": summary,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    serialized = json.dumps(document, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False)
    output.write_text(serialized + "\n", encoding="utf-8")
    print(serialized)
    if temporary_fixture is not None:
        temporary_fixture.cleanup()
    return 0 if document["summary"]["correctness_pass"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
