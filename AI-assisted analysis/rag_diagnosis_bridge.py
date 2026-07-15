#!/usr/bin/env python3
"""Typed NetworkSnapshot 到版本化知识库诊断的 JSONL bridge。

stdin 每行必须是一份结构化 NetworkSnapshot JSON；stdout 每行只输出一份稳定诊断 JSON。
依赖、索引和检索诊断统一写入 stderr，确保 Node BFF 可以严格解析 stdout 协议。
"""

from __future__ import annotations

import contextlib
import json
import math
import os
import sys
from dataclasses import asdict, is_dataclass
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple


SCHEMA_VERSION = "weaknet.diagnosis.v1"


def _log(message: str) -> None:
    """把运行诊断写入 stderr，不污染 JSONL stdout。"""
    print(message, file=sys.stderr, flush=True)


def _pick(value: Any, *names: str, default: Any = None) -> Any:
    """兼容 proto-loader camelCase 与独立调用方 snake_case 字段。"""
    if isinstance(value, Mapping):
        for name in names:
            if name in value:
                return value[name]
    return default


def _finite_number(value: Any) -> Optional[float]:
    """只接受有限数值，避免 NaN/Infinity 进入诊断协议。"""
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return None
    return parsed if math.isfinite(parsed) else None


def _active_interface(snapshot: Mapping[str, Any]) -> Optional[Mapping[str, Any]]:
    """优先选择 using_now 接口，再按 active_interface 名称匹配，最后回退首项。"""
    interfaces = _pick(snapshot, "interfaces", default=[]) or []
    for item in interfaces:
        if bool(_pick(item, "usingNow", "using_now", default=False)):
            return item
    active_name = str(_pick(snapshot, "activeInterface", "active_interface", default="") or "")
    for item in interfaces:
        if str(_pick(item, "interfaceName", "interface_name", default="")) == active_name:
            return item
    return interfaces[0] if interfaces else None


def _metric(item: Optional[Mapping[str, Any]], camel: str, snake: str) -> Optional[float]:
    """从活动接口读取一项已由 Node availability 归一化过的可选指标。"""
    if not item:
        return None
    return _finite_number(_pick(item, camel, snake))


def _snapshot_facts(snapshot: Mapping[str, Any]) -> Dict[str, Any]:
    """提取规则诊断、检索查询和置信度计算共用的 typed facts。"""
    active = _active_interface(snapshot)
    has_active_interface = bool(
        _pick(snapshot, "hasActiveInterface", "has_active_interface", default=bool(active))
    )
    if not has_active_interface:
        # 明确的 no-active 状态优先于接口数组中可能残留的旧指标。
        active = None
    quality = _pick(snapshot, "quality", default={}) or {}
    traffic = _pick(snapshot, "trafficObservation", "traffic_observation", default={}) or {}
    capture_complete = bool(
        _pick(traffic, "captureComplete", "capture_complete", default=False)
    )
    map_read_complete = bool(
        _pick(traffic, "mapReadComplete", "map_read_complete", default=False)
    )
    baseline_only = bool(_pick(traffic, "baselineOnly", "baseline_only", default=False))
    traffic_valid = bool(_pick(traffic, "valid", default=False)) \
        and capture_complete and map_read_complete and not baseline_only
    return {
        "interface": str(_pick(active, "interfaceName", "interface_name", default="") or "") if active else "",
        "interface_state": str(_pick(active, "state", "interface_state", default="") or "") if active else "",
        "has_active_interface": has_active_interface,
        "previous_active_interface": str(
            _pick(snapshot, "previousActiveInterface", "previous_active_interface", default="") or ""
        ),
        "current_default_route_interface": str(
            _pick(
                snapshot,
                "currentDefaultRouteInterface",
                "current_default_route_interface",
                default="",
            ) or ""
        ),
        "default_route_changed": bool(
            _pick(snapshot, "defaultRouteChanged", "default_route_changed", default=False)
        ),
        "route_generation": int(
            _finite_number(_pick(snapshot, "routeGeneration", "route_generation")) or 0
        ),
        "route_changed_at_unix_ms": int(
            _finite_number(
                _pick(snapshot, "routeChangedAtUnixMs", "route_changed_at_unix_ms")
            ) or 0
        ),
        "rtt_ms": _metric(active, "rttMs", "rtt_ms"),
        "tcp_retransmission_rate_percent": _metric(
            active,
            "tcpRetransmissionRatePercent",
            "tcp_retransmission_rate_percent",
        ),
        "rssi_dbm": _metric(active, "rssiDbm", "rssi_dbm"),
        # 即使接口对象残留旧数值，只要采集状态无效就不把 0/旧值作为真实流量证据。
        "traffic_bytes_per_second": _metric(
            active, "trafficBytesPerSecond", "traffic_bytes_per_second"
        ) if traffic_valid else None,
        "traffic_packets_per_second": _metric(
            active, "trafficPacketsPerSecond", "traffic_packets_per_second"
        ) if traffic_valid else None,
        "active_flows": _metric(active, "activeFlows", "active_flows") if traffic_valid else None,
        "collector_status": "available" if traffic_valid else "unavailable",
        "collector_reason": str(
            _pick(traffic, "degradedReason", "degraded_reason", default="") or ""
        ),
        "traffic_generation": int(_finite_number(_pick(traffic, "generation")) or 0),
        "traffic_bound_ifindex": int(
            _finite_number(_pick(traffic, "boundIfindex", "bound_ifindex")) or 0
        ),
        "traffic_capture_mode": str(
            _pick(traffic, "captureMode", "capture_mode", default="unavailable") or "unavailable"
        ),
        "capture_complete": capture_complete,
        "map_read_complete": map_read_complete,
        "baseline_only": baseline_only,
        "traffic_capabilities": {
            "libbpf_available": bool(_pick(traffic, "libbpfAvailable", "libbpf_available", default=False)),
            "bpf_loaded": bool(_pick(traffic, "bpfLoaded", "bpf_loaded", default=False)),
            "bidirectional": bool(_pick(traffic, "bidirectional", default=False)),
            "ipv4_supported": bool(_pick(traffic, "ipv4Supported", "ipv4_supported", default=False)),
            "ipv6_supported": bool(_pick(traffic, "ipv6Supported", "ipv6_supported", default=False)),
            "udp_interface_reliable": bool(
                _pick(traffic, "udpInterfaceReliable", "udp_interface_reliable", default=False)
            ),
        },
        "quality_score": _finite_number(_pick(quality, "score")),
        "quality_level": str(_pick(quality, "level", default="UNKNOWN") or "UNKNOWN"),
        "quality_degraded": bool(_pick(quality, "degraded", default=False)),
        "issues": [str(item) for item in (_pick(quality, "issues", default=[]) or [])],
        "missing_metrics": [
            str(item)
            for item in (_pick(quality, "missingMetrics", "missing_metrics", default=[]) or [])
        ],
    }


def _metric_evidence(facts: Mapping[str, Any]) -> List[Dict[str, Any]]:
    """把真实存在的 typed 指标编码为可审计证据，缺失字段不生成零值证据。"""
    if not facts["has_active_interface"]:
        return [{
            "kind": "state",
            "source": "typed_network_snapshot",
            "summary": "snapshot explicitly reports no active interface",
        }]
    source = facts["interface"] or "typed_network_snapshot"
    units = {
        "rtt_ms": "ms",
        "tcp_retransmission_rate_percent": "%",
        "rssi_dbm": "dBm",
        "traffic_bytes_per_second": "bytes/s",
        "traffic_packets_per_second": "packets/s",
        "active_flows": "",
        "quality_score": "/100",
    }
    evidence: List[Dict[str, Any]] = []
    for metric, unit in units.items():
        value = facts.get(metric)
        if value is None:
            continue
        evidence.append(
            {
                "kind": "metric",
                "source": source,
                "metric": metric,
                "value": value,
                "summary": f"{metric}={value:g}{unit}",
            }
        )
    for issue in facts["issues"]:
        evidence.append(
            {
                "kind": "assessment",
                "source": source,
                "summary": issue,
            }
        )
    if facts["default_route_changed"]:
        evidence.append(
            {
                "kind": "route_transition",
                "source": "typed_network_snapshot",
                "summary": "default route changed %s -> %s (generation=%d)"
                % (
                    facts["previous_active_interface"] or "unknown",
                    facts["current_default_route_interface"] or facts["interface"] or "unknown",
                    facts["route_generation"],
                ),
            }
        )
    return evidence


def _diagnosis_status(facts: Mapping[str, Any]) -> str:
    """基于结构化阈值给出保守状态；检索只解释和给建议，不改写观测事实。"""
    if not facts["has_active_interface"] or not facts["interface"]:
        return "unknown"
    score = facts["quality_score"]
    if (
        (score is not None and score < 50)
        or (facts["rtt_ms"] is not None and facts["rtt_ms"] > 200)
        or (
            facts["tcp_retransmission_rate_percent"] is not None
            and facts["tcp_retransmission_rate_percent"] > 2.0
        )
        or (facts["rssi_dbm"] is not None and facts["rssi_dbm"] < -70)
    ):
        return "unhealthy"
    if facts["quality_degraded"] or facts["missing_metrics"] or facts["collector_status"] != "available":
        return "degraded"
    if facts["default_route_changed"]:
        return "degraded"
    return "healthy"


def _rule_actions(facts: Mapping[str, Any]) -> List[str]:
    """即使生成模型不可用，也给出可执行且可由当前指标解释的动作。"""
    actions: List[str] = []
    if not facts["has_active_interface"]:
        actions.append("检查接口发现、默认路由与 using_now 状态是否正常更新。")
    if facts["rtt_ms"] is not None and facts["rtt_ms"] > 200:
        actions.append("对当前出口执行分段 Ping/路由追踪，区分本地链路与上游路径时延。")
    if (
        facts["tcp_retransmission_rate_percent"] is not None
        and facts["tcp_retransmission_rate_percent"] > 2.0
    ):
        actions.append("检查拥塞、MTU 与接收窗口；该字段是 TCP 重传代理值，不按真实丢包率下结论。")
    if facts["rssi_dbm"] is not None and facts["rssi_dbm"] < -70:
        actions.append("改善 Wi-Fi 覆盖或切换接入点，并复测 RSSI 与 RTT。")
    if facts["missing_metrics"]:
        actions.append(f"补齐缺失指标后复诊：{', '.join(facts['missing_metrics'])}。")
    if facts["collector_status"] != "available":
        reason = facts["collector_reason"] or "traffic observation unavailable"
        actions.append(f"恢复流量采集能力后再解释零流量：{reason}。")
    if facts["default_route_changed"]:
        actions.append("核对切换前后接口 ifindex，并确认流量采集器已重绑到新的默认出口。")
    if not actions:
        actions.append("保持当前采样，并关注 RTT、TCP 重传代理值和质量分数的趋势变化。")
    return actions


def _retrieval_query(facts: Mapping[str, Any]) -> str:
    """用 typed facts 构造可复现查询，不再把展示日志交给正则解析器。"""
    parts = [
        "网络诊断 弱网 根因 排查 建议",
        f"接口 {facts['interface'] or 'unknown'}",
        f"质量 {facts['quality_level']}",
        f"流量采集 {facts['collector_status']} {facts['collector_reason']}",
        "默认路由切换 %s -> %s generation=%d"
        % (
            facts["previous_active_interface"] or "unknown",
            facts["current_default_route_interface"] or facts["interface"] or "unknown",
            facts["route_generation"],
        ) if facts["default_route_changed"] else "默认路由未切换",
    ]
    for metric in (
        "rtt_ms",
        "tcp_retransmission_rate_percent",
        "rssi_dbm",
        "traffic_bytes_per_second",
        "traffic_packets_per_second",
        "active_flows",
        "quality_score",
    ):
        if facts[metric] is not None:
            parts.append(f"{metric} {facts[metric]}")
    parts.extend(facts["issues"])
    if facts["missing_metrics"]:
        parts.append(f"缺失指标 {' '.join(facts['missing_metrics'])}")
    return "；".join(parts)


def _canonical_snapshot(facts: Mapping[str, Any]) -> Dict[str, Any]:
    """将 Node camelCase DTO 收敛为 knowledge_pipeline 支持的 snake_case typed schema。"""
    canonical: Dict[str, Any] = {
        "has_active_interface": facts["has_active_interface"],
        "interface_name": facts["interface"],
        "interface_state": facts["interface_state"],
        "quality_level": facts["quality_level"],
        "issues": facts["issues"],
        "missing_metrics": facts["missing_metrics"],
        "collector_status": facts["collector_status"],
        "collector_reason": facts["collector_reason"],
        "ebpf_available": facts["collector_status"] == "available",
        "traffic_generation": facts["traffic_generation"],
        "traffic_bound_ifindex": facts["traffic_bound_ifindex"],
        "traffic_capture_mode": facts["traffic_capture_mode"],
        "traffic_capabilities": facts["traffic_capabilities"],
        "previous_active_interface": facts["previous_active_interface"],
        "current_default_route_interface": facts["current_default_route_interface"],
        "default_route_changed": facts["default_route_changed"],
        "route_generation": facts["route_generation"],
        "route_changed_at_unix_ms": facts["route_changed_at_unix_ms"],
    }
    for key in ("rtt_ms", "rssi_dbm", "quality_score", "active_flows"):
        if facts[key] is not None:
            canonical[key] = facts[key]
    if facts["tcp_retransmission_rate_percent"] is not None:
        canonical["tcp_retransmission_rate"] = facts["tcp_retransmission_rate_percent"]
    if facts["traffic_bytes_per_second"] is not None:
        canonical["traffic_mbps"] = facts["traffic_bytes_per_second"] / (1024.0 * 1024.0)
    return canonical


def _object_dict(value: Any) -> Dict[str, Any]:
    """把 pipeline dataclass/对象/字典转换为只读普通字典。"""
    if isinstance(value, Mapping):
        return dict(value)
    if is_dataclass(value):
        return asdict(value)
    result: Dict[str, Any] = {}
    for name in ("entry_id", "chunk_id", "content_hash", "score", "content", "metadata"):
        if hasattr(value, name):
            result[name] = getattr(value, name)
    return result


def _retrieval_config(snapshot: Mapping[str, Any]) -> Tuple[int, float]:
    """请求级配置优先于环境变量，并拒绝会绕过/放大检索的非法值。"""
    config = _pick(snapshot, "diagnosisConfig", "diagnosis_config", default={}) or {}
    top_k_value = _pick(config, "topK", "top_k", default=os.getenv("RAG_TOP_K", "4"))
    threshold_value = _pick(
        config,
        "similarityThreshold",
        "similarity_threshold",
        default=os.getenv("RAG_SIMILARITY_THRESHOLD", "0.08"),
    )
    try:
        top_k = int(top_k_value)
        threshold = float(threshold_value)
    except (TypeError, ValueError) as error:
        raise ValueError("invalid RAG top_k/similarity_threshold") from error
    if top_k <= 0 or top_k > 100:
        raise ValueError("RAG top_k must be in [1, 100]")
    if not math.isfinite(threshold) or threshold < -1.0 or threshold > 1.0:
        raise ValueError("RAG similarity_threshold must be finite and in [-1, 1]")
    return top_k, threshold


def _retrieve(canonical_snapshot: Mapping[str, Any], query: str, top_k: int,
              similarity_threshold: float) -> Tuple[
    List[Dict[str, Any]], bool, str, List[str], str, str, str, int, float
]:
    """优先调用 diagnose_snapshot；旧 pipeline 才回退到 VersionedKnowledgeStore.retrieve。"""
    try:
        with contextlib.redirect_stdout(sys.stderr):
            import knowledge_pipeline

            diagnose_snapshot = getattr(knowledge_pipeline, "diagnose_snapshot", None)
            if callable(diagnose_snapshot):
                diagnosis = diagnose_snapshot(
                    dict(canonical_snapshot),
                    top_k=top_k,
                    min_score=similarity_threshold,
                )
                raw_evidence = diagnosis.get("evidence", [])
                pipeline_status = str(diagnosis.get("status") or "unavailable")
                insufficient = pipeline_status in {"insufficient_evidence", "unavailable"}
                retrieval_error = str(diagnosis.get("error") or "")
                pipeline_actions = [str(item) for item in diagnosis.get("actions", [])]
                provider = str(diagnosis.get("provider") or "versioned-local-rag")
                artifact_version = str(diagnosis.get("artifact_version") or "unavailable")
                actual_top_k = int(diagnosis.get("top_k", top_k))
                actual_threshold = float(
                    diagnosis.get("similarity_threshold", similarity_threshold)
                )
            else:
                store = knowledge_pipeline.open_default_store(auto_rebuild=True)
                result = store.retrieve(
                    query,
                    top_k=top_k,
                    similarity_threshold=similarity_threshold,
                )
                raw_evidence = getattr(result, "evidence", [])
                insufficient = bool(getattr(result, "insufficient_evidence", False) or not raw_evidence)
                retrieval_error = "" if raw_evidence else "insufficient retrieval evidence"
                pipeline_actions = []
                provider = "versioned-local-rag"
                artifact_version = str(getattr(result, "artifact_version", "") or "current")
                pipeline_status = "unknown"
                actual_top_k = int(getattr(result, "top_k", top_k))
                actual_threshold = float(
                    getattr(result, "similarity_threshold", similarity_threshold)
                )
    except Exception as exc:  # noqa: BLE001 - bridge 必须把所有依赖故障转为 degraded
        _log(f"RAG retrieval unavailable: {exc}")
        return (
            [], True, str(exc), [], "typed-rule-fallback", "unavailable", "unavailable",
            top_k, similarity_threshold,
        )

    evidence: List[Dict[str, Any]] = []
    for item in raw_evidence or []:
        data = _object_dict(item)
        metadata = data.get("metadata") if isinstance(data.get("metadata"), Mapping) else {}
        entry_id = str(data.get("entry_id") or metadata.get("entry_id") or "")
        chunk_id = str(data.get("chunk_id") or metadata.get("chunk_id") or "")
        content = " ".join(str(data.get("content") or "").split())
        score = _finite_number(data.get("score"))
        provenance = metadata.get("source_provenance") \
            if isinstance(metadata.get("source_provenance"), Mapping) else {}
        anchor = provenance.get("anchor") if isinstance(provenance.get("anchor"), Mapping) else {}
        evidence.append(
            {
                "kind": "knowledge",
                "source": str(metadata.get("source") or ""),
                "knowledge_store": f"versioned_knowledge_store:{artifact_version}",
                "artifact_version": artifact_version,
                "summary": content[:240] or f"knowledge entry {entry_id or chunk_id}",
                "knowledge_entry_id": entry_id,
                "chunk_id": chunk_id,
                "content_hash": str(data.get("content_hash") or ""),
                "source_revision": str(metadata.get("source_revision") or ""),
                "source_sha256": str(provenance.get("sha256") or ""),
                "source_anchor": dict(anchor),
                "source_excerpt": str(provenance.get("excerpt") or ""),
                **({"score": score} if score is not None else {}),
            }
        )
    return (
        evidence, insufficient, retrieval_error, pipeline_actions, provider,
        pipeline_status, artifact_version, actual_top_k, actual_threshold,
    )


def _unique(values: Iterable[str]) -> List[str]:
    """保持首次出现顺序的字符串去重。"""
    seen = set()
    result = []
    for value in values:
        if value and value not in seen:
            seen.add(value)
            result.append(value)
    return result


def diagnose(snapshot: Mapping[str, Any]) -> Dict[str, Any]:
    """执行 typed rule + versioned retrieval，并产出稳定结构化诊断。"""
    facts = _snapshot_facts(snapshot)
    metric_evidence = _metric_evidence(facts)
    requested_top_k, requested_threshold = _retrieval_config(snapshot)
    (
        knowledge_evidence,
        insufficient,
        retrieval_error,
        pipeline_actions,
        provider,
        pipeline_status,
        artifact_version,
        actual_top_k,
        actual_threshold,
    ) = _retrieve(
        _canonical_snapshot(facts),
        _retrieval_query(facts),
        requested_top_k,
        requested_threshold,
    )
    knowledge_ids = _unique(
        str(item.get("knowledge_entry_id") or "") for item in knowledge_evidence
    )
    core_metrics = (
        facts["rtt_ms"],
        facts["tcp_retransmission_rate_percent"],
        facts["rssi_dbm"],
        facts["traffic_bytes_per_second"],
    )
    completeness = sum(value is not None for value in core_metrics) / len(core_metrics)
    top_score = max(
        (float(item["score"]) for item in knowledge_evidence if item.get("score") is not None),
        default=0.0,
    )
    snapshot_degraded = bool(
        facts["quality_degraded"]
        or facts["missing_metrics"]
        or facts["collector_status"] != "available"
    )
    fallback_status = _diagnosis_status(facts)
    if pipeline_status in {"healthy", "degraded", "unhealthy", "insufficient_evidence"}:
        status = pipeline_status
    elif pipeline_status == "unavailable":
        status = fallback_status if fallback_status in {"degraded", "unhealthy"} else "unavailable"
    else:
        status = fallback_status
        if insufficient and status == "healthy":
            status = "insufficient_evidence"
    degraded = snapshot_degraded or insufficient or status == "degraded"
    confidence = 0.25 + 0.35 * completeness + 0.3 * max(0.0, min(1.0, top_score))
    if insufficient:
        confidence = min(confidence, 0.45)
    if snapshot_degraded:
        confidence -= 0.1
    return {
        "schema_version": SCHEMA_VERSION,
        "status": status,
        "evidence": metric_evidence + knowledge_evidence,
        "knowledge_entry_ids": knowledge_ids,
        "confidence": round(max(0.05, min(0.95, confidence)), 3),
        "actions": _unique(pipeline_actions + _rule_actions(facts)),
        "degraded": degraded,
        "provider": provider,
        "artifact_version": artifact_version,
        "top_k": actual_top_k,
        "similarity_threshold": actual_threshold,
        "error": retrieval_error,
    }


def _serve(lines: Sequence[str]) -> int:
    """逐行处理 JSONL；单行格式错误也返回契约内 unknown/degraded 结果。"""
    for raw_line in lines:
        if not raw_line.strip():
            continue
        try:
            payload = json.loads(raw_line)
            if not isinstance(payload, Mapping):
                raise TypeError("typed NetworkSnapshot must be a JSON object")
            result = diagnose(payload)
        except Exception as exc:  # noqa: BLE001 - 保证每个请求都有协议响应
            _log(f"Bridge request failed: {exc}")
            result = {
                "schema_version": SCHEMA_VERSION,
                "status": "unknown",
                "evidence": [],
                "knowledge_entry_ids": [],
                "confidence": 0.0,
                "actions": ["修复 typed NetworkSnapshot 输入后重试。"],
                "degraded": True,
                "provider": "typed-rule-fallback",
                "artifact_version": "unavailable",
                "top_k": 4,
                "similarity_threshold": 0.08,
                "error": str(exc),
            }
        print(json.dumps(result, ensure_ascii=False, separators=(",", ":")), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(_serve(sys.stdin))
