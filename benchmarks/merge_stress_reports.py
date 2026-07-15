#!/usr/bin/env python3
"""严格校验并合并不同机器/阶段生成的 WeakNet benchmark summary。

合并器把输入报告视为不可信边界：只有符合统一 schema、profile 和状态契约
的报告才会作为子结果导入。非法、重复或自相矛盾的输入会保留为 failed
记录，确保总报告和进程退出码都不会出现“假绿”。
"""

from __future__ import annotations

import argparse
import copy
import json
import math
import os
import platform
import shlex
import time
from pathlib import Path
from typing import Any, Iterable

from run_stress_suite import atomic_json_write, atomic_text_write, render_markdown, utc_now


SCHEMA_VERSION = "weaknet.benchmark.v1"
VALID_STATUSES = frozenset({"passed", "failed", "skipped"})
REQUIRED_TOP_LEVEL_FIELDS = frozenset(
    {
        "schema_version",
        "component",
        "profile",
        "environment",
        "started_at",
        "duration_ms",
        "benchmarks",
        "summary",
    }
)
CORRECTNESS_FLAGS = frozenset(
    {
        "correctness_pass",
        "correctness_passed",
        "correctness_gate_passed",
        "mutation_guard_pass",
    }
)
FAILURE_COUNT_FIELDS = frozenset({"failed", "failures", "errors", "error_count"})
SOURCE_IDENTITY_FIELDS = ("algorithm", "sha256", "file_count", "scope_globs")


def _is_finite_number(value: Any) -> bool:
    """判断值是否为有限实数；bool 虽是 int 子类，但不能充当 benchmark 数值。"""

    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(float(value))
    )


def _validate_source_identity(value: Any, path: str) -> list[str]:
    """校验可重放源码指纹，返回全部字段/类型错误。

    identity 一旦出现就必须完整，不能只提供一个看似可信的 hash 而省略算法、
    文件数或范围；否则不同源码集合可能被错误合并为同一轮结果。
    """

    if not isinstance(value, dict):
        return [f"{path} must be an object"]

    errors = [
        f"{path} missing field: {field}"
        for field in SOURCE_IDENTITY_FIELDS
        if field not in value
    ]
    algorithm = value.get("algorithm")
    if not isinstance(algorithm, str) or not algorithm.strip():
        errors.append(f"{path}.algorithm must be a non-empty string")

    digest = value.get("sha256")
    if (
        not isinstance(digest, str)
        or len(digest) != 64
        or any(character not in "0123456789abcdefABCDEF" for character in digest)
    ):
        errors.append(f"{path}.sha256 must be a 64-character hexadecimal string")

    file_count = value.get("file_count")
    if (
        not isinstance(file_count, int)
        or isinstance(file_count, bool)
        or file_count < 0
    ):
        errors.append(f"{path}.file_count must be a non-negative integer")

    scope_globs = value.get("scope_globs")
    if not isinstance(scope_globs, list) or not scope_globs or not all(
        isinstance(pattern, str) and pattern for pattern in scope_globs
    ):
        errors.append(f"{path}.scope_globs must be a non-empty array of non-empty strings")
    return errors


def _source_identity_key(identity: dict[str, Any]) -> tuple[Any, ...]:
    """生成严格身份键；scope_globs 的内容和顺序都属于哈希口径。"""

    return (
        identity["algorithm"],
        identity["sha256"],
        identity["file_count"],
        tuple(identity["scope_globs"]),
    )


def _walk_correctness_flags(
    value: Any,
    path: str = "",
    report_status: str | None = None,
) -> Iterable[tuple[str, Any, str | None]]:
    """递归找出正确性门禁，并关联它所属的最近一层报告状态。"""

    if isinstance(value, dict):
        summary = value.get("summary")
        if isinstance(summary, dict) and summary.get("status") in VALID_STATUSES:
            report_status = summary["status"]
        for key, child in value.items():
            child_path = f"{path}.{key}" if path else str(key)
            if key in CORRECTNESS_FLAGS:
                yield child_path, child, report_status
            yield from _walk_correctness_flags(child, child_path, report_status)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from _walk_correctness_flags(child, f"{path}[{index}]", report_status)


def _walk_benchmark_entries(
    value: Any,
    path: str = "",
    report_status: str | None = None,
) -> Iterable[tuple[str, dict[str, Any], str | None]]:
    """递归枚举各级报告的 benchmark 项，并绑定最近一层 summary.status。"""

    if isinstance(value, dict):
        summary = value.get("summary")
        if isinstance(summary, dict) and summary.get("status") in VALID_STATUSES:
            report_status = summary["status"]
        benchmarks = value.get("benchmarks")
        if isinstance(benchmarks, list):
            benchmark_path = f"{path}.benchmarks" if path else "benchmarks"
            for index, benchmark in enumerate(benchmarks):
                if isinstance(benchmark, dict):
                    yield f"{benchmark_path}[{index}]", benchmark, report_status
        for key, child in value.items():
            child_path = f"{path}.{key}" if path else str(key)
            yield from _walk_benchmark_entries(child, child_path, report_status)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from _walk_benchmark_entries(child, f"{path}[{index}]", report_status)


def validate_summary(payload: Any, expected_profile: str) -> list[str]:
    """返回完整契约错误列表；合法的 failed 报告本身不是结构错误。

    校验采用 fail-closed：只有 schema、profile、数值、状态与所有嵌套正确性字段
    自洽时才允许导入。这样子项失败无法被外层的 0 error 或 passed 状态掩盖。
    """

    if not isinstance(payload, dict):
        return ["top-level JSON must be an object"]

    errors = [
        f"missing top-level field: {field}"
        for field in sorted(REQUIRED_TOP_LEVEL_FIELDS - payload.keys())
    ]

    if payload.get("schema_version") != SCHEMA_VERSION:
        errors.append(
            "schema_version mismatch: "
            f"expected {SCHEMA_VERSION!r}, got {payload.get('schema_version')!r}"
        )

    component = payload.get("component")
    if not isinstance(component, str) or not component.strip():
        errors.append("component must be a non-empty string")

    profile = payload.get("profile")
    if not isinstance(profile, str) or profile != expected_profile:
        errors.append(f"profile mismatch: expected {expected_profile!r}, got {profile!r}")

    environment = payload.get("environment")
    if not isinstance(environment, dict):
        errors.append("environment must be an object")
    else:
        # These fields are optional across component implementations, but their
        # types must be stable when present because they participate in identity.
        for key in ("system", "os", "platform", "release", "machine"):
            if key in environment and not isinstance(environment[key], str):
                errors.append(f"environment.{key} must be a string when present")
        if "cpu_count" in environment:
            cpu_count = environment["cpu_count"]
            if cpu_count is not None and (
                not isinstance(cpu_count, int) or isinstance(cpu_count, bool) or cpu_count < 0
            ):
                errors.append("environment.cpu_count must be a non-negative integer or null")
        if "source_identity" in environment:
            errors.extend(
                _validate_source_identity(
                    environment["source_identity"], "environment.source_identity"
                )
            )

    started_at = payload.get("started_at")
    if not isinstance(started_at, str) or not started_at.strip():
        errors.append("started_at must be a non-empty string")

    duration_ms = payload.get("duration_ms")
    if not _is_finite_number(duration_ms) or float(duration_ms) < 0:
        errors.append("duration_ms must be a finite non-negative number")

    benchmarks = payload.get("benchmarks")
    if not isinstance(benchmarks, list):
        errors.append("benchmarks must be an array")
    else:
        for index, benchmark in enumerate(benchmarks):
            if not isinstance(benchmark, dict):
                errors.append(f"benchmarks[{index}] must be an object")

    summary = payload.get("summary")
    if not isinstance(summary, dict):
        errors.append("summary must be an object")
        return errors

    status = summary.get("status")
    if not isinstance(status, str) or status not in VALID_STATUSES:
        errors.append(
            "summary.status must be exactly one of "
            f"{sorted(VALID_STATUSES)!r}, got {status!r}"
        )
        status = None
    if status == "passed":
        correctness_values = [
            summary[key]
            for key in CORRECTNESS_FLAGS
            if key in summary and isinstance(summary[key], bool)
        ]
        if not any(value is True for value in correctness_values):
            errors.append(
                "passed summary must contain at least one known correctness field set to true"
            )

    if isinstance(benchmarks, list) and status == "passed" and not benchmarks:
        errors.append("a passed report must contain at least one benchmark")
    if isinstance(benchmarks, list) and _is_finite_number(summary.get("benchmark_count")):
        if int(summary["benchmark_count"]) != len(benchmarks):
            errors.append(
                f"summary.benchmark_count={summary['benchmark_count']} does not match "
                f"benchmarks length {len(benchmarks)}"
            )
    if (
        status == "passed"
        and _is_finite_number(summary.get("request_count"))
        and _is_finite_number(summary.get("success_count"))
        and float(summary["request_count"]) != float(summary["success_count"])
    ):
        errors.append("summary.success_count must equal request_count for passed status")

    for key in FAILURE_COUNT_FIELDS:
        if key not in summary:
            continue
        value = summary[key]
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            errors.append(f"summary.{key} must be a non-negative integer")
        elif status in {"passed", "skipped"} and value != 0:
            errors.append(f"summary.status={status!r} contradicts summary.{key}={value}")

    for path, value, owning_status in _walk_correctness_flags(payload):
        if value is None and owning_status == "skipped":
            # Unsupported BPF/kernel reports can explicitly mark correctness N/A.
            continue
        if not isinstance(value, bool):
            errors.append(
                f"{path} must be boolean"
                + (" or null for skipped reports" if owning_status == "skipped" else "")
            )
        elif owning_status in {"passed", "skipped"} and value is False:
            errors.append(f"owning summary.status={owning_status!r} contradicts {path}=false")

    # summary 不能用 0 error 掩盖任一子 benchmark 的失败计数或失败状态。
    for path, benchmark, owning_status in _walk_benchmark_entries(payload):
        for key in ("error_count", "determinism_mismatch_count"):
            if key not in benchmark:
                continue
            value = benchmark[key]
            if not _is_finite_number(value) or float(value) < 0:
                errors.append(f"{path}.{key} must be a finite non-negative number")
            elif owning_status == "passed" and float(value) > 0:
                errors.append(f"owning summary.status='passed' contradicts {path}.{key}={value}")
        if "errors" in benchmark:
            value = benchmark["errors"]
            if isinstance(value, list):
                nonempty = bool(value)
            elif _is_finite_number(value) and float(value) >= 0:
                nonempty = float(value) > 0
            else:
                errors.append(f"{path}.errors must be a non-negative number or an array")
                nonempty = False
            if owning_status == "passed" and nonempty:
                errors.append(f"owning summary.status='passed' contradicts non-empty {path}.errors")
        item_status = benchmark.get("status")
        if owning_status == "passed" and isinstance(item_status, str) and item_status.lower() in {
            "fail", "failed", "failure", "error",
        }:
            errors.append(
                f"owning summary.status='passed' contradicts {path}.status={item_status!r}"
            )
        requests = benchmark.get("requests")
        successes = benchmark.get("success_count")
        if requests is not None and successes is not None:
            if not _is_finite_number(requests) or float(requests) < 0:
                errors.append(f"{path}.requests must be a finite non-negative number")
            if not _is_finite_number(successes) or float(successes) < 0:
                errors.append(f"{path}.success_count must be a finite non-negative number")
            if (
                owning_status == "passed"
                and _is_finite_number(requests)
                and _is_finite_number(successes)
                and float(requests) != float(successes)
            ):
                errors.append(
                    f"owning summary.status='passed' requires {path}.success_count==requests"
                )

    return errors


def _environment_label(environment: dict[str, Any]) -> str:
    """从兼容字段中挑选稳定环境标签；均缺失时返回 ``unknown``。"""

    for key in ("system", "os", "platform", "machine"):
        value = environment.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return "unknown"


def _command_for(path: Path) -> str:
    """生成仅用于报告展示的输入导入描述，不执行该字符串。"""

    return f"import {shlex.quote(str(path))}"


def _invalid_record(
    *,
    index: int,
    source_path: Path,
    reason: str,
    payload: Any = None,
) -> dict[str, Any]:
    """把非法输入包装成唯一 failed 记录，使其留在报告中可追溯。

    返回值刻意不携带原始 ``result``，避免未经校验的任意结构进入 Markdown
    渲染器；这也是解析失败时仍然 fail-closed 而不是静默丢弃输入的关键。
    """

    return {
        # Valid imported names always contain both ':' and '@'. This reserved
        # shape therefore cannot collide with a valid child identity.
        "name": f"invalid-input-{index}",
        "status": "failed",
        "reason": reason,
        "command": _command_for(source_path),
        "exit_code": 2,
        "wall_time_ms": 0.0,
        "started_at": utc_now(),
        "output_path": str(source_path),
        "validation_errors": [reason],
        "stdout_tail": "",
        "stderr_tail": "",
        # Invalid payload shapes must not reach render_markdown(), which expects
        # a validated result object. The source path and full validation reason
        # remain in the record for auditability.
        "result": None,
    }


def _load_record(
    *,
    index: int,
    source_path: Path,
    expected_profile: str,
    used_names: set[str],
) -> dict[str, Any]:
    """读取并校验一个 summary，返回标准子记录；任何异常都转换为 failed 记录。"""

    try:
        decoded = json.loads(source_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return _invalid_record(
            index=index,
            source_path=source_path,
            reason=f"cannot read benchmark summary: {exc}",
        )

    validation_errors = validate_summary(decoded, expected_profile)
    if validation_errors:
        return _invalid_record(
            index=index,
            source_path=source_path,
            reason="invalid benchmark summary: " + "; ".join(validation_errors),
            payload=decoded,
        )

    # All accessed fields have been type-checked above.
    payload: dict[str, Any] = decoded
    child_status: str = payload["summary"]["status"]
    child_environment: dict[str, Any] = payload["environment"]
    name = (
        f"{source_path.parent.name}:{payload['component']}@"
        f"{_environment_label(child_environment)}"
    )
    if name in used_names:
        return _invalid_record(
            index=index,
            source_path=source_path,
            reason=f"duplicate merged record name: {name!r}",
            payload=payload,
        )
    used_names.add(name)

    child_reason = None
    if child_status != "passed":
        summary_reason = payload["summary"].get("reason")
        child_reason = (
            str(summary_reason)
            if isinstance(summary_reason, str) and summary_reason.strip()
            else f"child suite status={child_status}"
        )
    return {
        "name": name,
        "status": child_status,
        "reason": child_reason,
        "command": _command_for(source_path),
        "exit_code": 2 if child_status == "failed" else 0,
        "wall_time_ms": round(float(payload["duration_ms"]), 3),
        "started_at": payload["started_at"],
        "output_path": str(source_path),
        "validation_errors": [],
        "stdout_tail": "",
        "stderr_tail": "",
        "result": payload,
    }


def _mark_record_failed(record: dict[str, Any], reason: str) -> None:
    """把合并边界发现的跨报告错误投影为可审计 failed 记录。"""

    previous_reason = record.get("reason")
    record["status"] = "failed"
    record["exit_code"] = 2
    record["reason"] = (
        f"{previous_reason}; {reason}"
        if isinstance(previous_reason, str) and previous_reason.strip()
        else reason
    )
    validation_errors = record.setdefault("validation_errors", [])
    if reason not in validation_errors:
        validation_errors.append(reason)


def _apply_source_identity_policy(
    records: list[dict[str, Any]],
) -> tuple[dict[str, Any] | None, dict[str, Any]]:
    """强制跨机器报告来自同一源码快照，并返回根报告的覆盖信息。

    全部旧报告都无指纹时保留 NOHASH 兼容状态；但“部分有、部分没有”以及任一
    指纹不一致都会把相关 child 标失败。只有所有输入完整同源时根报告才继承
    identity，防止把不同版本的性能数字拼成一份看似可复现的结论。
    """

    present: list[tuple[dict[str, Any], dict[str, Any]]] = []
    missing: list[dict[str, Any]] = []
    for record in records:
        payload = record.get("result")
        environment = payload.get("environment") if isinstance(payload, dict) else None
        identity = environment.get("source_identity") if isinstance(environment, dict) else None
        if isinstance(identity, dict):
            # validate_summary 已确保这里四个字段完整且类型合法。
            present.append((record, identity))
        else:
            missing.append(record)

    coverage: dict[str, Any] = {
        "status": "none",
        "input_count": len(records),
        "hashed_children": len(present),
        "missing_children": len(missing),
        "missing_identity_summaries": [record["output_path"] for record in missing],
        "mismatched_summaries": [],
    }
    if not present:
        # 兼容历史上全部不带 hash 的报告，但显式标成 NOHASH，不能误称已绑定源码。
        coverage["status"] = "NOHASH"
        return None, coverage

    reference_record, reference_identity = present[0]
    reference_key = _source_identity_key(reference_identity)
    coverage["reference_summary"] = reference_record["output_path"]
    mismatched: list[dict[str, Any]] = []
    for record, identity in present[1:]:
        if _source_identity_key(identity) == reference_key:
            continue
        differing_fields = [
            field
            for field in SOURCE_IDENTITY_FIELDS
            if identity[field] != reference_identity[field]
        ]
        reason = (
            "environment.source_identity mismatch against "
            f"{reference_record['output_path']}: fields={','.join(differing_fields)}"
        )
        _mark_record_failed(record, reason)
        mismatched.append(record)

    # “一部分有 hash、一部分没有”也无法证明同源；合法但缺失 identity 的 child 必须失败。
    if missing:
        for record in missing:
            if isinstance(record.get("result"), dict):
                _mark_record_failed(
                    record,
                    "environment.source_identity missing while another child supplies one",
                )

    coverage["mismatched_summaries"] = [record["output_path"] for record in mismatched]
    if mismatched and missing:
        coverage["status"] = "mismatch-and-partial"
    elif mismatched:
        coverage["status"] = "mismatch"
    elif missing:
        coverage["status"] = "partial"
    else:
        coverage["status"] = "complete"
        # 仅在每个输入都被同一份指纹覆盖时，根报告才继承该 identity。
        return copy.deepcopy(reference_identity), coverage
    return None, coverage


def main() -> int:
    """解析输入、逐份校验、执行同源策略并原子写出合并报告。

    返回 0 仅代表没有 failed 子记录；任何路径重复、解析错误、状态矛盾或源码
    身份不一致都返回 2，确保命令行和 CI 的最终状态与报告一致。
    """

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=("smoke", "standard", "stress"), required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("summaries", nargs="+", type=Path)
    args = parser.parse_args()

    merge_started_at = utc_now()
    merge_start_ns = time.perf_counter_ns()
    records: list[dict[str, Any]] = []
    used_paths: dict[Path, int] = {}
    used_names: set[str] = set()
    resolved_inputs = [path.expanduser().resolve() for path in args.summaries]

    for index, source_path in enumerate(resolved_inputs, start=1):
        previous_index = used_paths.get(source_path)
        if previous_index is not None:
            records.append(
                _invalid_record(
                    index=index,
                    source_path=source_path,
                    reason=(
                        "duplicate input path: "
                        f"argument {index} resolves to the same file as argument {previous_index}"
                    ),
                )
            )
            continue
        used_paths[source_path] = index
        records.append(
            _load_record(
                index=index,
                source_path=source_path,
                expected_profile=args.profile,
                used_names=used_names,
            )
        )

    common_source_identity, source_identity_coverage = _apply_source_identity_policy(records)

    passed = sum(record["status"] == "passed" for record in records)
    failed = sum(record["status"] == "failed" for record in records)
    skipped = sum(record["status"] == "skipped" for record in records)
    child_duration_ms = sum(float(record["wall_time_ms"]) for record in records)
    merge_processing_ms = (time.perf_counter_ns() - merge_start_ns) / 1_000_000.0
    overall_status = "failed" if failed else ("skipped" if passed == 0 and skipped else "passed")

    aggregate_environment: dict[str, Any] = {
        "system": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
        "cpu_count": os.cpu_count(),
        "source_summaries": [str(path) for path in resolved_inputs],
        "source_identity_coverage": source_identity_coverage,
        "duration_aggregation": "sum(child duration_ms) + merge processing time",
        "child_duration_total_ms": round(child_duration_ms, 3),
        "merge_processing_ms": round(merge_processing_ms, 3),
    }
    if common_source_identity is not None:
        aggregate_environment["source_identity"] = common_source_identity

    aggregate: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "component": "weaknet-mac-lima-stress-suite",
        "profile": args.profile,
        "environment": aggregate_environment,
        "started_at": merge_started_at,
        "duration_ms": round(child_duration_ms + merge_processing_ms, 3),
        "benchmarks": records,
        "summary": {
            "status": overall_status,
            "passed": passed,
            "failed": failed,
            "skipped": skipped,
            "correctness_gate_passed": failed == 0,
            "performance_regressions": 0,
        },
        "baseline_path": None,
        "performance_regressions": [],
    }
    args.output_dir.mkdir(parents=True, exist_ok=True)
    atomic_json_write(args.output_dir / "summary.json", aggregate)
    atomic_text_write(args.output_dir / "report.md", render_markdown(aggregate))
    print(f"[{overall_status}] merged report: {args.output_dir / 'report.md'}")
    return 0 if failed == 0 else 2


if __name__ == "__main__":
    raise SystemExit(main())
