#!/usr/bin/env python3
"""统一编排 WeakNet 各层压力测试，并生成机器可读 JSON 与中文 Markdown 报告。

这个入口只负责进程编排、环境记录、正确性门禁和可选基线比较；每个组件的
具体负载由对应 benchmark 自己实现，避免把测量逻辑和报告逻辑耦合在一起。
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import math
import os
import platform
import shlex
import shutil
import signal
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


SCHEMA_VERSION = "weaknet.benchmark.v1"
REQUIRED_RESULT_FIELDS = {
    "schema_version",
    "component",
    "profile",
    "environment",
    "started_at",
    "duration_ms",
    "benchmarks",
    "summary",
}
KNOWN_COMPONENTS = (
    "contracts", "core", "sanitizer", "bpf", "kernel", "rag", "service", "event-pipeline"
)
PROFILE_TIMEOUT_SECONDS = {"smoke": 300, "standard": 1800, "stress": 7200}
ALLOWED_SUMMARY_STATUSES = {"passed", "failed", "skipped"}
CORRECTNESS_FIELDS = (
    "correctness_pass",
    "correctness_passed",
    "correctness_gate_passed",
)
SOURCE_IDENTITY_GLOBS = (
    "Makefile",
    "config.mk",
    "benchmarks/*.py",
    "benchmarks/*.mjs",
    "benchmarks/*.sh",
    "client/*.cpp",
    "client/*.h",
    "server/Makefile",
    "server/include/*.h",
    "server/include/*.hpp",
    "server/src/*.c",
    "server/src/*.cpp",
    "server/tests/*.cpp",
    "server/tests/*.hpp",
    "server/tests/*.sh",
    "proto/*.proto",
    "dashboard/package.json",
    "dashboard/package-lock.json",
    "dashboard/server/*.mjs",
    "dashboard/src/*.ts",
    "dashboard/src/*.tsx",
    "dashboard/vite.config.ts",
    "dashboard/tsconfig.json",
    "AI-assisted analysis/*.py",
    "AI-assisted analysis/requirements.txt",
    "AI-assisted analysis/knowledge/raw/*.json",
    "AI-assisted analysis/knowledge/schema/*.json",
    "AI-assisted analysis/knowledge/*.json",
)


@dataclass(frozen=True)
class ComponentCommand:
    """描述一个待执行组件：逻辑名称、完整命令和它必须生成的 JSON 路径。"""

    name: str
    command: list[str]
    output_path: Path


def utc_now() -> str:
    """返回带毫秒精度的 UTC 时间戳，用于关联总报告与子报告。"""

    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds")


def atomic_json_write(path: Path, payload: dict[str, Any]) -> None:
    """先写临时文件再原子替换目标 JSON，避免中断时留下半份报告。"""

    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=False) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)


def atomic_text_write(path: Path, content: str) -> None:
    """原子写入文本报告；写入失败时保留上一份完整结果。"""

    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(content, encoding="utf-8")
    temporary.replace(path)


def command_output(command: list[str], cwd: Path, timeout: float = 10.0) -> str | None:
    """执行只读探测命令并返回非空 stdout；失败或超时统一返回 ``None``。"""

    try:
        completed = subprocess.run(
            command,
            cwd=cwd,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    value = completed.stdout.strip()
    return value if completed.returncode == 0 and value else None


def collect_source_identity(repo_root: Path) -> dict[str, Any]:
    """计算本轮压测源码指纹，返回算法、摘要、文件数和纳入范围。

    Git commit 无法描述未提交文件，因此把相对路径长度、路径、内容长度和内容
    逐项送入 SHA-256。路径也参与摘要，可防止“内容相同但文件归属不同”被误判
    为同一输入；读取失败会直接抛出异常，不能用缺失文件继续生成假可复现报告。
    """
    files = sorted(
        {
            path.resolve()
            for pattern in SOURCE_IDENTITY_GLOBS
            for path in repo_root.glob(pattern)
            if path.is_file()
        },
        key=lambda path: path.relative_to(repo_root).as_posix(),
    )
    digest = hashlib.sha256()
    for path in files:
        relative = path.relative_to(repo_root).as_posix().encode("utf-8")
        content = path.read_bytes()
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return {
        "algorithm": "sha256(path-length||path||content-length||content)",
        "sha256": digest.hexdigest(),
        "file_count": len(files),
        "scope_globs": list(SOURCE_IDENTITY_GLOBS),
    }


def collect_environment(repo_root: Path, node_path: str | None) -> dict[str, Any]:
    """采集宿主、运行时、Git 状态和源码指纹，作为报告的可复现环境。"""

    git_status = command_output(
        ["git", "-c", "core.fsmonitor=false", "status", "--porcelain"], repo_root
    )
    node_version = command_output([node_path, "--version"], repo_root) if node_path else None
    return {
        "hostname": platform.node(),
        "platform": platform.platform(),
        "system": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
        "cpu_count": os.cpu_count(),
        "python": sys.version.split()[0],
        "python_executable": sys.executable,
        "node": node_version,
        "is_root": hasattr(os, "geteuid") and os.geteuid() == 0,
        "git_commit": command_output(["git", "rev-parse", "HEAD"], repo_root),
        "git_dirty": bool(git_status),
        "source_identity": collect_source_identity(repo_root),
    }


def parse_components(value: str, profile: str, fixture: bool, service_requested: bool) -> list[str]:
    """解析组件选择并返回去重后的执行顺序；未知或空选择抛出 ``ValueError``。"""

    if value == "auto":
        # contracts 是所有并发性能数字的前置可信度门禁，默认档绝不能绕过它。
        selected = ["contracts", "core", "rag"]
        if platform.system() == "Linux":
            selected.append("sanitizer")
            if hasattr(os, "geteuid") and os.geteuid() == 0:
                selected.append("bpf")
                if profile != "smoke":
                    selected.append("kernel")
        if fixture or service_requested:
            selected.append("service")
        return selected
    if value == "all":
        # event-pipeline is an opt-in live component because it needs the
        # companion Linux driver control endpoint and a fresh Dashboard.
        return [name for name in KNOWN_COMPONENTS if name != "event-pipeline"]

    selected: list[str] = []
    for raw in value.split(","):
        name = raw.strip().lower()
        if not name:
            continue
        if name not in KNOWN_COMPONENTS:
            raise ValueError(f"unknown component: {name}; choose from {','.join(KNOWN_COMPONENTS)}")
        if name not in selected:
            selected.append(name)
    if not selected:
        raise ValueError("at least one component must be selected")
    return selected


def resolve_node(explicit: str | None) -> str | None:
    """优先使用显式 Node 路径，否则从 PATH 查找；找不到时返回 ``None``。"""

    if explicit:
        return explicit
    return shutil.which("node")


def append_common_load_overrides(command: list[str], args: argparse.Namespace) -> None:
    """把并发数、请求数和预热数覆盖项附加到子 benchmark 命令。"""

    if args.concurrency:
        command.extend(["--concurrency", args.concurrency])
    if args.requests is not None:
        command.extend(["--requests", str(args.requests)])
    if args.warmup is not None:
        command.extend(["--warmup", str(args.warmup)])


def build_component_command(
    component: str,
    args: argparse.Namespace,
    repo_root: Path,
    component_dir: Path,
    node_path: str | None,
) -> ComponentCommand:
    """按组件拼出唯一执行命令和输出位置；缺少必需运行时或端点时抛异常。"""

    output_path = component_dir / f"{component}.json"
    if component == "contracts":
        command = [
            args.python,
            str(repo_root / "benchmarks" / "pressure_contract_audit.py"),
            "--profile",
            args.profile,
            "--output",
            str(output_path),
        ]
    elif component == "core":
        command = [
            "make",
            "-C",
            "server",
            "benchmark-traffic-core",
            f"PROFILE={args.profile}",
            f"OUTPUT={output_path}",
        ]
    elif component == "sanitizer":
        command = [
            "make",
            "-C",
            "server",
            "benchmark-core-tsan",
            f"PROFILE={args.profile}",
            f"OUTPUT={output_path}",
        ]
    elif component == "bpf":
        command = [
            "make",
            "-C",
            "server",
            "benchmark-bpf-maps",
            f"PROFILE={args.profile}",
            f"OUTPUT={output_path}",
        ]
        if args.sudo_linux and hasattr(os, "geteuid") and os.geteuid() != 0:
            command.insert(0, "sudo")
    elif component == "kernel":
        command = [
            "make",
            "-C",
            "server",
            "benchmark-kernel-pressure",
            f"PROFILE={args.profile}",
            f"OUTPUT={output_path}",
        ]
        if args.sudo_linux and hasattr(os, "geteuid") and os.geteuid() != 0:
            command.insert(0, "sudo")
    elif component == "rag":
        command = [
            args.python,
            str(repo_root / "benchmarks" / "rag_benchmark.py"),
            "--profile",
            args.profile,
            "--output",
            str(output_path),
        ]
        if args.fixture:
            command.append("--fixture")
        if args.offline_artifact:
            command.append("--offline-artifact")
        if args.synthetic_entries is not None:
            command.extend(["--synthetic-entries", str(args.synthetic_entries)])
        append_common_load_overrides(command, args)
    elif component == "service":
        if not node_path:
            raise RuntimeError("node executable not found; pass --node /absolute/path/to/node")
        command = [
            node_path,
            str(repo_root / "benchmarks" / "service_benchmark.mjs"),
            "--profile",
            args.profile,
            "--output",
            str(output_path),
            "--timeout-ms",
            str(args.service_timeout_ms),
        ]
        if args.fixture:
            command.append("--fixture")
        if args.grpc_address:
            command.extend(["--grpc-address", args.grpc_address])
        if args.dashboard_url:
            command.extend(["--dashboard-url", args.dashboard_url])
        if args.skip_grpc:
            command.append("--skip-grpc")
        if args.skip_dashboard:
            command.append("--skip-dashboard")
        if args.events:
            command.append("--events")
        if args.require_event:
            command.append("--require-event")
        if args.service_targets:
            command.extend(["--targets", args.service_targets])
        if args.ping_target:
            command.extend(["--ping-target", args.ping_target])
        command.extend(
            [
                "--event-timeout-ms",
                str(args.event_timeout_ms),
                "--event-window-ms",
                str(args.event_window_ms),
                "--event-max-events",
                str(args.event_max_events),
            ]
        )
        if args.event_connections:
            command.extend(["--event-connections", args.event_connections])
        append_common_load_overrides(command, args)
    elif component == "event-pipeline":
        if not node_path:
            raise RuntimeError("node executable not found; pass --node /absolute/path/to/node")
        if not args.event_control_address:
            raise RuntimeError(
                "event-pipeline requires --event-control-address from event_pipeline_driver"
            )
        if not args.dashboard_url:
            raise RuntimeError("event-pipeline requires --dashboard-url")
        command = [
            node_path,
            str(repo_root / "benchmarks" / "event_pipeline_benchmark.mjs"),
            "--profile",
            args.profile,
            "--output",
            str(output_path),
            "--control-address",
            args.event_control_address,
            "--dashboard-url",
            args.dashboard_url,
            "--timeout-ms",
            str(args.event_timeout_ms),
        ]
        if args.event_run_id:
            command.extend(["--run-id", args.event_run_id])
    else:  # pragma: no cover - guarded by parse_components.
        raise ValueError(component)
    return ComponentCommand(component, command, output_path)


def is_finite_number(value: Any) -> bool:
    """判断值是否为有限实数，并显式排除 Python 中属于 ``int`` 子类的布尔值。"""

    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(float(value))
    )


def walk_correctness_flags(
    value: Any,
    path: str = "",
    report_status: str | None = None,
) -> Iterable[tuple[str, Any, str | None]]:
    """递归产出所有正确性字段，并把它绑定到最近一层报告状态。

    这使嵌套 child 的 ``correctness=false`` 无法被外层 ``passed`` 汇总掩盖。
    """

    if isinstance(value, dict):
        summary = value.get("summary")
        if isinstance(summary, dict) and summary.get("status") in ALLOWED_SUMMARY_STATUSES:
            report_status = summary["status"]
        for key, child in value.items():
            child_path = f"{path}.{key}" if path else str(key)
            if key in CORRECTNESS_FIELDS:
                yield child_path, child, report_status
            yield from walk_correctness_flags(child, child_path, report_status)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from walk_correctness_flags(child, f"{path}[{index}]", report_status)


def walk_benchmark_entries(
    value: Any,
    path: str = "",
    report_status: str | None = None,
) -> Iterable[tuple[str, dict[str, Any], str | None]]:
    """递归枚举 benchmark 项及其最近一层状态，供跨层矛盾校验使用。"""

    if isinstance(value, dict):
        summary = value.get("summary")
        if isinstance(summary, dict) and summary.get("status") in ALLOWED_SUMMARY_STATUSES:
            report_status = summary["status"]
        benchmarks = value.get("benchmarks")
        if isinstance(benchmarks, list):
            benchmark_path = f"{path}.benchmarks" if path else "benchmarks"
            for index, benchmark in enumerate(benchmarks):
                if isinstance(benchmark, dict):
                    yield f"{benchmark_path}[{index}]", benchmark, report_status
        for key, child in value.items():
            child_path = f"{path}.{key}" if path else str(key)
            yield from walk_benchmark_entries(child, child_path, report_status)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from walk_benchmark_entries(child, f"{path}[{index}]", report_status)


def validate_child_result(payload: Any, expected_component: str, profile: str) -> list[str]:
    """校验子结果的 schema、身份和正确性契约，返回全部错误而非首个错误。

    这是聚合器的 fail-closed 边界：字段缺失、状态模糊、计数矛盾或空的
    ``passed`` 报告都会被判失败，只有显式且自洽的结果才能进入总报告。
    """

    if not isinstance(payload, dict):
        return ["top-level JSON must be an object"]
    errors = [f"missing top-level field: {name}" for name in sorted(REQUIRED_RESULT_FIELDS - payload.keys())]
    if payload.get("schema_version") != SCHEMA_VERSION:
        errors.append(
            f"schema_version mismatch: expected {SCHEMA_VERSION!r}, "
            f"got {payload.get('schema_version')!r}"
        )
    if payload.get("profile") != profile:
        errors.append(f"profile mismatch: expected {profile!r}, got {payload.get('profile')!r}")
    raw_component = payload.get("component")
    actual_component = raw_component if isinstance(raw_component, str) else ""
    if not actual_component.strip():
        errors.append("component must be a non-empty string")
    # Component implementations may use a more specific stable name such as traffic-core.
    aliases = {
        "contracts": ("contract", "pressure", "audit"),
        "core": ("core", "traffic", "micro"),
        "sanitizer": ("traffic", "micro", "tsan", "sanitizer"),
        "bpf": ("bpf", "map"),
        "kernel": ("kernel", "flow"),
        "rag": ("rag",),
        "service": ("service", "grpc", "dashboard"),
        "event-pipeline": ("event-pipeline", "event_pipeline"),
    }[expected_component]
    if actual_component and not any(alias in actual_component.lower() for alias in aliases):
        errors.append(
            f"component mismatch: expected a {expected_component!r} result, got {actual_component!r}"
        )
    if not isinstance(payload.get("environment"), dict):
        errors.append("environment must be an object")
    started_at = payload.get("started_at")
    if not isinstance(started_at, str) or not started_at.strip():
        errors.append("started_at must be a non-empty string")
    duration_ms = payload.get("duration_ms")
    if not is_finite_number(duration_ms) or float(duration_ms) < 0:
        errors.append("duration_ms must be a finite non-negative number")

    benchmarks = payload.get("benchmarks")
    if not isinstance(benchmarks, list):
        errors.append("benchmarks must be an array")
    elif any(not isinstance(item, dict) for item in benchmarks):
        errors.append("every benchmark entry must be an object")

    summary = payload.get("summary")
    if not isinstance(summary, dict):
        errors.append("summary must be an object")
        return errors
    status = summary.get("status")
    if status not in ALLOWED_SUMMARY_STATUSES:
        errors.append(
            "summary.status must be exactly one of "
            + ", ".join(sorted(ALLOWED_SUMMARY_STATUSES))
        )
    if status == "passed":
        correctness_values = [
            summary[field]
            for field in CORRECTNESS_FIELDS
            if field in summary and isinstance(summary[field], bool)
        ]
        if not any(value is True for value in correctness_values):
            errors.append(
                "passed summary must contain at least one known correctness field set to true"
            )
    for path, value, owning_status in walk_correctness_flags(payload):
        if value is None and owning_status == "skipped":
            continue
        if not isinstance(value, bool):
            errors.append(
                f"{path} must be boolean"
                + (" or null for skipped reports" if owning_status == "skipped" else "")
            )
        elif owning_status in {"passed", "skipped"} and value is False:
            errors.append(
                f"owning summary.status={owning_status!r} contradicts {path}=false"
            )

    for path, benchmark, owning_status in walk_benchmark_entries(payload):
        for field in ("error_count", "determinism_mismatch_count"):
            if field not in benchmark:
                continue
            value = benchmark[field]
            if not is_finite_number(value) or float(value) < 0:
                errors.append(f"{path}.{field} must be a finite non-negative number")
            elif owning_status == "passed" and float(value) > 0:
                errors.append(f"owning summary.status='passed' contradicts {path}.{field}={value}")
        if "errors" in benchmark:
            value = benchmark["errors"]
            if isinstance(value, list):
                nonempty = bool(value)
            elif is_finite_number(value) and float(value) >= 0:
                nonempty = float(value) > 0
            else:
                errors.append(f"{path}.errors must be a non-negative number or an array")
                nonempty = False
            if owning_status == "passed" and nonempty:
                errors.append(
                    f"owning summary.status='passed' contradicts non-empty {path}.errors"
                )
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
            if not is_finite_number(requests) or float(requests) < 0:
                errors.append(f"{path}.requests must be a finite non-negative number")
            if not is_finite_number(successes) or float(successes) < 0:
                errors.append(f"{path}.success_count must be a finite non-negative number")
            if (
                owning_status == "passed"
                and is_finite_number(requests)
                and is_finite_number(successes)
                and float(requests) != float(successes)
            ):
                errors.append(f"{path}.success_count must equal requests for passed status")
    for field in (
        "benchmark_count", "request_count", "success_count", "error_count",
        "errors", "passed", "failed", "skipped", "total_operations",
    ):
        if field in summary and (
            not is_finite_number(summary[field]) or float(summary[field]) < 0
        ):
            errors.append(f"summary.{field} must be a finite non-negative number")
    if isinstance(benchmarks, list) and is_finite_number(summary.get("benchmark_count")):
        if int(summary["benchmark_count"]) != len(benchmarks):
            errors.append(
                f"summary.benchmark_count={summary['benchmark_count']} does not match "
                f"benchmarks length {len(benchmarks)}"
            )
    summary_requests = summary.get("request_count")
    summary_successes = summary.get("success_count")
    if (
        status == "passed"
        and is_finite_number(summary_requests)
        and is_finite_number(summary_successes)
        and float(summary_requests) != float(summary_successes)
    ):
        errors.append("summary.success_count must equal request_count for passed status")
    failed_count = summary.get("failed", 0)
    error_count = summary.get("errors", summary.get("error_count", 0))
    if status == "passed" and is_finite_number(failed_count) and float(failed_count) > 0:
        errors.append("summary.failed is non-zero for passed status")
    if status == "passed" and is_finite_number(error_count) and float(error_count) > 0:
        errors.append("summary error count is non-zero for passed status")
    if status == "passed" and isinstance(benchmarks, list) and not benchmarks:
        errors.append("passed result must contain at least one benchmark")
    return errors


def infer_child_status(payload: dict[str, Any] | None, return_code: int, validation_errors: list[str]) -> str:
    """综合退出码和契约校验推断状态；任一异常都优先返回 ``failed``。"""

    if return_code != 0 or validation_errors or payload is None:
        return "failed"
    # validate_child_result 已排除模糊/矛盾状态；只接受显式协议值，不做宽松推断。
    return str(payload["summary"]["status"])


def terminate_process_group(process: subprocess.Popen[str], grace_seconds: float = 2.0) -> None:
    """终止 benchmark 及其 make/sudo 孙进程，避免超时负载污染后续测量。

    先向独立进程组发送 SIGTERM，宽限期后再 SIGKILL；函数吞掉“进程已退出”
    这一正常竞态，但不会把仍存活的超时子进程留在后台。
    """
    if process.poll() is not None:
        return
    if os.name == "posix":
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            return
    else:  # pragma: no cover - suite is currently exercised on POSIX hosts.
        process.terminate()
    try:
        process.wait(timeout=grace_seconds)
        return
    except subprocess.TimeoutExpired:
        pass
    if os.name == "posix":
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            return
    else:  # pragma: no cover
        process.kill()
    try:
        process.wait(timeout=grace_seconds)
    except subprocess.TimeoutExpired:  # pragma: no cover - SIGKILL should be terminal.
        pass


def tail(value: str, lines: int = 80) -> str:
    """只保留日志末尾若干行，控制总 JSON 的体积。"""

    split = value.splitlines()
    return "\n".join(split[-lines:])


def run_component(
    spec: ComponentCommand,
    repo_root: Path,
    timeout_seconds: int,
    dry_run: bool,
    profile: str,
) -> dict[str, Any]:
    """运行单个组件并返回统一记录；超时、启动失败或非法 JSON 都 fail-closed。

    启动前先删除旧输出，防止子进程本轮未写文件却误读上轮成功结果。POSIX 下
    每个组件使用独立进程组，保证并发负载及其孙进程能在超时时一起回收。
    """

    started_at = utc_now()
    command_text = shlex.join(spec.command)
    if dry_run:
        return {
            "name": spec.name,
            "status": "skipped",
            "reason": "dry-run",
            "command": command_text,
            "exit_code": None,
            "wall_time_ms": 0.0,
            "started_at": started_at,
            "output_path": str(spec.output_path),
            "validation_errors": [],
            "stdout_tail": "",
            "stderr_tail": "",
            "result": None,
        }

    spec.output_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        spec.output_path.unlink(missing_ok=True)
    except OSError as exc:
        return {
            "name": spec.name,
            "status": "failed",
            "reason": f"cannot remove stale output before launch: {exc}",
            "command": command_text,
            "exit_code": 2,
            "wall_time_ms": 0.0,
            "started_at": started_at,
            "output_path": str(spec.output_path),
            "validation_errors": [str(exc)],
            "stdout_tail": "",
            "stderr_tail": "",
            "result": None,
        }
    start_ns = time.perf_counter_ns()
    process: subprocess.Popen[str] | None = None
    try:
        process = subprocess.Popen(
            spec.command,
            cwd=repo_root,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=os.name == "posix",
        )
        stdout, stderr = process.communicate(timeout=timeout_seconds)
        return_code = process.returncode
        timeout_reason = None
    except subprocess.TimeoutExpired:
        if process is not None:
            terminate_process_group(process)
            stdout, stderr = process.communicate()
        else:  # pragma: no cover - timeout cannot precede Popen success.
            stdout, stderr = "", ""
        return_code = 124
        timeout_reason = f"timed out after {timeout_seconds}s"
    except OSError as exc:
        return_code = 127
        stdout = ""
        stderr = str(exc)
        timeout_reason = f"failed to start: {exc}"
    wall_time_ms = (time.perf_counter_ns() - start_ns) / 1_000_000.0

    payload: dict[str, Any] | None = None
    validation_errors: list[str] = []
    if spec.output_path.exists():
        try:
            decoded = json.loads(spec.output_path.read_text(encoding="utf-8"))
            payload = decoded if isinstance(decoded, dict) else None
            validation_errors = validate_child_result(decoded, spec.name, profile)
        except (OSError, json.JSONDecodeError) as exc:
            validation_errors = [f"cannot parse component JSON: {exc}"]
    else:
        validation_errors = ["component did not create its requested JSON output"]

    status = infer_child_status(payload, return_code, validation_errors)
    reason = timeout_reason
    if status == "failed" and reason is None:
        if return_code:
            reason = f"exit={return_code}"
        elif validation_errors:
            reason = "; ".join(validation_errors)
        else:
            reason = "child summary.status=failed"
    return {
        "name": spec.name,
        "status": status,
        "reason": reason,
        "command": command_text,
        "exit_code": return_code,
        "wall_time_ms": round(wall_time_ms, 3),
        "started_at": started_at,
        "output_path": str(spec.output_path),
        "validation_errors": validation_errors,
        "stdout_tail": tail(stdout),
        "stderr_tail": tail(stderr),
        "result": payload,
    }


def flatten_numbers(value: Any, prefix: str = "") -> dict[str, float]:
    """把嵌套结果展平成稳定指标路径到数值的映射，供基线逐项对齐。"""

    flattened: dict[str, float] = {}
    if isinstance(value, dict):
        for key, child in value.items():
            child_prefix = f"{prefix}.{key}" if prefix else str(key)
            flattened.update(flatten_numbers(child, child_prefix))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            name = None
            if isinstance(child, dict):
                name = child.get("name") or child.get("benchmark") or child.get("operation")
            if name and isinstance(child, dict):
                identity = [str(name)]
                for key in (
                    "threads", "concurrency", "effective_concurrency", "operations", "requests",
                ):
                    if key in child:
                        identity.append(f"{key}={child[key]}")
                details = child.get("details")
                if isinstance(details, dict) and "requested_entries" in details:
                    identity.append(f"requested_entries={details['requested_entries']}")
                identity.append(f"index={index}")
                suffix = "|".join(identity)
            else:
                suffix = f"{name}|index={index}" if name else f"index={index}"
            child_prefix = f"{prefix}[{suffix}]"
            flattened.update(flatten_numbers(child, child_prefix))
    elif isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(float(value)):
        flattened[prefix] = float(value)
    return flattened


def metric_direction(path: str) -> str | None:
    """根据指标名返回回归方向：吞吐越高越好，延迟和内存越低越好。"""

    leaf = path.rsplit(".", 1)[-1].lower()
    if any(token in leaf for token in ("qps", "throughput", "ops_per", "requests_per", "events_per")):
        return "higher"
    latency_tokens = ("p50", "p95", "p99", "latency", "duration", "elapsed", "max_ms", "max_us", "max_ns")
    if any(token in leaf for token in latency_tokens):
        return "lower"
    if any(token in leaf for token in ("rss", "memory_bytes", "memory_mb")):
        return "lower-memory"
    return None


def compare_baseline(
    current: dict[str, Any],
    baseline: dict[str, Any],
    latency_pct: float,
    throughput_pct: float,
    memory_pct: float,
) -> list[dict[str, Any]]:
    """比较当前与基线的同名指标，返回所有超过方向性阈值的回归项。"""

    current_values = flatten_numbers(current.get("benchmarks", []), "benchmarks")
    baseline_values = flatten_numbers(baseline.get("benchmarks", []), "benchmarks")
    regressions: list[dict[str, Any]] = []
    for path, current_value in current_values.items():
        previous = baseline_values.get(path)
        direction = metric_direction(path)
        if previous is None or direction is None or previous <= 0:
            continue
        change_pct = (current_value - previous) / previous * 100.0
        if direction == "higher":
            regressed = change_pct < -throughput_pct
            threshold = -throughput_pct
        elif direction == "lower-memory":
            regressed = change_pct > memory_pct
            threshold = memory_pct
        else:
            regressed = change_pct > latency_pct
            threshold = latency_pct
        if regressed:
            regressions.append(
                {
                    "metric": path,
                    "baseline": previous,
                    "current": current_value,
                    "change_pct": round(change_pct, 3),
                    "threshold_pct": threshold,
                    "direction": direction,
                }
            )
    return regressions


def load_baseline(path: Path | None, current: dict[str, Any]) -> dict[str, Any] | None:
    """读取并校验可比较基线；环境、profile 或正确性不匹配时抛 ``ValueError``。"""

    if path is None:
        return None
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("baseline must be a JSON object")
    errors: list[str] = []
    if payload.get("schema_version") != SCHEMA_VERSION:
        errors.append("schema_version mismatch")
    if payload.get("component") != current.get("component"):
        errors.append("component mismatch")
    if payload.get("profile") != current.get("profile"):
        errors.append("profile mismatch")
    if not isinstance(payload.get("benchmarks"), list):
        errors.append("benchmarks must be an array")
    summary = payload.get("summary")
    if not isinstance(summary, dict) or summary.get("status") != "passed":
        errors.append("baseline summary.status must be passed")
    elif any(summary.get(field) is False for field in CORRECTNESS_FIELDS):
        errors.append("baseline correctness gate is false")
    baseline_environment = payload.get("environment")
    current_environment = current.get("environment")
    if not isinstance(baseline_environment, dict) or not isinstance(current_environment, dict):
        errors.append("environment must be an object")
    else:
        for field in ("system", "machine", "cpu_count"):
            if baseline_environment.get(field) != current_environment.get(field):
                errors.append(
                    f"environment.{field} mismatch: baseline={baseline_environment.get(field)!r}, "
                    f"current={current_environment.get(field)!r}"
                )
    if errors:
        raise ValueError("invalid baseline: " + "; ".join(errors))
    return payload


def format_number(value: Any) -> str:
    """把浮点数统一格式化为三位小数，其他值保留文本表示。"""

    if isinstance(value, float):
        return f"{value:.3f}"
    return str(value)


def selected_metrics(result: dict[str, Any] | None) -> list[str]:
    """从组件结果挑选延迟、吞吐、错误及碰撞等关键指标用于 Markdown 摘要。"""

    if not result:
        return []
    candidates: list[str] = []
    for index, benchmark in enumerate(result.get("benchmarks", [])):
        if not isinstance(benchmark, dict):
            continue
        name = benchmark.get("name") or benchmark.get("benchmark") or f"case-{index}"
        fields: list[str] = []
        for key in ("operations", "requests", "threads", "concurrency", "effective_concurrency"):
            if key in benchmark:
                fields.append(f"{key}={format_number(benchmark[key])}")
        rate = benchmark.get("qps", benchmark.get("ops_per_second", benchmark.get("throughput")))
        if rate is not None:
            fields.append(f"rate={format_number(rate)}/s")
        latency_unit = None
        latency = None
        for key, unit in (("latency_ms", "ms"), ("latency_us", "us"), ("latency_ns", "ns")):
            if isinstance(benchmark.get(key), dict):
                latency = benchmark[key]
                latency_unit = unit
                break
        if latency is not None:
            fields.append(f"p50={format_number(latency.get('p50'))}{latency_unit}")
            fields.append(f"p99={format_number(latency.get('p99'))}{latency_unit}")
        errors = benchmark.get("error_count", benchmark.get("errors"))
        if isinstance(errors, (int, float)):
            fields.append(f"errors={format_number(errors)}")
        mismatch = benchmark.get("determinism_mismatch_count")
        if isinstance(mismatch, (int, float)):
            fields.append(f"determinism_mismatches={format_number(mismatch)}")
        if "status" in benchmark:
            fields.append(f"status={benchmark['status']}")
        if fields:
            candidates.append(f"**{name}**：" + "，".join(fields))

        details: dict[str, float] = {}
        for source_key in ("details", "operation_metrics"):
            details.update(flatten_numbers(benchmark.get(source_key, {}), source_key))
        interesting_details = (
            "duplicate",
            "collision",
            "unique_full",
            "unique_tokens",
            "occupied_buckets",
            "corpus_size",
            "vector_dim",
            "cold_load",
            "warm_load",
            "final_entries",
            "lru_entries",
            "protected_entries",
            "short_flows",
            "rss",
        )
        extras = [
            f"`{path}`={format_number(value)}"
            for path, value in details.items()
            if any(token in path.lower() for token in interesting_details)
        ]
        if extras:
            candidates.append(f"{name} 门禁：" + "，".join(extras[:8]))
        if len(candidates) >= 30:
            break
    summary = flatten_numbers(result.get("summary", {}), "summary")
    summary_fields = [
        f"`{path}`={format_number(value)}"
        for path, value in summary.items()
        if any(
            token in path.lower()
            for token in (
                "error",
                "mismatch",
                "corpus",
                "collision",
                "unique_tokens",
                "short_flows",
                "lru_entries",
                "protected_entries",
                "max_rss",
            )
        )
    ]
    if summary_fields:
        candidates.append("组件汇总：" + "，".join(summary_fields[:12]))
    return candidates[:30]


def render_markdown(payload: dict[str, Any]) -> str:
    """把已校验的总 JSON 渲染为便于人工审阅的中文 Markdown 报告。"""

    summary = payload["summary"]
    environment = payload["environment"]
    lines = [
        f"# WeakNet {payload['profile']} 压力测试报告",
        "",
        f"- 总状态：**{summary['status']}**",
        f"- 组件：通过 {summary['passed']} / 失败 {summary['failed']} / 跳过 {summary['skipped']}",
        f"- 正确性门禁：{'通过' if summary['correctness_gate_passed'] else '失败'}",
        f"- 总耗时：{payload['duration_ms']:.3f} ms",
        f"- 环境：{environment.get('system')} {environment.get('release')} / {environment.get('machine')} / {environment.get('cpu_count')} CPU",
        f"- Git：{environment.get('git_commit') or 'unknown'}{'（dirty）' if environment.get('git_dirty') else ''}",
        "",
        "## 组件结果",
        "",
        "| 组件 | 状态 | 进程耗时 ms | 退出码 | 说明 |",
        "|---|---:|---:|---:|---|",
    ]
    for record in payload["benchmarks"]:
        reason = (record.get("reason") or "").replace("|", "\\|").replace("\n", " ")
        lines.append(
            f"| {record['name']} | {record['status']} | {record['wall_time_ms']} | "
            f"{record.get('exit_code')} | {reason} |"
        )

    lines.extend(["", "## 关键测量值", ""])
    any_metrics = False
    for record in payload["benchmarks"]:
        metrics = selected_metrics(record.get("result"))
        if metrics:
            any_metrics = True
            lines.append(f"### {record['name']}")
            lines.append("")
            lines.extend(f"- {metric}" for metric in metrics)
            lines.append("")
    if not any_metrics:
        lines.extend(["本次没有可展示的数值（例如 dry-run 或组件未生成结果）。", ""])

    regressions = payload.get("performance_regressions", [])
    lines.extend(["## 基线比较", ""])
    if regressions:
        lines.extend(
            [
                "| 指标 | 基线 | 当前 | 变化 | 阈值 |",
                "|---|---:|---:|---:|---:|",
            ]
        )
        for item in regressions:
            lines.append(
                f"| `{item['metric']}` | {item['baseline']:.3f} | {item['current']:.3f} | "
                f"{item['change_pct']:.3f}% | {item['threshold_pct']:.3f}% |"
            )
    elif payload.get("baseline_path"):
        lines.append("未检测到超过配置阈值的性能回归。")
    else:
        lines.append("本次未提供基线；当前结果可作为后续 `--baseline` 的输入。")

    lines.extend(["", "## 复现命令", ""])
    for record in payload["benchmarks"]:
        lines.extend([f"### {record['name']}", "", f"```bash\n{record['command']}\n```", ""])
        if record.get("validation_errors"):
            lines.append("结果校验错误：" + "; ".join(record["validation_errors"]))
            lines.append("")
    lines.extend(
        [
            "## 指标解释",
            "",
            "- p99 是 99% 请求不超过的延迟，不能只看平均值；QPS/throughput 需与并发度一起看。",
            "- 完整 `flow_key` 重复表示语义键发生别名，必须为 0；摘要 hash 碰撞不等于 BPF map 覆盖。",
            "- BPF HASH/LRU_HASH 即使出现 bucket 冲突仍会比较完整 key；碰撞主要体现为操作延迟退化。",
            "- `skipped` 说明环境能力未覆盖；使用 `--strict` 可把跳过升级为总任务失败。",
            "",
        ]
    )
    return "\n".join(lines)


def make_parser() -> argparse.ArgumentParser:
    """声明统一压测入口的命令行参数和各类覆盖项。"""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=("smoke", "standard", "stress"), default="smoke")
    parser.add_argument(
        "--components",
        default="auto",
        help=(
            "auto, all, or comma-separated contracts,core,sanitizer,bpf,kernel,rag,service,"
            "event-pipeline (live opt-in)"
        ),
    )
    parser.add_argument("--output-dir", type=Path, help="default: benchmark-results/<timestamp>-<profile>")
    parser.add_argument("--python", default=sys.executable)
    parser.add_argument("--node")
    parser.add_argument("--fixture", action="store_true", help="use self-contained RAG/service fixtures")
    parser.add_argument("--offline-artifact", action="store_true", help="RAG: never rebuild production artifact")
    parser.add_argument("--synthetic-entries", type=int, help="RAG fixture corpus size override")
    parser.add_argument("--grpc-address")
    parser.add_argument("--dashboard-url")
    parser.add_argument("--skip-grpc", action="store_true")
    parser.add_argument("--skip-dashboard", action="store_true")
    parser.add_argument("--events", action="store_true", help="include event-stream lifecycle smoke")
    parser.add_argument("--require-event", action="store_true", help="live event test must receive an event")
    parser.add_argument("--service-timeout-ms", type=int, default=5000)
    parser.add_argument("--service-targets", help="comma-separated service benchmark target names")
    parser.add_argument("--ping-target", help="one or more comma-separated Ping targets")
    parser.add_argument("--event-timeout-ms", type=int, default=5000)
    parser.add_argument("--event-window-ms", type=int, default=250)
    parser.add_argument("--event-max-events", type=int, default=128)
    parser.add_argument("--event-connections", help="event stream connection levels, e.g. 1,8,32")
    parser.add_argument(
        "--event-control-address",
        help="event_pipeline_driver control endpoint for --components event-pipeline",
    )
    parser.add_argument(
        "--event-run-id",
        help="exact deterministic payload run id for --components event-pipeline",
    )
    parser.add_argument("--concurrency", help="override child concurrency list, e.g. 1,4,8,16")
    parser.add_argument("--requests", type=int, help="override per-concurrency request count")
    parser.add_argument("--warmup", type=int, help="override warmup count")
    parser.add_argument("--sudo-linux", action="store_true", help="prefix Linux BPF/kernel make targets with sudo")
    parser.add_argument("--timeout-seconds", type=int)
    parser.add_argument("--strict", action="store_true", help="treat skipped components as a failed suite")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--baseline", type=Path)
    parser.add_argument("--latency-regression-pct", type=float, default=20.0)
    parser.add_argument("--throughput-regression-pct", type=float, default=15.0)
    parser.add_argument("--memory-regression-pct", type=float, default=25.0)
    parser.add_argument("--fail-on-regression", action="store_true")
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    """解析配置、串行编排组件、应用门禁与基线策略并写出最终报告。

    返回 0 仅表示总状态明确为 passed；组件失败、严格模式下跳过、非法基线或
    配置要求的性能回归都会返回 2，从进程退出码层面阻止 CI 假绿。
    """

    parser = make_parser()
    args = parser.parse_args(argv)
    if args.requests is not None and args.requests <= 0:
        parser.error("--requests must be positive")
    if args.warmup is not None and args.warmup < 0:
        parser.error("--warmup must be non-negative")
    if args.synthetic_entries is not None and args.synthetic_entries <= 0:
        parser.error("--synthetic-entries must be positive")
    if args.synthetic_entries is not None and not args.fixture:
        parser.error("--synthetic-entries requires --fixture")
    if args.service_timeout_ms <= 0 or args.event_timeout_ms <= 0 or args.event_max_events <= 0:
        parser.error("service/event timeouts and event max must be positive")
    if args.event_window_ms < 0:
        parser.error("--event-window-ms must be non-negative")

    repo_root = Path(__file__).resolve().parents[1]
    node_path = resolve_node(args.node)
    service_requested = bool(
        args.grpc_address
        or args.dashboard_url
        or args.events
        or args.require_event
        or args.service_targets
    )
    try:
        components = parse_components(args.components, args.profile, args.fixture, service_requested)
    except ValueError as exc:
        parser.error(str(exc))

    timestamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    output_dir = (args.output_dir or repo_root / "benchmark-results" / f"{timestamp}-{args.profile}").resolve()
    component_dir = output_dir / "components"
    output_dir.mkdir(parents=True, exist_ok=True)
    timeout_seconds = args.timeout_seconds or PROFILE_TIMEOUT_SECONDS[args.profile]

    environment = collect_environment(repo_root, node_path)
    suite_start_ns = time.perf_counter_ns()
    suite_started_at = utc_now()
    records: list[dict[str, Any]] = []

    for component in components:
        if component in {"sanitizer", "bpf", "kernel"} and platform.system() != "Linux":
            records.append(
                {
                    "name": component,
                    "status": "skipped",
                    "reason": "requires Linux kernel BPF/netns support",
                    "command": "",
                    "exit_code": None,
                    "wall_time_ms": 0.0,
                    "started_at": utc_now(),
                    "output_path": str(component_dir / f"{component}.json"),
                    "validation_errors": [],
                    "stdout_tail": "",
                    "stderr_tail": "",
                    "result": None,
                }
            )
            continue
        if (
            component in {"bpf", "kernel"}
            and platform.system() == "Linux"
            and hasattr(os, "geteuid")
            and os.geteuid() != 0
            and not args.sudo_linux
        ):
            records.append(
                {
                    "name": component,
                    "status": "skipped",
                    "reason": "requires root/CAP_BPF; rerun with --sudo-linux",
                    "command": "",
                    "exit_code": None,
                    "wall_time_ms": 0.0,
                    "started_at": utc_now(),
                    "output_path": str(component_dir / f"{component}.json"),
                    "validation_errors": [],
                    "stdout_tail": "",
                    "stderr_tail": "",
                    "result": None,
                }
            )
            continue
        try:
            spec = build_component_command(component, args, repo_root, component_dir, node_path)
        except RuntimeError as exc:
            # An explicitly requested live payload test that lacks its driver or
            # Dashboard is not an environmental capability skip: no payload
            # work ran, so treating it as skipped could make a zero-test suite
            # green unless --strict happened to be present.
            setup_status = "failed" if component == "event-pipeline" else "skipped"
            records.append(
                {
                    "name": component,
                    "status": setup_status,
                    "reason": str(exc),
                    "command": "",
                    "exit_code": None,
                    "wall_time_ms": 0.0,
                    "started_at": utc_now(),
                    "output_path": str(component_dir / f"{component}.json"),
                    "validation_errors": [],
                    "stdout_tail": "",
                    "stderr_tail": "",
                    "result": None,
                }
            )
            continue
        records.append(run_component(spec, repo_root, timeout_seconds, args.dry_run, args.profile))

    duration_ms = (time.perf_counter_ns() - suite_start_ns) / 1_000_000.0
    passed = sum(record["status"] == "passed" for record in records)
    failed = sum(record["status"] == "failed" for record in records)
    skipped = sum(record["status"] == "skipped" for record in records)
    correctness_gate_passed = failed == 0 and (not args.strict or skipped == 0)

    aggregate: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "component": "weaknet-stress-suite",
        "profile": args.profile,
        "environment": environment,
        "started_at": suite_started_at,
        "duration_ms": round(duration_ms, 3),
        "benchmarks": records,
        "summary": {
            "status": "passed" if correctness_gate_passed else "failed",
            "passed": passed,
            "failed": failed,
            "skipped": skipped,
            "correctness_gate_passed": correctness_gate_passed,
            "performance_regressions": 0,
        },
        "baseline_path": str(args.baseline.resolve()) if args.baseline else None,
        "performance_regressions": [],
        "configuration": {
            "components": components,
            "strict": args.strict,
            "fixture": args.fixture,
            "timeout_seconds": timeout_seconds,
            "latency_regression_pct": args.latency_regression_pct,
            "throughput_regression_pct": args.throughput_regression_pct,
            "memory_regression_pct": args.memory_regression_pct,
            "fail_on_regression": args.fail_on_regression,
        },
    }

    try:
        baseline = load_baseline(args.baseline, aggregate)
        if baseline is not None:
            regressions = compare_baseline(
                aggregate,
                baseline,
                args.latency_regression_pct,
                args.throughput_regression_pct,
                args.memory_regression_pct,
            )
            aggregate["performance_regressions"] = regressions
            aggregate["summary"]["performance_regressions"] = len(regressions)
            if regressions and args.fail_on_regression:
                aggregate["summary"]["status"] = "failed"
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        aggregate["baseline_error"] = str(exc)
        aggregate["summary"]["status"] = "failed"
        aggregate["summary"]["correctness_gate_passed"] = False

    aggregate_path = output_dir / "summary.json"
    markdown_path = output_dir / "report.md"
    atomic_json_write(aggregate_path, aggregate)
    atomic_text_write(markdown_path, render_markdown(aggregate))
    print(f"[{aggregate['summary']['status']}] JSON: {aggregate_path}")
    print(f"[{aggregate['summary']['status']}] report: {markdown_path}")
    return 0 if aggregate["summary"]["status"] == "passed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
