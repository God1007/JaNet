#!/usr/bin/env python3
"""JaNet 流量演示器。

macOS 在内存中启动一个临时 HTTP 端点，Lima 通过 host.lima.internal 与它通信，
因此上下行流量会真实经过 VM 的 eth0 和 JaNet TC/eBPF 采集路径。脚本同时轮询
Dashboard snapshot，把生成侧实际数据和 JaNet 观测结果一起打印出来。
"""

from __future__ import annotations

import argparse
import concurrent.futures
import dataclasses
import hmac
import http.server
import json
import os
import secrets
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any


MIB = 1024 * 1024
MAX_DURATION_SECONDS = 180
MAX_RATE_BYTES_PER_SECOND = 32 * MIB
MAX_UPLOAD_BYTES = MAX_DURATION_SECONDS * MAX_RATE_BYTES_PER_SECOND
GUEST_HOST = "host.lima.internal"


class DemoError(RuntimeError):
    """可向用户直接展示、无需 Python traceback 的演示失败。"""


@dataclasses.dataclass(frozen=True)
class Stage:
    """单个流量阶段；rate 是每条 TCP 连接的字节速率。"""

    key: str
    title: str
    direction: str
    duration: int
    connections: int
    rate: int
    purpose: str

    @property
    def total_rate(self) -> int:
        return self.connections * self.rate

    @property
    def is_failure(self) -> bool:
        """连接失败场景使用独立生成和判定逻辑，不套用字节吞吐门槛。"""

        return self.direction == "tcp-failure"


@dataclasses.dataclass(frozen=True)
class Observation:
    """从 Dashboard typed snapshot 提取出的 JaNet 流量观测。"""

    generation: int
    bps: int
    pps: int
    active_flows: int
    packets_seen: int
    lru_insert_attempts: int
    capture_mode: str
    capture_complete: bool
    capture_completeness: str
    map_read_complete: bool
    map_observability_read_complete: bool
    valid: bool
    baseline_only: bool
    interface: str
    degraded_reason: str


@dataclasses.dataclass
class StageResult:
    """一个阶段的生成侧 JSON 和阶段内 JaNet 样本。"""

    stage: Stage
    baseline: Observation
    generator: dict[str, Any]
    observations: list[Observation]


def format_rate(value: float | int) -> str:
    """把 B/s 转成人类可读的 IEC 速率。"""

    value = float(value)
    if value >= MIB:
        return f"{value / MIB:.2f} MiB/s"
    if value >= 1024:
        return f"{value / 1024:.1f} KiB/s"
    return f"{value:.0f} B/s"


def format_bytes(value: float | int) -> str:
    """把字节数转成人类可读的 IEC 容量。"""

    value = float(value)
    if value >= 1024 * MIB:
        return f"{value / (1024 * MIB):.2f} GiB"
    if value >= MIB:
        return f"{value / MIB:.1f} MiB"
    if value >= 1024:
        return f"{value / 1024:.1f} KiB"
    return f"{value:.0f} B"


def scenario_stages(name: str, duration_override: int | None) -> list[Stage]:
    """展开 CLI 场景；默认时长覆盖至少两个 10 秒采样窗口。"""

    def duration(default: int) -> int:
        return duration_override if duration_override is not None else default

    stages = {
        "download": Stage(
            "download", "稳定下载", "download", duration(30), 2, 4 * MIB,
            "生成经 eth0 入向的稳定业务流量，并核对 JaNet 聚合观测。",
        ),
        "upload": Stage(
            "upload", "稳定上传", "upload", duration(30), 2, 3 * MIB,
            "生成经 eth0 出向的稳定业务流量，并核对 JaNet 聚合观测。",
        ),
        "burst": Stage(
            "burst", "单连接高吞吐", "download", duration(30), 1, 24 * MIB,
            "生成超过项目 20 MiB/s high-volume 阈值的单流。",
        ),
        "connections": Stage(
            "connections", "多连接并发", "download", duration(30), 12, 512 * 1024,
            "用 12 条并发 TCP 流展示 active flows 与连接级归因。",
        ),
        "mixed": Stage(
            "mixed", "上下行混合", "mixed", duration(30), 8, 1 * MIB,
            "4 条下载和 4 条上传同时运行，展示双向聚合。",
        ),
        "tcp-failure": Stage(
            "tcp-failure", "TCP 建连失败", "tcp-failure", duration(30), 6, 0,
            "连接一个已占用但未监听的临时端口，统计握手失败并关联 TC 包观测。",
        ),
    }
    if name == "showcase":
        return [
            dataclasses.replace(
                stages["download"],
                key="baseline",
                title="低速基线",
                duration=duration(25),
                connections=2,
                rate=1 * MIB,
                purpose="先建立低速基线，展示正常稳定流量。",
            ),
            dataclasses.replace(stages["burst"], duration=duration(30)),
            dataclasses.replace(
                stages["mixed"],
                key="bidirectional",
                title="双向多连接",
                duration=duration(25),
                purpose="4 条下载和 4 条上传并发，展示聚合吞吐与 active flows。",
            ),
        ]
    return [stages[name]]


class DemoHttpServer(http.server.ThreadingHTTPServer):
    """只接受本轮 token 的内存 HTTP server，并累计真实收发字节。"""

    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int], token: str):
        super().__init__(address, DemoRequestHandler)
        self.token = token
        self._metrics_lock = threading.Lock()
        self.download_bytes = 0
        self.upload_bytes = 0

    def add_bytes(self, direction: str, amount: int) -> None:
        with self._metrics_lock:
            if direction == "download":
                self.download_bytes += amount
            else:
                self.upload_bytes += amount

    def metrics(self) -> dict[str, int]:
        with self._metrics_lock:
            return {
                "download_bytes": self.download_bytes,
                "upload_bytes": self.upload_bytes,
            }


class DemoRequestHandler(http.server.BaseHTTPRequestHandler):
    """实现健康检查、节流下载和定长上传三个最小端点。"""

    server: DemoHttpServer
    protocol_version = "HTTP/1.0"

    def setup(self) -> None:
        """给每条演示连接设置读写上限，异常客户端不能永久占住处理线程。"""

        super().setup()
        self.connection.settimeout(15)

    def log_message(self, _format: str, *_args: Any) -> None:
        # 演示终端只显示阶段和指标，逐请求访问日志会干扰观感。
        return

    def _authorized(self) -> bool:
        supplied = self.headers.get("X-JaNet-Demo-Token", "")
        return hmac.compare_digest(supplied, self.server.token)

    def _reject(self, code: int, message: str) -> None:
        body = (message + "\n").encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        if not self._authorized():
            self._reject(403, "invalid demo token")
            return
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/health":
            body = b'{"ok":true}\n'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if parsed.path != "/download":
            self._reject(404, "unknown endpoint")
            return

        try:
            query = urllib.parse.parse_qs(parsed.query)
            duration = float(query.get("duration", [""])[0])
            rate = int(query.get("rate", [""])[0])
            if not 0 < duration <= MAX_DURATION_SECONDS:
                raise ValueError("invalid duration")
            if not 0 < rate <= MAX_RATE_BYTES_PER_SECOND:
                raise ValueError("invalid rate")
        except (TypeError, ValueError):
            self._reject(400, "invalid download parameters")
            return

        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Connection", "close")
        self.end_headers()
        payload = b"J" * (64 * 1024)
        sent = 0
        started = time.monotonic()
        deadline = started + duration
        try:
            # 每个连接独立按 monotonic 时钟节流，避免先塞满 TCP buffer 再休眠形成假尖峰。
            while time.monotonic() < deadline:
                self.wfile.write(payload)
                sent += len(payload)
                target = started + sent / rate
                delay = target - time.monotonic()
                if delay > 0:
                    time.sleep(delay)
        except (BrokenPipeError, ConnectionResetError, TimeoutError):
            pass
        finally:
            self.server.add_bytes("download", sent)

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        if not self._authorized():
            self._reject(403, "invalid demo token")
            return
        if urllib.parse.urlparse(self.path).path != "/upload":
            self._reject(404, "unknown endpoint")
            return
        try:
            remaining = int(self.headers.get("Content-Length", ""))
            if not 0 <= remaining <= MAX_UPLOAD_BYTES:
                raise ValueError("invalid upload size")
        except ValueError:
            self._reject(400, "invalid Content-Length")
            return

        received = 0
        while remaining > 0:
            chunk = self.rfile.read(min(64 * 1024, remaining))
            if not chunk:
                break
            received += len(chunk)
            remaining -= len(chunk)
        self.server.add_bytes("upload", received)
        body = json.dumps({"received": received}).encode() + b"\n"
        self.send_response(200 if remaining == 0 else 400)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


# 该程序通过 stdin 交给 Lima 的 python3，不在 VM 写临时脚本或大流量文件。
GUEST_GENERATOR = r'''
import atexit
import concurrent.futures
import json
import os
import socket
import sys
import time
import urllib.parse

marker, host, port_raw, token, direction, duration_raw, connections_raw, rate_raw = sys.argv[1:]
port = int(port_raw)
duration = float(duration_raw)
connections = int(connections_raw)
rate = int(rate_raw)
payload = b"N" * (64 * 1024)

# host 中断时会通过 marker + PID 双重校验精准回收本进程，不扫描或误杀其他 Python。
pid_path = f"/tmp/{marker}.pid"
pid_fd = os.open(pid_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(pid_fd, "w") as pid_file:
    pid_file.write(str(os.getpid()) + "\n")

def remove_pid_file():
    try:
        os.unlink(pid_path)
    except FileNotFoundError:
        pass

atexit.register(remove_pid_file)

def read_response(sock):
    received = 0
    header = b""
    while b"\r\n\r\n" not in header:
        chunk = sock.recv(65536)
        if not chunk:
            raise RuntimeError("HTTP response ended before headers")
        header += chunk
        if len(header) > 1024 * 1024:
            raise RuntimeError("HTTP response headers are too large")
    raw_headers, body = header.split(b"\r\n\r\n", 1)
    status = raw_headers.split(b"\r\n", 1)[0]
    if b" 200 " not in status:
        raise RuntimeError(status.decode("utf-8", "replace"))
    received += len(body)
    while True:
        chunk = sock.recv(65536)
        if not chunk:
            return received
        received += len(chunk)

def download(index):
    started = time.monotonic()
    path = "/download?" + urllib.parse.urlencode({
        "duration": duration,
        "rate": rate,
        "flow": index,
    })
    with socket.create_connection((host, port), timeout=10) as sock:
        sock.settimeout(duration + 20)
        request = (
            f"GET {path} HTTP/1.0\r\nHost: {host}\r\n"
            f"X-JaNet-Demo-Token: {token}\r\nConnection: close\r\n\r\n"
        ).encode()
        sock.sendall(request)
        received = read_response(sock)
    return {"direction": "download", "bytes": received, "seconds": time.monotonic() - started}

def upload(index):
    del index
    total = int(duration * rate)
    started = time.monotonic()
    with socket.create_connection((host, port), timeout=10) as sock:
        sock.settimeout(duration + 20)
        header = (
            f"POST /upload HTTP/1.0\r\nHost: {host}\r\n"
            f"X-JaNet-Demo-Token: {token}\r\nContent-Type: application/octet-stream\r\n"
            f"Content-Length: {total}\r\nConnection: close\r\n\r\n"
        ).encode()
        sock.sendall(header)
        sent = 0
        while sent < total:
            chunk = payload[:min(len(payload), total - sent)]
            sock.sendall(chunk)
            sent += len(chunk)
            target = started + sent / rate
            delay = target - time.monotonic()
            if delay > 0:
                time.sleep(delay)
        response_bytes = read_response(sock)
    return {
        "direction": "upload",
        "bytes": sent,
        "response_bytes": response_bytes,
        "seconds": time.monotonic() - started,
    }

directions = []
for index in range(connections):
    if direction == "mixed":
        directions.append("download" if index % 2 == 0 else "upload")
    else:
        directions.append(direction)

started = time.monotonic()
results = []
errors = []
with concurrent.futures.ThreadPoolExecutor(max_workers=connections) as pool:
    futures = []
    for index, item_direction in enumerate(directions):
        worker = download if item_direction == "download" else upload
        futures.append(pool.submit(worker, index))
    for future in futures:
        try:
            results.append(future.result())
        except Exception as error:
            errors.append(f"{type(error).__name__}: {error}")

output = {
    "bytes": sum(item["bytes"] for item in results),
    "download_bytes": sum(item["bytes"] for item in results if item["direction"] == "download"),
    "upload_bytes": sum(item["bytes"] for item in results if item["direction"] == "upload"),
    "connections_requested": connections,
    "connections_succeeded": len(results),
    "requested_rate_bps": connections * rate,
    "elapsed_seconds": time.monotonic() - started,
    "errors": errors,
}
print(json.dumps(output, separators=(",", ":")), flush=True)
raise SystemExit(0 if not errors and len(results) == connections else 1)
'''


# TCP 建连失败生成器：同样经 stdin 执行和 marker/PID 回收，但不发送 HTTP 业务数据。
GUEST_FAILURE_GENERATOR = r'''
import atexit
import collections
import concurrent.futures
import json
import os
import socket
import sys
import time

marker, host, port_raw, _token, _direction, duration_raw, workers_raw, _rate = sys.argv[1:]
port = int(port_raw)
duration = float(duration_raw)
workers = int(workers_raw)

pid_path = f"/tmp/{marker}.pid"
pid_fd = os.open(pid_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(pid_fd, "w") as pid_file:
    pid_file.write(str(os.getpid()) + "\n")

def remove_pid_file():
    try:
        os.unlink(pid_path)
    except FileNotFoundError:
        pass

atexit.register(remove_pid_file)
scenario_started = time.monotonic()
scenario_deadline = scenario_started + duration

def worker(_index):
    counts = collections.Counter()
    latencies_ms = []
    while True:
        remaining = scenario_deadline - time.monotonic()
        if remaining <= 0.05:
            break
        attempt_started = time.monotonic()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(max(0.05, min(1.0, remaining)))
        try:
            sock.connect((host, port))
            counts["unexpected_success"] += 1
        except TimeoutError:
            counts["TimeoutError"] += 1
        except ConnectionRefusedError:
            counts["ConnectionRefusedError"] += 1
        except ConnectionResetError:
            counts["ConnectionResetError"] += 1
        except OSError as error:
            counts[f"OSError[{error.errno}]"] += 1
        finally:
            sock.close()
        latencies_ms.append((time.monotonic() - attempt_started) * 1000.0)

        # 若平台立即 RST，限制为每 worker 每 0.5 秒一次，避免短流 key 过快占用 LRU map。
        delay = 0.5 - (time.monotonic() - attempt_started)
        if delay > 0:
            time.sleep(min(delay, max(0.0, scenario_deadline - time.monotonic())))
    return {"counts": dict(counts), "latencies_ms": latencies_ms}

results = []
errors = []
with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
    futures = [pool.submit(worker, index) for index in range(workers)]
    for future in futures:
        try:
            results.append(future.result())
        except Exception as error:
            errors.append(f"{type(error).__name__}: {error}")

counts = collections.Counter()
latencies_ms = []
for result in results:
    counts.update(result["counts"])
    latencies_ms.extend(result["latencies_ms"])

unexpected_successes = counts.pop("unexpected_success", 0)
failed_connections = sum(counts.values())
attempts_total = failed_connections + unexpected_successes
other_errors = sum(
    count for failure_type, count in counts.items() if failure_type.startswith("OSError[")
)
latencies_ms.sort()

def percentile(values, fraction):
    if not values:
        return 0.0
    index = min(len(values) - 1, int((len(values) - 1) * fraction))
    return values[index]

scenario_pass = (
    not errors
    and attempts_total > 0
    and unexpected_successes == 0
    and failed_connections == attempts_total
    and other_errors == 0
)
output = {
    "scenario": "tcp-failure",
    "bytes": 0,
    "download_bytes": 0,
    "upload_bytes": 0,
    "connections_requested": attempts_total,
    "connections_succeeded": unexpected_successes,
    "attempts_total": attempts_total,
    "failed_connections": failed_connections,
    "unexpected_successes": unexpected_successes,
    "other_errors": other_errors,
    "failure_rate_percent": (failed_connections * 100.0 / attempts_total) if attempts_total else 0.0,
    "failures_by_type": dict(sorted(counts.items())),
    "latency_p50_ms": percentile(latencies_ms, 0.50),
    "latency_p95_ms": percentile(latencies_ms, 0.95),
    "requested_rate_bps": 0,
    "elapsed_seconds": time.monotonic() - scenario_started,
    "scenario_pass": scenario_pass,
    "errors": errors,
}
print(json.dumps(output, separators=(",", ":")), flush=True)
raise SystemExit(0 if scenario_pass else 1)
'''


# 中断或 limactl 传输异常时，通过随机 marker 和 /proc cmdline 双重校验远端 PID。
GUEST_CLEANUP = r'''
import os
import signal
import sys
import time

marker = sys.argv[1]
pid_path = f"/tmp/{marker}.pid"
try:
    with open(pid_path, encoding="ascii") as pid_file:
        pid = int(pid_file.readline().strip())
    with open(f"/proc/{pid}/cmdline", "rb") as cmdline_file:
        argv = cmdline_file.read().rstrip(b"\0").split(b"\0")
except (FileNotFoundError, PermissionError, ValueError):
    raise SystemExit(0)

if marker.encode() not in argv:
    print("guest demo PID ownership validation failed", file=sys.stderr)
    raise SystemExit(2)

try:
    os.kill(pid, signal.SIGTERM)
except ProcessLookupError:
    pass
else:
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            break
        time.sleep(0.1)
    else:
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
try:
    os.unlink(pid_path)
except FileNotFoundError:
    pass
'''


def fetch_snapshot(api_port: int) -> dict[str, Any]:
    """读取 Dashboard typed snapshot；其本身可能执行项目配置的 Ping 探测。"""

    url = f"http://127.0.0.1:{api_port}/api/snapshot"
    try:
        with urllib.request.urlopen(url, timeout=30) as response:
            return json.load(response)
    except (OSError, ValueError, urllib.error.URLError) as error:
        raise DemoError(f"无法读取 Dashboard snapshot ({url}): {error}") from error


def extract_observation(snapshot: dict[str, Any]) -> Observation:
    """按 usingNow/activeInterface 选择活动接口，并提取 typed 流量状态。"""

    if snapshot.get("grpc", {}).get("ok") is not True:
        errors = snapshot.get("grpc", {}).get("errors") or ["unknown gRPC error"]
        raise DemoError(f"Dashboard 无法访问 gRPC Server: {errors[0]}")
    network = snapshot.get("networkSnapshot") or {}
    active_name = str(network.get("activeInterface") or "")
    interfaces = network.get("interfaces") or []
    active = next((item for item in interfaces if item.get("usingNow") is True), None)
    if active is None:
        active = next((item for item in interfaces if item.get("interfaceName") == active_name), None)
    if active is None:
        raise DemoError("snapshot 中没有活动网络接口")
    traffic = network.get("trafficObservation") or {}
    map_observability = traffic.get("mapObservability") or {}
    return Observation(
        generation=int(traffic.get("generation") or 0),
        bps=int(active.get("trafficBytesPerSecond") or 0),
        pps=int(active.get("trafficPacketsPerSecond") or 0),
        active_flows=int(active.get("activeFlows") or 0),
        packets_seen=int(map_observability.get("packetsSeen") or 0),
        lru_insert_attempts=int(map_observability.get("lruInsertAttempts") or 0),
        capture_mode=str(traffic.get("captureMode") or "unavailable"),
        capture_complete=bool(traffic.get("captureComplete")),
        capture_completeness=str(traffic.get("captureCompleteness") or "unavailable"),
        map_read_complete=bool(traffic.get("mapReadComplete")),
        map_observability_read_complete=bool(map_observability.get("readComplete")),
        valid=bool(traffic.get("valid")),
        baseline_only=bool(traffic.get("baselineOnly")),
        interface=str(active.get("interfaceName") or active_name),
        degraded_reason=str(traffic.get("degradedReason") or ""),
    )


def run_command(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
    """统一执行文本子进程，便于错误中保留 stderr。"""

    return subprocess.run(command, text=True, **kwargs)


class DemoRunner:
    """管理临时 host server、Lima 生成器、指标轮询和退出清理。"""

    def __init__(self, vm: str, api_port: int, sample_interval: float):
        self.vm = vm
        self.api_port = api_port
        self.sample_interval = sample_interval
        self.token = secrets.token_urlsafe(24)
        self.marker = f"janet-demo-{secrets.token_hex(12)}"
        self.server = DemoHttpServer(("127.0.0.1", 0), self.token)
        self.server_thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.failure_socket: socket.socket | None = None
        self.active_process: subprocess.Popen[str] | None = None

    @property
    def server_port(self) -> int:
        return int(self.server.server_address[1])

    def failure_port(self) -> int:
        """占用一个动态端口但不 listen，使 connect 无法完成且无端口抢占窗口。"""

        if self.failure_socket is None:
            try:
                self.failure_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.failure_socket.bind(("127.0.0.1", 0))
            except OSError as error:
                if self.failure_socket is not None:
                    self.failure_socket.close()
                    self.failure_socket = None
                raise DemoError(f"无法创建 TCP failure 临时目标: {error}") from error
        return int(self.failure_socket.getsockname()[1])

    def start(self) -> None:
        self.server_thread.start()
        # guest 的 /health 请求同时证明 host.lima.internal 路由与本轮 token 都有效。
        check = r'''
import sys,urllib.request
host,port,token=sys.argv[1:]
request=urllib.request.Request(
    f"http://{host}:{port}/health", headers={"X-JaNet-Demo-Token":token})
with urllib.request.urlopen(request,timeout=5) as response:
    raise SystemExit(0 if response.status==200 else 1)
'''
        result = run_command(
            ["limactl", "shell", self.vm, "--", "python3", "-c", check,
             GUEST_HOST, str(self.server_port), self.token],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        if result.returncode != 0:
            raise DemoError(
                "Lima 无法访问 macOS 临时流量端点；请检查 host.lima.internal。"
                + (f"\n{result.stderr.strip()}" if result.stderr else "")
            )

    def close(self) -> None:
        self._terminate_active_process()
        if self.failure_socket is not None:
            self.failure_socket.close()
            self.failure_socket = None
        self.server.shutdown()
        self.server.server_close()
        self.server_thread.join(timeout=2)

    def _terminate_active_process(self) -> None:
        process = self.active_process
        # 先精确回收 guest，再收敛本地 limactl 进程组；任一侧异常都不会模糊扫描进程。
        self._cleanup_guest()
        if process is None or process.poll() is not None:
            return
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            return
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=1)

    def _cleanup_guest(self) -> None:
        """仅在 PID 文件与随机 marker 同时匹配时终止本轮 guest 生成器。"""

        try:
            run_command(
                ["limactl", "shell", self.vm, "--", "python3", "-c",
                 GUEST_CLEANUP, self.marker],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5,
            )
        except (OSError, subprocess.TimeoutExpired):
            # VM/SSH 已不可用时无法远程清理；host socket 关闭会使连接在超时内退出。
            pass

    def run_stage(self, stage: Stage, index: int, total: int) -> StageResult:
        print(f"\n[{index}/{total}] {stage.title}")
        if stage.is_failure:
            print(
                f"  模拟参数：{stage.connections} 个 worker · connect timeout 1s · "
                f"持续 {stage.duration}s"
            )
            print("  预期结果：所有 connect 均失败；失败类型由生成器按 errno 精确统计")
        else:
            print(
                f"  模拟参数：{stage.direction} · {stage.connections} 条 TCP · "
                f"{format_rate(stage.rate)}/连接 · {stage.duration}s"
            )
            print(f"  预期总速率：{format_rate(stage.total_rate)}")

        # 记录阶段边界；只有之后发布的新 generation 才能归因到本阶段，旧高流量不能导致假 PASS。
        stage_start = extract_observation(fetch_snapshot(self.api_port))
        start_generation = stage_start.generation

        target_port = self.failure_port() if stage.is_failure else self.server_port
        generator_source = GUEST_FAILURE_GENERATOR if stage.is_failure else GUEST_GENERATOR
        if stage.is_failure:
            print(f"  临时目标：{GUEST_HOST}:{target_port}（macOS bind-only socket）")
        command = [
            "limactl", "shell", self.vm, "--", "python3", "-",
            self.marker, GUEST_HOST, str(target_port), self.token, stage.direction,
            str(stage.duration), str(stage.connections), str(stage.rate),
        ]
        stdout_file = tempfile.TemporaryFile(mode="w+", encoding="utf-8")
        stderr_file = tempfile.TemporaryFile(mode="w+", encoding="utf-8")
        process: subprocess.Popen[str] | None = None
        observations: list[Observation] = []
        accepted_generations: set[int] = set()
        try:
            # 临时文件持续吸收输出，避免 PIPE 缓冲区塞满后 guest 与 host 互相等待。
            process = subprocess.Popen(
                command,
                stdin=subprocess.PIPE,
                stdout=stdout_file,
                stderr=stderr_file,
                text=True,
                start_new_session=True,
            )
            self.active_process = process
            assert process.stdin is not None
            try:
                process.stdin.write(generator_source)
                process.stdin.close()
            except (BrokenPipeError, OSError) as error:
                raise DemoError(f"无法把生成器发送到 Lima: {error}") from error

            last_generation = -1
            next_sample = time.monotonic()
            started = time.monotonic()
            generator_deadline = started + stage.duration + 30
            while process.poll() is None:
                now = time.monotonic()
                if now >= generator_deadline:
                    self._terminate_active_process()
                    raise DemoError(
                        f"{stage.title} 超过预期时限 ({stage.duration + 30}s)，已回收本轮生成器"
                    )
                if now >= next_sample:
                    try:
                        observation = extract_observation(fetch_snapshot(self.api_port))
                        if observation.generation != last_generation:
                            elapsed = int(now - started)
                            if stage.is_failure:
                                packet_delta = max(
                                    0, observation.packets_seen - stage_start.packets_seen
                                )
                                print(
                                    f"  JaNet +{elapsed:02d}s：{observation.pps} pps · "
                                    f"{observation.active_flows} flows · packets +{packet_delta} · "
                                    f"generation {observation.generation}"
                                )
                            else:
                                print(
                                    f"  JaNet +{elapsed:02d}s：{format_rate(observation.bps)} · "
                                    f"{observation.pps} pps · {observation.active_flows} flows · "
                                    f"generation {observation.generation}"
                                )
                            last_generation = observation.generation
                        if self._accept_observation(
                            observation, start_generation, accepted_generations
                        ):
                            observations.append(observation)
                    except DemoError as error:
                        print(f"  [WARN] 本轮 snapshot 暂不可用：{error}", file=sys.stderr)
                    next_sample = time.monotonic() + self.sample_interval
                time.sleep(0.2)

            return_code = process.wait()
            stdout_file.flush()
            stderr_file.flush()
            stdout_file.seek(0)
            stderr_file.seek(0)
            stdout = stdout_file.read()
            stderr = stderr_file.read()
        finally:
            if process is not None and process.poll() is None:
                self._terminate_active_process()
            else:
                # transport 先退出时 guest 仍可能存活，因此正常/异常路径都做所有权校验清理。
                self._cleanup_guest()
            self.active_process = None
            stdout_file.close()
            stderr_file.close()

        json_lines = [line for line in stdout.splitlines() if line.strip().startswith("{")]
        if not json_lines:
            raise DemoError(
                f"Lima 流量生成器没有返回结果 (code={return_code})"
                + (f"\n{stderr.strip()}" if stderr.strip() else "")
            )
        try:
            generator = json.loads(json_lines[-1])
        except json.JSONDecodeError as error:
            raise DemoError(f"Lima 流量生成器返回了无效 JSON: {error}") from error
        if return_code != 0 or generator.get("errors"):
            details = generator.get("errors") or {
                "attempts": generator.get("attempts_total"),
                "unexpected_successes": generator.get("unexpected_successes"),
                "other_errors": generator.get("other_errors"),
                "failures_by_type": generator.get("failures_by_type"),
            }
            raise DemoError(
                f"Lima 流量生成器失败: {details or stderr.strip()}"
            )

        # 短阶段可能恰好在 generation 边界开始：首个新样本只含极少本轮字节。
        # 若峰值尚未达到可见门槛，就继续等到“阶段结束时所见 generation”的下一代。
        settle_deadline = time.monotonic() + 15
        visibility_threshold = max(64 * 1024, int(stage.total_rate * 0.25))
        required_packets = max(1, int(generator.get("attempts_total") or 0))
        settle_after_generation = start_generation
        try:
            end_observation = extract_observation(fetch_snapshot(self.api_port))
            settle_after_generation = end_observation.generation
            if self._accept_observation(
                end_observation, start_generation, accepted_generations
            ):
                observations.append(end_observation)
        except DemoError as error:
            print(f"  [WARN] 结束 snapshot 暂不可用：{error}", file=sys.stderr)
        while True:
            peak = max((item.bps for item in observations), default=0)
            packet_delta = max(
                (item.packets_seen - stage_start.packets_seen for item in observations),
                default=0,
            )
            visibility_reached = (
                packet_delta >= required_packets
                if stage.is_failure
                else peak >= visibility_threshold
            )
            has_post_end_sample = any(
                item.generation > settle_after_generation for item in observations
            )
            settled = (
                has_post_end_sample and visibility_reached
                if stage.is_failure
                else visibility_reached or has_post_end_sample
            )
            if settled or time.monotonic() >= settle_deadline:
                break
            time.sleep(2)
            try:
                observation = extract_observation(fetch_snapshot(self.api_port))
                if self._accept_observation(
                    observation, start_generation, accepted_generations
                ):
                    observations.append(observation)
            except DemoError as error:
                print(f"  [WARN] 结束 snapshot 暂不可用：{error}", file=sys.stderr)
        peak = max((item.bps for item in observations), default=0)
        if stage.is_failure:
            packet_delta = max(
                (item.packets_seen - stage_start.packets_seen for item in observations),
                default=0,
            )
            print(
                f"  生成结果：{generator['failed_connections']}/{generator['attempts_total']} "
                f"连接失败 · 意外成功 {generator['unexpected_successes']} · "
                f"JaNet packets +{max(0, packet_delta)}"
            )
        else:
            print(
                f"  生成结果：{format_bytes(generator['bytes'])} · "
                f"{generator['connections_succeeded']}/{stage.connections} 连接成功 · "
                f"JaNet 阶段峰值 {format_rate(peak)}"
            )
        return StageResult(
            stage=stage,
            baseline=stage_start,
            generator=generator,
            observations=observations,
        )

    @staticmethod
    def _accept_observation(
        observation: Observation,
        start_generation: int,
        accepted_generations: set[int],
    ) -> bool:
        """只接纳本阶段发布、完整且未重复的 TC generation。"""

        accepted = (
            observation.generation > start_generation
            and observation.generation not in accepted_generations
            and observation.valid
            and not observation.baseline_only
            and observation.capture_mode == "tc"
            and observation.capture_complete
            and observation.map_read_complete
            and observation.map_observability_read_complete
        )
        if accepted:
            accepted_generations.add(observation.generation)
        return accepted


def wait_for_capture(api_port: int, timeout: int = 35) -> Observation:
    """等待 generation>1 的完整 TC snapshot，防止刚启动就把 baseline 当结果。"""

    deadline = time.monotonic() + timeout
    last: Observation | None = None
    last_error = "snapshot unavailable"
    while time.monotonic() < deadline:
        try:
            last = extract_observation(fetch_snapshot(api_port))
        except DemoError as error:
            last_error = str(error)
            print(f"[INFO] Dashboard snapshot 暂不可用，继续等待：{error}")
            time.sleep(min(5, max(0, deadline - time.monotonic())))
            continue
        if (
            last.capture_mode == "tc"
            and last.capture_complete
            and last.map_read_complete
            and last.map_observability_read_complete
            and last.valid
            and not last.baseline_only
        ):
            return last
        last_error = last.degraded_reason or (
            f"mode={last.capture_mode}, generation={last.generation}, "
            f"baseline={last.baseline_only}"
        )
        print(
            f"[INFO] 等待完整 TC 样本：mode={last.capture_mode}, "
            f"generation={last.generation}, baseline={last.baseline_only}"
        )
        time.sleep(5)
    raise DemoError(f"{timeout} 秒内没有取得完整 TC snapshot：{last_error}")


def print_plan(stages: list[Stage], vm: str, dashboard_url: str) -> None:
    """执行前明确说明模拟边界、阶段与预计时长。"""

    failure_demo = any(stage.is_failure for stage in stages)
    print("\nJaNet TCP Failure Demo" if failure_demo else "\nJaNet Traffic Demo")
    print("=" * 62)
    print("本次模拟做什么：")
    if failure_demo:
        print(f"  · Lima ({vm}) 并发连接 macOS 上一个已 bind、但故意不 listen 的临时端口。")
        print("  · 生成器按 Timeout/Refused/Reset/其他 errno 统计真实 connect 结果。")
        print("  · JaNet 侧只验证同期握手包、PPS、flow 和新 generation，不冒充失败计数。")
        print("  · 不修改 firewall、路由、qdisc 或 TC；临时 socket 在退出时直接关闭。")
    else:
        print(f"  · Lima ({vm}) 作为业务客户端，经 eth0 访问 macOS 临时内存 HTTP 服务。")
        print("  · 生成入向/出向业务流量；结果验证聚合可见性，tc/full 表示双 TC hook 完整。")
        print("  · 不修改 qdisc、不创建大文件、不依赖公网下载。")
    print("  · 项目自身已有的 RTT/Ping 探测仍按原配置运行。")
    print("  · 每隔数秒读取 Dashboard snapshot，展示 JaNet 实际观测值。")
    print("\n模拟阶段：")
    for index, stage in enumerate(stages, 1):
        if stage.is_failure:
            print(
                f"  {index}. {stage.title:<10} {stage.duration:>3}s · "
                f"{stage.connections:>2} workers · 1s timeout  {stage.purpose}"
            )
        else:
            print(
                f"  {index}. {stage.title:<10} {stage.duration:>3}s · "
                f"{stage.connections:>2} flows · {format_rate(stage.total_rate):>12}  {stage.purpose}"
            )
    expected_seconds = sum(stage.duration for stage in stages)
    if failure_demo:
        print(f"\n预计耗时：约 {expected_seconds} 秒，结束后最多等待 15 秒完成采样归属")
    else:
        print(f"\n预计耗时：约 {expected_seconds} 秒")
    print(f"Dashboard：{dashboard_url}")
    print("采样说明：服务端约 10 秒一轮，短于 20 秒的自定义阶段可能错过完整窗口。")
    print("按 Ctrl-C 可随时结束，临时服务和本轮生成器会自动回收。")
    print("=" * 62)


def print_failure_summary(result: StageResult) -> bool:
    """分别验证生成侧连接失败与 JaNet 同期包观测，避免混成一个语义。"""

    generator = result.generator
    observations = result.observations
    baseline = result.baseline
    latest = max(observations, key=lambda item: item.generation, default=baseline)
    peak_pps = max((item.pps for item in observations), default=0)
    peak_flows = max((item.active_flows for item in observations), default=0)
    packets_after = max((item.packets_seen for item in observations), default=baseline.packets_seen)
    inserts_after = max(
        (item.lru_insert_attempts for item in observations),
        default=baseline.lru_insert_attempts,
    )
    packets_delta = packets_after - baseline.packets_seen
    inserts_delta = inserts_after - baseline.lru_insert_attempts
    attempts = int(generator.get("attempts_total") or 0)
    failed = int(generator.get("failed_connections") or 0)
    unexpected_successes = int(generator.get("unexpected_successes") or 0)
    other_errors = int(generator.get("other_errors") or 0)
    failure_types = generator.get("failures_by_type") or {}
    failure_text = ", ".join(
        f"{failure_type}={count}" for failure_type, count in failure_types.items()
    ) or "none"

    generator_ok = (
        attempts > 0
        and failed == attempts
        and unexpected_successes == 0
        and other_errors == 0
        and bool(generator.get("scenario_pass"))
    )
    counters_monotonic = all(
        item.packets_seen >= baseline.packets_seen
        and item.lru_insert_attempts >= baseline.lru_insert_attempts
        for item in observations
    )
    interface_stable = all(item.interface == baseline.interface for item in observations)
    capture_ok = (
        bool(observations)
        and latest.capture_mode == "tc"
        and latest.capture_complete
        and latest.map_read_complete
        and latest.map_observability_read_complete
        and latest.valid
        and not latest.baseline_only
        and latest.generation > baseline.generation
        and counters_monotonic
        and interface_stable
    )
    observed = packets_delta >= attempts and inserts_delta >= attempts

    print("\n模拟结果")
    print("=" * 62)
    print(f"TCP 连接尝试：    {attempts}")
    print(f"连接失败：        {failed}")
    print(f"意外成功：        {unexpected_successes}")
    print(f"连接失败率：      {float(generator.get('failure_rate_percent') or 0):.2f}%")
    print(f"失败类型：        {failure_text}")
    print(
        f"失败耗时 P50/P95：{float(generator.get('latency_p50_ms') or 0):.1f}ms / "
        f"{float(generator.get('latency_p95_ms') or 0):.1f}ms"
    )
    print(f"生成阶段总时长：  {float(generator.get('elapsed_seconds') or 0):.1f}s")
    print("\nJaNet 同期观测：")
    print(
        f"  packetsSeen：   {baseline.packets_seen} → {packets_after} "
        f"(Δ {packets_delta})"
    )
    print(
        f"  LRU inserts：   {baseline.lru_insert_attempts} → {inserts_after} "
        f"(Δ {inserts_delta})"
    )
    print(f"  峰值 PPS/flows：{peak_pps} pps / {peak_flows} flows")
    print(
        f"  采集链路：      {latest.capture_mode}/{latest.capture_completeness} · "
        f"generation {baseline.generation} → {latest.generation} · {latest.interface}"
    )
    print("\n口径：失败次数来自 connect()；JaNet 只证明同期完整 TC 采集到了握手流量。")
    passed = generator_ok and capture_ok and observed
    if passed:
        print("[PASS] TCP 建连失败已生成，JaNet 在完成后的新样本中观测到同期包增量。")
    elif generator_ok:
        print("[WARN] 建连失败已生成，但 JaNet 新样本或包计数未达到可见性门槛。")
    else:
        print("[WARN] 未能生成纯粹、守恒的 TCP 建连失败结果。")
    print("=" * 62)
    return passed


def print_summary(
    baseline: Observation,
    results: list[StageResult],
    server_metrics: dict[str, int],
) -> bool:
    """汇总生成侧与 JaNet 观测侧数据，并返回演示是否达到可见性门槛。"""

    if len(results) == 1 and results[0].stage.is_failure:
        return print_failure_summary(results[0])
    if any(result.stage.is_failure for result in results):
        raise DemoError("tcp-failure 不能与吞吐阶段混合汇总")

    observations = [item for result in results for item in result.observations]
    peak = max(observations, key=lambda item: item.bps, default=baseline)
    peak_pps = max((item.pps for item in observations), default=0)
    peak_flows = max((item.active_flows for item in observations), default=0)
    generated_bytes = sum(int(result.generator["bytes"]) for result in results)
    generated_seconds = sum(float(result.generator["elapsed_seconds"]) for result in results)
    successful_connections = sum(
        int(result.generator["connections_succeeded"]) for result in results
    )
    requested_connections = sum(result.stage.connections for result in results)
    max_requested_rate = max((result.stage.total_rate for result in results), default=0)
    observed = peak.bps >= max(64 * 1024, int(max_requested_rate * 0.25))
    capture_ok = (
        peak.capture_mode == "tc"
        and peak.capture_complete
        and peak.map_read_complete
        and peak.map_observability_read_complete
        and peak.valid
        and not peak.baseline_only
        and peak.generation > baseline.generation
    )

    print("\n模拟结果")
    print("=" * 62)
    print(f"生成流量总量：  {format_bytes(generated_bytes)}")
    print(f"生成阶段总时长：{generated_seconds:.1f}s")
    print(f"成功 TCP 连接：  {successful_connections}/{requested_connections}")
    print(
        f"Host 实收/实发： {format_bytes(server_metrics['upload_bytes'])} upload / "
        f"{format_bytes(server_metrics['download_bytes'])} download"
    )
    print(f"JaNet 基线吞吐： {format_rate(baseline.bps)}")
    print(f"JaNet 峰值吞吐： {format_rate(peak.bps)}")
    print(f"JaNet 峰值 PPS：  {peak_pps}")
    print(f"JaNet 最大流数：  {peak_flows}")
    print(
        f"采集链路：        {peak.capture_mode}/{peak.capture_completeness} · "
        f"generation {peak.generation} · interface {peak.interface}"
    )
    print("\n分阶段对比：")
    for result in results:
        stage_peak = max((item.bps for item in result.observations), default=0)
        stage_pps = max((item.pps for item in result.observations), default=0)
        stage_flows = max((item.active_flows for item in result.observations), default=0)
        print(
            f"  · {result.stage.title:<10} 模拟 {format_rate(result.stage.total_rate):>12} "
            f"→ JaNet {format_rate(stage_peak):>12} · {stage_pps} pps · {stage_flows} flows"
        )
    if capture_ok and observed:
        print("\n[PASS] JaNet 在完整 TC 模式下观测到了本轮模拟流量。")
    else:
        print("\n[WARN] 流量已生成，但 JaNet 未达到可见性门槛；请检查采样窗口和 TC 状态。")
    print("=" * 62)
    return capture_ok and observed


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate deterministic JaNet demo traffic")
    parser.add_argument(
        "scenario", nargs="?", default="showcase",
        choices=(
            "showcase", "download", "upload", "burst", "connections", "mixed",
            "tcp-failure",
        ),
    )
    parser.add_argument("--vm", default=os.environ.get("WEAKNET_LIMA_VM", "weaknet-eval"))
    parser.add_argument("--api-port", type=int, default=5174)
    parser.add_argument("--web-port", type=int, default=5173)
    parser.add_argument(
        "--duration", type=int,
        default=int(os.environ["WEAKNET_DEMO_DURATION"])
        if os.environ.get("WEAKNET_DEMO_DURATION") else None,
        help="override every selected stage duration",
    )
    parser.add_argument("--no-open", action="store_true", help="do not open the Dashboard")
    parser.add_argument("--explain-only", action="store_true", help="print the plan without traffic")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    if args.duration is not None and not 3 <= args.duration <= MAX_DURATION_SECONDS:
        raise DemoError("--duration 必须在 3..180 秒之间")
    if not 1 <= args.api_port <= 65535 or not 1 <= args.web_port <= 65535:
        raise DemoError("Dashboard 端口必须在 1..65535 之间")

    stages = scenario_stages(args.scenario, args.duration)
    dashboard_url = f"http://127.0.0.1:{args.web_port}"
    print_plan(stages, args.vm, dashboard_url)
    if args.explain_only:
        return 0

    vm_check = run_command(
        ["limactl", "shell", args.vm, "--", "true"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if vm_check.returncode != 0:
        raise DemoError(
            f"Lima VM {args.vm} 未运行；请先执行 limactl start {args.vm} 和 ./run-mac.sh start"
        )

    baseline = wait_for_capture(args.api_port)
    print(
        f"\n[READY] {baseline.interface} · {baseline.capture_mode}/"
        f"{baseline.capture_completeness} · generation {baseline.generation}"
    )
    if not args.no_open and sys.platform == "darwin":
        subprocess.run(["open", dashboard_url], check=False)

    sample_interval = max(2.0, float(os.environ.get("WEAKNET_DEMO_SAMPLE_INTERVAL", "5")))
    runner = DemoRunner(args.vm, args.api_port, sample_interval)
    try:
        runner.start()
        results = [
            runner.run_stage(stage, index, len(stages))
            for index, stage in enumerate(stages, 1)
        ]
        passed = print_summary(baseline, results, runner.server.metrics())
        return 0 if passed else 3
    finally:
        runner.close()


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except KeyboardInterrupt:
        print("\n[INFO] 流量模拟已取消，正在回收临时资源……", file=sys.stderr)
        raise SystemExit(130)
    except DemoError as error:
        print(f"\n[ERROR] {error}", file=sys.stderr)
        raise SystemExit(1)
