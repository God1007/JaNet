#!/usr/bin/env bash
# 从 macOS 经 Lima 运行 WeakNet 确定性 live 事件链路压测。
#
# 脚本冻结当前工作区源码，在 Linux 来宾中编译/启动真实 GrpcServer/EventManager driver，
# 在 macOS 宿主中启动未改造 Dashboard，再运行 WebSocket 快/慢消费者测试。宿主和来宾进程
# 均放入本次专属进程组并在 EXIT 清理；产品正确性缺口返回 2，构建/启动/产物故障返回 1。

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/.." && pwd)

PROFILE=smoke
OUTPUT_DIR=""
VM_NAME=${WEAKNET_LIMA_VM:-weaknet-eval}
PYTHON_BIN=${WEAKNET_BENCH_PYTHON:-python3}
NODE_BIN=${WEAKNET_BENCH_NODE:-node}
GRPC_PORT=""
CONTROL_PORT=""
DASHBOARD_PORT=""
RUN_ID=""
KEEP_SNAPSHOT=false
EXTRA_BENCHMARK_ARGS=()

# 打印 helper 参数、透传边界与退出码约定；不读取或修改全局状态。
usage() {
  cat <<'EOF'
Usage:
  benchmarks/run_mac_lima_event_pipeline.sh [options] [-- benchmark-options]

Options:
  --profile smoke|standard|stress   Benchmark profile (default: smoke)
  --output-dir DIR                  Durable result directory
  --vm NAME                         Existing running Lima VM (default: weaknet-eval)
  --python PATH                     Python 3 executable
  --node PATH                       Node executable with dashboard dependencies
  --grpc-port PORT                  Fixed guest/host-forwarded gRPC port
  --control-port PORT               Fixed driver control port
  --dashboard-port PORT             Fixed host Dashboard API port
  --run-id TOKEN                    Exact payload run id
  --keep-snapshot                   Preserve temporary immutable source snapshot
  -h, --help                        Show this help

Arguments after -- are passed to event_pipeline_benchmark.mjs, for example:
  -- --fast-events 32 --pressure-events 400 --payload-bytes 1024

Exit codes:
  0  all product correctness gates passed
  1  helper/build/startup/artifact infrastructure failure
  2  valid report with one or more product correctness gates failed
EOF
}

# 校验一个选项是否带非空参数；输入当前 "$@"，缺失时打印错误并退出 1。
require_value() {
  if [[ $# -lt 2 || -z ${2:-} ]]; then
    echo "ERROR: $1 requires a value" >&2
    exit 1
  fi
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --profile)
      require_value "$@"
      PROFILE=$2
      shift 2
      ;;
    --output-dir)
      require_value "$@"
      OUTPUT_DIR=$2
      shift 2
      ;;
    --vm)
      require_value "$@"
      VM_NAME=$2
      shift 2
      ;;
    --python)
      require_value "$@"
      PYTHON_BIN=$2
      shift 2
      ;;
    --node)
      require_value "$@"
      NODE_BIN=$2
      shift 2
      ;;
    --grpc-port)
      require_value "$@"
      GRPC_PORT=$2
      shift 2
      ;;
    --control-port)
      require_value "$@"
      CONTROL_PORT=$2
      shift 2
      ;;
    --dashboard-port)
      require_value "$@"
      DASHBOARD_PORT=$2
      shift 2
      ;;
    --run-id)
      require_value "$@"
      RUN_ID=$2
      shift 2
      ;;
    --keep-snapshot)
      KEEP_SNAPSHOT=true
      shift
      ;;
    --)
      shift
      EXTRA_BENCHMARK_ARGS=("$@")
      break
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "ERROR: unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

# profile/地址/输出/run-id 由编排层统一绑定，禁止透传参数覆盖，保证报告与实际进程一致。
for extra_argument in "${EXTRA_BENCHMARK_ARGS[@]+"${EXTRA_BENCHMARK_ARGS[@]}"}"; do
  case "$extra_argument" in
    --profile|--profile=*|--output|--output=*|--control-address|--control-address=*|\
    --dashboard-url|--dashboard-url=*|--run-id|--run-id=*)
      echo "ERROR: benchmark argument '$extra_argument' is owned by the helper" >&2
      exit 1
      ;;
  esac
done

case "$PROFILE" in
  smoke|standard|stress) ;;
  *) echo "ERROR: invalid --profile: $PROFILE" >&2; exit 1 ;;
esac

# 在检查外部运行时前拒绝非空结果目录；即使 VM/Node 随后不可用，也不能让旧 summary
# 看起来像由本次调用生成，从源头避免“陈旧产物假绿”。
timestamp=$(date -u +%Y%m%dT%H%M%SZ)
if [[ -z "$OUTPUT_DIR" ]]; then
  OUTPUT_DIR="$REPO_ROOT/benchmark-results/event-pipeline-${PROFILE}-${timestamp}"
fi
if [[ -e "$OUTPUT_DIR" && ! -d "$OUTPUT_DIR" ]]; then
  echo "ERROR: --output-dir exists and is not a directory: $OUTPUT_DIR" >&2
  exit 1
fi
if [[ -d "$OUTPUT_DIR" && -n $(ls -A "$OUTPUT_DIR") ]]; then
  echo "ERROR: --output-dir must be new or empty to prevent stale artifacts: $OUTPUT_DIR" >&2
  exit 1
fi
mkdir -p "$OUTPUT_DIR"
OUTPUT_DIR=$(cd "$OUTPUT_DIR" && pwd)

for command in limactl tar curl; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "ERROR: required command not found: $command" >&2
    exit 1
  fi
done
if ! "$PYTHON_BIN" --version >/dev/null 2>&1; then
  echo "ERROR: unusable Python executable: $PYTHON_BIN" >&2
  exit 1
fi
if ! "$NODE_BIN" --version >/dev/null 2>&1; then
  echo "ERROR: unusable Node executable: $NODE_BIN" >&2
  exit 1
fi
if [[ $(uname -s) != Darwin ]]; then
  echo "ERROR: this helper is the macOS/Lima entrypoint (found $(uname -s))" >&2
  exit 1
fi
if ! limactl shell "$VM_NAME" -- true >/dev/null 2>&1; then
  echo "ERROR: Lima VM '$VM_NAME' is not running or not reachable" >&2
  exit 1
fi
if [[ ! -d "$REPO_ROOT/dashboard/node_modules/ws" ]]; then
  echo "ERROR: dashboard dependencies are missing; run npm --prefix dashboard ci" >&2
  exit 1
fi

# snapshot 通过软链复用宿主已安装的 node_modules，因此额外绑定实际文件字节和软链目标；
# package-lock 只能说明声明依赖，不能单独证明这次真正执行的是哪些依赖字节。
DEPENDENCY_IDENTITY_JSON=$(
  "$PYTHON_BIN" - "$REPO_ROOT/dashboard/node_modules" <<'PY'
import hashlib
import json
import os
import pathlib
import sys

root = pathlib.Path(sys.argv[1]).resolve()
digest = hashlib.sha256()
file_count = 0
total_bytes = 0
for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
    relative = path.relative_to(root).as_posix().encode()
    if path.is_symlink():
        kind = b"L"
        content = os.readlink(path).encode()
    elif path.is_file():
        kind = b"F"
        content = path.read_bytes()
    else:
        continue
    digest.update(kind)
    digest.update(len(relative).to_bytes(8, "big"))
    digest.update(relative)
    digest.update(len(content).to_bytes(8, "big"))
    digest.update(content)
    file_count += 1
    total_bytes += len(content)
print(json.dumps({
    "algorithm": "sha256(kind||path-length||path||content-length||content)",
    "sha256": digest.hexdigest(),
    "file_count": file_count,
    "total_bytes": total_bytes,
}, separators=(",", ":")))
PY
)

RUN_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/weaknet-event-pipeline.XXXXXX")
SOURCE_SNAPSHOT="$RUN_ROOT/source"
SOURCE_ARCHIVE="$RUN_ROOT/source.tar.gz"
VM_ARCHIVE="/tmp/weaknet-event-pipeline-${timestamp}-$$.tar.gz"
VM_RUN_DIR="/tmp/weaknet-event-pipeline-${timestamp}-$$"
DASHBOARD_PID=""
DASHBOARD_PGID=""
DRIVER_PID=""
DRIVER_PGID=""

# 终止宿主上的专属进程组；输入 PGID/leader PID，先 TERM 等待，再 KILL 并回收 leader。
terminate_host_group() {
  local pgid=${1:-}
  local leader_pid=${2:-}
  [[ -n "$pgid" ]] || return 0
  /bin/kill -TERM "-$pgid" >/dev/null 2>&1 || true
  local attempt
  local exited=false
  for attempt in 1 2 3 4 5 6 7 8 9 10; do
    if ! /bin/kill -0 "-$pgid" >/dev/null 2>&1; then
      exited=true
      break
    fi
    sleep 0.1
  done
  if [[ "$exited" != true ]]; then
    /bin/kill -KILL "-$pgid" >/dev/null 2>&1 || true
  fi
  if [[ -n "$leader_pid" ]]; then
    wait "$leader_pid" >/dev/null 2>&1 || true
  fi
}

# 终止 Lima 来宾中的 driver 进程组；使用已验证 PGID，采取同样的 TERM→等待→KILL 策略。
terminate_guest_group() {
  [[ -n "$DRIVER_PGID" ]] || return 0
  limactl shell "$VM_NAME" -- /bin/bash -s -- "$DRIVER_PGID" <<'REMOTE' >/dev/null 2>&1 || true
set +e
pgid=$1
/bin/kill -TERM "-$pgid" >/dev/null 2>&1
for attempt in 1 2 3 4 5 6 7 8 9 10; do
  /bin/kill -0 "-$pgid" >/dev/null 2>&1 || exit 0
  sleep 0.1
done
/bin/kill -KILL "-$pgid" >/dev/null 2>&1
REMOTE
}

# 尽力把来宾 driver 日志复制到持久结果目录；清理路径中失败不覆盖原始退出码。
copy_guest_log() {
  limactl copy "$VM_NAME:$VM_RUN_DIR/driver.log" "$OUTPUT_DIR/driver.log" \
    >/dev/null 2>&1 || true
}

# 唯一 EXIT 清理入口：保留原始状态，收敛宿主/来宾进程、日志和临时快照后原码退出。
cleanup() {
  local status=$?
  trap - EXIT INT TERM
  terminate_host_group "$DASHBOARD_PGID" "$DASHBOARD_PID"
  terminate_guest_group
  copy_guest_log
  limactl shell "$VM_NAME" -- rm -rf "$VM_RUN_DIR" "$VM_ARCHIVE" \
    >/dev/null 2>&1 || true
  if [[ "$KEEP_SNAPSHOT" == true ]]; then
    echo "source snapshot preserved at: $RUN_ROOT" >&2
  else
    rm -rf "$RUN_ROOT"
  fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# 只复制构建与测试所需文件来冻结 dirty worktree；排除缓存/依赖，避免运行期间源码漂移。
mkdir -p "$SOURCE_SNAPSHOT"
(
  cd "$REPO_ROOT"
  COPYFILE_DISABLE=1 tar --no-xattrs \
    --exclude='*/__pycache__' --exclude='*.pyc' --exclude='dashboard/node_modules' \
    -cf - \
    Makefile config.mk benchmarks client/*.cpp client/*.h \
    server/Makefile server/include server/src server/tests proto \
    dashboard/package.json dashboard/package-lock.json dashboard/server dashboard/src \
    dashboard/vite.config.ts dashboard/tsconfig.json \
    "AI-assisted analysis"
) | tar -xf - -C "$SOURCE_SNAPSHOT"

# 依赖字节已经单独计算 identity；用软链复用 100+ MiB 已安装树，避免放大快照成本。
ln -s "$REPO_ROOT/dashboard/node_modules" "$SOURCE_SNAPSHOT/dashboard/node_modules"

SOURCE_IDENTITY_JSON=$(
  "$PYTHON_BIN" - "$SOURCE_SNAPSHOT" <<'PY'
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1]).resolve()
sys.path.insert(0, str(root / "benchmarks"))
from run_stress_suite import collect_source_identity
print(json.dumps(collect_source_identity(root), separators=(",", ":")))
PY
)
SOURCE_SHA=$(
  "$PYTHON_BIN" -c 'import json,sys; print(json.loads(sys.argv[1])["sha256"])' \
    "$SOURCE_IDENTITY_JSON"
)
if [[ -z "$RUN_ID" ]]; then
  RUN_ID="weaknet-event-${PROFILE}-${SOURCE_SHA:0:12}"
fi
if [[ ! "$RUN_ID" =~ ^[A-Za-z0-9._-]{1,120}$ ]]; then
  echo "ERROR: --run-id must match [A-Za-z0-9._-]{1,120}" >&2
  exit 1
fi

# 三个 socket 都在 macOS 侧分配：Lima 的监听端口会转发至宿主 localhost；分配后仍校验
# 合法范围和互不相同，避免 gRPC、driver 控制口与 Dashboard API 相互抢占。
if [[ -z "$GRPC_PORT" || -z "$CONTROL_PORT" || -z "$DASHBOARD_PORT" ]]; then
  generated_ports=$(
    "$PYTHON_BIN" - <<'PY'
import socket
sockets = []
try:
    for _ in range(3):
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        sockets.append(sock)
    print(" ".join(str(sock.getsockname()[1]) for sock in sockets))
finally:
    for sock in sockets:
        sock.close()
PY
  )
  read -r generated_grpc generated_control generated_dashboard <<<"$generated_ports"
  GRPC_PORT=${GRPC_PORT:-$generated_grpc}
  CONTROL_PORT=${CONTROL_PORT:-$generated_control}
  DASHBOARD_PORT=${DASHBOARD_PORT:-$generated_dashboard}
fi
for port in "$GRPC_PORT" "$CONTROL_PORT" "$DASHBOARD_PORT"; do
  if [[ ! "$port" =~ ^[0-9]+$ ]] || (( port < 1 || port > 65535 )); then
    echo "ERROR: invalid port: $port" >&2
    exit 1
  fi
done
if [[ "$GRPC_PORT" == "$CONTROL_PORT" || "$GRPC_PORT" == "$DASHBOARD_PORT" \
      || "$CONTROL_PORT" == "$DASHBOARD_PORT" ]]; then
  echo "ERROR: gRPC, control and Dashboard ports must be distinct" >&2
  exit 1
fi

# 仅将 Linux driver 所需源码打包进入来宾；Dashboard/Node benchmark 始终在宿主快照中执行。
(
  cd "$SOURCE_SNAPSHOT"
  COPYFILE_DISABLE=1 tar --no-xattrs -czf "$SOURCE_ARCHIVE" \
    server/Makefile server/include server/src server/tests proto
)
limactl copy "$SOURCE_ARCHIVE" "$VM_NAME:$VM_ARCHIVE" >/dev/null

limactl shell "$VM_NAME" -- /bin/bash -s -- "$VM_ARCHIVE" "$VM_RUN_DIR" \
  >"$OUTPUT_DIR/build.log" 2>&1 <<'REMOTE'
set -euo pipefail
archive=$1
run_dir=$2
rm -rf "$run_dir"
mkdir -p "$run_dir"
tar -xzf "$archive" -C "$run_dir"
make -C "$run_dir/server" benchmark-event-driver -j2
REMOTE

# 来宾 driver 使用 setsid 建立独立进程组，并回传 PID/PGID；后续 cleanup 只作用于本次实例。
driver_start=$(
  limactl shell "$VM_NAME" -- /bin/bash -s -- \
    "$VM_RUN_DIR" "$GRPC_PORT" "$CONTROL_PORT" <<'REMOTE'
set -euo pipefail
run_dir=$1
grpc_port=$2
control_port=$3
cd "$run_dir"
nohup setsid server/build/event_pipeline_driver \
  --grpc-address "0.0.0.0:$grpc_port" \
  --control-address "0.0.0.0:$control_port" \
  >driver.log 2>&1 </dev/null &
pid=$!
sleep 0.2
kill -0 "$pid"
pgid=$(ps -o pgid= -p "$pid" | tr -d ' ')
if [[ -z "$pgid" || "$pid" != "$pgid" ]]; then
  /bin/kill -TERM "$pid" >/dev/null 2>&1 || true
  echo "driver did not establish a dedicated process group" >&2
  exit 1
fi
printf '%s %s\n' "$pid" "$pgid"
REMOTE
)
read -r DRIVER_PID DRIVER_PGID <<<"$driver_start"

# 等待 Lima 将来宾 control listener 转发到 macOS；不仅探测 TCP，还必须收到本次协议 PING。
"$PYTHON_BIN" - "$CONTROL_PORT" <<'PY'
import socket
import sys
import time

port = int(sys.argv[1])
deadline = time.monotonic() + 15
last = None
while time.monotonic() < deadline:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.5) as sock:
            sock.sendall(b"PING\n")
            data = sock.recv(4096)
            if b'"ok":true' in data:
                raise SystemExit(0)
    except OSError as error:
        last = error
    time.sleep(0.1)
raise SystemExit(f"driver control port did not become ready: {last}")
PY

# Dashboard 留在宿主运行，通过 Lima localhost 转发访问来宾 gRPC；Python wrapper 先 setsid
# 再 exec Node，使 Dashboard 及其潜在子进程共享可精确清理的独立进程组。
"$PYTHON_BIN" - "$NODE_BIN" "$SOURCE_SNAPSHOT/dashboard/server/index.mjs" \
  "$GRPC_PORT" "$DASHBOARD_PORT" >"$OUTPUT_DIR/dashboard.log" 2>&1 <<'PY' &
import os
import sys

node, entrypoint, grpc_port, dashboard_port = sys.argv[1:]
environment = dict(os.environ)
environment.update({
    "WEAKNET_GRPC_ADDRESS": f"127.0.0.1:{grpc_port}",
    "DASHBOARD_API_PORT": dashboard_port,
    "DASHBOARD_PING_TARGETS": "127.0.0.1",
})
os.setsid()
os.execvpe(node, [node, entrypoint], environment)
PY
DASHBOARD_PID=$!
sleep 0.1
DASHBOARD_PGID=$(ps -o pgid= -p "$DASHBOARD_PID" | tr -d ' ')
if [[ -z "$DASHBOARD_PGID" || "$DASHBOARD_PID" != "$DASHBOARD_PGID" ]]; then
  echo "ERROR: Dashboard did not establish a dedicated process group" >&2
  exit 1
fi

# ready 以 /api/status 的业务字段 ok=true 为准，单纯端口可连接不足以证明 gRPC 订阅已初始化。
dashboard_url="http://127.0.0.1:$DASHBOARD_PORT"
ready=false
for attempt in $(seq 1 150); do
  if curl --silent --fail --max-time 1 "$dashboard_url/api/status" \
      | "$PYTHON_BIN" -c 'import json,sys; raise SystemExit(0 if json.load(sys.stdin).get("ok") is True else 1)' \
      >/dev/null 2>&1; then
    ready=true
    break
  fi
  sleep 0.1
done
if [[ "$ready" != true ]]; then
  echo "ERROR: Dashboard did not become ready; see $OUTPUT_DIR/dashboard.log" >&2
  exit 1
fi

# helper 强制注入同一 profile/run-id/三端地址；其余负载参数才允许原样透传给 Node benchmark。
RAW_RESULT="$OUTPUT_DIR/event-pipeline.json"
BENCHMARK_COMMAND=(
  "$NODE_BIN" "$SOURCE_SNAPSHOT/benchmarks/event_pipeline_benchmark.mjs"
  --profile "$PROFILE"
  --output "$RAW_RESULT"
  --control-address "127.0.0.1:$CONTROL_PORT"
  --dashboard-url "$dashboard_url"
  --run-id "$RUN_ID"
)
if [[ ${#EXTRA_BENCHMARK_ARGS[@]} -gt 0 ]]; then
  BENCHMARK_COMMAND+=("${EXTRA_BENCHMARK_ARGS[@]}")
fi
set +e
"${BENCHMARK_COMMAND[@]}"
BENCHMARK_STATUS=$?
set -e

# 区分“有效失败报告”(2) 与基础设施异常；并交叉校验退出码和 summary.status，防止假绿。
if [[ ! -s "$RAW_RESULT" ]]; then
  echo "ERROR: benchmark produced no durable result (exit $BENCHMARK_STATUS)" >&2
  exit 1
fi
if [[ $BENCHMARK_STATUS -ne 0 && $BENCHMARK_STATUS -ne 2 ]]; then
  echo "ERROR: benchmark infrastructure failed with exit $BENCHMARK_STATUS" >&2
  exit 1
fi
RAW_SUMMARY_STATUS=$(
  "$PYTHON_BIN" -c \
    'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["summary"]["status"])' \
    "$RAW_RESULT"
) || { echo "ERROR: raw benchmark summary.status is unreadable" >&2; exit 1; }
if [[ $BENCHMARK_STATUS -eq 0 && "$RAW_SUMMARY_STATUS" != passed ]]; then
  echo "ERROR: benchmark exit 0 contradicts summary.status=$RAW_SUMMARY_STATUS" >&2
  exit 1
fi
if [[ $BENCHMARK_STATUS -eq 2 && "$RAW_SUMMARY_STATUS" != failed ]]; then
  echo "ERROR: benchmark exit 2 contradicts summary.status=$RAW_SUMMARY_STATUS" >&2
  exit 1
fi

# 把 host 快照、Node 依赖和 guest driver 进程信息写回原始结果，建立可追溯的宿主/来宾边界。
"$PYTHON_BIN" - "$RAW_RESULT" "$SOURCE_IDENTITY_JSON" "$DEPENDENCY_IDENTITY_JSON" "$VM_NAME" \
  "$DRIVER_PID" "$DRIVER_PGID" <<'PY'
import json
import os
import pathlib
import sys

result_path = pathlib.Path(sys.argv[1])
identity = json.loads(sys.argv[2])
dependency_identity = json.loads(sys.argv[3])
payload = json.loads(result_path.read_text(encoding="utf-8"))
environment = payload.setdefault("environment", {})
environment["source_identity"] = identity
environment["dashboard_node_modules_identity"] = dependency_identity
environment["lima_vm"] = sys.argv[4]
environment["driver_pid"] = int(sys.argv[5])
environment["driver_pgid"] = int(sys.argv[6])
temporary = result_path.with_suffix(result_path.suffix + ".tmp")
temporary.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
os.replace(temporary, result_path)
PY

# strict merge 再次验证 schema/status/source identity；产品失败必须保持 exit 2，不能被汇总吞掉。
set +e
"$PYTHON_BIN" "$SOURCE_SNAPSHOT/benchmarks/merge_stress_reports.py" \
  --profile "$PROFILE" --output-dir "$OUTPUT_DIR" "$RAW_RESULT"
MERGE_STATUS=$?
set -e
copy_guest_log

if [[ ! -s "$OUTPUT_DIR/summary.json" || ! -s "$OUTPUT_DIR/report.md" ]]; then
  echo "ERROR: strict merge did not produce summary.json and report.md" >&2
  exit 1
fi
if [[ $MERGE_STATUS -ne 0 && $MERGE_STATUS -ne 2 ]]; then
  echo "ERROR: strict merge failed with exit $MERGE_STATUS" >&2
  exit 1
fi
if [[ "$RAW_SUMMARY_STATUS" == passed && $MERGE_STATUS -ne 0 ]]; then
  echo "ERROR: passed raw result did not produce a passed strict merge" >&2
  exit 1
fi
if [[ "$RAW_SUMMARY_STATUS" == failed && $MERGE_STATUS -ne 2 ]]; then
  echo "ERROR: failed raw result was hidden by strict merge exit $MERGE_STATUS" >&2
  exit 1
fi

echo "event pipeline artifact: $RAW_RESULT"
echo "merged summary:          $OUTPUT_DIR/summary.json"
echo "markdown report:         $OUTPUT_DIR/report.md"
echo "source identity:         $SOURCE_SHA"
echo "ports: grpc=$GRPC_PORT control=$CONTROL_PORT dashboard=$DASHBOARD_PORT"

# 有效的失败门禁保持 exit 2；在产品补齐 sequence/drop/gap 与 WebSocket 背压前，这是可解释结果。
exit "$MERGE_STATUS"
