#!/usr/bin/env bash
# WeakNet macOS 一键运行入口。
#
# C++ 服务端依赖 Linux netlink、sock_diag、BTF、TC/eBPF 和 libbpf，无法直接在
# macOS 内核上完整运行。本脚本把边界固定为：
#   - Lima/Ubuntu：构建并运行 C++ gRPC Server 和命令行 Client；
#   - macOS：运行 Dashboard、版本化 RAG bridge 和浏览器。
#
# 默认执行 start；所有进程都用独立进程组启动。stop/异常清理只处理经 PID、
# PGID 和命令行共同校验的本轮进程，不使用 pkill 模糊匹配。

set -Eeuo pipefail

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
VM_NAME="${WEAKNET_LIMA_VM:-weaknet-eval}"
GRPC_PORT="${WEAKNET_GRPC_PORT:-50051}"
WEB_PORT="${DASHBOARD_WEB_PORT:-5173}"
API_PORT="${DASHBOARD_API_PORT:-5174}"
BUILD_JOBS="${WEAKNET_BUILD_JOBS:-2}"
BUILD_VERBOSE="${WEAKNET_BUILD_VERBOSE:-0}"
SERVER_LOG_MAX_MB="${WEAKNET_SERVER_LOG_MAX_MB:-10}"
SERVER_LOG_BACKUPS="${WEAKNET_SERVER_LOG_BACKUPS:-5}"
SERVER_LOG_MAX_BYTES=""
TRAFFIC_HISTORY_TTL_SEC="${WEAKNET_TRAFFIC_HISTORY_TTL_SEC:-1800}"
TRAFFIC_HISTORY_MAX_ENTRIES="${WEAKNET_TRAFFIC_HISTORY_MAX_ENTRIES:-4096}"
GRPC_PORT_EXPLICIT=0
WEB_PORT_EXPLICIT=0
API_PORT_EXPLICIT=0
[[ "${WEAKNET_GRPC_PORT+x}" == x ]] && GRPC_PORT_EXPLICIT=1
[[ "${DASHBOARD_WEB_PORT+x}" == x ]] && WEB_PORT_EXPLICIT=1
[[ "${DASHBOARD_API_PORT+x}" == x ]] && API_PORT_EXPLICIT=1
ACTION="start"
WITH_DASHBOARD=1
OPEN_BROWSER=1
FORCE_NPM_CI=0
DEMO_DURATION="${WEAKNET_DEMO_DURATION:-}"
DEMO_EXPLAIN_ONLY=0
DEMO_DURATION_OPTION_SET=0
LOG_LINES="${WEAKNET_LOG_LINES:-100}"
LOG_LINES_OPTION_SET=0
LOG_FOLLOW=0
BANNER_MODE="${WEAKNET_BANNER:-auto}"

PYTHON_BIN=""
NODE_BIN=""
NPM_BIN=""
RUNTIME_DIR=""
DASHBOARD_LOG=""
DASHBOARD_STATE=""
BUILD_LOG=""
SOURCE_ARCHIVE=""
REMOTE_ROOT="/tmp/weaknet-mac-runner"
STARTING=0
STARTED_SERVER=0
STARTED_DASHBOARD=0
OWNED_DASHBOARD_PID=""
STOPPING=0
LOCK_DIR=""
LOCK_HELD=0
LOG_FOLLOWER_PID=""
POSITIONAL=()

# 输出普通进度信息。
info() { printf '[INFO] %s\n' "$*"; }

# 输出成功信息。
ok() { printf '[OK] %s\n' "$*"; }

# 输出不会中断流程的边界或诊断提示。
warn() { printf '[WARN] %s\n' "$*" >&2; }

# 输出错误并退出；EXIT trap 会回收本轮已启动进程。
die() {
  printf '[ERROR] %s\n' "$*" >&2
  exit 1
}

# 打印零依赖 JaNet 欢迎页；颜色只在交互式终端启用，重定向时输出纯文本。
print_welcome() {
  local cyan="" green="" dim="" reset=""
  if [[ -t 1 && "${TERM:-dumb}" != dumb && -z "${NO_COLOR+x}" ]]; then
    cyan=$'\033[1;36m'
    green=$'\033[1;32m'
    dim=$'\033[2m'
    reset=$'\033[0m'
  fi

  printf '\n%b' "$cyan"
  cat <<'EOF'
       ██╗ █████╗ ███╗   ██╗███████╗████████╗
       ██║██╔══██╗████╗  ██║██╔════╝╚══██╔══╝
       ██║███████║██╔██╗ ██║█████╗     ██║
  ██   ██║██╔══██║██║╚██╗██║██╔══╝     ██║
  ╚█████╔╝██║  ██║██║ ╚████║███████╗   ██║
   ╚════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝   ╚═╝
EOF
  printf '%b  AI-powered Network Diagnostics%b\n' "$green" "$reset"
  printf '%b  Linux engine in Lima · Dashboard on macOS · gRPC at the core%b\n\n' "$dim" "$reset"
  cat <<'EOF'
  Quick commands
    ./run-mac.sh                     Start JaNet without opening a browser
    ./run-mac.sh dashboard           Open the Web Dashboard when you need it
    ./run-mac.sh browser-monitor     Open Chrome extension setup
    ./run-mac.sh status              Check stack health
    ./run-mac.sh logs                Show recent logs
    ./run-mac.sh follow              Follow live logs (Ctrl-C to stop)
    ./run-mac.sh test health         Verify the diagnosis path
    ./run-mac.sh test ping 8.8.8.8   Run an active probe
    ./run-mac.sh demo                Simulate traffic and show observed data
    ./run-mac.sh demo tcp-failure    Simulate failed TCP handshakes
    ./run-mac.sh stop                Stop JaNet

  Tip: append server/dashboard to focus one component; use -n N to choose history size.
  Engine metrics describe Lima; the optional browser monitor observes host Chrome failures.

EOF
}

# start 默认仅在真人终端显示；可用 WEAKNET_BANNER=always/never 显式覆盖。
maybe_print_welcome() {
  case "$BANNER_MODE" in
    always) print_welcome ;;
    never) ;;
    auto) [[ -t 1 && -z "${CI+x}" ]] && print_welcome || true ;;
    *) die "WEAKNET_BANNER must be auto, always, or never" ;;
  esac
}

# 打印命令和参数说明，不触发任何环境变更。
usage() {
  cat <<'EOF'
Usage:
  ./run-mac.sh [start] [options]
  ./run-mac.sh dashboard [options]
  ./run-mac.sh browser-monitor [--no-open]
  ./run-mac.sh intro
  ./run-mac.sh setup [options]
  ./run-mac.sh stop [options]
  ./run-mac.sh restart [options]
  ./run-mac.sh status [options]
  ./run-mac.sh logs [all|server|dashboard] [-n LINES]
  ./run-mac.sh follow [all|server|dashboard] [-n LINES]
  ./run-mac.sh logs -f [all|server|dashboard] [-n LINES]
  ./run-mac.sh test [get|health|ping HOST|all|events]
  ./run-mac.sh demo [showcase|download|upload|burst|connections|mixed|tcp-failure]

Options:
  --vm NAME
  --grpc-port PORT
  --web-port PORT
  --api-port PORT
  --no-dashboard
  --no-open
  --reinstall-dashboard
  --duration SECONDS       Demo stage duration override (3..180)
  --explain-only           Print the demo plan without generating traffic
  --banner
  --no-banner
  -n, --lines LINES
  -f, --follow
  -h, --help

Environment:
  WEAKNET_LIMA_VM, WEAKNET_GRPC_PORT, WEAKNET_MAC_PYTHON, WEAKNET_NODE
  WEAKNET_RAG_PYTHON, DASHBOARD_PING_TARGETS, WEAKNET_BUILD_JOBS
  WEAKNET_BUILD_VERBOSE=0|1 (1 prints full compiler commands)
  WEAKNET_SERVER_LOG_MAX_MB (1..1024, default 10)
  WEAKNET_SERVER_LOG_BACKUPS (1..50, default 5)
  WEAKNET_TRAFFIC_HISTORY_TTL_SEC (60..86400, default 1800)
  WEAKNET_TRAFFIC_HISTORY_MAX_ENTRIES (128..69632, default 4096)
  DASHBOARD_ANALYZE_MAX_CONCURRENCY (1..32, default 2)
  DASHBOARD_WS_MAX_CONNECTIONS (1..1024, default 32)
  DASHBOARD_WS_MAX_BUFFERED_BYTES (16384..16777216, default 262144)
  WEAKNET_DEMO_DURATION (same as demo --duration)
  WEAKNET_LOG_LINES, WEAKNET_BANNER=auto|always|never, NO_COLOR

Log modes:
  logs    Prints a bounded snapshot and exits.
  follow  Prints the initial snapshot, then streams new lines until Ctrl-C.

Boundary:
  Server metrics describe the Lima Linux VM network stack, not native macOS
  en0 or Wi-Fi RSSI. The optional browser monitor only observes real Chrome
  HTTP(S) failure metadata; it is not system-wide host traffic capture.
EOF
}

# 日志初始行数允许 0（只看新输出），并设置上限防止误输巨大值拖垮终端。
validate_log_lines() {
  case "$LOG_LINES" in ""|*[!0-9]*) die "log lines must be a non-negative integer: $LOG_LINES" ;; esac
  ((${#LOG_LINES} <= 6)) || die "log lines must be in [0, 100000]: $LOG_LINES"
  LOG_LINES=$((10#$LOG_LINES))
  ((LOG_LINES <= 100000)) || die "log lines must be in [0, 100000]: $LOG_LINES"
}

# 校验端口是合法 TCP 端口。
validate_port() {
  local name=$1
  local value=$2
  local numeric
  case "$value" in ""|*[!0-9]*) die "$name must be an integer: $value" ;; esac
  ((${#value} <= 5)) || die "$name must be in [1, 65535]: $value"
  numeric=$((10#$value))
  ((numeric >= 1 && numeric <= 65535)) || die "$name must be in [1, 65535]: $value"
}

# 校验参数并把运行状态放进 TMPDIR，避免污染工作区。
init_paths() {
  local user_id
  case "$VM_NAME" in ""|*[!A-Za-z0-9._-]*) die "Invalid VM name: $VM_NAME" ;; esac
  validate_port "gRPC port" "$GRPC_PORT"
  validate_port "web port" "$WEB_PORT"
  validate_port "API port" "$API_PORT"
  case "$BUILD_JOBS" in ""|*[!0-9]*) die "WEAKNET_BUILD_JOBS must be a positive integer" ;; esac
  ((${#BUILD_JOBS} <= 3)) || die "WEAKNET_BUILD_JOBS is unreasonably large: $BUILD_JOBS"
  ((10#$BUILD_JOBS >= 1)) || die "WEAKNET_BUILD_JOBS must be a positive integer"
  [[ "$BUILD_VERBOSE" == 0 || "$BUILD_VERBOSE" == 1 ]] \
    || die "WEAKNET_BUILD_VERBOSE must be 0 or 1"
  case "$SERVER_LOG_MAX_MB" in
    ""|*[!0-9]*) die "WEAKNET_SERVER_LOG_MAX_MB must be an integer in [1, 1024]" ;;
  esac
  ((${#SERVER_LOG_MAX_MB} <= 4)) \
    || die "WEAKNET_SERVER_LOG_MAX_MB must be in [1, 1024]"
  SERVER_LOG_MAX_MB=$((10#$SERVER_LOG_MAX_MB))
  ((SERVER_LOG_MAX_MB >= 1 && SERVER_LOG_MAX_MB <= 1024)) \
    || die "WEAKNET_SERVER_LOG_MAX_MB must be in [1, 1024]"
  case "$SERVER_LOG_BACKUPS" in
    ""|*[!0-9]*) die "WEAKNET_SERVER_LOG_BACKUPS must be an integer in [1, 50]" ;;
  esac
  ((${#SERVER_LOG_BACKUPS} <= 2)) \
    || die "WEAKNET_SERVER_LOG_BACKUPS must be in [1, 50]"
  SERVER_LOG_BACKUPS=$((10#$SERVER_LOG_BACKUPS))
  ((SERVER_LOG_BACKUPS >= 1 && SERVER_LOG_BACKUPS <= 50)) \
    || die "WEAKNET_SERVER_LOG_BACKUPS must be in [1, 50]"
  case "$TRAFFIC_HISTORY_TTL_SEC" in
    ""|*[!0-9]*) die "WEAKNET_TRAFFIC_HISTORY_TTL_SEC must be an integer in [60, 86400]" ;;
  esac
  ((${#TRAFFIC_HISTORY_TTL_SEC} <= 5)) \
    || die "WEAKNET_TRAFFIC_HISTORY_TTL_SEC must be in [60, 86400]"
  TRAFFIC_HISTORY_TTL_SEC=$((10#$TRAFFIC_HISTORY_TTL_SEC))
  ((TRAFFIC_HISTORY_TTL_SEC >= 60 && TRAFFIC_HISTORY_TTL_SEC <= 86400)) \
    || die "WEAKNET_TRAFFIC_HISTORY_TTL_SEC must be in [60, 86400]"
  case "$TRAFFIC_HISTORY_MAX_ENTRIES" in
    ""|*[!0-9]*) die "WEAKNET_TRAFFIC_HISTORY_MAX_ENTRIES must be an integer in [128, 69632]" ;;
  esac
  ((${#TRAFFIC_HISTORY_MAX_ENTRIES} <= 5)) \
    || die "WEAKNET_TRAFFIC_HISTORY_MAX_ENTRIES must be in [128, 69632]"
  TRAFFIC_HISTORY_MAX_ENTRIES=$((10#$TRAFFIC_HISTORY_MAX_ENTRIES))
  ((TRAFFIC_HISTORY_MAX_ENTRIES >= 128 && TRAFFIC_HISTORY_MAX_ENTRIES <= 69632)) \
    || die "WEAKNET_TRAFFIC_HISTORY_MAX_ENTRIES must be in [128, 69632]"
  SERVER_LOG_MAX_BYTES=$((SERVER_LOG_MAX_MB * 1024 * 1024))
  # 去掉前导零后再比较/传递，避免相同端口以不同字符串绕过冲突检查。
  GRPC_PORT=$((10#$GRPC_PORT))
  WEB_PORT=$((10#$WEB_PORT))
  API_PORT=$((10#$API_PORT))
  BUILD_JOBS=$((10#$BUILD_JOBS))
  [[ "$GRPC_PORT" != "$WEB_PORT" && "$GRPC_PORT" != "$API_PORT" && "$WEB_PORT" != "$API_PORT" ]] \
    || die "gRPC/web/API ports must be distinct"
  # 固定到 /tmp+uid，避免不同终端的 TMPDIR 不同而绕过同一 VM 的互斥锁。
  user_id="$(id -u)"
  RUNTIME_DIR="/tmp/weaknet-mac-${user_id}-${VM_NAME}"
  DASHBOARD_LOG="$RUNTIME_DIR/dashboard.log"
  DASHBOARD_STATE="$RUNTIME_DIR/dashboard.state"
  BUILD_LOG="$RUNTIME_DIR/build.log"
  LOCK_DIR="$RUNTIME_DIR/operation.lock"
  mkdir -p -- "$RUNTIME_DIR"
}

# 用原子 rename 写状态文件，避免 status/test 读到半截内容。
atomic_write() {
  local value=$1 path=$2 tmp="${2}.tmp.$$"
  printf '%s\n' "$value" >"$tmp"
  mv -f -- "$tmp" "$path"
}

# mutating action 共用固定运行目录，必须串行，避免互相覆盖源码或 PID。
acquire_lock() {
  local owner="" owner_cmd=""
  if mkdir -- "$LOCK_DIR" 2>/dev/null; then
    atomic_write "$$" "$LOCK_DIR/pid"
    LOCK_HELD=1
    return
  fi
  [[ -f "$LOCK_DIR/pid" ]] && owner="$(sed -n '1p' "$LOCK_DIR/pid" 2>/dev/null || true)"
  case "$owner" in
    ""|*[!0-9]*) ;;
    *)
      if /bin/kill -0 "$owner" >/dev/null 2>&1; then
        owner_cmd="$(ps -o command= -p "$owner" 2>/dev/null || true)"
        case "$owner_cmd" in *run-mac.sh*) die "Another run-mac.sh operation is active (PID $owner)" ;; esac
      fi
      ;;
  esac
  die "Stale operation lock: $LOCK_DIR (owner: ${owner:-unknown}). Confirm no runner is active, then remove that directory"
}

# 仅释放本进程持有的互斥锁。
release_lock() {
  local owner=""
  ((LOCK_HELD)) || return 0
  [[ -f "$LOCK_DIR/pid" ]] && owner="$(sed -n '1p' "$LOCK_DIR/pid" 2>/dev/null || true)"
  if [[ "$owner" == "$$" ]]; then
    rm -rf -- "$LOCK_DIR"
  fi
  LOCK_HELD=0
}

# 判断 Python 是否满足项目的 Python >=3.10 语法。
python_ok() {
  [[ -x "$1" ]] || return 1
  "$1" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3,10) else 1)' >/dev/null 2>&1
}

# 优先选择 RAG 环境或 Homebrew Python 3.12，避免误用 Apple Python 3.9。
find_python() {
  local candidate
  local path_python=""
  if [[ -n "${WEAKNET_MAC_PYTHON:-}" ]]; then
    python_ok "$WEAKNET_MAC_PYTHON" || die "WEAKNET_MAC_PYTHON must be Python >=3.10"
    PYTHON_BIN="$WEAKNET_MAC_PYTHON"
    return
  fi
  command -v python3 >/dev/null 2>&1 && path_python="$(command -v python3)"
  for candidate in \
    "$REPO_ROOT/AI-assisted analysis/rag_env/bin/python" \
    /opt/homebrew/bin/python3.12 "$path_python" \
    /opt/homebrew/bin/python3.11 /opt/homebrew/bin/python3.13 \
    /opt/homebrew/bin/python3.14 /usr/local/bin/python3; do
    if [[ -n "$candidate" ]] && python_ok "$candidate"; then
      PYTHON_BIN="$candidate"
      return
    fi
  done
  die "Python >=3.10 is required. Install: brew install python@3.12"
}

# 判断 Node 是否满足 Vite 8 的版本要求。
node_ok() {
  [[ -x "$1" ]] || return 1
  "$1" -e '
const [a,b]=process.versions.node.split(".").map(Number);
process.exit(a>22 || (a===22 && b>=12) || (a===20 && b>=19) ? 0 : 1);
' >/dev/null 2>&1
}

# 主动搜索 NVM；非交互 shell 往往不会加载 nvm.sh。
find_node() {
  local candidate
  local selected=""
  local path_node=""
  if [[ -n "${WEAKNET_NODE:-}" ]]; then
    node_ok "$WEAKNET_NODE" || die "WEAKNET_NODE must be Node 20.19+ or 22.12+"
    selected="$WEAKNET_NODE"
  else
    command -v node >/dev/null 2>&1 && path_node="$(command -v node)"
    for candidate in "$path_node" /opt/homebrew/bin/node /usr/local/bin/node \
      "$HOME"/.nvm/versions/node/*/bin/node; do
      if [[ -n "$candidate" ]] && node_ok "$candidate" \
        && [[ -x "$(dirname -- "$candidate")/npm" ]]; then
        selected="$candidate"
      fi
    done
  fi
  [[ -n "$selected" ]] || die "Compatible Node is required. Install with nvm or brew install node"
  NODE_BIN="$selected"
  NPM_BIN="$(dirname -- "$NODE_BIN")/npm"
  [[ -x "$NPM_BIN" ]] || die "npm was not found next to $NODE_BIN"
  export PATH="$(dirname -- "$NODE_BIN"):$PATH"
}

# 检查 macOS 与基础宿主命令；不静默修改 Homebrew。
host_preflight() {
  [[ "$(uname -s)" == Darwin ]] || die "This script is for macOS"
  local command_name
  for command_name in limactl tar curl ps; do
    command -v "$command_name" >/dev/null 2>&1 || die "Missing $command_name. Install Lima with: brew install lima"
  done
  find_python
}

# 从 limactl NDJSON 中读取指定 VM 状态。
vm_status() {
  limactl list --json 2>/dev/null | "$PYTHON_BIN" -c '
import json,sys
wanted=sys.argv[1]
for line in sys.stdin:
    if line.strip():
        item=json.loads(line)
        if item.get("name")==wanted:
            print(item.get("status") or "Unknown")
            raise SystemExit
print("missing")
' "$VM_NAME"
}

# 创建或启动 Ubuntu VM；VM 会保留，下一次无需重新下载。
ensure_vm() {
  local status
  status="$(vm_status)"
  case "$status" in
    Running) info "Lima VM $VM_NAME is running" ;;
    missing)
      info "Creating Lima VM $VM_NAME..."
      limactl start --name="$VM_NAME" --cpus=4 --memory=6 --disk=30 --tty=false template:ubuntu-24.04
      ;;
    *) info "Starting Lima VM $VM_NAME..."; limactl start --tty=false "$VM_NAME" ;;
  esac
  local attempt
  for ((attempt=0; attempt<180; attempt=attempt+1)); do
    [[ "$(vm_status)" == Running ]] && return
    sleep 1
  done
  die "Lima VM did not become ready"
}

# 检查 guest 构建、BPF、网络和进程组工具。
guest_deps_ready() {
  limactl shell "$VM_NAME" -- bash -lc '
set -e
sudo -n true
for c in g++ clang llvm-objdump pkg-config protoc grpc_cpp_plugin bpftool make tar setsid ip python3; do
  command -v "$c" >/dev/null
done
pkg-config --exists grpc++ protobuf libglog libbpf
test -r /sys/kernel/btf/vmlinux
dpkg-query -W libcap-dev >/dev/null 2>&1
tmp=$(mktemp); trap "rm -f \"$tmp\"" EXIT
printf "int weaknet_bpf_target_check;\n" | clang -target bpf -x c -c -o "$tmp" -
' >/dev/null 2>&1
}

# 幂等安装 Linux 构建和运行依赖。
provision_guest() {
  guest_deps_ready && { info "Lima dependencies are ready"; return; }
  info "Installing Linux gRPC/eBPF dependencies..."
  limactl shell "$VM_NAME" -- bash -lc '
set -e
test -f /etc/debian_version
sudo -n env DEBIAN_FRONTEND=noninteractive apt-get update
sudo -n env DEBIAN_FRONTEND=noninteractive apt-get install -y \
  build-essential clang llvm pkg-config \
  libgrpc++-dev protobuf-compiler protobuf-compiler-grpc \
  libgoogle-glog-dev libelf-dev zlib1g-dev libcap-dev libbpf-dev \
  bpftool iproute2 iputils-ping util-linux procps ca-certificates python3
'
  guest_deps_ready || die "Guest dependencies remain incomplete"
}

# 根据 package-lock 和 Node 版本决定是否需要 npm ci。
ensure_dashboard_deps() {
  find_node
  local lock="$REPO_ROOT/dashboard/package-lock.json"
  local stamp="$REPO_ROOT/dashboard/node_modules/.weaknet-package-lock.sha256"
  local expected actual=""
  [[ -f "$lock" ]] || die "dashboard/package-lock.json is missing"
  expected="$("$PYTHON_BIN" -c 'import hashlib,pathlib,sys; print(hashlib.sha256(pathlib.Path(sys.argv[1]).read_bytes()).hexdigest()+":"+sys.argv[2])' "$lock" "$("$NODE_BIN" --version)")"
  [[ -f "$stamp" ]] && actual="$(sed -n '1p' "$stamp" 2>/dev/null || true)"
  if ((FORCE_NPM_CI)) || [[ "$expected" != "$actual" ]]; then
    info "Synchronizing Dashboard dependencies with npm ci..."
    CI=1 "$NPM_BIN" --prefix "$REPO_ROOT/dashboard" ci --no-audit --no-fund
    mkdir -p -- "$(dirname -- "$stamp")"
    printf '%s\n' "$expected" >"$stamp"
  else
    info "Dashboard dependencies are synchronized"
  fi
}

# 检查 Mac 端口是否仍可绑定。
host_port_free() {
  "$PYTHON_BIN" -c '
import socket,sys
s=socket.socket()
s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
try: s.bind(("127.0.0.1",int(sys.argv[1])))
except OSError: raise SystemExit(1)
finally: s.close()
' "$1" >/dev/null 2>&1
}

# 检查 VM 端口是否仍可绑定。
guest_port_free() {
  limactl shell "$VM_NAME" -- python3 -c '
import socket,sys
s=socket.socket()
s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
try: s.bind(("0.0.0.0",int(sys.argv[1])))
except OSError: raise SystemExit(1)
finally: s.close()
' "$1" >/dev/null 2>&1
}

# 读取上次成功启动保存的端口；损坏时回退默认值。
saved_port() {
  local name=$1 fallback=$2 value="" numeric
  [[ -f "$RUNTIME_DIR/$name.port" ]] && value="$(sed -n '1p' "$RUNTIME_DIR/$name.port" || true)"
  case "$value" in
    ""|*[!0-9]*) printf '%s\n' "$fallback" ;;
    *)
      numeric=$((10#$value))
      if ((numeric >= 1 && numeric <= 65535)); then printf '%s\n' "$numeric"; else printf '%s\n' "$fallback"; fi
      ;;
  esac
}

# 保存成功运行的端口，供独立 status/test 调用。
save_ports() {
  atomic_write "$GRPC_PORT" "$RUNTIME_DIR/grpc.port"
  atomic_write "$WEB_PORT" "$RUNTIME_DIR/web.port"
  atomic_write "$API_PORT" "$RUNTIME_DIR/api.port"
}

# 验证 guest Server 的 PID、命令行和独立 PGID。
server_alive() {
  [[ "$(vm_status)" == Running ]] || return 1
  limactl shell "$VM_NAME" -- sudo -n sh -c '
root=$1; file="$root/server.pid"
test -f "$file" || exit 1
pid=$(sed -n "1p" "$file")
case "$pid" in ""|*[!0-9]*) exit 1 ;; esac
kill -0 "$pid" 2>/dev/null || exit 1
expected=$(readlink -f "$root/source/server/bin/weaknet-grpc-server" 2>/dev/null || true)
actual=$(readlink -f "/proc/$pid/exe" 2>/dev/null || true)
test -n "$expected" && test "$actual" = "$expected" || exit 1
pgid=$(ps -o pgid= -p "$pid" | tr -d "[:space:]")
test "$pid" = "$pgid"
' sh "$REMOTE_ROOT" >/dev/null 2>&1
}

# 正常停止只向 C++ leader 发 TERM：它完成 TC/eBPF 清理并关闭 stdout 后，日志
# 轮转器会排空管道、收到 EOF 并自然退出。只有整个进程组超时才一起 KILL。
stop_server() {
  [[ -n "$PYTHON_BIN" ]] || return 0
  [[ "$(vm_status)" == Running ]] || return 0
  limactl shell "$VM_NAME" -- sudo -n sh -c '
root=$1; file="$root/server.pid"
test -f "$file" || exit 0
pid=$(sed -n "1p" "$file")
case "$pid" in ""|*[!0-9]*) rm -f "$file"; exit 0 ;; esac
kill -0 "$pid" 2>/dev/null || { rm -f "$file"; exit 0; }
expected=$(readlink -f "$root/source/server/bin/weaknet-grpc-server" 2>/dev/null || true)
actual=$(readlink -f "/proc/$pid/exe" 2>/dev/null || true)
test -n "$expected" && test "$actual" = "$expected" || exit 2
pgid=$(ps -o pgid= -p "$pid" 2>/dev/null | tr -d "[:space:]")
test "$pid" = "$pgid" || { rm -f "$file"; exit 0; }
/bin/kill -TERM -- "$pid" >/dev/null 2>&1 || true
i=0
while /bin/kill -0 -- "-$pgid" >/dev/null 2>&1 && test "$i" -lt 100; do sleep .1; i=$((i+1)); done
/bin/kill -KILL -- "-$pgid" >/dev/null 2>&1 || true
i=0
while /bin/kill -0 -- "-$pgid" >/dev/null 2>&1 && test "$i" -lt 20; do sleep .1; i=$((i+1)); done
/bin/kill -0 -- "-$pgid" >/dev/null 2>&1 && exit 1
rm -f "$file"
' sh "$REMOTE_ROOT" >/dev/null 2>&1
}

# 验证状态文件指向的整个进程组里仍有本脚本写入的随机 token。
dashboard_group_owned() {
  local pid pgid token
  [[ -f "$DASHBOARD_STATE" ]] || return 1
  pid="$(sed -n '1p' "$DASHBOARD_STATE" || true)"
  pgid="$(sed -n '2p' "$DASHBOARD_STATE" || true)"
  token="$(sed -n '3p' "$DASHBOARD_STATE" || true)"
  case "$pid:$pgid" in *[!0-9:]*) return 1 ;; esac
  [[ -n "$pid" && -n "$token" && "$pid" == "$pgid" && "$pid" -gt 1 ]] || return 1
  /bin/kill -0 -- "-$pgid" >/dev/null 2>&1 || return 1
  ps eww -axo pgid=,command= 2>/dev/null | awk -v wanted="$pgid" \
    -v marker="WEAKNET_MAC_RUN_TOKEN=$token" '
      $1 == wanted && index($0, marker) { found=1 }
      END { exit(found ? 0 : 1) }
    ' >/dev/null
}

# Dashboard 只有在 leader 仍存活且整个进程组身份匹配时才算 running。
dashboard_alive() {
  local pid pgid actual
  dashboard_group_owned || return 1
  pid="$(sed -n '1p' "$DASHBOARD_STATE" || true)"
  pgid="$(sed -n '2p' "$DASHBOARD_STATE" || true)"
  /bin/kill -0 "$pid" >/dev/null 2>&1 || return 1
  actual="$(ps -o pgid= -p "$pid" 2>/dev/null | tr -d '[:space:]')"
  [[ "$actual" == "$pgid" ]] || return 1
}

# 停止 Dashboard 整个进程组，收敛 concurrently、Vite、BFF 和 RAG 子进程。
stop_dashboard() {
  local pid="" pgid="" i state_present=0
  [[ -e "$DASHBOARD_STATE" ]] && state_present=1
  if dashboard_group_owned; then
    pid="$(sed -n '1p' "$DASHBOARD_STATE")"
    pgid="$(sed -n '2p' "$DASHBOARD_STATE")"
    /bin/kill -TERM -- "-$pgid" >/dev/null 2>&1 || true
    for ((i=0; i<50; i=i+1)); do
      /bin/kill -0 -- "-$pgid" >/dev/null 2>&1 || break
      sleep .1
    done
    /bin/kill -KILL -- "-$pgid" >/dev/null 2>&1 || true
    for ((i=0; i<20; i=i+1)); do
      /bin/kill -0 -- "-$pgid" >/dev/null 2>&1 || break
      sleep .1
    done
    if /bin/kill -0 -- "-$pgid" >/dev/null 2>&1; then
      warn "Dashboard process group $pgid did not stop"
      return 1
    fi
  elif [[ -n "$OWNED_DASHBOARD_PID" ]] && /bin/kill -0 "$OWNED_DASHBOARD_PID" >/dev/null 2>&1; then
    # 启动早期尚未写完状态时，只回收本 shell 刚创建的 PID/进程组。
    pid="$OWNED_DASHBOARD_PID"
    pgid="$(ps -o pgid= -p "$pid" 2>/dev/null | tr -d '[:space:]')"
    if [[ "$pgid" == "$pid" ]]; then /bin/kill -TERM -- "-$pgid" >/dev/null 2>&1 || true
    else /bin/kill -TERM "$pid" >/dev/null 2>&1 || true
    fi
    for ((i=0; i<30; i=i+1)); do
      /bin/kill -0 "$pid" >/dev/null 2>&1 || break
      sleep .1
    done
    /bin/kill -KILL "$pid" >/dev/null 2>&1 || true
    wait "$pid" 2>/dev/null || true
  elif ((state_present)); then
    # 原子 manifest 只要损坏或 token 不匹配，就明确报错而不误杀/谎报停止。
    pgid="$(sed -n '2p' "$DASHBOARD_STATE" 2>/dev/null || true)"
    case "$pgid" in
      ""|*[!0-9]*) warn "Dashboard state is incomplete: $DASHBOARD_STATE"; return 1 ;;
      *) /bin/kill -0 -- "-$pgid" >/dev/null 2>&1 \
        && { warn "Dashboard state exists but ownership validation failed (PGID $pgid)"; return 1; } ;;
    esac
  fi
  rm -f -- "$DASHBOARD_STATE"
  OWNED_DASHBOARD_PID=""
}

# 仅回收 follow 命令创建的 Python 管理进程；Python 再负责收敛 tail/limactl 子进程组。
stop_log_follower() {
  local pid="$LOG_FOLLOWER_PID" i
  case "$pid" in ""|*[!0-9]*) LOG_FOLLOWER_PID=""; return 0 ;; esac
  if /bin/kill -0 "$pid" >/dev/null 2>&1; then
    /bin/kill -TERM "$pid" >/dev/null 2>&1 || true
    # Python 会先收敛本地进程组，再通过短连接精确回收远端 tail；最多等待 8 秒。
    for ((i=0; i<80; i=i+1)); do
      /bin/kill -0 "$pid" >/dev/null 2>&1 || break
      sleep .1
    done
    /bin/kill -KILL "$pid" >/dev/null 2>&1 || true
  fi
  wait "$pid" 2>/dev/null || true
  LOG_FOLLOWER_PID=""
}

# 异常时只回收本轮创建的进程；成功后 STARTING 会置零。
cleanup() {
  local rc=$?
  trap - EXIT INT TERM HUP
  set +e
  stop_log_follower
  [[ -n "$SOURCE_ARCHIVE" ]] && rm -f -- "$SOURCE_ARCHIVE"
  if ((rc != 0 && STARTING)); then
    warn "Startup failed; cleaning this run"
    ((STARTED_DASHBOARD)) && stop_dashboard
    ((STARTED_SERVER)) && stop_server
  fi
  if ((rc != 0 && STOPPING)); then
    warn "Stop was interrupted; retrying owned-process cleanup"
    stop_dashboard
    stop_server
  fi
  release_lock
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

# 打包当前 dirty worktree；不把 Mac 构建物/vmlinux.h 带进 Linux。
make_snapshot() {
  SOURCE_ARCHIVE="$(mktemp "${TMPDIR:-/tmp}/weaknet-source.XXXXXX")"
  COPYFILE_DISABLE=1 tar --no-xattrs \
    --exclude='server/build' --exclude='server/bin' --exclude='server/vmlinux.h' \
    --exclude='client/bin' --exclude='client/lib' --exclude='*/.DS_Store' \
    -czf "$SOURCE_ARCHIVE" -C "$REPO_ROOT" Makefile config.mk server client proto
}

# 在隔离的 guest 目录强制重建 BTF、Server 和 Client。
build_guest() {
  info "Copying current source into Lima..."
  limactl shell "$VM_NAME" -- mkdir -p -- "$REMOTE_ROOT"
  limactl copy "$SOURCE_ARCHIVE" "$VM_NAME:$REMOTE_ROOT/source.tar.gz"
  info "Building Linux Server and Client..."
  if ! limactl shell "$VM_NAME" -- bash -c '
set -Eeuo pipefail
root=$1; jobs=$2; verbose=$3; next="$root/source.next"
rm -rf "$next"; mkdir -p "$next"
tar -xzf "$root/source.tar.gz" -C "$next"
cd "$next"; export PATH="/usr/sbin:/usr/bin:/sbin:/bin:$PATH"
rm -f server/vmlinux.h
tmp="server/vmlinux.h.tmp.$$"; trap '\''rm -f "$tmp"'\'' EXIT
bpftool btf dump file /sys/kernel/btf/vmlinux format c >"$tmp"
test -s "$tmp"; mv "$tmp" server/vmlinux.h; trap - EXIT
if [ "$verbose" = 1 ]; then
  make --no-print-directory -j"$jobs" all
else
  make --silent --no-print-directory -j"$jobs" all
fi
sudo -n rm -rf "$root/source"; mv "$next" "$root/source"
' bash "$REMOTE_ROOT" "$BUILD_JOBS" "$BUILD_VERBOSE" 2>&1 | tee "$BUILD_LOG"; then
    die "Guest build failed; inspect $BUILD_LOG"
  fi
}

# 从 Mac 检查 Lima 自动转发后的 gRPC TCP 监听。
grpc_tcp_ready() {
  "$PYTHON_BIN" -c '
import socket,sys
try:
    with socket.create_connection(("127.0.0.1",int(sys.argv[1])),timeout=.5): pass
except OSError: raise SystemExit(1)
' "$GRPC_PORT" >/dev/null 2>&1
}

# 按“最旧归档 -> 当前文件”的顺序合并后再截取，避免刚轮转时 logs 只看到空的新文件。
tail_server_log() {
  local lines=$1
  limactl shell "$VM_NAME" -- sudo -n bash -c '
set -o pipefail
log=$1; lines=$2
test -r "$log"
{
  i=50
  while test "$i" -ge 1; do
    file="$log.$i"
    test ! -r "$file" || cat -- "$file"
    i=$((i-1))
  done
  cat -- "$log"
} | tail -n "$lines"
' bash "$REMOTE_ROOT/server.log" "$lines"
}

# 使用 root+setsid 启动 Linux Server，并执行一次真实 Client GetInterfaces RPC。
start_server() {
  info "Starting Linux gRPC Server..."
  STARTED_SERVER=1
  limactl shell "$VM_NAME" -- sudo -n sh -c '
set -eu
root=$1; port=$2; max_bytes=$3; backups=$4; history_ttl=$5; history_max=$6
src="$root/source"; run="$root/run"
mkdir -p "$run"; cd "$run"
test -r "$src/server/tools/stream_log_rotator.py"
rm -f "$root/server.pid"; : >"$root/server.log"; : >"$root/server-rotator.err"
ulimit -l unlimited 2>/dev/null || true
# Bash 进程替换让 Server 继续担任 session/PGID leader，同时由同组子进程持有
# 日志 fd；writer 可以安全关闭、重命名、重开，stop_server 也能按 PGID 一并回收。
nohup setsid bash -c '\''
root=$1; port=$2; max_bytes=$3; backups=$4; history_ttl=$5; history_max=$6
src="$root/source"
# 即使日志 writer 异常退出，也不能让一次 stdout 写入以 SIGPIPE 抢在 TC 清理前杀死 Server。
trap "" PIPE
exec env WEAKNET_GRPC_ADDRESS="0.0.0.0:$port" \
  WEAKNET_BPF_OBJECT="$src/server/build/flow_rate.bpf.o" \
  WEAKNET_TRAFFIC_HISTORY_TTL_SEC="$history_ttl" \
  WEAKNET_TRAFFIC_HISTORY_MAX_ENTRIES="$history_max" \
  "$src/server/bin/weaknet-grpc-server" \
  > >(exec python3 "$src/server/tools/stream_log_rotator.py" \
      --path "$root/server.log" --max-bytes "$max_bytes" --backups "$backups") 2>&1
'\'' bash "$root" "$port" "$max_bytes" "$backups" "$history_ttl" "$history_max" \
  </dev/null >/dev/null 2>"$root/server-rotator.err" &
pid=$!; tmp="$root/server.pid.tmp.$$"; echo "$pid" >"$tmp"; mv "$tmp" "$root/server.pid"
sleep .2; kill -0 "$pid"
pgid=$(ps -o pgid= -p "$pid" | tr -d "[:space:]"); test "$pid" = "$pgid"
chmod 0644 "$root/server.log" "$root/server-rotator.err" "$root/server.pid"
' sh "$REMOTE_ROOT" "$GRPC_PORT" "$SERVER_LOG_MAX_BYTES" "$SERVER_LOG_BACKUPS" \
  "$TRAFFIC_HISTORY_TTL_SEC" "$TRAFFIC_HISTORY_MAX_ENTRIES"
  local i
  for ((i=0; i<120; i=i+1)); do
    if server_alive && grpc_tcp_ready; then break; fi
    sleep .25
  done
  if ! server_alive || ! grpc_tcp_ready; then
    limactl shell "$VM_NAME" -- sudo -n sh -c '
test ! -s "$1/server-rotator.err" || {
  printf "===== Server log writer =====\n" >&2
  tail -n 20 "$1/server-rotator.err" >&2
}
' sh "$REMOTE_ROOT" || true
    tail_server_log 80 >&2 || true
    die "Linux Server did not become ready"
  fi
  limactl shell "$VM_NAME" -- bash -c '
root=$1; port=$2
exec env LD_LIBRARY_PATH="$root/source/client/lib" \
  WEAKNET_GRPC_ADDRESS="127.0.0.1:$port" "$root/source/client/bin/test-client" get
' bash "$REMOTE_ROOT" "$GRPC_PORT"
}

# /api/snapshot 必须同时返回 grpc.ok=true；HTTP 200 本身不是就绪证据。
snapshot_ready() {
  curl -fsS --max-time 30 "http://127.0.0.1:$API_PORT/api/snapshot" |
    "$PYTHON_BIN" -c 'import json,sys; p=json.load(sys.stdin); raise SystemExit(0 if p.get("grpc",{}).get("ok") is True else 1)' \
      >/dev/null
}

# 同时验证 BFF 与 Vite 监听；gRPC 链路由 snapshot_ready 单独验证。
dashboard_http_ready() {
  curl -fsS --max-time 2 "http://127.0.0.1:$API_PORT/api/status" >/dev/null 2>&1 \
    && curl -fsS --max-time 2 "http://127.0.0.1:$WEB_PORT" >/dev/null 2>&1
}

# 在 macOS 独立进程组中启动 npm dev，并验证 Vite、BFF 和 Dashboard→gRPC。
start_dashboard() {
  local rag_python="${WEAKNET_RAG_PYTHON:-$PYTHON_BIN}" token
  [[ -x "$rag_python" ]] || die "Invalid WEAKNET_RAG_PYTHON: $rag_python"
  info "Starting Dashboard..."
  token="weaknet-${VM_NAME}-$$-$(date +%s)"
  WEAKNET_MAC_RUN_TOKEN="$token" WEAKNET_GRPC_ADDRESS="127.0.0.1:$GRPC_PORT" \
  DASHBOARD_WEB_PORT="$WEB_PORT" DASHBOARD_API_PORT="$API_PORT" \
  VITE_API_BASE_URL="http://127.0.0.1:$API_PORT" \
  VITE_WS_BASE_URL="ws://127.0.0.1:$API_PORT" \
  WEAKNET_RAG_PYTHON="$rag_python" \
  "$PYTHON_BIN" - "$NPM_BIN" "$REPO_ROOT/dashboard" >"$DASHBOARD_LOG" 2>&1 <<'PY' &
import os,sys
npm,dashboard=sys.argv[1:]
os.chdir(dashboard)
os.setsid()
os.execvpe(npm,[npm,"run","dev"],os.environ)
PY
  local pid=$! pgid="" i
  OWNED_DASHBOARD_PID="$pid"
  STARTED_DASHBOARD=1
  # PID、期望 PGID 和 token 一次性发布，stop 永远不会看到三份半写状态。
  atomic_write "$(printf '%s\n%s\n%s' "$pid" "$pid" "$token")" "$DASHBOARD_STATE"
  for ((i=0; i<30; i=i+1)); do
    pgid="$(ps -o pgid= -p "$pid" 2>/dev/null | tr -d '[:space:]')"
    [[ "$pgid" == "$pid" ]] && break
    sleep .1
  done
  [[ "$pid" == "$pgid" ]] || die "Dashboard did not create an independent process group"

  for ((i=0; i<150; i=i+1)); do
    if curl -fsS --max-time 1 "http://127.0.0.1:$API_PORT/api/status" >/dev/null 2>&1 \
      && curl -fsS --max-time 1 "http://127.0.0.1:$WEB_PORT" >/dev/null 2>&1; then break; fi
    sleep .1
  done
  curl -fsS --max-time 2 "http://127.0.0.1:$API_PORT/api/status" >/dev/null \
    || { tail -n 100 "$DASHBOARD_LOG" >&2; die "Dashboard API is not ready"; }
  curl -fsS --max-time 2 "http://127.0.0.1:$WEB_PORT" >/dev/null \
    || { tail -n 100 "$DASHBOARD_LOG" >&2; die "Vite is not ready"; }
  snapshot_ready || { tail -n 100 "$DASHBOARD_LOG" >&2; die "Dashboard→gRPC validation failed"; }
}

# 启动前等待 Lima 转发释放，再强制端口无占用，避免 Vite 自动漂移。
check_ports() {
  local i
  for ((i=0; i<40; i=i+1)); do
    if host_port_free "$GRPC_PORT" && guest_port_free "$GRPC_PORT" \
      && { ((!WITH_DASHBOARD)) || { host_port_free "$WEB_PORT" && host_port_free "$API_PORT"; }; }; then
      return
    fi
    sleep .25
  done
  host_port_free "$GRPC_PORT" || die "Host port $GRPC_PORT is occupied"
  guest_port_free "$GRPC_PORT" || die "Guest port $GRPC_PORT is occupied"
  if ((WITH_DASHBOARD)); then
    host_port_free "$WEB_PORT" || die "Host port $WEB_PORT is occupied"
    host_port_free "$API_PORT" || die "Host port $API_PORT is occupied"
  fi
}

# 准备完整环境；start 与 setup 共用同一幂等流程。
setup_all() {
  host_preflight
  ensure_vm
  provision_guest
  if ((WITH_DASHBOARD)); then
    if dashboard_alive; then
      ((FORCE_NPM_CI)) && die "Stop JaNet before --reinstall-dashboard"
      info "Dashboard is running; dependency synchronization is already satisfied"
    else
      ensure_dashboard_deps
    fi
  fi
}

# 输出启动入口与采集边界。
summary() {
  ok "JaNet is running"
  printf '  gRPC:      127.0.0.1:%s -> Lima Linux\n' "$GRPC_PORT"
  ((WITH_DASHBOARD)) && printf '  Dashboard: http://127.0.0.1:%s\n' "$WEB_PORT"
  ((WITH_DASHBOARD)) && printf '  Browser:   ./run-mac.sh browser-monitor  (optional real-request failures)\n'
  printf '  Logs:      ./run-mac.sh logs        (recent)\n'
  printf '  Live logs: ./run-mac.sh follow      (Ctrl-C to exit)\n'
  printf '  Stop:      ./run-mac.sh stop\n'
  warn "Metrics are from the Lima VM, not native macOS en0/Wi-Fi"
}

# 打开 Chrome 的 unpacked extension 管理页；浏览器安全模型不允许脚本替用户静默安装扩展。
open_browser_monitor() {
  local extension_dir="$REPO_ROOT/browser-extension"
  [[ -f "$extension_dir/manifest.json" ]] \
    || die "Browser monitor manifest is missing: $extension_dir/manifest.json"
  API_PORT="$(saved_port api "$API_PORT")"

  if ! dashboard_alive; then
    warn "Dashboard BFF is not running; start JaNet before expecting browser failure delivery"
  fi

  printf 'JaNet browser request monitor\n'
  printf '  1. Enable Developer mode in chrome://extensions\n'
  printf '  2. Click Load unpacked and select:\n     %s\n' "$extension_dir"
  if [[ "$API_PORT" == 5174 ]]; then
    printf '  3. Keep the default options; a heartbeat should appear within 60s.\n'
  else
    printf '  3. In Extension options, set the local endpoint to http://127.0.0.1:%s/api/browser-failures.\n' "$API_PORT"
  fi
  printf '  Privacy: only failed request metadata is sent locally; no body, cookie, auth header, path, query or fragment.\n'

  if ((OPEN_BROWSER)); then
    command -v open >/dev/null 2>&1 || die "macOS open command is unavailable"
    if open -a "Google Chrome" "chrome://extensions/" 2>/dev/null; then
      ok "Opened Chrome extension setup"
    else
      warn "Google Chrome could not be opened automatically; visit chrome://extensions manually"
    fi
  fi
}

# 启动全栈；发现残缺的旧实例时先安全收敛。
start_all() {
  STARTING=1
  local server_up=0 dash_up=0
  local requested_grpc="$GRPC_PORT" requested_web="$WEB_PORT" requested_api="$API_PORT"
  host_preflight
  ensure_vm
  provision_guest
  server_alive && server_up=1 || true
  dashboard_alive && dash_up=1 || true
  # 只有复用运行中实例时才读取旧端口；fresh start 必须尊重本次 CLI/env。
  if ((server_up || dash_up)); then
    GRPC_PORT="$(saved_port grpc "$GRPC_PORT")"
    WEB_PORT="$(saved_port web "$WEB_PORT")"
    API_PORT="$(saved_port api "$API_PORT")"
  fi

  if ((!WITH_DASHBOARD)) && ((dash_up)); then
    info "Stopping the existing Dashboard (--no-dashboard)"
    STOPPING=1
    stop_dashboard || die "Failed to stop Dashboard"
    STOPPING=0
    dash_up=0
  fi
  if ((!FORCE_NPM_CI)) && ((server_up)) && grpc_tcp_ready \
    && { ((!WITH_DASHBOARD)) || { ((dash_up)) && dashboard_http_ready && snapshot_ready; }; }; then
    STARTING=0
    summary
    return
  fi
  if ((server_up || dash_up)); then
    warn "Stopping a partial previous stack"
    STOPPING=1
    stop_dashboard
    stop_server
    STOPPING=0
  fi
  GRPC_PORT="$requested_grpc"
  WEB_PORT="$requested_web"
  API_PORT="$requested_api"
  ((WITH_DASHBOARD)) && ensure_dashboard_deps
  check_ports
  make_snapshot
  build_guest
  start_server
  ((WITH_DASHBOARD)) && start_dashboard
  save_ports
  STARTING=0
  summary
}

# 停止脚本拥有的进程但保留 VM。
stop_all() {
  local vm
  STOPPING=1
  host_preflight
  vm="$(vm_status)"
  if [[ "$vm" != Running && "$vm" != missing ]]; then
    warn "Lima VM is $vm; starting it briefly so a suspended Server cannot revive later"
    ensure_vm
  fi
  stop_dashboard || die "Failed to stop Dashboard"
  stop_server || die "Failed to stop Linux Server"
  dashboard_alive && die "Dashboard is still running" || true
  server_alive && die "Linux Server is still running" || true
  STOPPING=0
  vm="$(vm_status)"
  if [[ "$vm" == Running ]]; then
    ok "JaNet stopped; Lima VM $VM_NAME remains running"
  else
    ok "JaNet stopped; Lima VM state is $vm"
  fi
}

# restart 默认继承上次成功端口；显式 CLI/环境变量只覆盖对应端口。
inherit_restart_ports() {
  ((!GRPC_PORT_EXPLICIT)) && GRPC_PORT="$(saved_port grpc "$GRPC_PORT")"
  ((!WEB_PORT_EXPLICIT)) && WEB_PORT="$(saved_port web "$WEB_PORT")"
  ((!API_PORT_EXPLICIT)) && API_PORT="$(saved_port api "$API_PORT")"
  [[ "$GRPC_PORT" != "$WEB_PORT" && "$GRPC_PORT" != "$API_PORT" && "$WEB_PORT" != "$API_PORT" ]] \
    || die "Saved restart ports conflict; pass explicit --grpc-port/--web-port/--api-port"
}

# 显示 VM、Server、Dashboard 和 Dashboard→gRPC 状态。
show_status() {
  host_preflight
  local vm server="stopped" dash="stopped" grpc="unknown"
  GRPC_PORT="$(saved_port grpc "$GRPC_PORT")"
  WEB_PORT="$(saved_port web "$WEB_PORT")"
  API_PORT="$(saved_port api "$API_PORT")"
  vm="$(vm_status)"
  [[ "$vm" == Running ]] && server_alive && server="running" || true
  dashboard_alive && dash="running" || true
  if ((WITH_DASHBOARD)); then
    [[ "$server" == running && "$dash" == running ]] \
      && dashboard_http_ready && snapshot_ready && grpc="healthy" || true
  else
    [[ "$server" == running ]] && grpc_tcp_ready && grpc="healthy" || true
  fi
  printf 'Lima VM:   %s (%s)\nServer:    %s\nDashboard: %s\ngRPC path: %s\n' \
    "$VM_NAME" "$vm" "$server" "$dash" "$grpc"
  if ((WITH_DASHBOARD)); then
    [[ "$server" == running && "$dash" == running && "$grpc" == healthy ]]
  else
    [[ "$server" == running && "$grpc" == healthy ]]
  fi
}

# 显式进入看板；start/restart 只准备后台服务，不再主动打断当前桌面工作流。
open_dashboard() {
  host_preflight
  WEB_PORT="$(saved_port web "$WEB_PORT")"
  API_PORT="$(saved_port api "$API_PORT")"
  dashboard_alive \
    || die "Dashboard is not running. Run ./run-mac.sh start first"
  dashboard_http_ready \
    || die "Dashboard is running but its HTTP endpoints are not ready"
  snapshot_ready \
    || die "Dashboard is running but the Dashboard-to-gRPC path is not healthy"

  local url="http://127.0.0.1:$WEB_PORT"
  if ((OPEN_BROWSER)); then
    command -v open >/dev/null 2>&1 || die "macOS open command is unavailable"
    open "$url"
    ok "Opened JaNet Dashboard: $url"
  else
    ok "JaNet Dashboard is ready: $url"
  fi
}

# 校验日志范围；额外位置参数必须报错，不能被静默忽略。
log_target() {
  ((${#POSITIONAL[@]} <= 1)) || die "logs accepts at most one target: all/server/dashboard"
  local target="${POSITIONAL[0]:-all}"
  case "$target" in all|server|dashboard) printf '%s\n' "$target" ;; *) die "logs target must be all/server/dashboard" ;; esac
}

# 输出最近日志，不进入无限 follow。
show_logs() {
  host_preflight
  local target
  target="$(log_target)"
  if [[ "$target" == all || "$target" == dashboard ]]; then
    printf '\n===== Dashboard =====\n'
    [[ -f "$DASHBOARD_LOG" ]] && tail -n "$LOG_LINES" "$DASHBOARD_LOG" || printf 'No Dashboard log.\n'
  fi
  if [[ "$target" == all || "$target" == server ]]; then
    printf '\n===== Linux Server =====\n'
    [[ "$(vm_status)" == Running ]] \
      && tail_server_log "$LOG_LINES" 2>/dev/null \
      || printf 'No Linux Server log.\n'
  fi
}

# 持续合并本机 Dashboard 与 Lima Server 日志；Python 负责前缀、多流复用和信号清理。
follow_logs() {
  host_preflight
  local target include_dashboard=0 include_server=0 vm
  target="$(log_target)"
  [[ "$target" == all || "$target" == dashboard ]] && include_dashboard=1
  if [[ "$target" == all || "$target" == server ]]; then
    vm="$(vm_status)"
    if [[ "$vm" == Running ]]; then
      include_server=1
      # 运行目录必须由 Lima 普通用户持有，后续 setup/start 才能向其中复制源码。
      # server.log 由 root Server 写入，因此只对日志文件本身提权创建并开放只读权限。
      limactl shell "$VM_NAME" -- sh -c '
root=$1
mkdir -p "$root"
sudo -n touch "$root/server.log"
sudo -n chmod 0644 "$root/server.log"
' sh "$REMOTE_ROOT"
    elif [[ "$target" == server ]]; then
      die "Lima VM $VM_NAME is $vm; start JaNet before following Server logs"
    else
      warn "Lima VM $VM_NAME is $vm; following Dashboard logs only"
    fi
  fi

  if ((include_dashboard)); then
    touch "$DASHBOARD_LOG"
    dashboard_alive || warn "Dashboard is not running; showing history and waiting for future output"
  fi
  if ((include_server)); then
    server_alive || warn "Linux Server is not running; showing history and waiting for future output"
  fi

  printf 'Following %s logs from the latest %s line(s). Press Ctrl-C to exit.\n' "$target" "$LOG_LINES"
  "$PYTHON_BIN" - "$include_dashboard" "$include_server" "$LOG_LINES" \
    "$DASHBOARD_LOG" "$VM_NAME" "$REMOTE_ROOT/server.log" <<'PY' &
import os
import secrets
import signal
import subprocess
import sys
import threading
import time

include_dashboard = sys.argv[1] == "1"
include_server = sys.argv[2] == "1"
lines, dashboard_log, vm_name, server_log = sys.argv[3:]

commands = []
remote_token = None
remote_manifest = None
if include_dashboard:
    commands.append(("dashboard", ["tail", "-n", lines, "-F", dashboard_log]))
if include_server:
    # argv[0] 与 PID manifest 共同标识本次远端 tail，允许 finally 精确清理并发 follower。
    remote_token = f"janet-follow-{os.getpid()}-{secrets.token_hex(8)}"
    remote_manifest = f"{server_log}.{remote_token}.pid"
    remote_runner = (
        'manifest=$1\n'
        'token=$2\n'
        'lines=$3\n'
        'log=$4\n'
        'printf "%s\\n" "$$" >"$manifest"\n'
        'exec -a "$token" tail -n "$lines" -F "$log"\n'
    )
    commands.append(("server", [
        "limactl", "shell", vm_name, "--", "sudo", "-n", "bash", "-c",
        remote_runner, "bash", remote_manifest, remote_token, lines, server_log,
    ]))
if not commands:
    raise SystemExit("no log source is available")

print_lock = threading.Lock()
processes = []
received_signal = None
source_failure = None

def request_stop(signum, _frame):
    global received_signal
    # 保留第一个退出原因；终端/父进程随后补发 TERM 时不能覆盖用户的 Ctrl-C。
    if received_signal is None:
        received_signal = signum

for watched_signal in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
    signal.signal(watched_signal, request_stop)

def pump(label, process):
    assert process.stdout is not None
    for line in process.stdout:
        with print_lock:
            print(f"[{label}] {line}", end="", flush=True)

def signal_group(process, signum):
    try:
        os.killpg(process.pid, signum)
    except (ProcessLookupError, PermissionError):
        pass

def group_exists(process):
    try:
        os.killpg(process.pid, 0)
        return True
    except (ProcessLookupError, PermissionError):
        return False

def stop_remote_follower():
    if remote_manifest is None or remote_token is None:
        return
    # 只在 manifest PID 的 argv[0] 等于本轮 token 时 kill，避免影响其他 follow。
    cleanup_script = r'''
manifest=$1
token=$2
if [ -r "$manifest" ]; then
  pid=$(cat -- "$manifest" 2>/dev/null || true)
  case "$pid" in
    ''|*[!0-9]*) ;;
    *)
      if [ -r "/proc/$pid/cmdline" ]; then
        current=$(tr '\000' '\n' <"/proc/$pid/cmdline" | sed -n '1p')
        if [ "$current" = "$token" ]; then
          kill -TERM "$pid" 2>/dev/null || true
          i=0
          while kill -0 "$pid" 2>/dev/null && [ "$i" -lt 20 ]; do
            sleep .1
            i=$((i + 1))
          done
          # TERM 等待窗口内 PID 可能被复用；KILL 前必须重新核对唯一 argv[0] token。
          if kill -0 "$pid" 2>/dev/null && [ -r "/proc/$pid/cmdline" ]; then
            current=$(tr '\000' '\n' <"/proc/$pid/cmdline" | sed -n '1p')
            [ "$current" = "$token" ] && kill -KILL "$pid" 2>/dev/null || true
          fi
        fi
      fi
      ;;
  esac
  rm -f -- "$manifest"
fi
'''
    command = [
        "limactl", "shell", vm_name, "--", "sudo", "-n", "bash", "-c",
        cleanup_script, "bash", remote_manifest, remote_token,
    ]
    cleanup_process = None
    try:
        cleanup_process = subprocess.Popen(
            command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        return_code = cleanup_process.wait(timeout=5.0)
        if return_code != 0:
            print(
                f"warning: remote log cleanup exited with code {return_code}",
                file=sys.stderr,
                flush=True,
            )
    except (OSError, subprocess.TimeoutExpired) as error:
        print(f"warning: remote log cleanup failed: {error}", file=sys.stderr, flush=True)
    finally:
        if cleanup_process is not None and cleanup_process.poll() is None:
            signal_group(cleanup_process, signal.SIGKILL)
            try:
                cleanup_process.wait(timeout=0.5)
            except subprocess.TimeoutExpired:
                pass

try:
    for label, command in commands:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            errors="replace",
            bufsize=1,
            start_new_session=True,
        )
        processes.append(process)
        threading.Thread(target=pump, args=(label, process), daemon=True).start()

    # tail/limactl 都应常驻；任一来源自行结束都表示持续日志链路已经降级。
    # 立即结束整个 follow，避免默认 all 模式只剩一个来源却继续伪装为完整输出。
    while received_signal is None:
        for index, process in enumerate(processes):
            return_code = process.poll()
            if return_code is not None:
                source_failure = return_code if return_code > 0 else 1
                print(
                    f"{commands[index][0]} log source exited unexpectedly "
                    f"(code={return_code})",
                    file=sys.stderr,
                    flush=True,
                )
                break
        if source_failure is not None:
            break
        time.sleep(0.2)
finally:
    # 即使 limactl 父进程已经退出，其 SSH 后代仍可能留在原进程组，因此总是 signal PGID。
    for process in processes:
        signal_group(process, signal.SIGTERM)
    deadline = time.monotonic() + 2.0
    while time.monotonic() < deadline:
        for process in processes:
            process.poll()
        if not any(group_exists(process) for process in processes):
            break
        time.sleep(0.05)
    for process in processes:
        if group_exists(process):
            signal_group(process, signal.SIGKILL)
        if process.poll() is None:
            try:
                process.wait(timeout=0.5)
            except subprocess.TimeoutExpired:
                pass
    stop_remote_follower()
if received_signal is not None:
    raise SystemExit(128 + received_signal)
if source_failure is not None:
    raise SystemExit(source_failure)
PY
  LOG_FOLLOWER_PID=$!
  local follow_rc=0
  if wait "$LOG_FOLLOWER_PID"; then follow_rc=0; else follow_rc=$?; fi
  LOG_FOLLOWER_PID=""
  return "$follow_rc"
}

# 在 VM 内运行本轮构建的真实 Client/C API。
run_test() {
  host_preflight
  [[ "$(vm_status)" == Running ]] && server_alive || die "Run ./run-mac.sh start first"
  if ((${#POSITIONAL[@]}==0)); then POSITIONAL=(get); fi
  case "${POSITIONAL[0]}" in
    get|health|all|events|check|event-types|test-basic|test-network|test-ping|test-events|test-performance) ;;
    ping) ((${#POSITIONAL[@]}==2)) || die "Usage: ./run-mac.sh test ping HOST" ;;
    *) die "Unsupported test command: ${POSITIONAL[0]}" ;;
  esac
  GRPC_PORT="$(saved_port grpc "$GRPC_PORT")"
  limactl shell "$VM_NAME" -- bash -c '
root=$1; port=$2; shift 2
exec env LD_LIBRARY_PATH="$root/source/client/lib" \
  WEAKNET_GRPC_ADDRESS="127.0.0.1:$port" "$root/source/client/bin/test-client" "$@"
' bash "$REMOTE_ROOT" "$GRPC_PORT" "${POSITIONAL[@]}"
}

# 启动确定性的 VM↔Mac 流量演示；生成逻辑和结果聚合由标准库 Python 脚本负责。
run_demo() {
  host_preflight
  ((WITH_DASHBOARD)) || die "demo requires Dashboard; remove --no-dashboard"
  ((${#POSITIONAL[@]} <= 1)) || die "demo accepts at most one scenario"
  local scenario="${POSITIONAL[0]:-showcase}"
  case "$scenario" in
    showcase|download|upload|burst|connections|mixed|tcp-failure) ;;
    *) die "Unsupported demo scenario: $scenario" ;;
  esac
  if [[ -n "$DEMO_DURATION" ]]; then
    case "$DEMO_DURATION" in ""|*[!0-9]*) die "demo duration must be an integer" ;; esac
    ((${#DEMO_DURATION} <= 3)) || die "demo duration must be in [3, 180] seconds"
    DEMO_DURATION=$((10#$DEMO_DURATION))
    ((DEMO_DURATION >= 3 && DEMO_DURATION <= 180)) \
      || die "demo duration must be in [3, 180] seconds"
  fi

  # 显式 CLI/env 端口优先；未指定时才复用当前运行栈保存的端口。
  ((WEB_PORT_EXPLICIT)) || WEB_PORT="$(saved_port web "$WEB_PORT")"
  ((API_PORT_EXPLICIT)) || API_PORT="$(saved_port api "$API_PORT")"
  local args=("$REPO_ROOT/demo-traffic.py" "$scenario" --vm "$VM_NAME" \
    --web-port "$WEB_PORT" --api-port "$API_PORT")
  [[ -n "$DEMO_DURATION" ]] && args+=(--duration "$DEMO_DURATION")
  ((OPEN_BROWSER)) || args+=(--no-open)
  ((DEMO_EXPLAIN_ONLY)) && args+=(--explain-only)
  # -u 保证被重定向或由 Codex/CI 调用时也能实时看到阶段与采样结果。
  "$PYTHON_BIN" -u "${args[@]}"
}

# 解析动作与公共参数；剩余位置参数只交给 logs/test/demo。
if (($#>0)); then
  case "$1" in
    setup|start|dashboard|browser-monitor|stop|restart|status|logs|follow|logs-follow|test|demo|intro|help) ACTION=$1; shift ;;
    -h|--help) usage; exit 0 ;;
    -*) ;;
    *) die "Unknown action: $1" ;;
  esac
fi
while (($#>0)); do
  case "$1" in
    --vm) VM_NAME="${2:?missing value}"; shift 2 ;;
    --grpc-port) GRPC_PORT="${2:?missing value}"; GRPC_PORT_EXPLICIT=1; shift 2 ;;
    --web-port) WEB_PORT="${2:?missing value}"; WEB_PORT_EXPLICIT=1; shift 2 ;;
    --api-port) API_PORT="${2:?missing value}"; API_PORT_EXPLICIT=1; shift 2 ;;
    --no-dashboard) WITH_DASHBOARD=0; shift ;;
    --no-open) OPEN_BROWSER=0; shift ;;
    --reinstall-dashboard) FORCE_NPM_CI=1; shift ;;
    --duration) DEMO_DURATION="${2:?missing value}"; DEMO_DURATION_OPTION_SET=1; shift 2 ;;
    --explain-only) DEMO_EXPLAIN_ONLY=1; shift ;;
    --no-banner) BANNER_MODE=never; shift ;;
    --banner) BANNER_MODE=always; shift ;;
    -n|--lines) LOG_LINES="${2:?missing value}"; LOG_LINES_OPTION_SET=1; shift 2 ;;
    -f|--follow) LOG_FOLLOW=1; shift ;;
    -h|--help) usage; exit 0 ;;
    -*) die "Unknown option: $1" ;;
    *) POSITIONAL+=("$1"); shift ;;
  esac
done

[[ "$ACTION" == follow || "$ACTION" == logs-follow ]] && LOG_FOLLOW=1
if [[ "$ACTION" != logs && "$ACTION" != follow && "$ACTION" != logs-follow \
  && "$ACTION" != test && "$ACTION" != demo ]] \
  && ((${#POSITIONAL[@]}>0)); then
  die "Unexpected argument for $ACTION: ${POSITIONAL[0]}"
fi
if ((LOG_FOLLOW)) && [[ "$ACTION" != logs && "$ACTION" != follow && "$ACTION" != logs-follow ]]; then
  die "--follow is only valid with logs"
fi
if ((LOG_LINES_OPTION_SET)) && [[ "$ACTION" != logs && "$ACTION" != follow && "$ACTION" != logs-follow ]]; then
  die "--lines is only valid with logs/follow"
fi
((FORCE_NPM_CI && !WITH_DASHBOARD)) && die "--reinstall-dashboard cannot be combined with --no-dashboard"
((DEMO_DURATION_OPTION_SET)) && [[ "$ACTION" != demo ]] && die "--duration is only valid with demo"
((DEMO_EXPLAIN_ONLY)) && [[ "$ACTION" != demo ]] && die "--explain-only is only valid with demo"

# help/intro 都是纯展示命令，不应被无关的日志或 banner 环境变量阻断。
case "$ACTION" in
  intro) print_welcome; exit 0 ;;
  help) usage; exit 0 ;;
esac

case "$ACTION" in logs|follow|logs-follow) validate_log_lines ;; esac
if [[ "$ACTION" == start ]]; then
  case "$BANNER_MODE" in auto|always|never) ;; *) die "WEAKNET_BANNER must be auto, always, or never" ;; esac
  maybe_print_welcome
fi

init_paths
# demo 与启停/构建共用一把锁，避免并发流量或中途重启污染本轮观测结果。
case "$ACTION" in setup|start|stop|restart|demo) acquire_lock ;; esac
case "$ACTION" in
  setup) setup_all; ok "macOS/Lima environment is ready" ;;
  start) start_all ;;
  dashboard) open_dashboard ;;
  browser-monitor) open_browser_monitor ;;
  stop) stop_all ;;
  restart) inherit_restart_ports; stop_all; start_all ;;
  status) show_status ;;
  logs)
    if ((LOG_FOLLOW)); then follow_logs; else show_logs; fi
    ;;
  follow|logs-follow) follow_logs ;;
  test) run_test ;;
  demo) run_demo ;;
esac
