#!/usr/bin/env bash
# JaNet 原生 Linux / WSL2 一键运行入口。
#
# 本脚本与 run-mac.sh 保持相同的日常命令模型，但直接在当前 Linux 内核中
# 构建并运行 C++ Engine。构建与 Dashboard 始终使用普通用户；只有系统依赖
# 安装以及需要 eBPF、TC、RAW socket 权限的 Engine 启停通过 sudo 执行。
#
# 进程回收只使用本脚本写入且经过 PID、PGID、启动时间、可执行文件和随机
# token 校验的状态文件，不使用 pgrep/pkill，也不会自动删除未知 TC/qdisc。

set -Eeuo pipefail

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
GRPC_PORT="${WEAKNET_GRPC_PORT:-50051}"
WEB_PORT="${DASHBOARD_WEB_PORT:-5173}"
API_PORT="${DASHBOARD_API_PORT:-5174}"
BUILD_JOBS="${WEAKNET_BUILD_JOBS:-2}"
BUILD_VERBOSE="${WEAKNET_BUILD_VERBOSE:-0}"
SERVER_LOG_MAX_MB="${WEAKNET_SERVER_LOG_MAX_MB:-10}"
SERVER_LOG_BACKUPS="${WEAKNET_SERVER_LOG_BACKUPS:-5}"
TRAFFIC_HISTORY_TTL_SEC="${WEAKNET_TRAFFIC_HISTORY_TTL_SEC:-1800}"
TRAFFIC_HISTORY_MAX_ENTRIES="${WEAKNET_TRAFFIC_HISTORY_MAX_ENTRIES:-4096}"
SERVER_LOG_MAX_BYTES=""

GRPC_PORT_EXPLICIT=0
WEB_PORT_EXPLICIT=0
API_PORT_EXPLICIT=0
[[ "${WEAKNET_GRPC_PORT+x}" == x ]] && GRPC_PORT_EXPLICIT=1
[[ "${DASHBOARD_WEB_PORT+x}" == x ]] && WEB_PORT_EXPLICIT=1
[[ "${DASHBOARD_API_PORT+x}" == x ]] && API_PORT_EXPLICIT=1

ACTION="start"
WITH_DASHBOARD=1
OPEN_BROWSER=1
INSTALL_DEPS=0
FORCE_REBUILD=0
FORCE_NPM_CI=0
DEMO_DURATION="${WEAKNET_DEMO_DURATION:-}"
DEMO_DURATION_OPTION_SET=0
DEMO_EXPLAIN_ONLY=0
LOG_LINES="${WEAKNET_LOG_LINES:-100}"
LOG_LINES_OPTION_SET=0
LOG_FOLLOW=0
BANNER_MODE="${WEAKNET_BANNER:-auto}"

PLATFORM_KIND="linux"
PLATFORM_LABEL="native Linux"
PYTHON_BIN=""
NODE_BIN=""
NPM_BIN=""
RUNTIME_DIR=""
SERVER_STATE=""
SERVER_LOG=""
SERVER_ROTATOR_LOG=""
DASHBOARD_STATE=""
DASHBOARD_LOG=""
BUILD_LOG=""
LOCK_DIR=""

SUDO_READY=0
LOCK_HELD=0
STARTING=0
STOPPING=0
STARTED_SERVER=0
STARTED_DASHBOARD=0
OWNED_DASHBOARD_PID=""
LOG_FOLLOWER_PIDS=()
POSITIONAL=()

info() { printf '[INFO] %s\n' "$*"; }
ok() { printf '[OK] %s\n' "$*"; }
warn() { printf '[WARN] %s\n' "$*" >&2; }
die() { printf '[ERROR] %s\n' "$*" >&2; exit 1; }

# 欢迎页不依赖 Linux 工具链，intro 在未安装依赖时也能使用。
print_welcome() {
  local cyan="" green="" dim="" reset=""
  if [[ -t 1 && "${TERM:-dumb}" != dumb && -z "${NO_COLOR+x}" ]]; then
    cyan=$'\033[1;36m'; green=$'\033[1;32m'; dim=$'\033[2m'; reset=$'\033[0m'
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
  printf '%b  Native Linux engine · WSL2 ready · gRPC at the core%b\n\n' "$dim" "$reset"
  cat <<'EOF'
  Quick commands
    ./run-linux.sh setup --install-deps  Install/check Ubuntu dependencies
    ./run-linux.sh                       Start JaNet without opening a browser
    ./run-linux.sh dashboard             Open the Web Dashboard when needed
    ./run-linux.sh browser-monitor       Show Chrome extension setup
    ./run-linux.sh status                Check Engine and Dashboard health
    ./run-linux.sh logs                  Show recent bounded logs
    ./run-linux.sh follow                Follow live logs (Ctrl-C to stop)
    ./run-linux.sh test health           Verify the diagnosis path
    ./run-linux.sh test ping 8.8.8.8     Run an active probe
    ./run-linux.sh restart               Gracefully restart JaNet
    ./run-linux.sh stop                  Stop only runner-owned processes

  WSL2 boundary: Engine metrics describe the WSL Linux network namespace,
  not Windows-native processes or the physical Wi-Fi RSSI.

EOF
}

maybe_print_welcome() {
  case "$BANNER_MODE" in
    always) print_welcome ;;
    never) ;;
    auto) [[ -t 1 && -z "${CI+x}" ]] && print_welcome || true ;;
    *) die "WEAKNET_BANNER must be auto, always, or never" ;;
  esac
}

usage() {
  cat <<'EOF'
Usage:
  ./run-linux.sh [start] [options]
  ./run-linux.sh setup [--install-deps] [options]
  ./run-linux.sh dashboard [--no-open]
  ./run-linux.sh browser-monitor [--no-open]
  ./run-linux.sh stop [options]
  ./run-linux.sh restart [options]
  ./run-linux.sh status [options]
  ./run-linux.sh logs [all|server|dashboard] [-n LINES]
  ./run-linux.sh follow [all|server|dashboard] [-n LINES]
  ./run-linux.sh logs -f [all|server|dashboard] [-n LINES]
  ./run-linux.sh test [get|health|ping HOST|all|events]
  ./run-linux.sh demo [showcase|download|upload|burst|connections|mixed|tcp-failure] --explain-only
  ./run-linux.sh intro

Options:
  --grpc-port PORT
  --web-port PORT
  --api-port PORT
  --install-deps          Install Ubuntu/Debian system packages with apt
  --rebuild               Clean native artifacts before rebuilding
  --no-dashboard
  --no-open
  --reinstall-dashboard
  --duration SECONDS      Reserved demo duration (3..180)
  --explain-only          Explain the safe Linux demo boundary; generate no traffic
  --banner
  --no-banner
  -n, --lines LINES
  -f, --follow
  -h, --help

Environment:
  WEAKNET_GRPC_PORT, DASHBOARD_WEB_PORT, DASHBOARD_API_PORT
  WEAKNET_PYTHON, WEAKNET_NODE, WEAKNET_RAG_PYTHON
  WEAKNET_BUILD_JOBS, WEAKNET_BUILD_VERBOSE=0|1
  WEAKNET_SERVER_LOG_MAX_MB (1..1024, default 10)
  WEAKNET_SERVER_LOG_BACKUPS (1..50, default 5)
  WEAKNET_TRAFFIC_HISTORY_TTL_SEC (60..86400, default 1800)
  WEAKNET_TRAFFIC_HISTORY_MAX_ENTRIES (128..69632, default 4096)
  DASHBOARD_ANALYZE_MAX_CONCURRENCY, DASHBOARD_WS_MAX_CONNECTIONS
  DASHBOARD_WS_MAX_BUFFERED_BYTES, DASHBOARD_PING_TARGETS
  WEAKNET_LOG_LINES, WEAKNET_BANNER=auto|always|never, NO_COLOR

Notes:
  Do not run the whole script with sudo. It requests sudo only for package
  installation and Engine lifecycle. Dashboard and builds remain unprivileged.
  This local deployment binds gRPC, Web and API listeners to 127.0.0.1 only.
EOF
}

validate_decimal_range() {
  local name=$1 value=$2 minimum=$3 maximum=$4 max_digits=${5:-8}
  case "$value" in ""|*[!0-9]*) die "$name must be an integer in [$minimum, $maximum]: $value" ;; esac
  ((${#value} <= max_digits)) || die "$name must be in [$minimum, $maximum]: $value"
  value=$((10#$value))
  ((value >= minimum && value <= maximum)) || die "$name must be in [$minimum, $maximum]: $value"
  printf '%s\n' "$value"
}

validate_log_lines() {
  LOG_LINES="$(validate_decimal_range "log lines" "$LOG_LINES" 0 100000 6)"
}

detect_platform() {
  [[ "$(uname -s)" == Linux ]] || die "run-linux.sh requires Linux; use ./run-mac.sh on macOS"
  local release version
  release="$(uname -r 2>/dev/null || true)"
  version="$(sed -n '1p' /proc/version 2>/dev/null || true)"
  if [[ "${WSL_DISTRO_NAME:-} $release $version" =~ [Mm]icrosoft|WSL ]]; then
    if [[ "$release" =~ [Mm]icrosoft-standard|WSL2 ]]; then
      PLATFORM_KIND="wsl2"
      PLATFORM_LABEL="Windows WSL2"
    else
      PLATFORM_KIND="wsl1"
      PLATFORM_LABEL="Windows WSL1"
    fi
  else
    PLATFORM_KIND="linux"
    PLATFORM_LABEL="native Linux"
  fi
}

init_paths() {
  GRPC_PORT="$(validate_decimal_range "gRPC port" "$GRPC_PORT" 1 65535 5)"
  WEB_PORT="$(validate_decimal_range "web port" "$WEB_PORT" 1 65535 5)"
  API_PORT="$(validate_decimal_range "API port" "$API_PORT" 1 65535 5)"
  BUILD_JOBS="$(validate_decimal_range "WEAKNET_BUILD_JOBS" "$BUILD_JOBS" 1 512 3)"
  SERVER_LOG_MAX_MB="$(validate_decimal_range "WEAKNET_SERVER_LOG_MAX_MB" "$SERVER_LOG_MAX_MB" 1 1024 4)"
  SERVER_LOG_BACKUPS="$(validate_decimal_range "WEAKNET_SERVER_LOG_BACKUPS" "$SERVER_LOG_BACKUPS" 1 50 2)"
  TRAFFIC_HISTORY_TTL_SEC="$(validate_decimal_range "WEAKNET_TRAFFIC_HISTORY_TTL_SEC" "$TRAFFIC_HISTORY_TTL_SEC" 60 86400 5)"
  TRAFFIC_HISTORY_MAX_ENTRIES="$(validate_decimal_range "WEAKNET_TRAFFIC_HISTORY_MAX_ENTRIES" "$TRAFFIC_HISTORY_MAX_ENTRIES" 128 69632 5)"
  [[ "$BUILD_VERBOSE" == 0 || "$BUILD_VERBOSE" == 1 ]] || die "WEAKNET_BUILD_VERBOSE must be 0 or 1"
  [[ "$GRPC_PORT" != "$WEB_PORT" && "$GRPC_PORT" != "$API_PORT" && "$WEB_PORT" != "$API_PORT" ]] \
    || die "gRPC/web/API ports must be distinct"
  SERVER_LOG_MAX_BYTES=$((SERVER_LOG_MAX_MB * 1024 * 1024))

  local repo_hash runtime_base
  repo_hash="$(printf '%s' "$REPO_ROOT" | cksum | awk '{print $1}')"
  runtime_base="${XDG_RUNTIME_DIR:-/tmp}"
  [[ -d "$runtime_base" && -w "$runtime_base" ]] || runtime_base=/tmp
  RUNTIME_DIR="$runtime_base/janet-linux-$(id -u)-$repo_hash"
  SERVER_STATE="$RUNTIME_DIR/server.state"
  SERVER_LOG="$RUNTIME_DIR/server.log"
  SERVER_ROTATOR_LOG="$RUNTIME_DIR/server-rotator.err"
  DASHBOARD_STATE="$RUNTIME_DIR/dashboard.state"
  DASHBOARD_LOG="$RUNTIME_DIR/dashboard.log"
  BUILD_LOG="$RUNTIME_DIR/build.log"
  LOCK_DIR="$RUNTIME_DIR/operation.lock"
  mkdir -p -- "$RUNTIME_DIR"
  chmod 0700 "$RUNTIME_DIR"
}

atomic_write() {
  local value=$1 path=$2 tmp="${2}.tmp.$$"
  printf '%s\n' "$value" >"$tmp"
  chmod 0600 "$tmp"
  mv -f -- "$tmp" "$path"
}

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
      if [[ -d "/proc/$owner" ]]; then
        owner_cmd="$(tr '\0' ' ' <"/proc/$owner/cmdline" 2>/dev/null || true)"
        [[ "$owner_cmd" == *run-linux.sh* ]] && die "Another run-linux.sh operation is active (PID $owner)"
      fi
      ;;
  esac
  die "Stale operation lock: $LOCK_DIR. Confirm no runner is active, then remove it"
}

release_lock() {
  local owner=""
  ((LOCK_HELD)) || return 0
  [[ -f "$LOCK_DIR/pid" ]] && owner="$(sed -n '1p' "$LOCK_DIR/pid" 2>/dev/null || true)"
  [[ "$owner" == "$$" ]] && rm -rf -- "$LOCK_DIR"
  LOCK_HELD=0
}

python_ok() {
  [[ -x "$1" ]] || return 1
  "$1" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3,10) else 1)' >/dev/null 2>&1
}

# 把用户传入的相对解释器路径固化为绝对路径；Dashboard 会切换 cwd，不能把
# 相对 WEAKNET_NODE/WEAKNET_PYTHON 带到另一个目录后再执行。
absolute_path() {
  local path=$1 directory base
  [[ "$path" == /* ]] || path="$PWD/$path"
  directory="$(cd -- "$(dirname -- "$path")" && pwd -P)" || return 1
  base="$(basename -- "$path")"
  printf '%s/%s\n' "$directory" "$base"
}

find_python() {
  local candidate path_python=""
  if [[ -n "${WEAKNET_PYTHON:-}" ]]; then
    python_ok "$WEAKNET_PYTHON" || die "WEAKNET_PYTHON must be Python >=3.10"
    PYTHON_BIN="$(absolute_path "$WEAKNET_PYTHON")"
    return
  fi
  command -v python3 >/dev/null 2>&1 && path_python="$(command -v python3)"
  for candidate in "$REPO_ROOT/AI-assisted analysis/rag_env/bin/python" "$path_python" \
    /usr/local/bin/python3 /usr/bin/python3; do
    if [[ -n "$candidate" ]] && python_ok "$candidate"; then PYTHON_BIN="$(absolute_path "$candidate")"; return; fi
  done
  die "Python >=3.10 is required"
}

node_ok() {
  [[ -x "$1" ]] || return 1
  "$1" -e '
const [a,b]=process.versions.node.split(".").map(Number);
process.exit(a>22 || (a===22 && b>=12) || (a===20 && b>=19) ? 0 : 1);
' >/dev/null 2>&1
}

find_node() {
  local candidate selected="" path_node=""
  if [[ -n "${WEAKNET_NODE:-}" ]]; then
    node_ok "$WEAKNET_NODE" || die "WEAKNET_NODE must be Node 20.19+ or 22.12+"
    selected="$WEAKNET_NODE"
  else
    command -v node >/dev/null 2>&1 && path_node="$(command -v node)"
    for candidate in "$path_node" /usr/local/bin/node "$HOME"/.nvm/versions/node/*/bin/node \
      "$HOME"/.local/share/fnm/node-versions/*/installation/bin/node; do
      if [[ -n "$candidate" ]] && node_ok "$candidate" \
        && [[ -x "$(dirname -- "$candidate")/npm" ]]; then selected="$candidate"; fi
    done
  fi
  [[ -n "$selected" ]] || die "Dashboard requires Node 20.19+ or 22.12+. Install Node 22 with nvm, or use --no-dashboard"
  NODE_BIN="$(absolute_path "$selected")"
  NPM_BIN="$(dirname -- "$NODE_BIN")/npm"
  [[ -x "$NPM_BIN" ]] || die "npm was not found next to $NODE_BIN"
  export PATH="$(dirname -- "$NODE_BIN"):$PATH"
}

ensure_sudo() {
  ((SUDO_READY)) && return 0
  command -v sudo >/dev/null 2>&1 || die "sudo is required for the Linux Engine"
  info "Validating sudo for eBPF/TC Engine access..."
  sudo -v || die "sudo authorization failed"
  SUDO_READY=1
}

# 该探针覆盖 Makefile 实际依赖和常见的“clang 存在但没有 BPF backend”问题。
dependencies_ready() {
  local command_name tmp
  for command_name in g++ clang pkg-config protoc grpc_cpp_plugin bpftool make setsid ip \
    curl ps awk sed tail cksum sha256sum; do
    command -v "$command_name" >/dev/null 2>&1 || return 1
  done
  if [[ -n "${WEAKNET_PYTHON:-}" ]]; then python_ok "$WEAKNET_PYTHON" || return 1
  else command -v python3 >/dev/null 2>&1 && python_ok "$(command -v python3)" || return 1
  fi
  { command -v llvm-objdump >/dev/null 2>&1 || command -v objdump >/dev/null 2>&1; } || return 1
  pkg-config --exists grpc++ protobuf libbpf || return 1
  { pkg-config --exists libglog || pkg-config --exists glog; } || return 1
  [[ -r /sys/kernel/btf/vmlinux ]] || return 1
  tmp="$(mktemp "${TMPDIR:-/tmp}/janet-bpf-check.XXXXXX")"
  if ! printf 'int janet_bpf_target_check;\n' | clang -target bpf -x c -c -o "$tmp" - >/dev/null 2>&1; then
    rm -f -- "$tmp"
    return 1
  fi
  rm -f -- "$tmp"
}

dependency_report() {
  local command_name missing=()
  for command_name in g++ clang pkg-config protoc grpc_cpp_plugin bpftool make setsid ip \
    curl ps awk sed tail cksum sha256sum; do
    command -v "$command_name" >/dev/null 2>&1 || missing+=("$command_name")
  done
  if [[ -n "${WEAKNET_PYTHON:-}" ]]; then
    python_ok "$WEAKNET_PYTHON" || warn "WEAKNET_PYTHON must point to Python >=3.10"
  elif ! command -v python3 >/dev/null 2>&1 || ! python_ok "$(command -v python3 2>/dev/null || true)"; then
    warn "Python >=3.10 is unavailable"
  fi
  if ((${#missing[@]})); then warn "Missing commands: ${missing[*]}"; fi
  pkg-config --exists grpc++ protobuf libbpf 2>/dev/null \
    || warn "Missing pkg-config packages: grpc++, protobuf, and/or libbpf"
  { pkg-config --exists libglog 2>/dev/null || pkg-config --exists glog 2>/dev/null; } \
    || warn "Missing pkg-config package: libglog/glog"
  [[ -r /sys/kernel/btf/vmlinux ]] \
    || warn "Kernel BTF is unavailable: /sys/kernel/btf/vmlinux is not readable"
  if command -v clang >/dev/null 2>&1; then
    local tmp
    tmp="$(mktemp "${TMPDIR:-/tmp}/janet-bpf-check.XXXXXX")"
    printf 'int janet_bpf_target_check;\n' | clang -target bpf -x c -c -o "$tmp" - >/dev/null 2>&1 \
      || warn "clang exists but its BPF backend is unavailable"
    rm -f -- "$tmp"
  fi
}

install_system_dependencies() {
  [[ -f /etc/debian_version ]] \
    || die "--install-deps currently supports Ubuntu/Debian. Install the dependencies listed in README.md on this distribution"
  ensure_sudo
  info "Installing Linux gRPC/eBPF dependencies with apt..."
  sudo -n env DEBIAN_FRONTEND=noninteractive apt-get update
  sudo -n env DEBIAN_FRONTEND=noninteractive apt-get install -y \
    build-essential clang llvm pkg-config \
    libgrpc++-dev libprotobuf-dev protobuf-compiler protobuf-compiler-grpc \
    libgoogle-glog-dev libelf-dev zlib1g-dev libcap-dev libbpf-dev \
    bpftool iproute2 iputils-ping util-linux procps ca-certificates python3 curl
}

ensure_dependencies() {
  if dependencies_ready; then info "Linux build and kernel dependencies are ready"; return; fi
  if ((INSTALL_DEPS)); then install_system_dependencies; fi
  if ! dependencies_ready; then
    dependency_report
    die "Linux dependencies are incomplete. On Ubuntu/WSL2 run: ./run-linux.sh setup --install-deps"
  fi
}

platform_preflight() {
  detect_platform
  ((EUID != 0)) || die "Do not run ./run-linux.sh with sudo; run it as your normal user"
  [[ -r /proc/self/stat ]] || die "/proc is required"
  [[ "$PLATFORM_KIND" != wsl1 ]] || die "WSL1 is not supported; convert this distribution to WSL2 with: wsl --set-version <Distro> 2"
  if [[ "$PLATFORM_KIND" == wsl2 && ! -r /sys/kernel/btf/vmlinux ]]; then
    warn "This WSL kernel does not expose BTF; full TC/eBPF mode cannot start"
  fi
}

ensure_dashboard_dependencies() {
  find_node
  local lock="$REPO_ROOT/dashboard/package-lock.json"
  local stamp="$REPO_ROOT/dashboard/node_modules/.weaknet-package-lock.sha256"
  local expected actual=""
  [[ -f "$lock" ]] || die "dashboard/package-lock.json is missing"
  expected="$(sha256sum "$lock" | awk '{print $1}'):$("$NODE_BIN" --version)"
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

saved_port() {
  local name=$1 fallback=$2 value=""
  [[ -f "$RUNTIME_DIR/$name.port" ]] && value="$(sed -n '1p' "$RUNTIME_DIR/$name.port" 2>/dev/null || true)"
  case "$value" in
    ""|*[!0-9]*) printf '%s\n' "$fallback" ;;
    *) if ((10#$value >= 1 && 10#$value <= 65535)); then printf '%s\n' "$((10#$value))"; else printf '%s\n' "$fallback"; fi ;;
  esac
}

save_ports() {
  atomic_write "$GRPC_PORT" "$RUNTIME_DIR/grpc.port"
  atomic_write "$WEB_PORT" "$RUNTIME_DIR/web.port"
  atomic_write "$API_PORT" "$RUNTIME_DIR/api.port"
}

process_start_time() {
  [[ -r "/proc/$1/stat" ]] || return 1
  awk '{print $22}' "/proc/$1/stat" 2>/dev/null
}

# hidepid 挂载下普通用户不可读取 root /proc；如果已有非交互 sudo 凭据，就在
# root 视角复核 starttime、可执行 inode 和随机 token，status 本身不会弹密码框。
server_alive_as_root() {
  command -v sudo >/dev/null 2>&1 || return 1
  sudo -n bash -c '
state=$1
test -r "$state" || exit 1
pid=$(sed -n "1p" "$state"); pgid=$(sed -n "2p" "$state")
token=$(sed -n "3p" "$state"); starttime=$(sed -n "5p" "$state"); identity=$(sed -n "6p" "$state")
case "$pid:$pgid:$starttime:$identity" in *[!0-9:]*) exit 1 ;; esac
test -n "$pid" -a "$pid" = "$pgid" -a "$pid" -gt 1 -a -n "$token" || exit 1
test -r "/proc/$pid/stat" || exit 1
actual_pgid=$(ps -o pgid= -p "$pid" 2>/dev/null | tr -d "[:space:]")
actual_start=$(awk "{print \$22}" "/proc/$pid/stat" 2>/dev/null || true)
actual_identity=$(stat -Lc "%d:%i" "/proc/$pid/exe" 2>/dev/null || true)
actual_token=$(tr "\000" "\n" <"/proc/$pid/environ" 2>/dev/null | sed -n "s/^WEAKNET_LINUX_RUN_TOKEN=//p")
test "$actual_pgid" = "$pgid" -a "$actual_start" = "$starttime" \
  -a "$actual_identity" = "$identity" -a "$actual_token" = "$token"
' bash "$SERVER_STATE" >/dev/null 2>&1
}

# 非 root 状态检查用 PID+PGID+内核 starttime 防 PID 复用；stop 还会在 sudo
# 边界内复核进程自身 inode 和随机 token 后才发送信号。
server_alive() {
  [[ -f "$SERVER_STATE" ]] || return 1
  local pid pgid token expected starttime identity actual_pgid actual_start cmdline
  pid="$(sed -n '1p' "$SERVER_STATE" 2>/dev/null || true)"
  pgid="$(sed -n '2p' "$SERVER_STATE" 2>/dev/null || true)"
  token="$(sed -n '3p' "$SERVER_STATE" 2>/dev/null || true)"
  expected="$(sed -n '4p' "$SERVER_STATE" 2>/dev/null || true)"
  starttime="$(sed -n '5p' "$SERVER_STATE" 2>/dev/null || true)"
  identity="$(sed -n '6p' "$SERVER_STATE" 2>/dev/null || true)"
  case "$pid:$pgid:$starttime:$identity" in *[!0-9:]*) return 1 ;; esac
  [[ -n "$pid" && "$pid" == "$pgid" && "$pid" -gt 1 && -n "$token" && -n "$expected" ]] || return 1
  [[ -r "/proc/$pid/stat" ]] || { server_alive_as_root; return; }
  actual_pgid="$(ps -o pgid= -p "$pid" 2>/dev/null | tr -d '[:space:]')"
  [[ "$actual_pgid" == "$pgid" ]] || return 1
  actual_start="$(process_start_time "$pid" || true)"
  [[ "$actual_start" == "$starttime" ]] || return 1
  cmdline="$(tr '\0' '\n' <"/proc/$pid/cmdline" 2>/dev/null | sed -n '1p' || true)"
  [[ -z "$cmdline" || "$cmdline" == "$expected" ]] || return 1
}

stop_server() {
  [[ -f "$SERVER_STATE" ]] || return 0
  local pid=""
  pid="$(sed -n '1p' "$SERVER_STATE" 2>/dev/null || true)"
  case "$pid" in ""|*[!0-9]*) warn "Server state has an invalid PID: $SERVER_STATE"; return 1 ;; esac
  ensure_sudo
  if ! sudo -n bash -c '
set -u
state=$1
test -f "$state" || exit 0
pid=$(sed -n "1p" "$state"); pgid=$(sed -n "2p" "$state")
token=$(sed -n "3p" "$state"); expected=$(sed -n "4p" "$state")
starttime=$(sed -n "5p" "$state")
identity=$(sed -n "6p" "$state")
case "$pid:$pgid:$starttime:$identity" in *[!0-9:]*) exit 2 ;; esac
test -n "$pid" -a "$pid" = "$pgid" -a "$pid" -gt 1 -a -n "$token" -a -n "$expected" -a -n "$identity" || exit 2
test -d "/proc/$pid" || { rm -f -- "$state"; exit 0; }
actual_pgid=$(ps -o pgid= -p "$pid" 2>/dev/null | tr -d "[:space:]")
actual_start=$(awk "{print \$22}" "/proc/$pid/stat" 2>/dev/null || true)
actual_identity=$(stat -Lc "%d:%i" "/proc/$pid/exe" 2>/dev/null || true)
actual_token=$(tr "\000" "\n" <"/proc/$pid/environ" 2>/dev/null | sed -n "s/^WEAKNET_LINUX_RUN_TOKEN=//p")
test "$actual_pgid" = "$pgid" -a "$actual_start" = "$starttime" \
  -a "$actual_identity" = "$identity" -a "$actual_token" = "$token" || exit 3
# SIGTERM 只发给 C++ leader，让它先 detach 自己拥有的 TC filter；日志 writer
# 收到 EOF 后自然退出。10 秒后仍有同组进程才执行最终 KILL。
/bin/kill -TERM -- "$pid" >/dev/null 2>&1 || true
i=0
while /bin/kill -0 -- "-$pgid" >/dev/null 2>&1 && test "$i" -lt 100; do sleep .1; i=$((i+1)); done
/bin/kill -KILL -- "-$pgid" >/dev/null 2>&1 || true
i=0
while /bin/kill -0 -- "-$pgid" >/dev/null 2>&1 && test "$i" -lt 20; do sleep .1; i=$((i+1)); done
/bin/kill -0 -- "-$pgid" >/dev/null 2>&1 && exit 4
rm -f -- "$state"
' bash "$SERVER_STATE"; then
    warn "Server ownership validation failed; no unverified process was killed"
    return 1
  fi
}

dashboard_group_owned() {
  [[ -f "$DASHBOARD_STATE" ]] || return 1
  local pid pgid token
  pid="$(sed -n '1p' "$DASHBOARD_STATE" 2>/dev/null || true)"
  pgid="$(sed -n '2p' "$DASHBOARD_STATE" 2>/dev/null || true)"
  token="$(sed -n '3p' "$DASHBOARD_STATE" 2>/dev/null || true)"
  case "$pid:$pgid" in *[!0-9:]*) return 1 ;; esac
  [[ -n "$pid" && "$pid" == "$pgid" && "$pid" -gt 1 && -n "$token" ]] || return 1
  /bin/kill -0 -- "-$pgid" >/dev/null 2>&1 || return 1
  # procps 的字段语法与 macOS ps 不同；-eo args= 同时保留 eww 追加的环境，
  # 让 token 能在 Linux/WSL2 中完成整组归属校验。
  ps eww -eo pgid=,args= 2>/dev/null | awk -v wanted="$pgid" \
    -v marker="WEAKNET_LINUX_RUN_TOKEN=$token" '
      $1 == wanted && index($0, marker) { found=1 }
      END { exit(found ? 0 : 1) }
    ' >/dev/null
}

dashboard_alive() {
  dashboard_group_owned || return 1
  local pid pgid actual
  pid="$(sed -n '1p' "$DASHBOARD_STATE")"; pgid="$(sed -n '2p' "$DASHBOARD_STATE")"
  /bin/kill -0 "$pid" >/dev/null 2>&1 || return 1
  actual="$(ps -o pgid= -p "$pid" 2>/dev/null | tr -d '[:space:]')"
  [[ "$actual" == "$pgid" ]]
}

stop_dashboard() {
  local pid="" pgid="" i state_present=0
  [[ -e "$DASHBOARD_STATE" ]] && state_present=1
  if dashboard_group_owned; then
    pid="$(sed -n '1p' "$DASHBOARD_STATE")"; pgid="$(sed -n '2p' "$DASHBOARD_STATE")"
    /bin/kill -TERM -- "-$pgid" >/dev/null 2>&1 || true
    for ((i=0; i<50; i=i+1)); do /bin/kill -0 -- "-$pgid" >/dev/null 2>&1 || break; sleep .1; done
    /bin/kill -KILL -- "-$pgid" >/dev/null 2>&1 || true
    for ((i=0; i<20; i=i+1)); do /bin/kill -0 -- "-$pgid" >/dev/null 2>&1 || break; sleep .1; done
    /bin/kill -0 -- "-$pgid" >/dev/null 2>&1 && { warn "Dashboard process group $pgid did not stop"; return 1; }
  elif [[ -n "$OWNED_DASHBOARD_PID" && -d "/proc/$OWNED_DASHBOARD_PID" ]]; then
    pid="$OWNED_DASHBOARD_PID"
    pgid="$(ps -o pgid= -p "$pid" 2>/dev/null | tr -d '[:space:]')"
    [[ "$pgid" == "$pid" ]] && /bin/kill -TERM -- "-$pgid" >/dev/null 2>&1 || /bin/kill -TERM "$pid" >/dev/null 2>&1 || true
    wait "$pid" 2>/dev/null || true
  elif ((state_present)); then
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

stop_log_followers() {
  local pid
  for pid in "${LOG_FOLLOWER_PIDS[@]:-}"; do
    case "$pid" in ""|*[!0-9]*) continue ;; esac
    /bin/kill -TERM -- "-$pid" >/dev/null 2>&1 || /bin/kill -TERM "$pid" >/dev/null 2>&1 || true
  done
  for pid in "${LOG_FOLLOWER_PIDS[@]:-}"; do wait "$pid" 2>/dev/null || true; done
  LOG_FOLLOWER_PIDS=()
}

cleanup() {
  local rc=$?
  trap - EXIT INT TERM HUP
  set +e
  stop_log_followers
  if ((rc != 0 && STARTING)); then
    warn "Startup failed; cleaning processes created by this run"
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

port_free() {
  "$PYTHON_BIN" -c '
import socket,sys
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
try: s.bind(("127.0.0.1",int(sys.argv[1])))
except OSError: raise SystemExit(1)
finally: s.close()
' "$1" >/dev/null 2>&1
}

check_ports() {
  port_free "$GRPC_PORT" || die "Local gRPC port $GRPC_PORT is occupied; JaNet will not kill the owner"
  if ((WITH_DASHBOARD)); then
    port_free "$WEB_PORT" || die "Local web port $WEB_PORT is occupied; JaNet will not kill the owner"
    port_free "$API_PORT" || die "Local API port $API_PORT is occupied; JaNet will not kill the owner"
  fi
}

grpc_tcp_ready() {
  "$PYTHON_BIN" -c '
import socket,sys
try:
    with socket.create_connection(("127.0.0.1",int(sys.argv[1])),timeout=.5): pass
except OSError: raise SystemExit(1)
' "$GRPC_PORT" >/dev/null 2>&1
}

snapshot_ready() {
  curl -fsS --max-time 30 "http://127.0.0.1:$API_PORT/api/snapshot" |
    "$PYTHON_BIN" -c 'import json,sys; p=json.load(sys.stdin); raise SystemExit(0 if p.get("grpc",{}).get("ok") is True else 1)' \
      >/dev/null
}

dashboard_http_ready() {
  curl -fsS --max-time 2 "http://127.0.0.1:$API_PORT/api/status" >/dev/null 2>&1 \
    && curl -fsS --max-time 2 "http://127.0.0.1:$WEB_PORT" >/dev/null 2>&1
}

generate_vmlinux_header() {
  local target="$REPO_ROOT/server/vmlinux.h" tmp
  tmp="${target}.tmp.$$"
  info "Checking the current kernel BTF contract..."
  bpftool btf dump file /sys/kernel/btf/vmlinux format c >"$tmp"
  [[ -s "$tmp" ]] || { rm -f -- "$tmp"; die "bpftool generated an empty server/vmlinux.h"; }
  if [[ -s "$target" ]] && cmp -s "$tmp" "$target"; then rm -f -- "$tmp"; else mv -f -- "$tmp" "$target"; fi
}

build_project() {
  server_alive && die "Stop JaNet before rebuilding the native Engine"
  if ((FORCE_REBUILD)); then
    info "Removing native build artifacts (--rebuild)..."
    make --no-print-directory -C "$REPO_ROOT" clean
    rm -f -- "$REPO_ROOT/server/vmlinux.h"
  fi
  generate_vmlinux_header
  info "Building Linux Engine and gRPC Client..."
  local make_args=(--no-print-directory -C "$REPO_ROOT" -j"$BUILD_JOBS" all)
  ((BUILD_VERBOSE)) || make_args=(--silent "${make_args[@]}")
  if ! make "${make_args[@]}" 2>&1 | tee "$BUILD_LOG"; then
    die "Native build failed; inspect $BUILD_LOG"
  fi
  [[ -x "$REPO_ROOT/server/bin/weaknet-grpc-server" ]] || die "Server binary was not built"
  [[ -x "$REPO_ROOT/client/bin/test-client" ]] || die "Client binary was not built"
  [[ -s "$REPO_ROOT/server/build/flow_rate.bpf.o" ]] || die "eBPF object was not built"
}

tail_server_log() {
  local lines=$1 i
  [[ -r "$SERVER_LOG" ]] || return 1
  {
    for ((i=SERVER_LOG_BACKUPS; i>=1; i=i-1)); do
      [[ -r "$SERVER_LOG.$i" ]] && cat -- "$SERVER_LOG.$i"
    done
    cat -- "$SERVER_LOG"
  } | tail -n "$lines"
}

start_server() {
  local token expected="$REPO_ROOT/server/bin/weaknet-grpc-server"
  token="janet-linux-$$-$(date +%s)-$RANDOM"
  ensure_sudo
  info "Starting Linux gRPC Engine with isolated root privileges..."
  STARTED_SERVER=1
  sudo -n bash -c '
set -Eeuo pipefail
runtime=$1; state=$2; log=$3; rotator_log=$4; expected=$5; bpf_object=$6
rotator=$7; port=$8; max_bytes=$9; backups=${10}; history_ttl=${11}; history_max=${12}; token=${13}; python_bin=${14}
run="$runtime/engine-cwd"
mkdir -p -- "$run/logs"
rm -f -- "$state"
touch "$log"; : >"$rotator_log"
cd "$run"
ulimit -l unlimited 2>/dev/null || true
pid=""; spawn_start=""; tmp=""; committed=0
# Engine 已 setsid、状态文件尚未原子提交时，任何包装器异常都必须回收刚创建
# 的 PID/PGID，避免留下无 manifest 的 root 进程和 TC attachment。
cleanup_uncommitted() {
  rc=$?
  trap - EXIT INT TERM HUP
  if test "$committed" = 0 -a -n "$pid" -a -r "/proc/$pid/stat"; then
    current_start=$(awk "{print \$22}" "/proc/$pid/stat" 2>/dev/null || true)
    current_pgid=$(ps -o pgid= -p "$pid" 2>/dev/null | tr -d "[:space:]")
    if test -n "$current_start" && { test -z "$spawn_start" || test "$current_start" = "$spawn_start"; }; then
      /bin/kill -TERM -- "$pid" >/dev/null 2>&1 || true
      i=0
      while test "$current_pgid" = "$pid" && /bin/kill -0 -- "-$pid" >/dev/null 2>&1 && test "$i" -lt 30; do sleep .1; i=$((i+1)); done
      if test "$current_pgid" = "$pid"; then /bin/kill -KILL -- "-$pid" >/dev/null 2>&1 || true
      else /bin/kill -KILL -- "$pid" >/dev/null 2>&1 || true
      fi
    fi
  fi
  test -z "$tmp" || rm -f -- "$tmp"
  exit "$rc"
}
trap cleanup_uncommitted EXIT
trap "exit 130" INT
trap "exit 143" TERM
trap "exit 129" HUP
nohup setsid bash -c '\''
set -Eeuo pipefail
expected=$1; bpf_object=$2; rotator=$3; log=$4; max_bytes=$5; backups=$6
port=$7; history_ttl=$8; history_max=$9; token=${10}; python_bin=${11}
trap "" PIPE
export WEAKNET_LINUX_RUN_TOKEN="$token"
exec env WEAKNET_GRPC_ADDRESS="127.0.0.1:$port" \
  WEAKNET_BPF_OBJECT="$bpf_object" \
  WEAKNET_TRAFFIC_HISTORY_TTL_SEC="$history_ttl" \
  WEAKNET_TRAFFIC_HISTORY_MAX_ENTRIES="$history_max" \
  "$expected" \
  > >(exec "$python_bin" "$rotator" --path "$log" --max-bytes "$max_bytes" --backups "$backups") 2>&1
'\'' bash "$expected" "$bpf_object" "$rotator" "$log" "$max_bytes" "$backups" \
  "$port" "$history_ttl" "$history_max" "$token" "$python_bin" </dev/null >/dev/null 2>"$rotator_log" &
pid=$!
spawn_start=$(awk "{print \$22}" "/proc/$pid/stat" 2>/dev/null || true)
sleep .2
test -d "/proc/$pid"
pgid=$(ps -o pgid= -p "$pid" | tr -d "[:space:]")
test "$pid" = "$pgid"
starttime=$(awk "{print \$22}" "/proc/$pid/stat")
actual_exe=$(readlink -f "/proc/$pid/exe" 2>/dev/null || true)
expected_exe=$(readlink -f "$expected" 2>/dev/null || true)
test -n "$expected_exe" -a "$actual_exe" = "$expected_exe"
identity=$(stat -Lc "%d:%i" "/proc/$pid/exe")
tmp="$state.tmp.$$"
printf "%s\n%s\n%s\n%s\n%s\n%s\n" "$pid" "$pgid" "$token" "$expected" "$starttime" "$identity" >"$tmp"
chmod 0644 "$tmp" "$log" "$rotator_log"
mv -f -- "$tmp" "$state"
committed=1
trap - EXIT INT TERM HUP
' bash "$RUNTIME_DIR" "$SERVER_STATE" "$SERVER_LOG" "$SERVER_ROTATOR_LOG" \
    "$expected" "$REPO_ROOT/server/build/flow_rate.bpf.o" \
    "$REPO_ROOT/server/tools/stream_log_rotator.py" "$GRPC_PORT" "$SERVER_LOG_MAX_BYTES" \
    "$SERVER_LOG_BACKUPS" "$TRAFFIC_HISTORY_TTL_SEC" "$TRAFFIC_HISTORY_MAX_ENTRIES" "$token" "$PYTHON_BIN"

  local i
  for ((i=0; i<120; i=i+1)); do
    if server_alive && grpc_tcp_ready; then break; fi
    sleep .25
  done
  if ! server_alive || ! grpc_tcp_ready; then
    [[ ! -s "$SERVER_ROTATOR_LOG" ]] || { printf '===== Server log writer =====\n' >&2; tail -n 20 "$SERVER_ROTATOR_LOG" >&2; }
    tail_server_log 80 >&2 || true
    die "Linux Engine did not become ready"
  fi
  env LD_LIBRARY_PATH="$REPO_ROOT/client/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" \
    WEAKNET_GRPC_ADDRESS="127.0.0.1:$GRPC_PORT" "$REPO_ROOT/client/bin/test-client" get
}

start_dashboard() {
  local rag_python="${WEAKNET_RAG_PYTHON:-$PYTHON_BIN}" token pid pgid="" i
  [[ -x "$rag_python" ]] || die "Invalid WEAKNET_RAG_PYTHON: $rag_python"
  rag_python="$(absolute_path "$rag_python")"
  token="janet-dashboard-$$-$(date +%s)-$RANDOM"
  info "Starting Dashboard as the unprivileged user..."
  WEAKNET_LINUX_RUN_TOKEN="$token" WEAKNET_GRPC_ADDRESS="127.0.0.1:$GRPC_PORT" \
  DASHBOARD_WEB_PORT="$WEB_PORT" DASHBOARD_API_PORT="$API_PORT" \
  VITE_API_BASE_URL="http://127.0.0.1:$API_PORT" VITE_WS_BASE_URL="ws://127.0.0.1:$API_PORT" \
  WEAKNET_RAG_PYTHON="$rag_python" \
  "$PYTHON_BIN" - "$NPM_BIN" "$REPO_ROOT/dashboard" >"$DASHBOARD_LOG" 2>&1 <<'PY' &
import os,sys
npm,dashboard=sys.argv[1:]
os.chdir(dashboard)
os.setsid()
os.execvpe(npm,[npm,"run","dev"],os.environ)
PY
  pid=$!
  OWNED_DASHBOARD_PID="$pid"; STARTED_DASHBOARD=1
  atomic_write "$(printf '%s\n%s\n%s' "$pid" "$pid" "$token")" "$DASHBOARD_STATE"
  for ((i=0; i<30; i=i+1)); do
    pgid="$(ps -o pgid= -p "$pid" 2>/dev/null | tr -d '[:space:]')"
    [[ "$pgid" == "$pid" ]] && break
    sleep .1
  done
  [[ "$pgid" == "$pid" ]] || die "Dashboard did not create an independent process group"
  # A cold Node/Vite start on a Windows-mounted WSL filesystem can exceed 15 seconds.
  for ((i=0; i<600; i=i+1)); do
    dashboard_http_ready && break
    sleep .1
  done
  dashboard_http_ready || { tail -n 100 "$DASHBOARD_LOG" >&2; die "Dashboard HTTP endpoints are not ready"; }
  snapshot_ready || { tail -n 100 "$DASHBOARD_LOG" >&2; die "Dashboard-to-gRPC validation failed"; }
}

setup_all() {
  platform_preflight
  ensure_dependencies
  find_python
  if ((WITH_DASHBOARD)); then
    if dashboard_group_owned; then
      ((FORCE_NPM_CI)) && die "Stop JaNet before --reinstall-dashboard"
      info "Dashboard is running; dependency synchronization is already satisfied"
    else
      ensure_dashboard_dependencies
    fi
  fi
  ok "$PLATFORM_LABEL environment is ready"
}

summary() {
  ok "JaNet is running on $PLATFORM_LABEL"
  printf '  gRPC:      127.0.0.1:%s\n' "$GRPC_PORT"
  ((WITH_DASHBOARD)) && printf '  Dashboard: http://127.0.0.1:%s\n' "$WEB_PORT"
  ((WITH_DASHBOARD)) && printf '  Browser:   ./run-linux.sh browser-monitor  (optional real-request failures)\n'
  printf '  Logs:      ./run-linux.sh logs\n'
  printf '  Live logs: ./run-linux.sh follow\n'
  printf '  Stop:      ./run-linux.sh stop\n'
  if [[ "$PLATFORM_KIND" == wsl2 ]]; then
    warn "Engine traffic is WSL2 traffic; Windows-native traffic and physical Wi-Fi RSSI are outside this Engine"
  fi
}

start_all() {
  STARTING=1
  platform_preflight
  find_python
  local requested_grpc="$GRPC_PORT" requested_web="$WEB_PORT" requested_api="$API_PORT"
  local server_up=0 dash_up=0 dashboard_owned=0 server_state_present=0 dashboard_state_present=0
  local stored_grpc stored_web stored_api config_matches=1
  server_alive && server_up=1 || true
  dashboard_alive && dash_up=1 || true
  dashboard_group_owned && dashboard_owned=1 || true
  [[ -e "$SERVER_STATE" ]] && server_state_present=1
  [[ -e "$DASHBOARD_STATE" ]] && dashboard_state_present=1
  stored_grpc="$(saved_port grpc "$GRPC_PORT")"
  stored_web="$(saved_port web "$WEB_PORT")"
  stored_api="$(saved_port api "$API_PORT")"
  ((GRPC_PORT_EXPLICIT && requested_grpc != stored_grpc)) && config_matches=0
  ((WEB_PORT_EXPLICIT && requested_web != stored_web)) && config_matches=0
  ((API_PORT_EXPLICIT && requested_api != stored_api)) && config_matches=0
  if ((server_up || dash_up || dashboard_owned || server_state_present || dashboard_state_present)); then
    GRPC_PORT="$stored_grpc"; WEB_PORT="$stored_web"; API_PORT="$stored_api"
  fi
  if ((!WITH_DASHBOARD)) && ((dash_up || dashboard_owned || dashboard_state_present)); then
    info "Stopping the existing Dashboard (--no-dashboard)"
    STOPPING=1; stop_dashboard; STOPPING=0; dash_up=0; dashboard_owned=0; dashboard_state_present=0
  fi
  if ((!FORCE_REBUILD && !FORCE_NPM_CI && config_matches && server_up)) \
    && grpc_tcp_ready \
    && { ((!WITH_DASHBOARD)) || { ((dash_up)) && dashboard_http_ready && snapshot_ready; }; }; then
    STARTING=0
    summary
    return
  fi
  if ((server_up || dash_up || dashboard_owned || server_state_present || dashboard_state_present)); then
    warn "Stopping a partial or differently configured previous stack"
    STOPPING=1
    stop_dashboard || die "Failed to stop Dashboard"
    stop_server || die "Failed to stop Linux Engine"
    STOPPING=0
  fi
  GRPC_PORT="$requested_grpc"; WEB_PORT="$requested_web"; API_PORT="$requested_api"
  ensure_dependencies
  ((WITH_DASHBOARD)) && ensure_dashboard_dependencies
  check_ports
  build_project
  start_server
  ((WITH_DASHBOARD)) && start_dashboard
  save_ports
  STARTING=0
  summary
}

stop_all() {
  STOPPING=1
  platform_preflight
  stop_dashboard || die "Failed to stop Dashboard"
  stop_server || die "Failed to stop Linux Engine"
  dashboard_alive && die "Dashboard is still running" || true
  server_alive && die "Linux Engine is still running" || true
  STOPPING=0
  ok "JaNet stopped; no unknown process or TC/qdisc was modified"
}

inherit_restart_ports() {
  ((!GRPC_PORT_EXPLICIT)) && GRPC_PORT="$(saved_port grpc "$GRPC_PORT")"
  ((!WEB_PORT_EXPLICIT)) && WEB_PORT="$(saved_port web "$WEB_PORT")"
  ((!API_PORT_EXPLICIT)) && API_PORT="$(saved_port api "$API_PORT")"
  [[ "$GRPC_PORT" != "$WEB_PORT" && "$GRPC_PORT" != "$API_PORT" && "$WEB_PORT" != "$API_PORT" ]] \
    || die "Saved restart ports conflict; pass explicit ports"
}

show_capture_status() {
  curl -fsS --max-time 3 "http://127.0.0.1:$API_PORT/api/snapshot" 2>/dev/null |
    "$PYTHON_BIN" -c '
import json,sys
p=json.load(sys.stdin); t=(p.get("networkSnapshot") or {}).get("trafficObservation") or {}
mode=t.get("captureMode") or "unavailable"
complete=bool(t.get("captureComplete")); bpf=bool(t.get("bpfLoaded"))
map_complete=bool(t.get("mapReadComplete")); ifindex=t.get("boundIfindex",0)
reason=t.get("degradedReason") or "-"
print(f"Capture:   {mode} (bpfLoaded={str(bpf).lower()}, complete={str(complete).lower()}, mapReadComplete={str(map_complete).lower()}, ifindex={ifindex})")
if reason != "-": print(f"Degraded:  {reason}")
' || true
}

show_status() {
  platform_preflight
  find_python
  local server="stopped" dash="stopped" grpc="unavailable"
  GRPC_PORT="$(saved_port grpc "$GRPC_PORT")"
  WEB_PORT="$(saved_port web "$WEB_PORT")"
  API_PORT="$(saved_port api "$API_PORT")"
  server_alive && server="running" || true
  dashboard_alive && dash="running" || true
  if [[ "$server" == running ]] && grpc_tcp_ready; then grpc="tcp-ready"; fi
  if [[ "$server" == running && "$dash" == running ]] && dashboard_http_ready && snapshot_ready; then grpc="healthy"; fi
  printf 'Platform:  %s\nEngine:    %s\nDashboard: %s\ngRPC path: %s\n' "$PLATFORM_LABEL" "$server" "$dash" "$grpc"
  [[ "$dash" == running ]] && show_capture_status
  if ((WITH_DASHBOARD)); then [[ "$server" == running && "$dash" == running && "$grpc" == healthy ]]
  else [[ "$server" == running && "$grpc" != unavailable ]]
  fi
}

open_url() {
  local url=$1
  ((OPEN_BROWSER)) || { ok "Open manually: $url"; return; }
  if [[ "$PLATFORM_KIND" == wsl2 ]]; then
    if command -v wslview >/dev/null 2>&1 && wslview "$url" >/dev/null 2>&1; then return; fi
    if command -v powershell.exe >/dev/null 2>&1 \
      && powershell.exe -NoProfile -Command "Start-Process '$url'" >/dev/null 2>&1; then return; fi
    if command -v cmd.exe >/dev/null 2>&1 && cmd.exe /C start "" "$url" >/dev/null 2>&1; then return; fi
  else
    if command -v xdg-open >/dev/null 2>&1 && xdg-open "$url" >/dev/null 2>&1; then return; fi
    if command -v gio >/dev/null 2>&1 && gio open "$url" >/dev/null 2>&1; then return; fi
  fi
  warn "No desktop opener succeeded; open manually: $url"
}

open_dashboard() {
  platform_preflight
  find_python
  WEB_PORT="$(saved_port web "$WEB_PORT")"; API_PORT="$(saved_port api "$API_PORT")"
  dashboard_alive || die "Dashboard is not running. Run ./run-linux.sh start first"
  dashboard_http_ready || die "Dashboard HTTP endpoints are not ready"
  snapshot_ready || die "Dashboard-to-gRPC path is not healthy"
  local url="http://127.0.0.1:$WEB_PORT"
  if [[ "$PLATFORM_KIND" == wsl2 ]] && command -v curl.exe >/dev/null 2>&1; then
    curl.exe -fsS --max-time 3 "$url" >/dev/null 2>&1 \
      || warn "Windows localhost forwarding did not pass the curl.exe check; open $url from Windows to verify"
  fi
  open_url "$url"
  ok "JaNet Dashboard is ready: $url"
}

open_browser_monitor() {
  platform_preflight
  local extension_dir="$REPO_ROOT/browser-extension" display_path
  [[ -f "$extension_dir/manifest.json" ]] || die "Browser monitor manifest is missing: $extension_dir/manifest.json"
  API_PORT="$(saved_port api "$API_PORT")"
  display_path="$extension_dir"
  if [[ "$PLATFORM_KIND" == wsl2 ]] && command -v wslpath >/dev/null 2>&1; then
    display_path="$(wslpath -w "$extension_dir" 2>/dev/null || printf '%s' "$extension_dir")"
  fi
  dashboard_alive || warn "Dashboard BFF is not running; start JaNet before expecting browser failure delivery"
  printf 'JaNet browser request monitor\n'
  printf '  1. Enable Developer mode in chrome://extensions\n'
  printf '  2. Click Load unpacked and select:\n     %s\n' "$display_path"
  printf '  3. Set the local endpoint to http://127.0.0.1:%s/api/browser-failures if it is not the default.\n' "$API_PORT"
  printf '  Privacy: only failed request metadata is sent locally; no body, cookie, auth header, path, query or fragment.\n'
  open_url "chrome://extensions/"
}

log_target() {
  ((${#POSITIONAL[@]} <= 1)) || die "logs accepts at most one target: all/server/dashboard"
  local target="${POSITIONAL[0]:-all}"
  case "$target" in all|server|dashboard) printf '%s\n' "$target" ;; *) die "logs target must be all/server/dashboard" ;; esac
}

show_logs() {
  platform_preflight
  local target
  target="$(log_target)"
  if [[ "$target" == all || "$target" == dashboard ]]; then
    printf '\n===== Dashboard =====\n'
    [[ -r "$DASHBOARD_LOG" ]] && tail -n "$LOG_LINES" "$DASHBOARD_LOG" || printf 'No Dashboard log.\n'
  fi
  if [[ "$target" == all || "$target" == server ]]; then
    printf '\n===== Linux Engine =====\n'
    tail_server_log "$LOG_LINES" 2>/dev/null || printf 'No Linux Engine log.\n'
  fi
}

follow_logs() {
  platform_preflight
  local target include_server=0 include_dashboard=0 pid
  target="$(log_target)"
  [[ "$target" == all || "$target" == server ]] && include_server=1
  [[ "$target" == all || "$target" == dashboard ]] && include_dashboard=1
  ((include_server)) && [[ ! -e "$SERVER_LOG" ]] && warn "Engine log does not exist yet"
  if ((include_dashboard)); then touch "$DASHBOARD_LOG"; fi
  show_logs
  printf '\nFollowing %s logs. Press Ctrl-C to exit; JaNet keeps running.\n' "$target"
  if ((include_server)) && [[ -e "$SERVER_LOG" ]]; then
    setsid bash -c 'exec tail -n 0 -F "$1" | sed -u "s/^/[server] /"' bash "$SERVER_LOG" &
    pid=$!; LOG_FOLLOWER_PIDS+=("$pid")
  fi
  if ((include_dashboard)); then
    setsid bash -c 'exec tail -n 0 -F "$1" | sed -u "s/^/[dashboard] /"' bash "$DASHBOARD_LOG" &
    pid=$!; LOG_FOLLOWER_PIDS+=("$pid")
  fi
  ((${#LOG_FOLLOWER_PIDS[@]})) || die "No log source is available"
  wait "${LOG_FOLLOWER_PIDS[0]}"
}

run_test() {
  platform_preflight
  server_alive || die "Run ./run-linux.sh start first"
  ((${#POSITIONAL[@]})) || POSITIONAL=(get)
  case "${POSITIONAL[0]}" in
    get|health|all|events|check|event-types|test-basic|test-network|test-ping|test-events|test-performance) ;;
    ping) ((${#POSITIONAL[@]} == 2)) || die "Usage: ./run-linux.sh test ping HOST" ;;
    *) die "Unsupported test command: ${POSITIONAL[0]}" ;;
  esac
  GRPC_PORT="$(saved_port grpc "$GRPC_PORT")"
  exec env LD_LIBRARY_PATH="$REPO_ROOT/client/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" \
    WEAKNET_GRPC_ADDRESS="127.0.0.1:$GRPC_PORT" "$REPO_ROOT/client/bin/test-client" "${POSITIONAL[@]}"
}

run_demo() {
  platform_preflight
  ((${#POSITIONAL[@]} <= 1)) || die "demo accepts at most one scenario"
  local scenario="${POSITIONAL[0]:-showcase}"
  case "$scenario" in showcase|download|upload|burst|connections|mixed|tcp-failure) ;; *) die "Unsupported demo scenario: $scenario" ;; esac
  if [[ -n "$DEMO_DURATION" ]]; then
    DEMO_DURATION="$(validate_decimal_range "demo duration" "$DEMO_DURATION" 3 180 3)"
  fi
  cat <<EOF
Linux demo plan: $scenario
  - The macOS generator uses a Lima guest and a macOS remote peer; that topology does not exist here.
  - A local client-to-local server flow normally stays on loopback and does not prove default-interface TC capture.
  - JaNet will not rewrite routes, firewall rules, NAT, qdisc, or unknown TC filters to manufacture a graph.
  - A future executable Linux demo must use an explicit remote peer or an isolated netns/veth topology.
EOF
  ((DEMO_EXPLAIN_ONLY)) && { ok "Explanation complete; no traffic or network state was changed"; return; }
  die "Executable native Linux demo is intentionally disabled; use ./run-linux.sh demo $scenario --explain-only"
}

# 解析动作与公共参数；剩余位置参数只交给 logs/test/demo。
if (($# > 0)); then
  case "$1" in
    setup|start|dashboard|browser-monitor|stop|restart|status|logs|follow|logs-follow|test|demo|intro|help) ACTION=$1; shift ;;
    -h|--help) usage; exit 0 ;;
    -*) ;;
    *) die "Unknown action: $1" ;;
  esac
fi
while (($# > 0)); do
  case "$1" in
    --grpc-port) GRPC_PORT="${2:?missing value}"; GRPC_PORT_EXPLICIT=1; shift 2 ;;
    --web-port) WEB_PORT="${2:?missing value}"; WEB_PORT_EXPLICIT=1; shift 2 ;;
    --api-port) API_PORT="${2:?missing value}"; API_PORT_EXPLICIT=1; shift 2 ;;
    --install-deps) INSTALL_DEPS=1; shift ;;
    --rebuild) FORCE_REBUILD=1; shift ;;
    --no-dashboard) WITH_DASHBOARD=0; shift ;;
    --no-open) OPEN_BROWSER=0; shift ;;
    --reinstall-dashboard) FORCE_NPM_CI=1; shift ;;
    --duration) DEMO_DURATION="${2:?missing value}"; DEMO_DURATION_OPTION_SET=1; shift 2 ;;
    --explain-only) DEMO_EXPLAIN_ONLY=1; shift ;;
    --banner) BANNER_MODE=always; shift ;;
    --no-banner) BANNER_MODE=never; shift ;;
    -n|--lines) LOG_LINES="${2:?missing value}"; LOG_LINES_OPTION_SET=1; shift 2 ;;
    -f|--follow) LOG_FOLLOW=1; shift ;;
    -h|--help) usage; exit 0 ;;
    -*) die "Unknown option: $1" ;;
    *) POSITIONAL+=("$1"); shift ;;
  esac
done

[[ "$ACTION" == follow || "$ACTION" == logs-follow ]] && LOG_FOLLOW=1
if [[ "$ACTION" != logs && "$ACTION" != follow && "$ACTION" != logs-follow \
  && "$ACTION" != test && "$ACTION" != demo ]] && ((${#POSITIONAL[@]})); then
  die "Unexpected argument for $ACTION: ${POSITIONAL[0]}"
fi
if ((LOG_FOLLOW)) && [[ "$ACTION" != logs && "$ACTION" != follow && "$ACTION" != logs-follow ]]; then
  die "--follow is only valid with logs/follow"
fi
if ((LOG_LINES_OPTION_SET)) && [[ "$ACTION" != logs && "$ACTION" != follow && "$ACTION" != logs-follow ]]; then
  die "--lines is only valid with logs/follow"
fi
((INSTALL_DEPS)) && [[ "$ACTION" != setup && "$ACTION" != start && "$ACTION" != restart ]] \
  && die "--install-deps is only valid with setup/start/restart"
((FORCE_REBUILD)) && [[ "$ACTION" != start && "$ACTION" != restart ]] \
  && die "--rebuild is only valid with start/restart"
((FORCE_NPM_CI && !WITH_DASHBOARD)) && die "--reinstall-dashboard cannot be combined with --no-dashboard"
((DEMO_DURATION_OPTION_SET)) && [[ "$ACTION" != demo ]] && die "--duration is only valid with demo"
((DEMO_EXPLAIN_ONLY)) && [[ "$ACTION" != demo ]] && die "--explain-only is only valid with demo"

case "$ACTION" in
  intro) print_welcome; exit 0 ;;
  help) usage; exit 0 ;;
esac

case "$ACTION" in logs|follow|logs-follow) validate_log_lines ;; esac
[[ "$ACTION" == start ]] && maybe_print_welcome
detect_platform
init_paths

case "$ACTION" in setup|start|stop|restart) acquire_lock ;; esac
case "$ACTION" in
  setup) setup_all ;;
  start) start_all ;;
  dashboard) open_dashboard ;;
  browser-monitor) open_browser_monitor ;;
  stop) stop_all ;;
  restart) inherit_restart_ports; stop_all; start_all ;;
  status) show_status ;;
  logs) if ((LOG_FOLLOW)); then follow_logs; else show_logs; fi ;;
  follow|logs-follow) follow_logs ;;
  test) run_test ;;
  demo) run_demo ;;
esac
