#!/usr/bin/env bash
# WeakNet macOS/Lima 分层压力测试的总编排入口。
#
# 它冻结当前源码并复制到 Lima：Linux 来宾负责 sanitizer、BPF/内核及真实 gRPC server，
# macOS 宿主负责 core/RAG、Dashboard 和服务请求发生器；最后严格合并两端报告。脚本还负责
# 跨 host/guest 端口选择、进程组隔离、异常清理，以及将每个编排失败物化为可审计 JSON。

set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
PROFILE="standard"
VM_NAME="${WEAKNET_LIMA_VM:-weaknet-eval}"
HOST_PYTHON="${WEAKNET_BENCH_PYTHON:-python3}"
HOST_NODE="${WEAKNET_BENCH_NODE:-node}"
OUTPUT_DIR=""
USE_FIXTURE=0
WITH_SERVICE=1
KEEP_REMOTE=0
SERVICE_CONCURRENCY=""
SERVICE_REQUESTS=""
SERVICE_WARMUP=""
SERVICE_EVENT_CONNECTIONS=""

# 打印总编排的 CLI 使用说明；无输入，输出到 stdout，不启动任何测试。
usage() {
  printf '%s\n' \
    "Usage: $0 [--profile smoke|standard|stress] [--vm NAME] [--output-dir PATH]" \
    "          [--python PATH] [--node PATH] [--fixture] [--skip-service] [--keep-remote]" \
    "          [--service-concurrency LIST] [--service-requests N] [--service-warmup N]" \
    "          [--service-event-connections LIST]" \
    "" \
    "The Linux VM must already contain the project's compiler, gRPC, libbpf, bpftool and iproute2 dependencies."
}

while (($#)); do
  case "$1" in
    --profile)
      PROFILE="${2:?missing profile}"
      shift 2
      ;;
    --vm)
      VM_NAME="${2:?missing VM name}"
      shift 2
      ;;
    --output-dir)
      OUTPUT_DIR="${2:?missing output directory}"
      shift 2
      ;;
    --python)
      HOST_PYTHON="${2:?missing Python path}"
      shift 2
      ;;
    --node)
      HOST_NODE="${2:?missing Node path}"
      shift 2
      ;;
    --fixture)
      USE_FIXTURE=1
      shift
      ;;
    --skip-service)
      WITH_SERVICE=0
      shift
      ;;
    --keep-remote)
      KEEP_REMOTE=1
      shift
      ;;
    --service-concurrency)
      SERVICE_CONCURRENCY="${2:?missing service concurrency list}"
      shift 2
      ;;
    --service-requests)
      SERVICE_REQUESTS="${2:?missing service request count}"
      shift 2
      ;;
    --service-warmup)
      SERVICE_WARMUP="${2:?missing service warmup count}"
      shift 2
      ;;
    --service-event-connections)
      SERVICE_EVENT_CONNECTIONS="${2:?missing service event connection list}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      printf 'Unknown argument: %s\n' "$1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

case "${PROFILE}" in
  smoke|standard|stress) ;;
  *)
    printf 'Invalid profile: %s\n' "${PROFILE}" >&2
    exit 2
    ;;
esac

command -v limactl >/dev/null 2>&1 || {
  printf 'limactl is required.\n' >&2
  exit 2
}
command -v tar >/dev/null 2>&1 || {
  printf 'tar is required.\n' >&2
  exit 2
}
"${HOST_PYTHON}" --version >/dev/null
if ((WITH_SERVICE)); then
  "${HOST_NODE}" --version >/dev/null
fi

timestamp="$(date +%Y%m%d-%H%M%S)"
if [[ -z "${OUTPUT_DIR}" ]]; then
  OUTPUT_DIR="${REPO_ROOT}/benchmark-results/mac-lima-${timestamp}-${PROFILE}"
fi
if [[ -e "${OUTPUT_DIR}" ]]; then
  if [[ ! -d "${OUTPUT_DIR}" ]]; then
    printf 'Output path exists but is not a directory: %s\n' "${OUTPUT_DIR}" >&2
    exit 2
  fi
  shopt -s nullglob dotglob
  output_entries=("${OUTPUT_DIR}"/*)
  shopt -u nullglob dotglob
  if ((${#output_entries[@]} != 0)); then
    printf 'Output directory must be new or empty: %s\n' "${OUTPUT_DIR}" >&2
    exit 2
  fi
  unset output_entries
else
  mkdir -p -- "${OUTPUT_DIR}"
fi
OUTPUT_DIR="$(cd -- "${OUTPUT_DIR}" && pwd -P)"

# 把编排层失败物化为标准 child summary；输入阶段名/退出码/原因，幂等写入失败 JSON。
# 这样即使真正 benchmark 没启动、没复制回来或谎报 passed，根报告仍保留 failed 证据。
record_orchestration_failure() {
  local stage=$1
  local stage_rc=$2
  local reason=$3
  local summary_path="${OUTPUT_DIR}/orchestration/${stage}.json"

  if [[ -f "${summary_path}" ]]; then
    return 0
  fi
  "${HOST_PYTHON}" -c \
    'import datetime,json,os,platform,sys
from pathlib import Path

repo_root=Path(sys.argv[1]).resolve()
output_path=Path(sys.argv[2])
profile,stage,stage_rc,reason=sys.argv[3],sys.argv[4],int(sys.argv[5]),sys.argv[6]
sys.path.insert(0,str(repo_root/"benchmarks"))
from run_stress_suite import collect_source_identity
identity=collect_source_identity(repo_root)
payload={
    "schema_version":"weaknet.benchmark.v1",
    "component":f"orchestration-{stage}",
    "profile":profile,
    "environment":{
        "system":platform.system(), "release":platform.release(),
        "machine":platform.machine(), "cpu_count":os.cpu_count(),
        "source_identity":identity,
    },
    "started_at":datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "duration_ms":0.0,
    "benchmarks":[{
        "name":stage, "status":"failed", "exit_code":stage_rc,
        "error_count":1, "orchestration_failure":True, "reason":reason,
    }],
    "summary":{
        "status":"failed", "passed":0, "failed":1, "skipped":0,
        "errors":1, "correctness_gate_passed":False,
        "orchestration_failure":True, "reason":reason,
    },
    "baseline_path":None, "performance_regressions":[],
}
output_path.parent.mkdir(parents=True,exist_ok=True)
temporary=output_path.with_suffix(output_path.suffix+".tmp")
temporary.write_text(json.dumps(payload,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
os.replace(temporary,output_path)' \
    "${REPO_ROOT}" "${summary_path}" "${PROFILE}" "${stage}" "${stage_rc}" "${reason}"
}

remote_root="/tmp/weaknet-benchmark-${timestamp}-$$"
remote_archive="${remote_root}.tar.gz"
remote_output="${remote_root}-results"
local_archive="$(mktemp -t weaknet-benchmark-src.XXXXXX.tar.gz)"
dashboard_pid=""
dashboard_group_ready=0
server_started=0
grpc_port=""
dashboard_port=""

# 唯一 EXIT 清理入口：保留原退出码，收敛宿主 Dashboard/RAG 子进程、来宾 server 与临时文件。
cleanup() {
  local exit_code=$?
  # INT/TERM 通过 exit 进入唯一的 EXIT cleanup；先移除 traps，避免 cleanup 内再次递归。
  trap - EXIT INT TERM
  set +e
  if [[ -n "${dashboard_pid}" ]]; then
    if ((dashboard_group_ready)); then
      # Dashboard 与它为 /api/analyze 创建的 Python bridge 位于同一独立进程组。
      /bin/kill -TERM -- "-${dashboard_pid}" >/dev/null 2>&1 || true
      for ((attempt = 0; attempt < 50; ++attempt)); do
        /bin/kill -0 -- "-${dashboard_pid}" >/dev/null 2>&1 || break
        sleep 0.1
      done
      /bin/kill -KILL -- "-${dashboard_pid}" >/dev/null 2>&1 || true
    else
      kill "${dashboard_pid}" >/dev/null 2>&1 || true
    fi
    wait "${dashboard_pid}" >/dev/null 2>&1 || true
  fi
  if ((server_started)); then
    # server 由 setsid 启动，PID 同时是 PGID。只杀命令行匹配的本次进程组，规避 PID 复用。
    limactl shell "${VM_NAME}" -- sudo sh -c '
      root=$1
      pid_file=$root/server.pid
      test -f "$pid_file" || exit 0
      pid=$(sed -n "1p" "$pid_file")
      case "$pid" in ""|*[!0-9]*) exit 0 ;; esac
      test "$pid" -gt 1 || exit 0
      test -r "/proc/$pid/cmdline" || exit 0
      command_line=$(tr "\000" " " < "/proc/$pid/cmdline")
      case "$command_line" in *weaknet-grpc-server*) ;; *) exit 0 ;; esac
      pgid=$(ps -o pgid= -p "$pid" 2>/dev/null | tr -d "[:space:]")
      test "$pgid" = "$pid" || exit 0
      # Ubuntu /bin/sh(dash) 的 kill builtin 不接受 `-- -PGID`，会静默留下 server。
      # 显式调用 coreutils /bin/kill，确保负数参数按进程组解释。
      /bin/kill -TERM -- "-$pgid" >/dev/null 2>&1 || true
      count=0
      while /bin/kill -0 -- "-$pgid" >/dev/null 2>&1 && test "$count" -lt 50; do
        sleep 0.1
        count=$((count + 1))
      done
      /bin/kill -KILL -- "-$pgid" >/dev/null 2>&1 || true
    ' sh "${remote_root}" \
      >/dev/null 2>&1 || true
  fi
  rm -f -- "${local_archive}"
  # 默认删除 guest 快照/产物，--keep-remote 只用于人工诊断；宿主持久报告不受此开关影响。
  if ((!KEEP_REMOTE)); then
    limactl shell "${VM_NAME}" -- rm -rf -- "${remote_root}" "${remote_archive}" "${remote_output}" \
      >/dev/null 2>&1 || true
  fi
  exit "${exit_code}"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# 让 macOS 内核临时分配空闲 localhost 端口并返回端口号；socket 随 Python 退出释放。
allocate_host_port() {
  "${HOST_PYTHON}" -c \
    'import socket
s=socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()'
}

# gRPC 端口需同时在 host 与 VM 可用；返回首个两端均可 bind 的候选，最多尝试 20 次。
allocate_shared_port() {
  local candidate
  local attempt
  for ((attempt = 0; attempt < 20; ++attempt)); do
    candidate="$(allocate_host_port)"
    if limactl shell "${VM_NAME}" -- python3 -c \
      'import socket,sys
s=socket.socket()
s.bind(("0.0.0.0", int(sys.argv[1])))
s.close()' \
      "${candidate}" >/dev/null 2>&1; then
      printf '%s\n' "${candidate}"
      return 0
    fi
  done
  return 1
}

# 校验 guest 中本次 server：PID 存活、命令匹配且 PID==PGID；成功返回 0，否则返回非 0。
remote_server_alive() {
  limactl shell "${VM_NAME}" -- sudo sh -c '
    root=$1
    pid_file=$root/server.pid
    test -f "$pid_file" || exit 1
    pid=$(sed -n "1p" "$pid_file")
    case "$pid" in ""|*[!0-9]*) exit 1 ;; esac
    test "$pid" -gt 1 || exit 1
    kill -0 "$pid" 2>/dev/null || exit 1
    test -r "/proc/$pid/cmdline" || exit 1
    command_line=$(tr "\000" " " < "/proc/$pid/cmdline")
    case "$command_line" in *weaknet-grpc-server*) ;; *) exit 1 ;; esac
    pgid=$(ps -o pgid= -p "$pid" 2>/dev/null | tr -d "[:space:]")
    test "$pgid" = "$pid"
  ' sh "${remote_root}" >/dev/null 2>&1
}

# 从 macOS 探测 Lima 转发后的 localhost TCP 端口；输入端口，连接成功返回 0。
host_tcp_ready() {
  "${HOST_PYTHON}" -c \
    'import socket,sys
try:
    with socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=.5):
        pass
except OSError:
    raise SystemExit(1)' \
    "$1"
}

# 从宿主调用 Dashboard /api/status；只有 HTTP 200、JSON object 且 ok=true 才认为 ready。
dashboard_http_ready() {
  "${HOST_PYTHON}" -c \
    'import json,sys,urllib.request
try:
    with urllib.request.urlopen("http://127.0.0.1:%s/api/status" % sys.argv[1], timeout=2) as response:
        payload=json.load(response)
        raise SystemExit(0 if response.status == 200 and isinstance(payload, dict) and payload.get("ok") is True else 1)
except Exception:
    raise SystemExit(1)' \
    "$1"
}

# 先确认指定 VM 处于 Running；不可用时仍写 orchestration failure，后续可继续生成总报告。
vm_ready=1
if ! limactl list --json | "${HOST_PYTHON}" -c \
  'import json,sys; wanted=sys.argv[1]; raise SystemExit(0 if any(json.loads(line).get("name")==wanted and json.loads(line).get("status")=="Running" for line in sys.stdin if line.strip()) else 1)' \
  "${VM_NAME}"; then
  printf 'Lima VM %s is not running. Start it first with: limactl start %s\n' "${VM_NAME}" "${VM_NAME}" >&2
  record_orchestration_failure \
    "lima-vm-ready" 2 "Lima VM ${VM_NAME} is not running"
  vm_ready=0
fi

printf '[1/5] Creating clean source snapshot...\n'
remote_setup_ok=${vm_ready}
set +e
# host 快照排除构建物、node_modules 和历史结果；复制 dirty worktree 的真实字节而非 Git HEAD。
COPYFILE_DISABLE=1 tar \
    --no-xattrs \
    --exclude='./.git' \
    --exclude='./benchmark-results' \
    --exclude='./dashboard/node_modules' \
    --exclude='./dashboard/dist' \
    --exclude='./server/build' \
    --exclude='./server/bin' \
    --exclude='*/__pycache__' \
    --exclude='*.pyc' \
    -czf "${local_archive}" \
    -C "${REPO_ROOT}" .
source_snapshot_rc=$?
set -e
if ((source_snapshot_rc != 0)); then
  printf 'Local source snapshot failed; Linux/service stages cannot run.\n' >&2
  record_orchestration_failure \
    "source-snapshot" "${source_snapshot_rc}" \
    "local source snapshot command exited non-zero (rc=${source_snapshot_rc})"
  remote_setup_ok=0
fi

printf '[2/5] Copying snapshot into Lima VM %s...\n' "${VM_NAME}"
if ((remote_setup_ok)); then
  set +e
  limactl copy "${local_archive}" "${VM_NAME}:${remote_archive}"
  source_copy_rc=$?
  set -e
  if ((source_copy_rc != 0)); then
    printf 'Source snapshot copy into Lima failed.\n' >&2
    record_orchestration_failure \
      "source-copy" "${source_copy_rc}" \
      "limactl source snapshot copy exited non-zero (rc=${source_copy_rc})"
    remote_setup_ok=0
  fi
fi
if ((remote_setup_ok)); then
  set +e
  limactl shell "${VM_NAME}" -- bash -c '
    set -eu
    mkdir -p -- "$1" "$2"
    tar -xzf "$3" -C "$1"
  ' bash "${remote_root}" "${remote_output}" "${remote_archive}"
  source_extract_rc=$?
  set -e
  if ((source_extract_rc != 0)); then
    printf 'Source snapshot extraction inside Lima failed.\n' >&2
    record_orchestration_failure \
      "source-extract" "${source_extract_rc}" \
      "guest source snapshot extraction exited non-zero (rc=${source_extract_rc})"
    remote_setup_ok=0
  fi
fi

# snapshot 可能携带 host/x86 vmlinux.h；任何 guest BPF build 前必须从当前 Linux BTF 原子重建，
# 否则会用错误架构的内核类型编译，产生难以解释的 verifier/运行时失败。
if ((remote_setup_ok)); then
  set +e
  limactl shell "${VM_NAME}" -- bash -c '
    set -eu
    root=$1
    cd -- "$root"
    command -v bpftool >/dev/null 2>&1
    test -r /sys/kernel/btf/vmlinux
    temporary="$root/server/vmlinux.h.tmp.$$"
    cleanup_vmlinux() { rm -f -- "$temporary"; }
    trap cleanup_vmlinux EXIT
    bpftool btf dump file /sys/kernel/btf/vmlinux format c > "$temporary"
    test -s "$temporary"
    case "$(uname -m)" in
      aarch64|arm64) grep -q "struct user_pt_regs {" "$temporary" ;;
    esac
    mv -f -- "$temporary" "$root/server/vmlinux.h"
    trap - EXIT
  ' bash "${remote_root}"
  guest_btf_rc=$?
  set -e
  if ((guest_btf_rc != 0)); then
    printf 'Guest vmlinux.h regeneration failed.\n' >&2
    record_orchestration_failure \
      "guest-btf-ready" "${guest_btf_rc}" \
      "guest BTF/vmlinux.h regeneration exited non-zero (rc=${guest_btf_rc})"
    remote_setup_ok=0
  fi
fi

# kernel 压测需要更高权限和时长，因此 smoke 只跑用户态/BPF map，standard/stress 再加入 kernel。
linux_components="core,sanitizer,bpf"
if [[ "${PROFILE}" != "smoke" ]]; then
  linux_components="core,sanitizer,bpf,kernel"
fi

printf '[3/5] Running Linux %s benchmarks (%s)...\n' "${PROFILE}" "${linux_components}"
linux_rc=0
linux_copy_rc=0
if ((remote_setup_ok)); then
  set +e
  limactl shell "${VM_NAME}" -- bash -c '
    set -eu
    cd -- "$1"
    exec python3 benchmarks/run_stress_suite.py \
      --profile "$2" --components "$3" --sudo-linux --strict --output-dir "$4"
  ' bash "${remote_root}" "${PROFILE}" "${linux_components}" "${remote_output}/linux"
  linux_rc=$?
  set -e
  if ((linux_rc != 0)); then
    record_orchestration_failure \
      "linux-run" "${linux_rc}" "Linux benchmark command exited non-zero (rc=${linux_rc})"
  fi

  set +e
  # limactl/scp 复制目录到同名目标会形成 linux/linux；复制到已存在 parent 才得到 linux/summary.json。
  limactl copy "${VM_NAME}:${remote_output}/linux" "${OUTPUT_DIR}"
  linux_copy_rc=$?
  set -e
  if ((linux_copy_rc != 0)); then
    printf 'Linux report copy failed (rc=%s); continuing with macOS/service/merge.\n' \
      "${linux_copy_rc}" >&2
    record_orchestration_failure \
      "linux-report-copy" "${linux_copy_rc}" \
      "Linux report copy exited non-zero (rc=${linux_copy_rc})"
  fi
else
  linux_rc=2
  linux_copy_rc=2
  record_orchestration_failure \
    "linux-run" 2 "Linux benchmark command was not run because remote setup failed"
  record_orchestration_failure \
    "linux-report-copy" 2 "Linux report was not copied because remote setup failed"
fi
if [[ ! -f "${OUTPUT_DIR}/linux/summary.json" ]]; then
  record_orchestration_failure \
    "linux-summary" 2 "requested Linux stage did not produce a host-side summary.json"
fi

printf '[4/5] Running macOS core/RAG benchmarks...\n'
# 默认用离线冻结 RAG artifact，--fixture 才切到纯 fixture；两者都在宿主运行以覆盖真实 Dashboard 环境。
rag_mode=(--offline-artifact)
if ((USE_FIXTURE)); then
  rag_mode=(--fixture)
fi
set +e
"${HOST_PYTHON}" "${REPO_ROOT}/benchmarks/run_stress_suite.py" \
  --profile "${PROFILE}" \
  --components contracts,core,rag \
  --python "${HOST_PYTHON}" \
  --node "${HOST_NODE}" \
  --strict \
  --output-dir "${OUTPUT_DIR}/mac" \
  "${rag_mode[@]}"
mac_rc=$?
set -e
if ((mac_rc != 0)); then
  record_orchestration_failure \
    "mac-run" "${mac_rc}" "macOS benchmark command exited non-zero (rc=${mac_rc})"
fi
if [[ ! -f "${OUTPUT_DIR}/mac/summary.json" ]]; then
  record_orchestration_failure \
    "mac-summary" 2 "requested macOS stage did not produce summary.json"
fi

service_rc=0
if ((WITH_SERVICE)); then
  printf '[5/5] Starting Linux server and host Dashboard for live service pressure...\n'
  service_build_ok=0
  server_ready=0
  dashboard_ready=0
  service_run_attempted=0
  if ((remote_setup_ok)); then
    set +e
    limactl shell "${VM_NAME}" -- bash -c '
      set -eu
      cd -- "$1"
      make -j2
    ' bash "${remote_root}"
    service_build_rc=$?
    set -e
    if ((service_build_rc == 0)); then
      service_build_ok=1
    else
      printf 'Remote server build failed; service pressure will be reported as failed.\n' >&2
      service_rc=2
      record_orchestration_failure \
        "service-build" "${service_build_rc}" \
        "remote service build exited non-zero (rc=${service_build_rc})"
    fi
  else
    service_rc=2
    record_orchestration_failure \
      "service-build" 2 "remote service build was not run because remote setup failed"
  fi

  if ((service_build_ok)); then
    if ! grpc_port="$(allocate_shared_port)"; then
      printf 'Could not allocate a free gRPC port on both host and VM.\n' >&2
      service_rc=2
      record_orchestration_failure \
        "service-port-ready" 2 "could not allocate a port available on both host and VM"
    else
      while :; do
        dashboard_port="$(allocate_host_port)"
        [[ "${dashboard_port}" != "${grpc_port}" ]] && break
      done
      printf 'Using run-scoped ports: gRPC=%s Dashboard=%s\n' "${grpc_port}" "${dashboard_port}"

      # make 已同步成功；guest 用 sudo+setsid 单独启动 server，本次 $! 必须同时是 PID/PGID，
      # 从而 cleanup 不会误杀 VM 内其他同名服务。
      server_started=1
      if ! limactl shell "${VM_NAME}" -- sudo sh -c '
        set -eu
        root=$1
        port=$2
        cd "$root"
        command -v setsid >/dev/null 2>&1
        rm -f -- "$root/server.pid"
        : > "$root/server.log"
        nohup setsid env WEAKNET_GRPC_ADDRESS="0.0.0.0:$port" \
          ./server/bin/weaknet-grpc-server \
          > "$root/server.log" 2>&1 < /dev/null &
        pid=$!
        echo "$pid" > "$root/server.pid"
        kill -0 "$pid"
        pgid=$(ps -o pgid= -p "$pid" | tr -d "[:space:]")
        test "$pgid" = "$pid"
      ' sh "${remote_root}" "${grpc_port}"; then
        printf 'Linux server launch failed before PID/PGID validation.\n' >&2
        service_rc=2
        record_orchestration_failure \
          "service-server-launch" 2 "Linux server launch/PID/PGID validation failed"
      else
        # Lima 将 guest listener 转发至 host localhost；只有“当前 guest PID 仍存活 + host 可连”
        # 同时成立才算 ready，避免误连端口复用后的其他进程。
        server_ready=0
        for ((attempt = 0; attempt < 90; ++attempt)); do
          if ! remote_server_alive; then
            break
          fi
          if host_tcp_ready "${grpc_port}" && remote_server_alive; then
            server_ready=1
            break
          fi
          sleep 0.5
        done

        if ((!server_ready)); then
          printf 'Current remote server PID did not become ready on 127.0.0.1:%s.\n' \
            "${grpc_port}" >&2
          limactl copy "${VM_NAME}:${remote_root}/server.log" \
            "${OUTPUT_DIR}/linux-server.log" || true
          service_rc=2
          record_orchestration_failure \
            "service-server-ready" 2 \
            "current remote server PID did not become reachable through Lima forwarding"
        else
          # Dashboard 在 host 运行并访问 Lima 转发的 gRPC；Python wrapper 先 setsid 再 exec Node，
          # PID 保持不变且成为 PGID，异常退出时可连同未结束的 RAG bridge 子进程一起收敛。
          env \
            WEAKNET_GRPC_ADDRESS="127.0.0.1:${grpc_port}" \
            DASHBOARD_API_PORT="${dashboard_port}" \
            DASHBOARD_PING_TARGETS=127.0.0.1 \
            WEAKNET_RAG_PYTHON="${HOST_PYTHON}" \
            "${HOST_PYTHON}" -c \
              'import os, sys; os.setsid(); os.execvpe(sys.argv[1], sys.argv[1:], os.environ)' \
            "${HOST_NODE}" "${REPO_ROOT}/dashboard/server/index.mjs" \
            >"${OUTPUT_DIR}/dashboard.log" 2>&1 &
          dashboard_pid=$!

          # setsid 与父 shell 并发发生；只在确认 PID==PGID 后启用进程组 cleanup。
          for ((attempt = 0; attempt < 40; ++attempt)); do
            dashboard_pgid="$(ps -o pgid= -p "${dashboard_pid}" 2>/dev/null | tr -d '[:space:]')"
            if [[ "${dashboard_pgid}" == "${dashboard_pid}" ]]; then
              dashboard_group_ready=1
              break
            fi
            kill -0 "${dashboard_pid}" >/dev/null 2>&1 || break
            sleep 0.05
          done
          if ((!dashboard_group_ready)); then
            printf 'Dashboard failed PID/PGID isolation; refusing to run live pressure.\n' >&2
            service_rc=2
            record_orchestration_failure \
              "service-dashboard-process-ready" 2 \
              "Dashboard failed PID/PGID isolation"
          fi

          dashboard_ready=0
          for ((attempt = 0; dashboard_group_ready && attempt < 60; ++attempt)); do
            if ! kill -0 "${dashboard_pid}" >/dev/null 2>&1; then
              break
            fi
            if dashboard_http_ready "${dashboard_port}"; then
              dashboard_ready=1
              break
            fi
            sleep 0.5
          done

          if ((!dashboard_ready)); then
            printf 'Dashboard PID did not become ready on 127.0.0.1:%s; see %s/dashboard.log.\n' \
              "${dashboard_port}" "${OUTPUT_DIR}" >&2
            service_rc=2
            record_orchestration_failure \
              "service-dashboard-ready" 2 \
              "Dashboard /api/status did not return HTTP 200 JSON ok=true"
          else
            # live Dashboard analyze 每次会启动独立 Python 诊断进程；允许显式收窄并发、请求、
            # warmup 和事件连接矩阵，避免默认 stress 档无意制造过量子进程，同时保留真实端点验证。
            service_load_args=()
            if [[ -n "${SERVICE_CONCURRENCY}" ]]; then
              service_load_args+=(--concurrency "${SERVICE_CONCURRENCY}")
            fi
            if [[ -n "${SERVICE_REQUESTS}" ]]; then
              service_load_args+=(--requests "${SERVICE_REQUESTS}")
            fi
            if [[ -n "${SERVICE_WARMUP}" ]]; then
              service_load_args+=(--warmup "${SERVICE_WARMUP}")
            fi
            if [[ -n "${SERVICE_EVENT_CONNECTIONS}" ]]; then
              service_load_args+=(--event-connections "${SERVICE_EVENT_CONNECTIONS}")
            fi
            service_run_attempted=1
            set +e
            "${HOST_PYTHON}" "${REPO_ROOT}/benchmarks/run_stress_suite.py" \
              --profile "${PROFILE}" \
              --components service \
              --python "${HOST_PYTHON}" \
              --node "${HOST_NODE}" \
              --grpc-address "127.0.0.1:${grpc_port}" \
              --dashboard-url "http://127.0.0.1:${dashboard_port}" \
              --events \
              --strict \
              --output-dir "${OUTPUT_DIR}/service" \
              "${service_load_args[@]}"
            service_rc=$?
            set -e
            if ((service_rc != 0)); then
              record_orchestration_failure \
                "service-run" "${service_rc}" \
                "live service benchmark command exited non-zero (rc=${service_rc})"
            fi
          fi
        fi
      fi
    fi
  fi
  if ((!server_ready)); then
    record_orchestration_failure \
      "service-server-ready" 2 "requested live service stage never reached server-ready state"
  fi
  if ((!dashboard_ready)); then
    record_orchestration_failure \
      "service-dashboard-ready" 2 "requested live service stage never reached Dashboard-ready state"
  fi
  if ((!service_run_attempted)); then
    record_orchestration_failure \
      "service-run" 2 "live service benchmark command was not run"
  fi
  if [[ ! -f "${OUTPUT_DIR}/service/summary.json" ]]; then
    record_orchestration_failure \
      "service-summary" 2 "requested live service stage did not produce summary.json"
  fi
else
  printf '[5/5] Live service pressure skipped by request.\n'
fi

# 只合并实际存在的套件 summary 和所有编排失败 JSON；缺失阶段已在上方显式补失败证据。
summary_paths=()
for summary_path in \
  "${OUTPUT_DIR}/linux/summary.json" \
  "${OUTPUT_DIR}/mac/summary.json" \
  "${OUTPUT_DIR}/service/summary.json"; do
  if [[ -f "${summary_path}" ]]; then
    summary_paths+=("${summary_path}")
  fi
done
shopt -s nullglob
orchestration_paths=("${OUTPUT_DIR}/orchestration/"*.json)
shopt -u nullglob
for summary_path in "${orchestration_paths[@]}"; do
  summary_paths+=("${summary_path}")
done
if ((${#summary_paths[@]} == 0)); then
  printf 'No suite summary was available for report merge.\n' >&2
  merge_rc=2
else
  set +e
  "${HOST_PYTHON}" "${REPO_ROOT}/benchmarks/merge_stress_reports.py" \
    --profile "${PROFILE}" \
    --output-dir "${OUTPUT_DIR}" \
    "${summary_paths[@]}"
  merge_rc=$?
  set -e
fi

printf 'Reports: %s\n' "${OUTPUT_DIR}"
if ((linux_rc != 0 || linux_copy_rc != 0 || mac_rc != 0 || service_rc != 0 || merge_rc != 0)); then
  printf 'One or more suites failed: linux=%s linux_copy=%s mac=%s service=%s merge=%s\n' \
    "${linux_rc}" "${linux_copy_rc}" "${mac_rc}" "${service_rc}" "${merge_rc}" >&2
  exit 2
fi
printf 'All requested suites passed.\n'
