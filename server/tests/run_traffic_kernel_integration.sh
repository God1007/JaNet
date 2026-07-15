#!/usr/bin/env bash
# 在隔离 network namespaces 中运行真实 TC/eBPF LRU 压力验收；必须由 root 在 Linux 执行。
# 脚本负责环境门禁、veth 拓扑、peer 服务和失败后的幂等清理；C++ 驱动负责业务断言与计时。
set -euo pipefail

mode="${1:-pressure}"
if [[ "${mode}" != "pressure" && "${mode}" != "--tc-ownership" ]]; then
  echo "ERROR: usage: $0 [--tc-ownership]" >&2
  exit 2
fi
test_name="test-traffic-kernel"
if [[ "${mode}" == "--tc-ownership" ]]; then test_name="test-tc-ownership"; fi

# macOS 没有 Linux netns/TC/eBPF map，明确 SKIP，不能以本机模拟结果替代内核验收。
if [[ "$(uname -s)" != "Linux" ]]; then
  echo "SKIP: ${test_name} requires Linux network namespaces and TC/eBPF"
  exit 0
fi
# 创建 namespace、装载 TC 和枚举 BPF map 都需要 root；缺权限直接失败而非部分执行。
if [[ "${EUID}" -ne 0 ]]; then
  echo "ERROR: ${test_name} requires root (run: sudo make -C server ${test_name})" >&2
  exit 2
fi
# ip 创建隔离拓扑，python3 提供轻量 UDP/TCP peer，两者都是测试协议的必要依赖。
required_commands=(ip python3)
if [[ "${mode}" == "--tc-ownership" ]]; then required_commands+=(tc); fi
for command in "${required_commands[@]}"; do
  command -v "${command}" >/dev/null 2>&1 || {
    echo "ERROR: missing required command: ${command}" >&2
    exit 2
  }
done

suffix="$$"
client_ns="weaknet-client-${suffix}"
peer_ns="weaknet-peer-${suffix}"
peer_pid=""
probe_pid=""
test_tmp=""
ownership_lock_file=""
# 无论正常退出、断言失败还是收到信号，都杀掉 peer 并删除两端 namespace；
# 删除 namespace 会连带回收 veth、TC attachment 和其中的网络资源，避免污染下一轮。
cleanup() {
  if [[ -n "${probe_pid}" ]]; then kill "${probe_pid}" >/dev/null 2>&1 || true; fi
  if [[ -n "${peer_pid}" ]]; then kill "${peer_pid}" >/dev/null 2>&1 || true; fi
  ip netns del "${client_ns}" >/dev/null 2>&1 || true
  ip netns del "${peer_ns}" >/dev/null 2>&1 || true
  if [[ -n "${ownership_lock_file}" ]]; then rm -f "${ownership_lock_file}"; fi
  if [[ -n "${test_tmp}" ]]; then rm -rf "${test_tmp}"; fi
}
trap cleanup EXIT INT TERM

# 建立 client/peer 两个完全隔离的 network namespace，用一对 veth 提供唯一流量路径。
ip netns add "${client_ns}"
ip netns add "${peer_ns}"
ip link add wnc0 type veth peer name wnp0
ip link set wnc0 netns "${client_ns}"
ip link set wnp0 netns "${peer_ns}"
ip -n "${client_ns}" link set lo up
ip -n "${peer_ns}" link set lo up
ip -n "${client_ns}" addr add 10.203.0.1/24 dev wnc0
ip -n "${peer_ns}" addr add 10.203.0.2/24 dev wnp0
ip -n "${client_ns}" link set wnc0 up
ip -n "${peer_ns}" link set wnp0 up

server_dir="$(pwd)"

# 返回固定 pref=1/handle=1 槽中的 BPF prog_id；空槽返回空字符串。
tc_program_id() {
  local direction="$1"
  ip netns exec "${client_ns}" tc -j filter show dev wnc0 "${direction}" | python3 -c '
import json, sys
for item in json.load(sys.stdin):
    options = item.get("options", {})
    program = options.get("prog", {})
    program_id = program.get("id", options.get("id"))
    if item.get("kind") == "bpf" and program_id is not None:
        print(program_id)
        break
'
}

tc_test_fail() {
  echo "tc_ownership_integration: FAIL: $*" >&2
  exit 1
}

assert_quiet_tc_attach() {
  local log="$1"
  if grep -Eq 'Exclusivity flag on|Filter already exists|Cannot find specified filter chain' "${log}"; then
    sed -n '1,160p' "${log}" >&2
    tc_test_fail "unsafe TC attach warning leaked to stderr"
  fi
}

reset_clsact() {
  ip netns exec "${client_ns}" tc qdisc del dev wnc0 clsact >/dev/null 2>&1 || true
  ip netns exec "${client_ns}" tc qdisc add dev wnc0 clsact
  # 显式创建两个空 chain，让“槽位为空”和“chain 不存在”成为两个可区分的内核状态。
  ip netns exec "${client_ns}" tc chain add dev wnc0 ingress chain 0
  ip netns exec "${client_ns}" tc chain add dev wnc0 egress chain 0
}

# 启动 expect-tc 探针并等到 TC 状态已提交；调用方随后可安全检查或外部替换槽位。
start_hold_probe() {
  local scenario="$1"
  probe_ready="${test_tmp}/${scenario}.ready"
  probe_release="${test_tmp}/${scenario}.release"
  probe_log="${test_tmp}/${scenario}.log"
  rm -f "${probe_ready}" "${probe_release}" "${probe_log}"
  ip netns exec "${client_ns}" \
    "${server_dir}/build/traffic_kernel_integration" \
    --tc-ownership-probe wnc0 "${server_dir}/build/flow_rate.bpf.o" \
    expect-tc "${probe_ready}" "${probe_release}" >"${probe_log}" 2>&1 &
  probe_pid="$!"
  for _ in $(seq 1 200); do
    if [[ -s "${probe_ready}" ]]; then return 0; fi
    if ! kill -0 "${probe_pid}" >/dev/null 2>&1; then
      wait "${probe_pid}" >/dev/null 2>&1 || true
      probe_pid=""
      sed -n '1,160p' "${probe_log}" >&2
      tc_test_fail "${scenario} probe exited before ready"
    fi
    sleep 0.05
  done
  tc_test_fail "${scenario} probe did not become ready"
}

finish_hold_probe() {
  touch "${probe_release}"
  if ! wait "${probe_pid}"; then
    probe_pid=""
    sed -n '1,160p' "${probe_log}" >&2
    tc_test_fail "held probe failed"
  fi
  probe_pid=""
  assert_quiet_tc_attach "${probe_log}"
}

run_tc_ownership_suite() {
  test_tmp="$(mktemp -d /tmp/weaknet-tc-ownership.XXXXXX)"
  local netns_inode ifindex
  netns_inode="$(ip netns exec "${client_ns}" stat -Lc '%i' /proc/self/ns/net)"
  ifindex="$(ip netns exec "${client_ns}" cat /sys/class/net/wnc0/ifindex)"
  ownership_lock_file="/run/weaknet-tc-${netns_inode}-if${ifindex}.lock"

  # A: 两个同 object 遗留槽位必须按 name/tag 安全 REPLACE，且不再触发 libbpf EEXIST 噪声。
  reset_clsact
  ip netns exec "${client_ns}" tc filter add dev wnc0 ingress protocol all pref 1 handle 1 \
    bpf da obj "${server_dir}/build/flow_rate.bpf.o" sec tc/ingress
  ip netns exec "${client_ns}" tc filter add dev wnc0 egress protocol all pref 1 handle 1 \
    bpf da obj "${server_dir}/build/flow_rate.bpf.o" sec tc/egress
  local stale_ingress stale_egress active_ingress active_egress
  stale_ingress="$(tc_program_id ingress)"
  stale_egress="$(tc_program_id egress)"
  [[ -n "${stale_ingress}" && -n "${stale_egress}" ]] || tc_test_fail "A did not seed both stale slots"
  start_hold_probe "same-object-replace"
  active_ingress="$(tc_program_id ingress)"
  active_egress="$(tc_program_id egress)"
  [[ -n "${active_ingress}" && "${active_ingress}" != "${stale_ingress}" ]] ||
    tc_test_fail "A ingress stale program was not replaced"
  [[ -n "${active_egress}" && "${active_egress}" != "${stale_egress}" ]] ||
    tc_test_fail "A egress stale program was not replaced"
  finish_hold_probe
  [[ -z "$(tc_program_id ingress)" && -z "$(tc_program_id egress)" ]] ||
    tc_test_fail "A destructor did not remove its two owned slots"

  # B: egress 故意放 ingress 程序。prepare 必须在第一次写入前拒绝，因此 ingress 仍为空、foreign id 不变。
  reset_clsact
  ip netns exec "${client_ns}" tc filter add dev wnc0 egress protocol all pref 1 handle 1 \
    bpf da obj "${server_dir}/build/flow_rate.bpf.o" sec tc/ingress
  local foreign_egress reject_log
  foreign_egress="$(tc_program_id egress)"
  reject_log="${test_tmp}/foreign-reject.log"
  if ! ip netns exec "${client_ns}" \
      "${server_dir}/build/traffic_kernel_integration" \
      --tc-ownership-probe wnc0 "${server_dir}/build/flow_rate.bpf.o" expect-reject \
      >"${reject_log}" 2>&1; then
    sed -n '1,160p' "${reject_log}" >&2
    tc_test_fail "B foreign-slot probe failed"
  fi
  assert_quiet_tc_attach "${reject_log}"
  [[ -z "$(tc_program_id ingress)" ]] || tc_test_fail "B modified the empty ingress slot"
  [[ "$(tc_program_id egress)" == "${foreign_egress}" ]] || tc_test_fail "B replaced or deleted foreign egress"

  # C: 从连 clsact 都不存在的全新接口启动，再由外部抢占 ingress。析构只删 prog_id
  # 仍匹配的 egress，绝不盲删 foreign ingress；同时锁定首次启动不能被 ownership query 阻断。
  ip netns exec "${client_ns}" tc qdisc del dev wnc0 clsact >/dev/null 2>&1 || true
  start_hold_probe "destructor-race"
  local owned_ingress owned_egress foreign_ingress
  owned_ingress="$(tc_program_id ingress)"
  owned_egress="$(tc_program_id egress)"
  [[ -n "${owned_ingress}" && -n "${owned_egress}" ]] || tc_test_fail "C did not attach both JaNet slots"
  ip netns exec "${client_ns}" tc filter replace dev wnc0 ingress protocol all pref 1 handle 1 \
    bpf da obj "${server_dir}/build/flow_rate.bpf.o" sec tc/egress
  foreign_ingress="$(tc_program_id ingress)"
  [[ -n "${foreign_ingress}" && "${foreign_ingress}" != "${owned_ingress}" ]] ||
    tc_test_fail "C external ingress replacement did not take effect"
  finish_hold_probe
  [[ "$(tc_program_id ingress)" == "${foreign_ingress}" ]] || tc_test_fail "C destructor deleted foreign ingress"
  [[ -z "$(tc_program_id egress)" ]] || tc_test_fail "C destructor retained its owned egress"

  echo "tc_ownership_integration: PASS scenarios=A,B,C"
}

if [[ "${mode}" == "--tc-ownership" ]]; then
  run_tc_ownership_suite
  exit 0
fi

# peer 预绑定 240 个 UDP 目的端口以承接短流矩阵，同时监听 43210 TCP 作为保护流。
# Python 进程保持所有 UDP socket 存活，并持续读取 TCP，直到 C++ 驱动关闭连接。
ip netns exec "${peer_ns}" python3 -c '
import socket
udp = []
for port in range(10000, 10240):
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    u.bind(("10.203.0.2", port))
    udp.append(u)
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("10.203.0.2", 43210))
s.listen(1)
c, _ = s.accept()
while c.recv(65536):
    pass
' &
peer_pid="$!"
# 给后台 listener 一个很短的就绪窗口；C++ 的保护 TCP connect 仍有重试兜底。
sleep 0.3

# benchmark-kernel-pressure 通过环境变量附加统一 profile/output；普通 test-traffic-kernel
# 不设置 output，继续只做 correctness gate，不在源码树制造结果文件。
benchmark_args=()
if [[ -n "${WEAKNET_BENCHMARK_OUTPUT:-}" ]]; then
  benchmark_args+=(
    --profile "${WEAKNET_BENCHMARK_PROFILE:-standard}"
    --output "${WEAKNET_BENCHMARK_OUTPUT}"
  )
fi
# 这些环境变量把 TCP 立即纳入长流保护并缩短 sock_diag 周期，使测试在可控时间内
# 覆盖“晋升 -> LRU 压力下存活 -> close 后移除”的完整生命周期。
ip netns exec "${client_ns}" env \
  WEAKNET_LONG_FLOW_MIN_SEC=0 \
  WEAKNET_LONG_FLOW_LOW_RATE_MIN_SEC=0 \
  WEAKNET_PROTECTED_PORTS=43210 \
  WEAKNET_SOCK_DIAG_INTERVAL_SEC=1 \
  "${server_dir}/build/traffic_kernel_integration" \
  wnc0 10.203.0.2 43210 "${server_dir}/build/flow_rate.bpf.o" \
  "${benchmark_args[@]}"
