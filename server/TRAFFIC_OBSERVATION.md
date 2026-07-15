# Traffic observation implementation notes

This module has one sampling owner. `TrafficAnalyzer::analyzeLoop()` calls
`NetTrafficAnalyzer::refreshSnapshot()` once per interval and publishes a
`shared_ptr<const TrafficSnapshot>`. Totals, Top Flow, anomaly detection and
service state read that same generation; query methods never sleep.

## Shared ABI and maps

`include/flow_abi.h` is included by both `flow_rate.bpf.c` and C++. Its static
assertions lock the exact key/value sizes and important offsets. The loader also
checks map key size, value size and capacity before accepting an object. Layout
changes require a `FLOW_ABI_VERSION` bump.

| Map | Type | Capacity | Purpose |
| --- | --- | ---: | --- |
| `current_sec` | `LRU_HASH` | 65,536 | High-cardinality flow details |
| `protected_policy` | `HASH` | 4,096 | Cookie policy with monotonic TTL |
| `protected_flows` | `HASH` | 4,096 | Non-LRU counters for selected long flows |
| `runtime_config` | `ARRAY` | 1 | ABI version, dynamic ifindex and capture mode |
| `map_stats` | `PERCPU_ARRAY` | 15 | Lookup/insert/failure/event counters |
| `iface_totals` | `PERCPU_HASH` | 512 | Interface/family/protocol/direction totals |
| `flow_events` | `RINGBUF` | 256 KiB | Rate-limited lifecycle/failure events |

`TrafficSnapshot::mapObservability` exposes both capacities, current entry
counts, disappeared entries, continuity losses, counter resets and the raw
per-CPU kernel counters. Map enumeration is deduplicated and syscall-bounded;
`mapReadComplete=false` plus lookup/restart/error diagnostics prevents a
high-churn partial walk from being published as a trustworthy low/zero sample.

## Counter continuity

An LRU value is an accumulated counter only for the lifetime of that map entry.
The sampler compares `first_seen_ns`, generation and monotonic values. If an
entry was recreated or its counters decreased, the delta is the current value,
not unsigned subtraction. The flow and snapshot then expose
`continuityLost/counterReset`, and a low-frequency event is published.

The first sample after startup or an ifindex change is `baselineOnly=true` and
`RealTimeStats::valid=false`. Switching A -> B -> A clears flow/interface
baselines and anomaly history under the same sampler lock used by refresh. The
old TC/kprobe writers are detached before maps are cleared, so an old interface
cannot race to reinsert keys. History keys also include ifindex, and a
`continuityLost` sample is never fed into the normal-rate baseline.

Sock-diag and `/proc` ownership calibration runs before the map read. The
published monotonic/wall-clock boundary is the midpoint of the actual bounded
map-read interval, so a slow process scan cannot shorten the elapsed time while
its bytes are included in the counter delta.

## Long-flow protection

The 30-second `NETLINK_SOCK_DIAG` reconciliation inspects established IPv4 and
IPv6 TCP sockets. It maintains observed duration, resolves inode ownership via
`/proc/<tgid>/fd`, and reads `comm` and cgroup paths on a best-effort basis.
Protection always requires a duration threshold and then one or more of:

- configured local/remote port;
- configured process-name fragment;
- configured cgroup-path fragment;
- a much longer low-rate connection.

Port 22 is therefore only one default signal. A matching cookie is written to
`protected_policy`; subsequent packets use the non-LRU `protected_flows` map.
Promotion deletes the stale LRU generation. Demotion or socket close deletes
both policy and protected values and emits `PROTECTED_DEMOTED` or
`PROTECTED_CLOSED`.

IPv4 and IPv6 installed-policy sets are reconciled independently. If one
sock-diag family fails, that family's policy/duration/owner state is retained;
only successfully queried families can produce negative close/demotion
evidence.

Runtime policy overrides:

```text
WEAKNET_LONG_FLOW_MIN_SEC=300
WEAKNET_LONG_FLOW_LOW_RATE_MIN_SEC=900
WEAKNET_LONG_FLOW_LOW_RATE_BPS=65536
WEAKNET_PROTECTED_PORTS=22,2022
WEAKNET_PROTECTED_COMMS=ssh,sshd,mosh,git,build-tunnel
WEAKNET_PROTECTED_CGROUPS=critical-build,release-runner
```

## Capture and degradation truth

The preferred path is TC ingress plus egress. It covers IPv4/IPv6 base headers,
TCP/UDP, both directions and a dynamically selected ifindex. If either TC
attachment fails, both TC programs are detached and the collector explicitly
falls back to send-path kprobes.

The support object distinguishes unavailable, partial and full capability. It
does not treat zero traffic as proof that collection worked.

- The parser does not walk IPv6 extension headers; these packets increment
  `FLOW_STAT_PARSE_FAILURE`.
- A TC ingress skb can precede socket association, so its cookie may be zero.
- The kprobe fallback is egress-only. Unbound UDP has no trustworthy ifindex
  and is rejected when an interface filter is active. It is always
  `captureCompleteness=partial`, even when both kprobes attach, and therefore
  never makes `RealTimeStats::valid` or gRPC metric availability true.
- Sock-diag IPv4 and IPv6 availability are separate fields. Partial success is
  reported as partial, and a later full result clears the stale degraded state.
- Connection duration means “observed since this daemon saw the cookie”, not
  kernel socket creation time.
- `/proc` ownership is permission-dependent. TGID, comm and cgroup path are
  best effort; a numeric socket cgroup ID is not supplied by sock_diag.
- Real eBPF load/attach needs a Linux kernel with BTF plus suitable BPF and
  network-admin privileges. The macOS build only exercises portable logic and
  explicit degraded behavior.

## Event channel

The kernel ring buffer only receives protected promotion and true map insertion
failure. A per-CPU one-second limiter prevents failure storms from flooding the
channel. Ordinary packets never emit ring-buffer events. Counter reset,
continuity loss, sock-diag degradation, policy demotion and socket close are
added by the central user-space reconciliation/sampling pass.

## Verification

Portable tests (no libbpf, root or Linux required):

```bash
make -C server test-traffic-core
```

This covers ABI layout, safe counter deltas, reappearance/reset, a portable
container model of protected-vs-LRU behavior, promotion/demotion semantics,
family-partial reconciliation, map-read time boundaries, policy signals,
A -> B -> A baseline reset, immutable generations, non-blocking queries and
source contracts. It is not a kernel pressure test.

Linux compile gates:

```bash
make -C server check-bpf-syntax
make -B -C server check-bpf-object
make -C server check-traffic-userspace
make -C server test-traffic-linux
```

`check-bpf-object` rejects the tracked legacy object unless the rebuilt ELF has
both TC sections and all new map symbols. A target Linux host must additionally
run the server and verify the actual attachment/permissions:

```bash
sudo tc filter show dev "$IFACE" ingress
sudo tc filter show dev "$IFACE" egress
sudo bpftool map show
ss -tinp
```

Actual privileged kernel pressure acceptance (Linux only):

```bash
sudo make -C server test-traffic-kernel
```

This target creates two temporary network namespaces and a veth pair, attaches
the rebuilt TC object, keeps a policy-matched low-rate TCP connection alive,
generates 72,000 distinct UDP flows, reads real maps/snapshots/events, then
closes the protected socket. It requires root, `iproute2`, Python 3, kernel BTF,
clang's BPF backend, libbpf development files and the usual BPF/NET_ADMIN
capabilities. On macOS it prints an explicit `SKIP` and does not claim a pass.

The harness verifies:

1. the protected entry remains present and its rate follows only its own byte
   delta;
2. `lruEntries` approaches capacity while `protectedEntries` stays stable;
3. no rate approaches an unsigned-wrap magnitude;
4. any ordinary-map reset increments `counterResetsThisWindow` and emits a
   continuity event;
5. removing the policy produces a demotion event and the next ordinary packet
   starts a clean LRU generation.
