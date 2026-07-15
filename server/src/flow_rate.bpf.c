// 双栈、双向流量采集器：优先在 TC ingress/egress 统一解析 TCP/UDP，旧内核回退到发送 kprobe。
// 所有 map 的 key/value 都来自共享 flow_abi.h；低频 ring buffer 仅承载保护晋升和插入失败事件。
#include "../vmlinux.h"
#include "../include/flow_abi.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#ifndef AF_INET
#define AF_INET 2
#endif
#ifndef AF_INET6
#define AF_INET6 10
#endif
#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif
#ifndef ETH_P_IPV6
#define ETH_P_IPV6 0x86DD
#endif
#ifndef ETH_P_8021Q
#define ETH_P_8021Q 0x8100
#endif
#ifndef ETH_P_8021AD
#define ETH_P_8021AD 0x88A8
#endif
#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif
#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif

char LICENSE[] SEC("license") = "GPL";

// 高基数明细流允许 LRU 淘汰；任何淘汰/重建都会在用户态安全差分并暴露 continuity_lost。
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, FLOW_LRU_MAX_ENTRIES);
    __type(key, struct flow_key);
    __type(value, struct flow_value);
} current_sec SEC(".maps");

// 保护策略由 sock_diag 校准器按 socket cookie 写入，TTL 防止进程异常退出留下永久白名单。
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, FLOW_PROTECTED_MAX_ENTRIES);
    __type(key, flow_u64);
    __type(value, struct flow_protection_policy);
} protected_policy SEC(".maps");

// 低频长连接进入非 LRU map，避免被瞬时高基数流量冲刷；满载失败会降级回普通 LRU map。
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, FLOW_PROTECTED_MAX_ENTRIES);
    __type(key, struct flow_key);
    __type(value, struct flow_value);
} protected_flows SEC(".maps");

// 单元素运行时配置允许用户态动态切换 ifindex 和 TC/kprobe 捕获模式，无需重载对象。
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, flow_u32);
    __type(value, struct flow_runtime_config);
} runtime_config SEC(".maps");

// 每 CPU 统计规避热点原子竞争；用户态读取时汇总所有 possible CPU。
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, FLOW_STAT_MAX);
    __type(key, flow_u32);
    __type(value, flow_u64);
} map_stats SEC(".maps");

// 接口/协议/方向级累计量用于可信聚合，避免 TopN 明细截断后反推总量。
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, FLOW_IFACE_MAX_ENTRIES);
    __type(key, struct flow_iface_key);
    __type(value, struct flow_iface_counters);
} iface_totals SEC(".maps");

// 仅发送低频状态事件；普通包和普通新流不会进入 ring buffer。
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} flow_events SEC(".maps");

// 每 CPU 最多每秒提交一个内核事件，避免 map 压力故障反过来淹没观测通道。
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, flow_u32);
    __type(value, flow_u64);
} event_last_ns SEC(".maps");

static __always_inline void stat_inc(flow_u32 id)
{
    flow_u64 *value = bpf_map_lookup_elem(&map_stats, &id);
    if (value) (*value)++;
}

static __always_inline const struct flow_runtime_config *get_config(void)
{
    flow_u32 zero = 0;
    return bpf_map_lookup_elem(&runtime_config, &zero);
}

static __always_inline bool iface_allowed(flow_u32 ifindex)
{
    const struct flow_runtime_config *cfg = get_config();
    if (!cfg || cfg->ifindex == 0) return true;
    if (ifindex == cfg->ifindex) return true;
    stat_inc(FLOW_STAT_IFACE_REJECTED);
    return false;
}

static __always_inline bool kprobe_fallback_enabled(void)
{
    const struct flow_runtime_config *cfg = get_config();
    return !cfg || cfg->capture_mode == FLOW_CAPTURE_KPROBE_FALLBACK;
}

static __always_inline void emit_event(flow_u32 type,
                                       flow_u32 reason,
                                       const struct flow_key *key,
                                       const struct flow_value *value)
{
    const flow_u64 now = bpf_ktime_get_ns();
    flow_u32 zero = 0;
    flow_u64 *last = bpf_map_lookup_elem(&event_last_ns, &zero);
    if (last && now - *last < 1000000000ULL) {
        stat_inc(FLOW_STAT_EVENT_DROPPED);
        return;
    }
    if (last) *last = now;
    struct flow_event *event = bpf_ringbuf_reserve(&flow_events, sizeof(*event), 0);
    if (!event) {
        stat_inc(FLOW_STAT_EVENT_DROPPED);
        return;
    }
    __builtin_memset(event, 0, sizeof(*event));
    event->abi_version = FLOW_ABI_VERSION;
    event->type = type;
    event->timestamp_ns = now;
    event->socket_cookie = key->socket_cookie;
    event->bytes = value ? value->bytes : 0;
    event->packets = value ? value->packets : 0;
    event->reason = reason;
    __builtin_memcpy(&event->key, key, sizeof(*key));
    bpf_ringbuf_submit(event, 0);
    stat_inc(FLOW_STAT_EVENT_EMITTED);
}

static __always_inline void fill_owner(struct flow_value *value)
{
    flow_u64 pid_tgid = bpf_get_current_pid_tgid();
    value->tgid = (flow_u32)(pid_tgid >> 32);
    value->pid = (flow_u32)pid_tgid;
    value->cgroup_id = bpf_get_current_cgroup_id();
    bpf_get_current_comm(value->comm, sizeof(value->comm));
}

static __always_inline void account_interface(const struct flow_key *key, flow_u64 bytes)
{
    struct flow_iface_key iface_key = {};
    iface_key.ifindex = key->ifindex;
    iface_key.family = key->family;
    iface_key.protocol = key->protocol;
    iface_key.direction = key->direction;

    struct flow_iface_counters *counters = bpf_map_lookup_elem(&iface_totals, &iface_key);
    if (!counters) {
        struct flow_iface_counters initial = {.bytes = bytes, .packets = 1};
        stat_inc(FLOW_STAT_IFACE_INSERT_ATTEMPT);
        if (bpf_map_update_elem(&iface_totals, &iface_key, &initial, BPF_NOEXIST) != 0) {
            // 并发 CPU 可能已经创建同一 key；只有二次 lookup 仍失败才是真插入失败。
            counters = bpf_map_lookup_elem(&iface_totals, &iface_key);
            if (counters) {
                counters->bytes += bytes;
                counters->packets += 1;
            } else {
                stat_inc(FLOW_STAT_IFACE_INSERT_FAILURE);
            }
        }
        return;
    }
    counters->bytes += bytes;
    counters->packets += 1;
}

// 保护 map 满载时回退普通 LRU map；这样保护能力降级不会造成流量观测整体中断。
static __always_inline bool account_protected(const struct flow_key *key,
                                              flow_u64 bytes,
                                              flow_u64 now)
{
    if (key->socket_cookie == 0) return false;
    struct flow_protection_policy *policy =
        bpf_map_lookup_elem(&protected_policy, &key->socket_cookie);
    if (!policy || policy->expires_ns <= now) return false;

    stat_inc(FLOW_STAT_PROTECTED_HIT);
    struct flow_value *value = bpf_map_lookup_elem(&protected_flows, key);
    if (value) {
        __sync_fetch_and_add(&value->bytes, bytes);
        __sync_fetch_and_add(&value->packets, 1);
        value->last_seen_ns = now;
        return true;
    }

    struct flow_value initial = {};
    initial.bytes = bytes;
    initial.packets = 1;
    initial.first_seen_ns = now;
    initial.last_seen_ns = now;
    initial.cgroup_id = policy->cgroup_id;
    initial.tgid = policy->tgid;
    initial.flags = FLOW_VALUE_PROTECTED | FLOW_VALUE_OWNER_FROM_POLICY;
    __builtin_memcpy(initial.comm, policy->comm, sizeof(initial.comm));

    stat_inc(FLOW_STAT_PROTECTED_INSERT_ATTEMPT);
    if (bpf_map_update_elem(&protected_flows, key, &initial, BPF_NOEXIST) != 0) {
        // EEXIST 可能只是并发首包竞争；成功找到后补记本包，不计为容量/权限失败。
        value = bpf_map_lookup_elem(&protected_flows, key);
        if (value) {
            __sync_fetch_and_add(&value->bytes, bytes);
            __sync_fetch_and_add(&value->packets, 1);
            value->last_seen_ns = now;
            return true;
        }
        stat_inc(FLOW_STAT_PROTECTED_INSERT_FAILURE);
        emit_event(FLOW_EVENT_MAP_INSERT_FAILURE, FLOW_VALUE_PROTECTED, key, &initial);
        return false;
    }
    stat_inc(FLOW_STAT_PROTECTED_INSERT_SUCCESS);
    // 晋升完成后释放同 key 的旧 LRU 占用，后续以 non-LRU counter 为唯一权威来源。
    bpf_map_delete_elem(&current_sec, key);
    emit_event(FLOW_EVENT_PROTECTED_PROMOTED, policy->reason_flags, key, &initial);
    return true;
}

static __always_inline void account_flow(struct flow_key *key, flow_u64 bytes)
{
    const flow_u64 now = bpf_ktime_get_ns();
    stat_inc(FLOW_STAT_PACKETS_SEEN);
    account_interface(key, bytes);
    if (account_protected(key, bytes, now)) return;

    struct flow_value *value = bpf_map_lookup_elem(&current_sec, key);
    if (value) {
        __sync_fetch_and_add(&value->bytes, bytes);
        __sync_fetch_and_add(&value->packets, 1);
        value->last_seen_ns = now;
        return;
    }

    stat_inc(FLOW_STAT_LRU_LOOKUP_MISS);
    struct flow_value initial = {};
    initial.bytes = bytes;
    initial.packets = 1;
    initial.first_seen_ns = now;
    initial.last_seen_ns = now;
    fill_owner(&initial);

    stat_inc(FLOW_STAT_LRU_INSERT_ATTEMPT);
    if (bpf_map_update_elem(&current_sec, key, &initial, BPF_NOEXIST) != 0) {
        // 并发 miss 后的 EEXIST 不是失败：二次 lookup 并补记本包。
        value = bpf_map_lookup_elem(&current_sec, key);
        if (value) {
            __sync_fetch_and_add(&value->bytes, bytes);
            __sync_fetch_and_add(&value->packets, 1);
            value->last_seen_ns = now;
        } else {
            stat_inc(FLOW_STAT_LRU_INSERT_FAILURE);
            emit_event(FLOW_EVENT_MAP_INSERT_FAILURE, 0, key, &initial);
        }
    } else {
        stat_inc(FLOW_STAT_LRU_INSERT_SUCCESS);
    }
}

static __always_inline flow_u64 read_socket_cookie(struct sock *sk)
{
    // sock_diag 会通过 sock_gen_cookie 物化该值；尚未物化时为 0，用户态会明确暴露降级。
    return (flow_u64)BPF_CORE_READ(sk, __sk_common.skc_cookie.counter);
}

// kprobe fallback 从 sock 提取双栈五元组；ifindex 仅能使用绑定设备或 TCP skb 的实际设备。
static __always_inline int fill_key_from_sock(struct sock *sk,
                                              flow_u8 protocol,
                                              flow_u32 ifindex,
                                              struct flow_key *key)
{
    __builtin_memset(key, 0, sizeof(*key));
    flow_u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    if (family == AF_INET) {
        key->family = FLOW_AF_INET4;
        flow_u32 src = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
        flow_u32 dst = BPF_CORE_READ(sk, __sk_common.skc_daddr);
        __builtin_memcpy(key->saddr, &src, sizeof(src));
        __builtin_memcpy(key->daddr, &dst, sizeof(dst));
    } else if (family == AF_INET6) {
        key->family = FLOW_AF_INET6;
        struct in6_addr src = {};
        struct in6_addr dst = {};
        BPF_CORE_READ_INTO(&src, sk, __sk_common.skc_v6_rcv_saddr);
        BPF_CORE_READ_INTO(&dst, sk, __sk_common.skc_v6_daddr);
        __builtin_memcpy(key->saddr, &src, sizeof(src));
        __builtin_memcpy(key->daddr, &dst, sizeof(dst));
    } else {
        stat_inc(FLOW_STAT_PARSE_FAILURE);
        return -1;
    }

    key->protocol = protocol;
    key->direction = FLOW_DIR_EGRESS;
    key->ifindex = ifindex;
    key->sport_be = bpf_htons(BPF_CORE_READ(sk, __sk_common.skc_num));
    key->dport_be = BPF_CORE_READ(sk, __sk_common.skc_dport);
    key->socket_cookie = read_socket_cookie(sk);
    return 0;
}

struct vlan_hdr_local {
    __be16 tci;
    __be16 encapsulated_proto;
};

// TC 包解析覆盖 IPv4/IPv6、TCP/UDP 和一个 VLAN 标签；IPv6 扩展头当前显式计为 parse failure。
static __always_inline int parse_skb(struct __sk_buff *skb,
                                     flow_u8 direction,
                                     struct flow_key *key)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return -1;

    flow_u32 offset = sizeof(*eth);
    __be16 protocol = eth->h_proto;
    if (protocol == bpf_htons(ETH_P_8021Q) || protocol == bpf_htons(ETH_P_8021AD)) {
        struct vlan_hdr_local *vlan = data + offset;
        if ((void *)(vlan + 1) > data_end) return -1;
        protocol = vlan->encapsulated_proto;
        offset += sizeof(*vlan);
    }

    __builtin_memset(key, 0, sizeof(*key));
    key->direction = direction;
    key->ifindex = skb->ifindex;
    key->socket_cookie = bpf_get_socket_cookie(skb);

    flow_u32 l4_offset;
    if (protocol == bpf_htons(ETH_P_IP)) {
        struct iphdr *ip = data + offset;
        if ((void *)(ip + 1) > data_end || ip->ihl < 5) return -1;
        l4_offset = offset + (flow_u32)ip->ihl * 4;
        if (data + l4_offset > data_end) return -1;
        // 非首片没有传输层端口，不能安全构造五元组。
        if (ip->frag_off & bpf_htons(0x1FFF)) return -1;
        key->family = FLOW_AF_INET4;
        key->protocol = ip->protocol;
        __builtin_memcpy(key->saddr, &ip->saddr, sizeof(ip->saddr));
        __builtin_memcpy(key->daddr, &ip->daddr, sizeof(ip->daddr));
    } else if (protocol == bpf_htons(ETH_P_IPV6)) {
        struct ipv6hdr *ip6 = data + offset;
        if ((void *)(ip6 + 1) > data_end) return -1;
        l4_offset = offset + sizeof(*ip6);
        key->family = FLOW_AF_INET6;
        key->protocol = ip6->nexthdr;
        __builtin_memcpy(key->saddr, &ip6->saddr, sizeof(ip6->saddr));
        __builtin_memcpy(key->daddr, &ip6->daddr, sizeof(ip6->daddr));
    } else {
        return -1;
    }

    if (key->protocol != IPPROTO_TCP && key->protocol != IPPROTO_UDP) return -1;
    flow_u16 *ports = data + l4_offset;
    if ((void *)(ports + 2) > data_end) return -1;
    key->sport_be = ports[0];
    key->dport_be = ports[1];
    return 0;
}

static __always_inline int account_tc_skb(struct __sk_buff *skb, flow_u8 direction)
{
    if (!iface_allowed(skb->ifindex)) return 0;
    struct flow_key key = {};
    if (parse_skb(skb, direction, &key) != 0) {
        stat_inc(FLOW_STAT_PARSE_FAILURE);
        return 0;
    }
    account_flow(&key, skb->len);
    return 0;
}

SEC("tc/ingress")
int weaknet_tc_ingress(struct __sk_buff *skb)
{
    return account_tc_skb(skb, FLOW_DIR_INGRESS);
}

SEC("tc/egress")
int weaknet_tc_egress(struct __sk_buff *skb)
{
    return account_tc_skb(skb, FLOW_DIR_EGRESS);
}

// 旧内核 fallback：仅出站 TCP 有可靠 skb/接口；启用 TC 后由 runtime_config 禁止重复计数。
SEC("kprobe/ip_queue_xmit")
int tcp_transmit_entry(struct pt_regs *ctx)
{
    if (!kprobe_fallback_enabled()) return 0;
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM2(ctx);
    if (!sk || !skb) return 0;

    struct net_device *dev = BPF_CORE_READ(skb, dev);
    flow_u32 ifindex = dev ? BPF_CORE_READ(dev, ifindex) : 0;
    if (!iface_allowed(ifindex)) return 0;

    struct flow_key key = {};
    if (fill_key_from_sock(sk, IPPROTO_TCP, ifindex, &key) == 0) {
        account_flow(&key, BPF_CORE_READ(skb, len));
    }
    return 0;
}

// UDP fallback 没有 skb；仅当 socket 显式 SO_BINDTODEVICE 时才能满足指定接口过滤。
SEC("kprobe/udp_sendmsg")
int udp_send_entry(struct pt_regs *ctx)
{
    if (!kprobe_fallback_enabled()) return 0;
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    if (!sk) return 0;
    flow_u32 ifindex = BPF_CORE_READ(sk, __sk_common.skc_bound_dev_if);
    if (!iface_allowed(ifindex)) return 0;

    struct flow_key key = {};
    if (fill_key_from_sock(sk, IPPROTO_UDP, ifindex, &key) == 0) {
        account_flow(&key, (flow_u64)PT_REGS_PARM3(ctx));
    }
    return 0;
}
