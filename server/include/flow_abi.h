// eBPF 与用户态共享的流量观测 ABI：固定字段宽度、布局、事件与统计编号。
// 修改任何结构布局时都必须同步提升 FLOW_ABI_VERSION，并通过静态断言与核心测试。

#pragma once

// 同一头文件同时被 C eBPF 程序和 C++ 用户态读取；别名保证两侧字段宽度完全一致。
#ifdef __cplusplus
#include <cstddef>
#include <cstdint>
using flow_u8 = std::uint8_t;
using flow_u16 = std::uint16_t;
using flow_u32 = std::uint32_t;
using flow_u64 = std::uint64_t;
#else
typedef __u8 flow_u8;
typedef __u16 flow_u16;
typedef __u32 flow_u32;
typedef __u64 flow_u64;
#endif

#define FLOW_ABI_VERSION 1U
#define FLOW_COMM_LEN 16U
#define FLOW_LRU_MAX_ENTRIES 65536U
#define FLOW_PROTECTED_MAX_ENTRIES 4096U
#define FLOW_IFACE_MAX_ENTRIES 512U
// 端口 ABI：sport_be/dport_be 始终是 16-bit 网络字节序；用户态展示前必须 ntohs。
// 其余多字节整数是本机字节序的本地 kernel/userspace 共享 ABI，不是跨机器线协议。
#define FLOW_PORT_BYTE_ORDER_NETWORK 1U

// 地址族使用稳定的 ABI 自定义值，不直接把平台相关 AF_* 常量写进 map。
enum flow_address_family {
    FLOW_AF_UNSPEC = 0,
    FLOW_AF_INET4 = 4,
    FLOW_AF_INET6 = 6,
};

// 标识流量是在绑定接口的 ingress 还是 egress TC hook 被观测到。
enum flow_direction {
    FLOW_DIR_UNKNOWN = 0,
    FLOW_DIR_INGRESS = 1,
    FLOW_DIR_EGRESS = 2,
};

// 声明当前采集能力；fallback 只能提供降级视图，TC 才代表完整双向捕获。
enum flow_capture_mode {
    FLOW_CAPTURE_KPROBE_FALLBACK = 0,
    FLOW_CAPTURE_TC = 1,
};

// flow_value 的位标记，说明条目是否受保护以及 owner 是否来自用户态策略。
enum flow_value_flags {
    FLOW_VALUE_PROTECTED = 1U << 0,
    FLOW_VALUE_OWNER_FROM_POLICY = 1U << 1,
};

// 长流保护的可组合原因位；同一策略可以同时命中多个信号。
enum flow_policy_reason {
    FLOW_POLICY_PORT = 1U << 0,
    FLOW_POLICY_PROCESS = 1U << 1,
    FLOW_POLICY_CGROUP = 1U << 2,
    FLOW_POLICY_LONG_LOW_RATE = 1U << 3,
};

// map_stats 的固定数组下标；只能追加并同步提升 ABI，不能重排已有编号。
enum flow_map_stat_id {
    FLOW_STAT_PACKETS_SEEN = 0,
    FLOW_STAT_IFACE_REJECTED = 1,
    FLOW_STAT_PARSE_FAILURE = 2,
    FLOW_STAT_LRU_LOOKUP_MISS = 3,
    FLOW_STAT_LRU_INSERT_ATTEMPT = 4,
    FLOW_STAT_LRU_INSERT_SUCCESS = 5,
    FLOW_STAT_LRU_INSERT_FAILURE = 6,
    FLOW_STAT_PROTECTED_HIT = 7,
    FLOW_STAT_PROTECTED_INSERT_ATTEMPT = 8,
    FLOW_STAT_PROTECTED_INSERT_SUCCESS = 9,
    FLOW_STAT_PROTECTED_INSERT_FAILURE = 10,
    FLOW_STAT_IFACE_INSERT_ATTEMPT = 11,
    FLOW_STAT_IFACE_INSERT_FAILURE = 12,
    FLOW_STAT_EVENT_EMITTED = 13,
    FLOW_STAT_EVENT_DROPPED = 14,
    FLOW_STAT_MAX = 15,
};

// ring-buffer 事件类型；数值是内核到用户态协议的一部分，已有编号不可复用。
enum flow_event_type {
    FLOW_EVENT_UNSPEC = 0,
    FLOW_EVENT_PROTECTED_PROMOTED = 1,
    FLOW_EVENT_MAP_INSERT_FAILURE = 2,
    FLOW_EVENT_CONTINUITY_LOST = 3,
    FLOW_EVENT_COUNTER_RESET = 4,
    FLOW_EVENT_SOCK_DIAG_DEGRADED = 5,
    FLOW_EVENT_PROTECTED_DEMOTED = 6,
    FLOW_EVENT_PROTECTED_CLOSED = 7,
    // 用户态从同一 generation 派生的低频流量异常；内核不直接发送此类型。
    FLOW_EVENT_TRAFFIC_ANOMALY = 8,
};

// 地址统一保存为 16 字节；IPv4 只使用前 4 字节，其余字节必须清零。
// 完整 56 字节共同构成 BPF map key：reserved/padding 未清零会制造语义相同但字节不同的键。
struct flow_key {
    flow_u8 family;          // offset 0
    flow_u8 protocol;        // offset 1: IPPROTO_TCP/IPPROTO_UDP
    flow_u8 direction;       // offset 2: flow_direction
    flow_u8 reserved0;       // offset 3, must be zero
    flow_u32 ifindex;        // offset 4
    flow_u16 sport_be;       // offset 8, network byte order
    flow_u16 dport_be;       // offset 10, network byte order
    flow_u32 reserved1;      // offset 12, must be zero
    flow_u8 saddr[16];       // offset 16
    flow_u8 daddr[16];       // offset 32
    flow_u64 socket_cookie;  // offset 48, 0 means unavailable
};

// 单条流的累计计数与 owner 元数据；bytes/packets 只在同一 entry generation 内单调。
struct flow_value {
    flow_u64 bytes;          // offset 0, monotonic within one map entry
    flow_u64 packets;        // offset 8, monotonic within one map entry
    flow_u64 first_seen_ns;  // offset 16, entry generation identity
    flow_u64 last_seen_ns;   // offset 24
    flow_u64 cgroup_id;      // offset 32, best effort
    flow_u32 tgid;           // offset 40
    flow_u32 pid;            // offset 44
    char comm[FLOW_COMM_LEN];// offset 48
    flow_u32 generation;     // offset 64, reserved for explicit reset generations
    flow_u32 flags;          // offset 68: flow_value_flags
};

// 从短流 LRU 晋升出的保护记录，把原完整 key 与累计 value 一起保存在非 LRU map。
struct flow_protected_record {
    struct flow_key key;     // offset 0
    struct flow_value value; // offset 56
};

// 用户态根据 sock_diag/进程/cgroup 生成的保护策略；expires_ns 使用内核单调时钟域。
struct flow_protection_policy {
    flow_u64 observed_since_ns;
    flow_u64 expires_ns;
    flow_u64 cgroup_id;
    flow_u32 tgid;
    flow_u32 reason_flags;
    char comm[FLOW_COMM_LEN];
};

// 单元素运行配置：用户态写入 ABI 版本、绑定 ifindex 和采集模式，eBPF 热路径读取。
struct flow_runtime_config {
    flow_u32 abi_version;
    flow_u32 ifindex;
    flow_u32 capture_mode;
    flow_u32 flags;
};

// 按接口聚合 map 的键；reserved 必须清零，避免同一逻辑维度形成多个原始字节键。
struct flow_iface_key {
    flow_u32 ifindex;
    flow_u8 family;
    flow_u8 protocol;
    flow_u8 direction;
    flow_u8 reserved;
};

// PERCPU_HASH 的单 CPU 累计值；用户态 lookup 后需按 possible CPU 槽位求和。
struct flow_iface_counters {
    flow_u64 bytes;
    flow_u64 packets;
};

// 内核发送给用户态的固定尺寸事件；timestamp_ns 属于单调时钟，key 仍遵循端口网络序契约。
struct flow_event {
    flow_u32 abi_version;
    flow_u32 type;
    flow_u64 timestamp_ns;
    flow_u64 socket_cookie;
    flow_u64 bytes;
    flow_u64 packets;
    flow_u32 reason;
    flow_u32 reserved;
    struct flow_key key;
};

#ifdef __cplusplus
// C++ 编译侧锁定全部尺寸与关键 offset，防止普通字段调整静默破坏已加载 BPF map ABI。
static_assert(sizeof(flow_key) == 56, "flow_key ABI size changed");
static_assert(offsetof(flow_key, ifindex) == 4, "flow_key.ifindex ABI offset changed");
static_assert(offsetof(flow_key, sport_be) == 8, "flow_key.sport_be ABI offset changed");
static_assert(offsetof(flow_key, dport_be) == 10, "flow_key.dport_be ABI offset changed");
static_assert(sizeof(flow_key::sport_be) == 2 && sizeof(flow_key::dport_be) == 2,
              "flow ports must remain 16-bit network-order fields");
static_assert(FLOW_PORT_BYTE_ORDER_NETWORK == 1U, "flow port byte-order ABI changed");
static_assert(offsetof(flow_key, saddr) == 16, "flow_key.saddr ABI offset changed");
static_assert(offsetof(flow_key, socket_cookie) == 48, "flow_key.socket_cookie ABI offset changed");
static_assert(sizeof(flow_value) == 72, "flow_value ABI size changed");
static_assert(offsetof(flow_value, bytes) == 0, "flow_value.bytes ABI offset changed");
static_assert(offsetof(flow_value, packets) == 8, "flow_value.packets ABI offset changed");
static_assert(offsetof(flow_value, first_seen_ns) == 16, "flow_value.first_seen_ns ABI offset changed");
static_assert(offsetof(flow_value, last_seen_ns) == 24, "flow_value.last_seen_ns ABI offset changed");
static_assert(offsetof(flow_value, cgroup_id) == 32, "flow_value.cgroup_id ABI offset changed");
static_assert(offsetof(flow_value, tgid) == 40, "flow_value.tgid ABI offset changed");
static_assert(offsetof(flow_value, pid) == 44, "flow_value.pid ABI offset changed");
static_assert(offsetof(flow_value, comm) == 48, "flow_value.comm ABI offset changed");
static_assert(offsetof(flow_value, generation) == 64, "flow_value.generation ABI offset changed");
static_assert(offsetof(flow_value, flags) == 68, "flow_value.flags ABI offset changed");
static_assert(sizeof(flow_protected_record) == 128, "flow_protected_record ABI size changed");
static_assert(offsetof(flow_protected_record, key) == 0, "protected_record.key ABI offset changed");
static_assert(offsetof(flow_protected_record, value) == 56, "protected_record.value ABI offset changed");
static_assert(sizeof(flow_protection_policy) == 48, "flow_protection_policy ABI size changed");
static_assert(offsetof(flow_protection_policy, observed_since_ns) == 0, "policy.observed ABI offset changed");
static_assert(offsetof(flow_protection_policy, expires_ns) == 8, "policy.expires ABI offset changed");
static_assert(offsetof(flow_protection_policy, cgroup_id) == 16, "policy.cgroup ABI offset changed");
static_assert(offsetof(flow_protection_policy, tgid) == 24, "policy.tgid ABI offset changed");
static_assert(offsetof(flow_protection_policy, reason_flags) == 28, "policy.reason ABI offset changed");
static_assert(offsetof(flow_protection_policy, comm) == 32, "policy.comm ABI offset changed");
static_assert(sizeof(flow_runtime_config) == 16, "flow_runtime_config ABI size changed");
static_assert(offsetof(flow_runtime_config, abi_version) == 0, "runtime.abi ABI offset changed");
static_assert(offsetof(flow_runtime_config, ifindex) == 4, "runtime.ifindex ABI offset changed");
static_assert(offsetof(flow_runtime_config, capture_mode) == 8, "runtime.capture ABI offset changed");
static_assert(offsetof(flow_runtime_config, flags) == 12, "runtime.flags ABI offset changed");
static_assert(sizeof(flow_iface_key) == 8, "flow_iface_key ABI size changed");
static_assert(offsetof(flow_iface_key, ifindex) == 0, "iface_key.ifindex ABI offset changed");
static_assert(offsetof(flow_iface_key, family) == 4, "iface_key.family ABI offset changed");
static_assert(offsetof(flow_iface_key, protocol) == 5, "iface_key.protocol ABI offset changed");
static_assert(offsetof(flow_iface_key, direction) == 6, "iface_key.direction ABI offset changed");
static_assert(sizeof(flow_iface_counters) == 16, "flow_iface_counters ABI size changed");
static_assert(offsetof(flow_iface_counters, bytes) == 0, "iface_counters.bytes ABI offset changed");
static_assert(offsetof(flow_iface_counters, packets) == 8, "iface_counters.packets ABI offset changed");
static_assert(sizeof(flow_event) == 104, "flow_event ABI size changed");
static_assert(offsetof(flow_event, abi_version) == 0, "flow_event.abi ABI offset changed");
static_assert(offsetof(flow_event, type) == 4, "flow_event.type ABI offset changed");
static_assert(offsetof(flow_event, timestamp_ns) == 8, "flow_event.timestamp ABI offset changed");
static_assert(offsetof(flow_event, socket_cookie) == 16, "flow_event.cookie ABI offset changed");
static_assert(offsetof(flow_event, bytes) == 24, "flow_event.bytes ABI offset changed");
static_assert(offsetof(flow_event, packets) == 32, "flow_event.packets ABI offset changed");
static_assert(offsetof(flow_event, reason) == 40, "flow_event.reason ABI offset changed");
static_assert(offsetof(flow_event, key) == 48, "flow_event.key ABI offset changed");
#else
// eBPF/C 编译侧执行同一组布局门禁，确保两种语言看到的结构完全相同。
_Static_assert(sizeof(struct flow_key) == 56, "flow_key ABI size changed");
_Static_assert(__builtin_offsetof(struct flow_key, ifindex) == 4, "flow_key ifindex offset changed");
_Static_assert(__builtin_offsetof(struct flow_key, sport_be) == 8, "flow_key sport offset changed");
_Static_assert(__builtin_offsetof(struct flow_key, dport_be) == 10, "flow_key dport offset changed");
_Static_assert(sizeof(((struct flow_key*)0)->sport_be) == 2 &&
               sizeof(((struct flow_key*)0)->dport_be) == 2,
               "flow ports must remain 16-bit network-order fields");
_Static_assert(FLOW_PORT_BYTE_ORDER_NETWORK == 1U, "flow port byte-order ABI changed");
_Static_assert(__builtin_offsetof(struct flow_key, saddr) == 16, "flow_key source offset changed");
_Static_assert(__builtin_offsetof(struct flow_key, socket_cookie) == 48, "flow_key cookie offset changed");
_Static_assert(sizeof(struct flow_value) == 72, "flow_value ABI size changed");
_Static_assert(__builtin_offsetof(struct flow_value, bytes) == 0, "flow_value bytes offset changed");
_Static_assert(__builtin_offsetof(struct flow_value, packets) == 8, "flow_value packets offset changed");
_Static_assert(__builtin_offsetof(struct flow_value, first_seen_ns) == 16,
               "flow_value first_seen offset changed");
_Static_assert(__builtin_offsetof(struct flow_value, last_seen_ns) == 24,
               "flow_value last_seen offset changed");
_Static_assert(__builtin_offsetof(struct flow_value, cgroup_id) == 32,
               "flow_value cgroup offset changed");
_Static_assert(__builtin_offsetof(struct flow_value, tgid) == 40, "flow_value tgid offset changed");
_Static_assert(__builtin_offsetof(struct flow_value, pid) == 44, "flow_value pid offset changed");
_Static_assert(__builtin_offsetof(struct flow_value, comm) == 48, "flow_value comm offset changed");
_Static_assert(__builtin_offsetof(struct flow_value, generation) == 64,
               "flow_value generation offset changed");
_Static_assert(__builtin_offsetof(struct flow_value, flags) == 68, "flow_value flags offset changed");
_Static_assert(sizeof(struct flow_protected_record) == 128, "protected record ABI size changed");
_Static_assert(__builtin_offsetof(struct flow_protected_record, key) == 0,
               "protected record key offset changed");
_Static_assert(__builtin_offsetof(struct flow_protected_record, value) == 56,
               "protected record value offset changed");
_Static_assert(sizeof(struct flow_protection_policy) == 48, "policy ABI size changed");
_Static_assert(__builtin_offsetof(struct flow_protection_policy, observed_since_ns) == 0,
               "policy observed offset changed");
_Static_assert(__builtin_offsetof(struct flow_protection_policy, expires_ns) == 8,
               "policy expires offset changed");
_Static_assert(__builtin_offsetof(struct flow_protection_policy, cgroup_id) == 16,
               "policy cgroup offset changed");
_Static_assert(__builtin_offsetof(struct flow_protection_policy, tgid) == 24,
               "policy tgid offset changed");
_Static_assert(__builtin_offsetof(struct flow_protection_policy, reason_flags) == 28,
               "policy reason offset changed");
_Static_assert(__builtin_offsetof(struct flow_protection_policy, comm) == 32,
               "policy comm offset changed");
_Static_assert(sizeof(struct flow_runtime_config) == 16, "runtime config ABI size changed");
_Static_assert(__builtin_offsetof(struct flow_runtime_config, abi_version) == 0,
               "runtime abi offset changed");
_Static_assert(__builtin_offsetof(struct flow_runtime_config, ifindex) == 4,
               "runtime ifindex offset changed");
_Static_assert(__builtin_offsetof(struct flow_runtime_config, capture_mode) == 8,
               "runtime capture offset changed");
_Static_assert(__builtin_offsetof(struct flow_runtime_config, flags) == 12,
               "runtime flags offset changed");
_Static_assert(sizeof(struct flow_iface_key) == 8, "iface key ABI size changed");
_Static_assert(__builtin_offsetof(struct flow_iface_key, ifindex) == 0,
               "iface key ifindex offset changed");
_Static_assert(__builtin_offsetof(struct flow_iface_key, family) == 4,
               "iface key family offset changed");
_Static_assert(__builtin_offsetof(struct flow_iface_key, protocol) == 5,
               "iface key protocol offset changed");
_Static_assert(__builtin_offsetof(struct flow_iface_key, direction) == 6,
               "iface key direction offset changed");
_Static_assert(sizeof(struct flow_iface_counters) == 16, "iface counters ABI size changed");
_Static_assert(__builtin_offsetof(struct flow_iface_counters, bytes) == 0,
               "iface counters bytes offset changed");
_Static_assert(__builtin_offsetof(struct flow_iface_counters, packets) == 8,
               "iface counters packets offset changed");
_Static_assert(sizeof(struct flow_event) == 104, "flow_event ABI size changed");
_Static_assert(__builtin_offsetof(struct flow_event, abi_version) == 0,
               "flow_event abi offset changed");
_Static_assert(__builtin_offsetof(struct flow_event, type) == 4,
               "flow_event type offset changed");
_Static_assert(__builtin_offsetof(struct flow_event, timestamp_ns) == 8,
               "flow_event timestamp offset changed");
_Static_assert(__builtin_offsetof(struct flow_event, socket_cookie) == 16,
               "flow_event cookie offset changed");
_Static_assert(__builtin_offsetof(struct flow_event, bytes) == 24,
               "flow_event bytes offset changed");
_Static_assert(__builtin_offsetof(struct flow_event, packets) == 32,
               "flow_event packets offset changed");
_Static_assert(__builtin_offsetof(struct flow_event, reason) == 40,
               "flow_event reason offset changed");
_Static_assert(__builtin_offsetof(struct flow_event, key) == 48,
               "flow_event key offset changed");
#endif
