// 无 Linux 工具链静态门禁：确保关键内核挂载点、maps、校准器和单一采样入口没有被误删。

#include <cstdlib>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

// 读取生产源码供静态契约检查；不依赖 Linux/libbpf 运行环境。
std::string readFile(const char* path) {
    std::ifstream input(path);
    std::ostringstream output;
    output << input.rdbuf();
    return output.str();
}

// 要求关键 map、挂载点、统计字段和单一采样入口全部仍存在。
bool requireTokens(const std::string& text, const std::vector<std::string>& tokens, const char* file) {
    for (const auto& token : tokens) {
        if (text.find(token) == std::string::npos) {
            std::cerr << file << " is missing contract token: " << token << '\n';
            return false;
        }
    }
    return true;
}

// 统计关键调用出现次数，用于阻止重复采样入口或重复线程被重新引入。
size_t countToken(const std::string& text, const std::string& token) {
    size_t count = 0;
    size_t position = 0;
    while ((position = text.find(token, position)) != std::string::npos) {
        ++count;
        position += token.size();
    }
    return count;
}

// 对 eBPF、用户态采样、线程编排、proto 与 gRPC 暴露面执行跨文件静态门禁。
int main() {
    const std::string bpf = readFile("src/flow_rate.bpf.c");
    const std::string user = readFile("src/net_traffic.cpp");
    const std::string worker = readFile("src/traffic_analyzer.cpp");
    const std::string server = readFile("src/server.cpp");
    const std::string usingIface = readFile("src/using_iface.cpp");
    const std::string netIface = readFile("src/net_iface.cpp");
    const std::string netlinkDump = readFile("include/netlink_dump.hpp");
    const std::string grpc = readFile("src/grpc_service.cpp");
    const std::string proto = readFile("../proto/weaknet.proto");
    const std::string weakMgr = readFile("src/weak_netmgr.cpp");
    const std::string abi = readFile("include/flow_abi.h");
    if (!requireTokens(bpf, {
            "BPF_MAP_TYPE_LRU_HASH", "protected_policy", "protected_flows",
            "BPF_MAP_TYPE_PERCPU_ARRAY", "BPF_MAP_TYPE_PERCPU_HASH", "BPF_MAP_TYPE_RINGBUF",
            "SEC(\"tc/ingress\")", "SEC(\"tc/egress\")", "FLOW_AF_INET6",
            "runtime_config", "FLOW_CAPTURE_KPROBE_FALLBACK", "FLOW_EVENT_PROTECTED_PROMOTED"
        }, "src/flow_rate.bpf.c")) return EXIT_FAILURE;
    if (!requireTokens(bpf, {"event_last_ns", "1000000000ULL"}, "src/flow_rate.bpf.c")) {
        return EXIT_FAILURE;
    }
    // 定义 + protected insert failure + promoted + LRU insert failure；普通包路径不得提交 ringbuf。
    if (countToken(bpf, "emit_event(") != 4) {
        std::cerr << "ordinary packet paths must not emit ring-buffer events\n";
        return EXIT_FAILURE;
    }
    const auto promotion = bpf.find("FLOW_STAT_PROTECTED_INSERT_SUCCESS");
    const auto clearOldLru = bpf.find("bpf_map_delete_elem(&current_sec, key)", promotion);
    if (promotion == std::string::npos || clearOldLru == std::string::npos ||
        clearOldLru - promotion > 400) {
        std::cerr << "promotion must remove the stale LRU generation\n";
        return EXIT_FAILURE;
    }
    if (!requireTokens(user, {
            "calculateCounterDelta", "NETLINK_SOCK_DIAG", "resolveProcOwners",
            "flow_protection_policy", "ring_buffer__poll", "TrafficSnapshotPtr",
            "updateInterface", "FLOW_EVENT_COUNTER_RESET", "deleteProtectedFlowsForCookie",
            "sockDiagIpv4Available", "sockDiagIpv6Available", "disappearedThisWindow",
            "counterResetsThisWindow", "policyUpdateAttempts", "policyUpdateFailures", "snapshotUsable",
            "enumerateMapKeys", "stepBudget", "mapReadComplete", "mapReadBoundary",
            "installedPoliciesByFamily", "captureCompleteness", "if (flow.continuityLost) continue",
            "receiveCompleteDump", "completeBatch", "protectionTtl()", "next->anomalies",
            "bpf_tc_query", "BPF_TC_F_REPLACE", "flock(fd, LOCK_EX | LOCK_NB)",
            "prepareTcSlot", "detachOwnedTcSlot", "ownedProgramId", "RTM_GETTFILTER",
            "inspectTcFilterSlot", "if (!slot.exists) return true"
        }, "src/net_traffic.cpp")) return EXIT_FAILURE;
    // 空 qdisc/chain 要在 raw netlink 阶段判定，不能先调用会打印预期内核错误的 bpf_tc_query。
    const auto prepareFunction = user.find("bool prepareTcSlot");
    const auto rawSlotInspection = user.find("inspectTcFilterSlot", prepareFunction);
    const auto libbpfSlotQuery = user.find("queryTcSlot", rawSlotInspection);
    if (prepareFunction == std::string::npos || rawSlotInspection == std::string::npos ||
        libbpfSlotQuery == std::string::npos || rawSlotInspection >= libbpfSlotQuery) {
        std::cerr << "TC prepare must prove that the BPF slot exists before bpf_tc_query\n";
        return EXIT_FAILURE;
    }
    // TC takeover 必须先只读检查两个方向，再做第一次写入，避免 ingress 已改而 egress foreign。
    const auto attachFunction = user.find("bool attachTc");
    const auto inspectHook = user.find("clsactHookExists", attachFunction);
    const auto prepareIngress = user.find("prepareTcSlot(ingressPlan", inspectHook);
    const auto prepareEgress = user.find("prepareTcSlot(egressPlan", prepareIngress);
    const auto applyIngress = user.find("applyTcSlot(ingressPlan", prepareEgress);
    if (attachFunction == std::string::npos || inspectHook == std::string::npos ||
        prepareIngress == std::string::npos || prepareEgress == std::string::npos ||
        applyIngress == std::string::npos || !(prepareIngress < prepareEgress && prepareEgress < applyIngress)) {
        std::cerr << "TC ownership must inspect clsact and prepare both slots before the first write\n";
        return EXIT_FAILURE;
    }
    // 析构只能在固定槽位仍指向本轮记录 prog_id 时 detach，外部 replace 后必须零修改。
    const auto detachOwned = user.find("void detachOwnedTcSlot");
    const auto exactIdCheck = user.find("tcSlotMatches(ifindex, point, ownedProgramId)", detachOwned);
    const auto exactDetach = user.find("bpf_tc_detach(&hook, &options)", exactIdCheck);
    if (detachOwned == std::string::npos || exactIdCheck == std::string::npos ||
        exactDetach == std::string::npos || exactDetach - detachOwned > 1200) {
        std::cerr << "TC detach must compare the live slot against the exact owned prog_id\n";
        return EXIT_FAILURE;
    }
    const auto calibration = user.find("reconcileProtectedSockets(*impl_");
    const auto mapBoundary = user.find("const auto readBeginSteady", calibration);
    if (calibration == std::string::npos || mapBoundary == std::string::npos || calibration >= mapBoundary) {
        std::cerr << "sock_diag calibration must finish before the map read time boundary\n";
        return EXIT_FAILURE;
    }
    const auto switchBranch = user.find("if (interfaceChanged)");
    const auto detachOld = user.find("detachTc(*impl_)", switchBranch);
    const auto clearOld = user.find("clearMap<flow_key>", switchBranch);
    if (detachOld == std::string::npos || clearOld == std::string::npos || detachOld >= clearOld) {
        std::cerr << "interface switch must detach writers before clearing maps\n";
        return EXIT_FAILURE;
    }
    const auto deletePolicy = user.find("bpf_map_delete_elem(state.mapProtectedPolicyFd, &cookie)");
    const auto deleteValue = user.find("deleteProtectedFlowsForCookie(state.mapProtectedFlowsFd, cookie)",
                                       deletePolicy);
    if (deletePolicy == std::string::npos || deleteValue == std::string::npos ||
        deleteValue - deletePolicy > 300) {
        std::cerr << "policy demotion must delete protected values in the same branch\n";
        return EXIT_FAILURE;
    }

    const std::string refreshCall = "analyzer_->refreshSnapshot()";
    const auto first = worker.find(refreshCall);
    if (first == std::string::npos || worker.find(refreshCall, first + 1) != std::string::npos) {
        std::cerr << "traffic worker must have exactly one center refresh call\n";
        return EXIT_FAILURE;
    }
    if (!requireTokens(worker, {"isBaselinePending", "invalidateForRebind",
                                "sampleMatchesBinding", "observation_state_.publish",
                                "getRealTimeStats(snapshot)"},
                       "src/traffic_analyzer.cpp")) return EXIT_FAILURE;
    const auto samplerLock = user.find("std::lock_guard<std::mutex> samplerLock(impl_->samplerMutex)",
                                       user.find("void NetTrafficAnalyzer::clearHistory"));
    const auto historyLock = user.find("std::lock_guard<std::mutex> historyLock(impl_->historyMutex)",
                                       user.find("void NetTrafficAnalyzer::clearHistory"));
    if (samplerLock == std::string::npos || historyLock == std::string::npos || samplerLock >= historyLock) {
        std::cerr << "clearHistory must preserve sampler -> history lock order\n";
        return EXIT_FAILURE;
    }
    if (!requireTokens(server, {"selectTrafficInterface", "waiting for a valid interface",
                                "mergeTopologySnapshot",
                                "startTrafficAnalysis(selectedInterface"}, "src/server.cpp")) {
        return EXIT_FAILURE;
    }
    if (server.find("startTrafficAnalysis(\"eth0\"") != std::string::npos) {
        std::cerr << "traffic startup must not hardcode eth0\n";
        return EXIT_FAILURE;
    }
    if (!requireTokens(usingIface, {"RTA_PRIORITY", "RTA_TABLE", "RTA_MULTIPATH",
                                    "RTNH_OK", "defaultRoutes", "routeDebouncer",
                                    "retryTransactionalSnapshot", "MSG_TRUNC", "NLMSG_OVERRUN",
                                    "dumpInitial();", "#include \"flow_observation_core.hpp\""},
                       "src/using_iface.cpp")) return EXIT_FAILURE;
    if (usingIface.find("hasGw") != std::string::npos) {
        std::cerr << "direct default routes must not require RTA_GATEWAY\n";
        return EXIT_FAILURE;
    }
    if (!requireTokens(netIface, {"RTA_PRIORITY", "RTA_TABLE", "RTA_MULTIPATH",
                                  "defaultRoutes_", "activeInterfaces", "retryTransactionalSnapshot",
                                  "requestCompleteDump", "#include \"flow_observation_core.hpp\""},
                       "src/net_iface.cpp")) return EXIT_FAILURE;
    if (netIface.find("hasGateway") != std::string::npos) {
        std::cerr << "interface discovery must include direct default dev routes\n";
        return EXIT_FAILURE;
    }
    if (!requireTokens(netlinkDump, {"poll(", "MSG_TRUNC", "NLM_F_DUMP_INTR",
                                     "expectedSequence", "expectedPort", "NLMSG_DONE",
                                     "NLMSG_OVERRUN"}, "include/netlink_dump.hpp")) {
        return EXIT_FAILURE;
    }
    if (!requireTokens(grpc, {"getCurrentObservationState()", "trafficGenerationAligned",
                              "EVENT_TYPE_TRAFFIC_OBSERVATION", "mutable_traffic_observation",
                              "set_lru_insert_attempts", "add_recent_events"},
                       "src/grpc_service.cpp")) return EXIT_FAILURE;
    if (countToken(grpc, "getCurrentObservationState()") != 1 ||
        grpc.find("trafficAnalyzer->getCurrentStats()") != std::string::npos) {
        std::cerr << "gRPC must read the paired traffic observation state exactly once\n";
        return EXIT_FAILURE;
    }
    if (!requireTokens(proto, {"EVENT_TYPE_TRAFFIC_OBSERVATION = 8",
                               "TRAFFIC_OBSERVATION_EVENT_TRAFFIC_ANOMALY = 8",
                               "TrafficObservationEvent traffic_observation = 9",
                               "lru_insert_attempts", "protected_insert_attempts",
                               "interface_insert_attempts", "user_events_truncated"},
                       "../proto/weaknet.proto")) return EXIT_FAILURE;
    if (!requireTokens(weakMgr, {"traffic_analyzer_mutex_", "stats.boundIfindex != activeIfindex",
                                 "detectAnomalies(observationState.snapshot)"},
                       "src/weak_netmgr.cpp")) return EXIT_FAILURE;
    if (!requireTokens(abi, {"sizeof(struct flow_runtime_config) == 16",
                             "sizeof(struct flow_iface_key) == 8",
                             "sizeof(struct flow_iface_counters) == 16",
                             "__builtin_offsetof(struct flow_event, key) == 48"},
                       "include/flow_abi.h")) return EXIT_FAILURE;
    const std::string header = readFile("include/net_traffic.h");
    if (!requireTokens(header, {"ipv6ExtensionHeadersSupported", "coverageLimitations",
                                "TrafficMapObservability", "baselineOnly", "captureComplete",
                                "mapReadComplete"}, "include/net_traffic.h")) {
        return EXIT_FAILURE;
    }
    std::cout << "traffic_source_contract_test: all checks passed\n";
    return EXIT_SUCCESS;
}
