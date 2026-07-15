// 接口拓扑快照合并：拓扑字段采用最新采集，同名接口保留其他监控线程写入的诊断指标。

#pragma once

#include <unordered_map>
#include <utility>
#include <vector>

#include "net_info.hpp"

namespace weaknet_grpc {

// 以最新拓扑决定接口增删和 route/using 字段，同时按接口名继承异步监控积累的诊断指标。
inline std::vector<NetInfo> mergeTopologyPreservingMetrics(
    const std::vector<NetInfo>& existing,
    const std::vector<NetInfo>& observedTopology) {
    // 指针只在 existing 生命周期内使用；构造 merged 期间不会修改 existing。
    std::unordered_map<std::string, const NetInfo*> existingByName;
    existingByName.reserve(existing.size());
    for (const auto& item : existing) existingByName[item.ifName()] = &item;

    std::vector<NetInfo> merged;
    merged.reserve(observedTopology.size());
    for (const auto& observed : observedTopology) {
        const auto found = existingByName.find(observed.ifName());
        if (found == existingByName.end()) {
            merged.push_back(observed); // 真正新增接口从明确的未知指标哨兵开始。
            continue;
        }

        NetInfo value = *found->second; // 先继承 RTT/RSSI/TCP/traffic/quality 等监控值。
        value.setIfName(observed.ifName());
        value.setDefaultRoute(observed.isDefaultRoute());
        value.setUsingNow(observed.usingNow());
        // state/quality 由连通性监控维护；“仍在拓扑中”不等价于主动探测一定成功。
        // 基础采集常返回 Unknown；不能用 Unknown 抹掉已经识别出的 Wi-Fi/Ethernet 类型。
        if (observed.type() != NetType::Unknown || value.type() == NetType::Unknown) {
            value.setType(observed.type());
        }
        merged.push_back(std::move(value));
    }
    // 未出现在 observedTopology 的接口即已删除，不进入结果。
    return merged;
}

}  // namespace weaknet_grpc
