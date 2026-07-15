// RTT 数值工具：统一有效性判断、旧协议整数兼容和面向用户的毫秒格式化。
// 新链路使用 double 保存亚毫秒精度；旧 int32 字段仅用于滚动升级期间兼容旧客户端。

#pragma once

#include <cmath>
#include <cstdint>
#include <iomanip>
#include <limits>
#include <sstream>
#include <string>

namespace weaknet_grpc {

// RTT 只有在有限且非负时才代表一次成功测量；负值继续保留为采集错误哨兵。
inline bool isRttAvailable(double rttMs) noexcept {
    return std::isfinite(rttMs) && rttMs >= 0.0;
}

// 把精确 RTT 降级成旧协议的整数毫秒。
// 成功的亚毫秒测量至少写成 1ms，避免旧客户端再次把真实成功误读成“0ms/未知”。
inline int32_t toLegacyRttMilliseconds(double rttMs) noexcept {
    if (!isRttAvailable(rttMs)) return -1;

    const double rounded = std::round(rttMs);
    if (rounded < 1.0) return 1;
    if (rounded > static_cast<double>(std::numeric_limits<int32_t>::max())) {
        return std::numeric_limits<int32_t>::max();
    }
    return static_cast<int32_t>(rounded);
}

// PingReply 的旧字段历史上也承载负错误码，因此失败时尽量原样保留该整数错误码。
inline int32_t toLegacyPingMilliseconds(double rttOrError) noexcept {
    if (isRttAvailable(rttOrError)) return toLegacyRttMilliseconds(rttOrError);
    if (!std::isfinite(rttOrError)
        || rttOrError < static_cast<double>(std::numeric_limits<int32_t>::min())
        || rttOrError > static_cast<double>(std::numeric_limits<int32_t>::max())) {
        return -1;
    }
    return static_cast<int32_t>(rttOrError);
}

// 最多保留三位小数并移除无意义的尾零，既能展示 0.134ms，也避免输出 10.000ms。
inline std::string formatRttMilliseconds(double rttMs) {
    std::ostringstream output;
    output << std::fixed << std::setprecision(3) << rttMs;
    std::string value = output.str();
    const auto decimalPoint = value.find('.');
    if (decimalPoint != std::string::npos) {
        while (!value.empty() && value.back() == '0') value.pop_back();
        if (!value.empty() && value.back() == '.') value.pop_back();
    }
    return value;
}

}  // namespace weaknet_grpc
