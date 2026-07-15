// RTT protobuf 契约回归测试：锁定兼容旧 int32 的 optional double schema，并验证二进制往返。
// 使用真实生成的 weaknet.pb.cc，而不是手写结构体，防止 proto 已改但陈旧生成代码仍被链接。

#include "weaknet.pb.h"

#include <cmath>
#include <cstdlib>
#include <iostream>
#include <string>

#include <google/protobuf/descriptor.h>
#include <google/protobuf/descriptor.pb.h>

#define TEST_CHECK(condition) do { \
    if (!(condition)) { \
        std::cerr << "TEST_CHECK failed at " << __FILE__ << ':' << __LINE__ << ": " #condition "\n"; \
        return EXIT_FAILURE; \
    } \
} while (false)

namespace {

constexpr double kTolerance = 1e-12;

bool nearlyEqual(double lhs, double rhs) {
    return std::abs(lhs - rhs) <= kTolerance;
}

// Descriptor 断言直接检查 schema 类型，避免字段名存在但类型或 presence 契约发生漂移。
bool fieldHasType(const google::protobuf::Descriptor* descriptor,
                  const char* name,
                  google::protobuf::FieldDescriptor::CppType cppType) {
    const auto* field = descriptor ? descriptor->FindFieldByName(name) : nullptr;
    return field && field->cpp_type() == cppType;
}

bool fieldHasNumber(const google::protobuf::Descriptor* descriptor,
                    const char* name,
                    int number) {
    const auto* field = descriptor ? descriptor->FindFieldByName(name) : nullptr;
    return field && field->number() == number;
}

bool fieldIsPresentDouble(const google::protobuf::Descriptor* descriptor, const char* name) {
    const auto* field = descriptor ? descriptor->FindFieldByName(name) : nullptr;
    return field
        && field->cpp_type() == google::protobuf::FieldDescriptor::CPPTYPE_DOUBLE
        && field->has_presence();
}

bool fieldIsDeprecated(const google::protobuf::Descriptor* descriptor, const char* name) {
    const auto* field = descriptor ? descriptor->FindFieldByName(name) : nullptr;
    return field && field->options().deprecated();
}

}  // namespace

int main() {
    using weaknet::v1::InterfaceSnapshot;
    using weaknet::v1::MetricAvailability;
    using weaknet::v1::PingReply;

    // 旧 tag 保持 int32 且标记 deprecated，避免滚动升级时发生 wire type 不兼容。
    TEST_CHECK(fieldHasType(InterfaceSnapshot::descriptor(), "rtt_ms",
                       google::protobuf::FieldDescriptor::CPPTYPE_INT32));
    TEST_CHECK(fieldHasType(InterfaceSnapshot::descriptor(), "previous_rtt_ms",
                       google::protobuf::FieldDescriptor::CPPTYPE_INT32));
    TEST_CHECK(fieldHasType(PingReply::descriptor(), "latency_ms",
                       google::protobuf::FieldDescriptor::CPPTYPE_INT32));
    TEST_CHECK(fieldIsDeprecated(InterfaceSnapshot::descriptor(), "rtt_ms"));
    TEST_CHECK(fieldIsDeprecated(InterfaceSnapshot::descriptor(), "previous_rtt_ms"));
    TEST_CHECK(fieldIsDeprecated(PingReply::descriptor(), "latency_ms"));
    TEST_CHECK(fieldHasNumber(InterfaceSnapshot::descriptor(), "rtt_ms", 6));
    TEST_CHECK(fieldHasNumber(InterfaceSnapshot::descriptor(), "previous_rtt_ms", 7));
    TEST_CHECK(fieldHasNumber(PingReply::descriptor(), "latency_ms", 4));

    // 新字段必须是带 presence 的 double；presence 用来区分有效 0 与旧服务端未发送字段。
    TEST_CHECK(fieldIsPresentDouble(InterfaceSnapshot::descriptor(), "rtt_ms_precise"));
    TEST_CHECK(fieldIsPresentDouble(InterfaceSnapshot::descriptor(), "previous_rtt_ms_precise"));
    TEST_CHECK(fieldIsPresentDouble(PingReply::descriptor(), "latency_ms_precise"));
    TEST_CHECK(fieldHasNumber(InterfaceSnapshot::descriptor(), "rtt_ms_precise", 19));
    TEST_CHECK(fieldHasNumber(InterfaceSnapshot::descriptor(), "previous_rtt_ms_precise", 20));
    TEST_CHECK(fieldHasNumber(PingReply::descriptor(), "latency_ms_precise", 6));

    // 快照同时写兼容整数与精确值，证明新客户端可保留 0.134、旧客户端仍看到至少 1ms。
    InterfaceSnapshot source;
    source.set_interface_name("eth0");
    source.set_rtt_ms(1);
    source.set_previous_rtt_ms(1);
    source.set_rtt_ms_precise(0.134);
    source.set_previous_rtt_ms_precise(0.287);
    source.set_rtt_availability(MetricAvailability::METRIC_AVAILABILITY_AVAILABLE);
    std::string bytes;
    TEST_CHECK(source.SerializeToString(&bytes));

    InterfaceSnapshot decoded;
    TEST_CHECK(decoded.ParseFromString(bytes));
    TEST_CHECK(decoded.rtt_ms() == 1);
    TEST_CHECK(decoded.previous_rtt_ms() == 1);
    TEST_CHECK(decoded.has_rtt_ms_precise());
    TEST_CHECK(decoded.has_previous_rtt_ms_precise());
    TEST_CHECK(nearlyEqual(decoded.rtt_ms_precise(), 0.134));
    TEST_CHECK(nearlyEqual(decoded.previous_rtt_ms_precise(), 0.287));
    TEST_CHECK(decoded.rtt_availability() == MetricAvailability::METRIC_AVAILABILITY_AVAILABLE);

    // 数值零仍可用；optional presence 与 availability 一起证明它不是“字段缺失”。
    InterfaceSnapshot zero;
    zero.set_rtt_ms(1);
    zero.set_rtt_ms_precise(0.0);
    zero.set_rtt_availability(MetricAvailability::METRIC_AVAILABILITY_AVAILABLE);
    TEST_CHECK(zero.SerializeToString(&bytes));
    decoded.Clear();
    TEST_CHECK(decoded.ParseFromString(bytes));
    TEST_CHECK(decoded.rtt_ms() == 1);
    TEST_CHECK(decoded.has_rtt_ms_precise());
    TEST_CHECK(nearlyEqual(decoded.rtt_ms_precise(), 0.0));
    TEST_CHECK(decoded.rtt_availability() == MetricAvailability::METRIC_AVAILABILITY_AVAILABLE);

    // 失败仅写旧负哨兵并省略当前 precise 字段；上一轮成功的精确值仍可独立存在。
    InterfaceSnapshot failed;
    failed.set_rtt_ms(-1);
    failed.set_previous_rtt_ms(1);
    failed.set_previous_rtt_ms_precise(0.134);
    failed.set_rtt_availability(MetricAvailability::METRIC_AVAILABILITY_UNAVAILABLE);
    TEST_CHECK(failed.SerializeToString(&bytes));
    decoded.Clear();
    TEST_CHECK(decoded.ParseFromString(bytes));
    TEST_CHECK(decoded.rtt_ms() == -1);
    TEST_CHECK(!decoded.has_rtt_ms_precise());
    TEST_CHECK(decoded.has_previous_rtt_ms_precise());
    TEST_CHECK(nearlyEqual(decoded.previous_rtt_ms_precise(), 0.134));
    TEST_CHECK(decoded.rtt_availability() == MetricAvailability::METRIC_AVAILABILITY_UNAVAILABLE);

    // 主动 Ping RPC 同样双写：成功时 precise 有 presence，失败时只保留旧负错误码。
    PingReply ping;
    ping.set_success(true);
    ping.set_latency_ms(1);
    ping.set_latency_ms_precise(0.134);
    TEST_CHECK(ping.SerializeToString(&bytes));
    PingReply decodedPing;
    TEST_CHECK(decodedPing.ParseFromString(bytes));
    TEST_CHECK(decodedPing.success());
    TEST_CHECK(decodedPing.latency_ms() == 1);
    TEST_CHECK(decodedPing.has_latency_ms_precise());
    TEST_CHECK(nearlyEqual(decodedPing.latency_ms_precise(), 0.134));

    ping.Clear();
    ping.set_success(false);
    ping.set_latency_ms(-5);
    TEST_CHECK(ping.SerializeToString(&bytes));
    decodedPing.Clear();
    TEST_CHECK(decodedPing.ParseFromString(bytes));
    TEST_CHECK(!decodedPing.success());
    TEST_CHECK(decodedPing.latency_ms() == -5);
    TEST_CHECK(!decodedPing.has_latency_ms_precise());

    std::cout << "rtt_proto_roundtrip_test: all checks passed\n";
    return EXIT_SUCCESS;
}
