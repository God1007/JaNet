// WeakNet 离线状态的轻量二进制序列化接口。
// 文件格式采用主机字节序整数和长度前缀字符串，读写函数均同步完成且不管理跨线程互斥。

#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace weaknet_grpc {

// Changed 事件持久化所需的最小载荷。
struct ChangedPayload {
    std::string message; // 事件摘要文本
    int32_t counter;     // 生产者提供的事件计数值
};

// 覆盖写入完整字节缓冲；成功返回 true，失败时可写入 error_message。
bool writeBufferToFile(const std::vector<uint8_t>& buffer, const std::string& filepath, std::string* error_message);

// 同步读取完整文件到 buffer；成功返回 true，失败时可写入 error_message。
bool readFileToBuffer(const std::string& filepath, std::vector<uint8_t>* buffer, std::string* error_message);

// 按 [uint32 长度][原始字节] 追加字符串到 out_buffer。
void serializeString(const std::string& value, std::vector<uint8_t>& out_buffer);

// 从 offset 解码长度前缀字符串并推进 offset；数据越界时返回 false。
bool deserializeString(const std::vector<uint8_t>& buffer, size_t& offset, std::string& out_value);

// 以当前主机字节序追加一个 int32 值。
void serializeInt32(int32_t value, std::vector<uint8_t>& out_buffer);
// 从 offset 解码 int32 并推进 offset；数据不足时返回 false。
bool deserializeInt32(const std::vector<uint8_t>& buffer, size_t& offset, int32_t& out_value);

// 将 Get 的字符串应答覆盖写入 filepath，返回文件写入是否成功。
bool serializeGetReplyToFile(const std::string& reply, const std::string& filepath, std::string* error_message);

// 从 filepath 解码 Get 字符串应答，成功返回 true。
bool deserializeGetReplyFromFile(const std::string& filepath, std::string* out_reply, std::string* error_message);

// 将 ChangedPayload 覆盖写入 filepath，返回文件写入是否成功。
bool serializeChangedPayloadToFile(const ChangedPayload& payload, const std::string& filepath, std::string* error_message);

// 从 filepath 解码 ChangedPayload，成功返回 true。
bool deserializeChangedPayloadFromFile(const std::string& filepath, ChangedPayload* out_payload, std::string* error_message);

}  // namespace weaknet_grpc

