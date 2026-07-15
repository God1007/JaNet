// 轻量二进制序列化：为兼容文件接口编码 Get 回复和 Changed 事件载荷。
// 读取端始终先做长度边界检查，避免损坏文件触发越界访问。

#include "serializer.hpp"

#include <cstdint>
#include <cstring>
#include <fstream>
#include <limits>

namespace weaknet_grpc {

// 将一段原始字节追加到输出缓冲区，供各基础类型编码复用。
static void appendBytes(const void* data, size_t len, std::vector<uint8_t>& out) {
    const uint8_t* p = static_cast<const uint8_t*>(data);
    out.insert(out.end(), p, p + len);
}

// 覆盖写入完整缓冲区，并把可诊断错误返回给调用方。
bool writeBufferToFile(const std::vector<uint8_t>& buffer, const std::string& filepath, std::string* error_message) {
    std::ofstream ofs(filepath, std::ios::binary | std::ios::trunc);
    if (!ofs.is_open()) {
        if (error_message) *error_message = "无法打开文件写入: " + filepath;
        return false;
    }
    ofs.write(reinterpret_cast<const char*>(buffer.data()), static_cast<std::streamsize>(buffer.size()));
    if (!ofs.good()) {
        if (error_message) *error_message = "写入失败: " + filepath;
        return false;
    }
    return true;
}

// 先确定文件长度再一次性读取，确保后续反序列化拥有完整输入。
bool readFileToBuffer(const std::string& filepath, std::vector<uint8_t>* buffer, std::string* error_message) {
    std::ifstream ifs(filepath, std::ios::binary);
    if (!ifs.is_open()) {
        if (error_message) *error_message = "无法打开文件读取: " + filepath;
        return false;
    }
    ifs.seekg(0, std::ios::end);
    std::streamsize size = ifs.tellg();
    if (size < 0) {
        if (error_message) *error_message = "读取文件大小失败: " + filepath;
        return false;
    }
    ifs.seekg(0, std::ios::beg);
    buffer->resize(static_cast<size_t>(size));
    if (size > 0) {
        ifs.read(reinterpret_cast<char*>(buffer->data()), size);
        if (!ifs.good()) {
            if (error_message) *error_message = "读取失败: " + filepath;
            return false;
        }
    }
    return true;
}

// 按“32 位长度 + 原始字节”编码字符串，空串只写长度字段。
void serializeString(const std::string& value, std::vector<uint8_t>& out_buffer) {
    uint32_t len = static_cast<uint32_t>(value.size());
    appendBytes(&len, sizeof(len), out_buffer);
    if (len > 0) {
        appendBytes(value.data(), len, out_buffer);
    }
}

// 从当前位置解码长度前缀字符串；任何截断都返回 false 而不越界。
bool deserializeString(const std::vector<uint8_t>& buffer, size_t& offset, std::string& out_value) {
    if (offset + sizeof(uint32_t) > buffer.size()) return false;
    uint32_t len = 0;
    std::memcpy(&len, buffer.data() + offset, sizeof(uint32_t));
    offset += sizeof(uint32_t);
    if (offset + len > buffer.size()) return false;
    out_value.assign(reinterpret_cast<const char*>(buffer.data() + offset), len);
    offset += len;
    return true;
}

// 追加一个 32 位整数，保持与现有文件格式兼容。
void serializeInt32(int32_t value, std::vector<uint8_t>& out_buffer) {
    appendBytes(&value, sizeof(value), out_buffer);
}

// 在确认剩余字节充足后读取 32 位整数并推进游标。
bool deserializeInt32(const std::vector<uint8_t>& buffer, size_t& offset, int32_t& out_value) {
    if (offset + sizeof(int32_t) > buffer.size()) return false;
    std::memcpy(&out_value, buffer.data() + offset, sizeof(int32_t));
    offset += sizeof(int32_t);
    return true;
}

// 编码 Get 文本回复并覆盖持久化文件。
bool serializeGetReplyToFile(const std::string& reply, const std::string& filepath, std::string* error_message) {
    std::vector<uint8_t> buf;
    serializeString(reply, buf);
    return writeBufferToFile(buf, filepath, error_message);
}

// 读取并解码 Get 文本回复。
bool deserializeGetReplyFromFile(const std::string& filepath, std::string* out_reply, std::string* error_message) {
    std::vector<uint8_t> buf;
    if (!readFileToBuffer(filepath, &buf, error_message)) return false;
    size_t off = 0;
    return deserializeString(buf, off, *out_reply);
}

// 按固定字段顺序编码 Changed 消息和计数器。
bool serializeChangedPayloadToFile(const ChangedPayload& payload, const std::string& filepath, std::string* error_message) {
    std::vector<uint8_t> buf;
    serializeString(payload.message, buf);
    serializeInt32(payload.counter, buf);
    return writeBufferToFile(buf, filepath, error_message);
}

// 按与写入端一致的顺序恢复 Changed 载荷，截断字段即失败。
bool deserializeChangedPayloadFromFile(const std::string& filepath, ChangedPayload* out_payload, std::string* error_message) {
    std::vector<uint8_t> buf;
    if (!readFileToBuffer(filepath, &buf, error_message)) return false;
    size_t off = 0;
    if (!deserializeString(buf, off, out_payload->message)) return false;
    if (!deserializeInt32(buf, off, out_payload->counter)) return false;
    return true;
}

}  // namespace weaknet_grpc

