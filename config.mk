# WeakNet 跨 Makefile 路径配置：集中定义源码、构建、日志和 eBPF 产物位置。
# 变量由根 Makefile 导出给 server/Makefile 及其子进程使用。

# 项目根目录；依据当前被 include 的 config.mk 位置计算。
PROJECT_ROOT := $(dir $(lastword $(MAKEFILE_LIST)))

# 服务端和客户端源码目录。
SERVER_DIR := $(PROJECT_ROOT)server
CLIENT_DIR := $(PROJECT_ROOT)client

# 编译缓存、服务端二进制及客户端二进制/动态库目录。
BUILD_DIR := $(SERVER_DIR)/build
BIN_DIR := $(SERVER_DIR)/bin
CLIENT_BIN_DIR := $(CLIENT_DIR)/bin
CLIENT_LIB_DIR := $(CLIENT_DIR)/lib

# 运行期日志目录。
LOG_DIR := $(PROJECT_ROOT)logs

# 离线状态序列化文件目录。
SERIALIZE_DIR := $(PROJECT_ROOT)

# eBPF 源码与目标文件路径。
BPF_SOURCE := $(SERVER_DIR)/src/flow_rate.bpf.c
BPF_TARGET := $(BUILD_DIR)/flow_rate.bpf.o

# 导出全部路径变量，确保递归 make 与命令子进程看到一致配置。
export PROJECT_ROOT
export SERVER_DIR
export CLIENT_DIR
export BUILD_DIR
export BIN_DIR
export CLIENT_BIN_DIR
export CLIENT_LIB_DIR
export LOG_DIR
export SERIALIZE_DIR
export BPF_SOURCE
export BPF_TARGET
