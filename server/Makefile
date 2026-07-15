# WeakNet 服务端构建入口：生成协议代码、eBPF 对象并链接服务端可执行文件。
# 本文件在 server 目录执行，产物写入 bin/ 与 build/。

# C++ 编译器与通用告警、优化选项。
CC=g++
CXXFLAGS=-std=c++17 -O2 -Wall -Wextra -Wpedantic

# eBPF 架构由构建主机推导，也可通过 BPF_ARCH=x86/arm64 显式覆盖。
UNAME_M := $(shell uname -m)
UNAME_S := $(shell uname -s)
BPF_ARCH ?= $(if $(filter x86_64 amd64,$(UNAME_M)),x86,$(if $(filter aarch64 arm64,$(UNAME_M)),arm64,x86))
BPF_CLANG ?= clang
BPF_CFLAGS ?= $(shell pkg-config --cflags libbpf 2>/dev/null)
# vmlinux.h 由 bpftool 生成，里面的内核声明不提供普通 C prototype；仅在 BPF 翻译单元关闭该生成代码告警。
BPF_GENERATED_HEADER_WARNINGS=-Wno-missing-declarations
BPF_SYNTAX_TRIPLE ?= $(if $(filter arm64,$(BPF_ARCH)),aarch64-unknown-linux-gnu,x86_64-unknown-linux-gnu)
BPF_OBJDUMP ?= $(shell command -v llvm-objdump 2>/dev/null || command -v objdump 2>/dev/null)
BPF_NM ?= $(shell command -v llvm-nm 2>/dev/null || command -v nm 2>/dev/null)
LIBBPF_TEST_LIBS := $(if $(filter Linux,$(UNAME_S)),$(if $(shell pkg-config --libs libbpf 2>/dev/null),$(shell pkg-config --libs libbpf 2>/dev/null),-lbpf),)

# 发现 gRPC/Protobuf 编译链接参数及 protoc 的 gRPC C++ 插件。
GRPC_CFLAGS=$(shell pkg-config --cflags grpc++ protobuf 2>/dev/null)
GRPC_LIBS=$(shell pkg-config --libs grpc++ protobuf 2>/dev/null)
GRPC_FALLBACK_LIBS=-lgrpc++ -lprotobuf -lpthread
PROTOBUF_CFLAGS=$(shell pkg-config --cflags protobuf 2>/dev/null)
PROTOBUF_LIBS=$(shell pkg-config --libs protobuf 2>/dev/null)
# RTT 协议测试必须使用与 pkg-config headers 同版本的 protoc，避免 macOS 上 protobuf@21 与新版 headers 混用。
PROTOBUF_PROTOC ?= $(shell prefix=$$(pkg-config --variable=prefix protobuf 2>/dev/null); if [ -n "$$prefix" ] && [ -x "$$prefix/bin/protoc" ]; then printf '%s\n' "$$prefix/bin/protoc"; else command -v protoc; fi)
# glog 0.7 的非 CMake 消费方式需要显式启用 export 宏；旧版 glog 会安全忽略该定义。
GLOG_CFLAGS=-DGLOG_USE_GLOG_EXPORT $(shell pkg-config --cflags libglog 2>/dev/null || pkg-config --cflags glog 2>/dev/null)
GLOG_LIBS=$(shell pkg-config --libs libglog 2>/dev/null || pkg-config --libs glog 2>/dev/null)
GRPC_CPP_PLUGIN ?= $(shell which grpc_cpp_plugin 2>/dev/null)
PROTOC ?= $(if $(wildcard /opt/homebrew/opt/protobuf@21/bin/protoc),/opt/homebrew/opt/protobuf@21/bin/protoc,protoc)

# 服务端编译的头文件搜索路径与 gRPC、glog、libbpf 链接参数。
INCLUDES=$(GRPC_CFLAGS) -Iinclude -Ibuild/generated
LDFLAGS=$(if $(GRPC_LIBS),$(GRPC_LIBS),$(GRPC_FALLBACK_LIBS)) -lglog -lbpf -lanl

# Protobuf 输入、生成目录及用于增量构建的标记文件。
PROTO=../proto/weaknet.proto
PROTO_GEN_DIR=build/generated
PROTO_CC=$(PROTO_GEN_DIR)/weaknet.pb.cc
PROTO_H=$(PROTO_GEN_DIR)/weaknet.pb.h
GRPC_CC=$(PROTO_GEN_DIR)/weaknet.grpc.pb.cc
GRPC_H=$(PROTO_GEN_DIR)/weaknet.grpc.pb.h
PROTO_SRCS=$(PROTO_CC) $(GRPC_CC)
PROTO_HDRS=$(PROTO_H) $(GRPC_H)
PROTO_STAMP=$(PROTO_GEN_DIR)/.weaknet_proto.stamp

# 服务端手写源文件、头文件依赖和最终产物路径。
SRC=src/server.cpp src/grpc_service.cpp src/net_iface.cpp src/serializer.cpp src/net_info.cpp src/weak_netmgr.cpp src/using_iface.cpp src/net_ping.cpp src/rtt_monitor.cpp src/rssi_monitor.cpp src/net_wifiriss.cpp src/net_tcp.cpp src/tcp_loss_monitor.cpp src/event_manager.cpp src/logger.cpp src/traffic_analyzer.cpp src/net_traffic.cpp src/traffic_anomaly_detector.cpp src/network_quality_assessor.cpp src/main.cpp
INC=include/common.hpp include/grpc_service.hpp include/net_iface.h include/serializer.hpp include/server.hpp include/net_tcp.h include/tcp_loss_monitor.hpp include/weak_netmgr.hpp include/net_info.hpp include/rtt_monitor.hpp include/rssi_monitor.hpp include/event_manager.hpp include/logger.hpp include/traffic_analyzer.hpp include/traffic_observation_state.hpp include/network_quality_assessor.hpp include/net_traffic.h include/flow_abi.h include/flow_observation_core.hpp include/interface_snapshot_merge.hpp include/route_selection.hpp include/netlink_dump.hpp include/rtt_utils.hpp

# 服务端可执行文件、eBPF 对象与内核类型头文件的输出路径。
BIN_DIR=bin
BUILD_DIR=build
TARGET=$(BIN_DIR)/weaknet-grpc-server
BPF_TARGET=$(BUILD_DIR)/flow_rate.bpf.o
VMLINUX ?= vmlinux.h
TRAFFIC_CORE_TEST=$(BUILD_DIR)/traffic_core_test
TRAFFIC_SNAPSHOT_TEST=$(BUILD_DIR)/traffic_snapshot_test
TRAFFIC_SOURCE_CONTRACT_TEST=$(BUILD_DIR)/traffic_source_contract_test
INTERFACE_SNAPSHOT_MERGE_TEST=$(BUILD_DIR)/interface_snapshot_merge_test
SERVER_LIFECYCLE_CONTRACT_TEST=$(BUILD_DIR)/server_lifecycle_contract_test
ROUTE_SELECTION_TEST=$(BUILD_DIR)/route_selection_test
SERVER_CONTEXT_LIFECYCLE_TEST=$(BUILD_DIR)/server_context_lifecycle_test
TRAFFIC_OBSERVATION_STATE_TEST=$(BUILD_DIR)/traffic_observation_state_test
RTT_PRECISION_TEST=$(BUILD_DIR)/rtt_precision_test
RTT_PROTO_ROUNDTRIP_TEST=$(BUILD_DIR)/rtt_proto_roundtrip_test
RTT_PROTO_GEN_DIR=$(BUILD_DIR)/rtt-proto-generated
RTT_PROTO_TEST_CC=$(RTT_PROTO_GEN_DIR)/weaknet.pb.cc
# Apple Clang 对新版 Protobuf/Abseil 扩展非常啰嗦；这些开关仅屏蔽第三方头告警和测试刻意调用的 deprecated 旧字段。
RTT_PROTO_TEST_WARNINGS=$(if $(filter Darwin,$(UNAME_S)),-Wno-nullability-extension -Wno-variadic-macro-arguments-omitted -Wno-gcc-compat -Wno-gnu-anonymous-struct -Wno-nested-anon-types,) -Wno-deprecated-declarations
TRAFFIC_USERSPACE_CHECK=$(BUILD_DIR)/net_traffic.check.o
TRAFFIC_KERNEL_TEST=$(BUILD_DIR)/traffic_kernel_integration
TRAFFIC_MICROBENCHMARK=$(BUILD_DIR)/traffic_microbenchmark
TRAFFIC_TSAN_BENCHMARK=$(BUILD_DIR)/traffic_microbenchmark_tsan
BPF_MAP_BENCHMARK=$(BUILD_DIR)/bpf_map_benchmark
EVENT_PIPELINE_DRIVER=$(BUILD_DIR)/event_pipeline_driver
BENCHMARK_DIR=$(BUILD_DIR)/benchmarks
PROFILE ?= standard

# 默认目标：准备目录、生成协议与内核类型、编译 eBPF 后链接服务端。
all: dirs $(PROTO_STAMP) $(VMLINUX) $(BPF_TARGET) $(TARGET)

# 创建服务端二进制、构建缓存和协议生成目录。
dirs:
	mkdir -p $(BIN_DIR) $(BUILD_DIR) $(PROTO_GEN_DIR)

# weaknet.proto 变化时重新生成 Protobuf 与 gRPC C++ 桩代码。
$(PROTO_STAMP): $(PROTO) | dirs
	@if [ -z "$(GRPC_CPP_PLUGIN)" ]; then echo "grpc_cpp_plugin not found. Install gRPC C++ development tools."; exit 1; fi
	$(PROTOC) -I../proto --cpp_out=$(PROTO_GEN_DIR) --grpc_out=$(PROTO_GEN_DIR) --plugin=protoc-gen-grpc=$(GRPC_CPP_PLUGIN) $(PROTO)
	touch $@

# 生成文件统一依赖协议标记，避免并行构建时重复执行 protoc。
$(PROTO_SRCS) $(PROTO_HDRS): $(PROTO_STAMP)

# 从当前 Linux 内核 BTF 导出 eBPF 程序所需的 vmlinux.h。
$(VMLINUX):
	@if [ ! -s "$@" ]; then \
		if [ ! -e /sys/kernel/btf/vmlinux ]; then echo "/sys/kernel/btf/vmlinux not found. Install/enable kernel BTF or provide server/vmlinux.h."; exit 1; fi; \
		if ! command -v bpftool >/dev/null 2>&1; then echo "bpftool not found. Install bpftool or provide server/vmlinux.h."; exit 1; fi; \
		bpftool btf dump file /sys/kernel/btf/vmlinux format c > "$@"; \
	fi

# 将流量采集程序编译为 eBPF 目标文件。
$(BPF_TARGET): src/flow_rate.bpf.c include/flow_abi.h $(VMLINUX) | dirs
	@tmp="$@.tmp"; rm -f "$$tmp"; \
	$(BPF_CLANG) -g -O2 -target bpf $(BPF_GENERATED_HEADER_WARNINGS) -D__TARGET_ARCH_$(BPF_ARCH) $(BPF_CFLAGS) -Iinclude -c $< -o "$$tmp" && mv "$$tmp" "$@"

# 链接监控模块、gRPC 服务和协议生成代码，产出服务端程序。
$(TARGET): $(SRC) $(INC) $(PROTO_SRCS) $(PROTO_HDRS) $(BPF_TARGET)
	$(CC) $(CXXFLAGS) $(INCLUDES) -o $@ $(SRC) $(PROTO_SRCS) $(LDFLAGS)

# clean 与 run 是命令目标，不依赖同名文件是否存在。
.PHONY: clean run test-rtt test-traffic-core check-bpf-syntax check-bpf-object check-traffic-userspace test-traffic-linux test-traffic-kernel test-tc-ownership benchmark benchmark-smoke benchmark-standard benchmark-stress benchmark-traffic-core benchmark-core-tsan benchmark-bpf-maps benchmark-kernel-pressure benchmark-event-driver benchmark-help

# 无网络、无 root 的 RTT 回归：分别锁定领域模型/质量评分与 protobuf 二进制契约。
test-rtt: dirs
	$(CC) $(CXXFLAGS) $(GLOG_CFLAGS) -Iinclude tests/rtt_precision_test.cpp src/network_quality_assessor.cpp -o $(RTT_PRECISION_TEST) $(if $(GLOG_LIBS),$(GLOG_LIBS),-lglog)
	$(RTT_PRECISION_TEST)
	@mkdir -p $(RTT_PROTO_GEN_DIR)
	$(PROTOBUF_PROTOC) -I../proto --cpp_out=$(RTT_PROTO_GEN_DIR) $(PROTO)
	$(CC) $(CXXFLAGS) $(RTT_PROTO_TEST_WARNINGS) $(PROTOBUF_CFLAGS) -I$(RTT_PROTO_GEN_DIR) tests/rtt_proto_roundtrip_test.cpp $(RTT_PROTO_TEST_CC) -o $(RTT_PROTO_ROUNDTRIP_TEST) $(if $(PROTOBUF_LIBS),$(PROTOBUF_LIBS),-lprotobuf)
	$(RTT_PROTO_ROUNDTRIP_TEST)

# 不依赖 Linux/libbpf/root，验证 ABI、counter reset/continuity 和长连接策略。
test-traffic-core: dirs
	$(CC) $(CXXFLAGS) -Iinclude tests/traffic_core_test.cpp -o $(TRAFFIC_CORE_TEST)
	$(TRAFFIC_CORE_TEST)
	$(CC) $(CXXFLAGS) -Iinclude tests/traffic_snapshot_test.cpp src/net_traffic.cpp -o $(TRAFFIC_SNAPSHOT_TEST) $(LIBBPF_TEST_LIBS)
	$(TRAFFIC_SNAPSHOT_TEST)
	$(CC) $(CXXFLAGS) tests/traffic_source_contract_test.cpp -o $(TRAFFIC_SOURCE_CONTRACT_TEST)
	$(TRAFFIC_SOURCE_CONTRACT_TEST)
	$(CC) $(CXXFLAGS) -Iinclude tests/interface_snapshot_merge_test.cpp -o $(INTERFACE_SNAPSHOT_MERGE_TEST)
	$(INTERFACE_SNAPSHOT_MERGE_TEST)
	$(CC) $(CXXFLAGS) tests/server_lifecycle_contract_test.cpp -o $(SERVER_LIFECYCLE_CONTRACT_TEST)
	$(SERVER_LIFECYCLE_CONTRACT_TEST)
	$(CC) $(CXXFLAGS) -Iinclude tests/route_selection_test.cpp -o $(ROUTE_SELECTION_TEST)
	$(ROUTE_SELECTION_TEST)
	$(CC) $(CXXFLAGS) -pthread -Iinclude tests/server_context_lifecycle_test.cpp -o $(SERVER_CONTEXT_LIFECYCLE_TEST)
	$(SERVER_CONTEXT_LIFECYCLE_TEST)
	$(CC) $(CXXFLAGS) -pthread -Iinclude tests/traffic_observation_state_test.cpp -o $(TRAFFIC_OBSERVATION_STATE_TEST)
	$(TRAFFIC_OBSERVATION_STATE_TEST)

# Linux 编译门禁：单独编译用户态采样器，尽早发现 libbpf/sock_diag API 不兼容。
check-traffic-userspace: dirs
	$(CC) $(CXXFLAGS) -Iinclude $(shell pkg-config --cflags libbpf 2>/dev/null) -c src/net_traffic.cpp -o $(TRAFFIC_USERSPACE_CHECK)

# 只做 C/CO-RE 语法检查，不要求本机 clang 带 BPF codegen 后端；BPF_CFLAGS 需能找到 libbpf headers。
check-bpf-syntax:
	$(BPF_CLANG) -std=gnu11 -target $(BPF_SYNTAX_TRIPLE) -fsyntax-only -Werror -Wno-unknown-attributes $(BPF_GENERATED_HEADER_WARNINGS) -D__TARGET_ARCH_$(BPF_ARCH) $(BPF_CFLAGS) -Iinclude src/flow_rate.bpf.c

# 编译成功后强制检查新对象的 TC sections 和所有关键 map 符号，拒绝误用仓库内旧对象。
check-bpf-object: $(BPF_TARGET)
	@test -n "$(BPF_OBJDUMP)" -a -n "$(BPF_NM)" || { echo "llvm-objdump/objdump and llvm-nm/nm are required"; exit 1; }
	@$(BPF_OBJDUMP) -h $(BPF_TARGET) | grep -q 'tc/ingress'
	@$(BPF_OBJDUMP) -h $(BPF_TARGET) | grep -q 'tc/egress'
	@$(BPF_OBJDUMP) -h $(BPF_TARGET) | grep -q '\.maps'
	@for symbol in current_sec protected_policy protected_flows runtime_config map_stats iface_totals flow_events; do \
		$(BPF_NM) $(BPF_TARGET) | grep -q " $$symbol$$" || { echo "missing BPF map symbol: $$symbol"; exit 1; }; \
	done

# Linux 完整静态门禁；真正 attach/权限验证仍需在目标机启动服务后检查 support 状态。
test-traffic-linux: test-traffic-core check-bpf-object check-traffic-userspace

# 真正的 Linux 内核验收：root + network namespaces + TC，制造 72k 短流并检查保护连接与事件。
ifeq ($(UNAME_S),Linux)
$(TRAFFIC_KERNEL_TEST): tests/traffic_kernel_integration.cpp tests/benchmark_support.hpp src/net_traffic.cpp include/net_traffic.h include/flow_abi.h include/flow_observation_core.hpp | dirs
	$(CC) $(CXXFLAGS) -pthread -Iinclude -Itests $(shell pkg-config --cflags libbpf 2>/dev/null) tests/traffic_kernel_integration.cpp src/net_traffic.cpp -o $@ $(LIBBPF_TEST_LIBS)

test-traffic-kernel: check-bpf-object $(TRAFFIC_KERNEL_TEST)
	@tests/run_traffic_kernel_integration.sh

# 快速 TC 所有权门禁：隔离 netns 覆盖 stale takeover、foreign 零修改和析构竞态，不制造压力流量。
test-tc-ownership: check-bpf-object $(TRAFFIC_KERNEL_TEST)
	@tests/run_traffic_kernel_integration.sh --tc-ownership
else
test-traffic-kernel:
	@echo "SKIP: test-traffic-kernel requires Linux network namespaces, TC/eBPF and root"

test-tc-ownership:
	@echo "SKIP: test-tc-ownership requires Linux network namespaces, TC/eBPF and root"
endif

# 用户态 benchmark 在所有平台运行；输出由 CLI 强制写成单个 JSON artifact。
$(TRAFFIC_MICROBENCHMARK): tests/traffic_microbenchmark.cpp tests/benchmark_support.hpp include/flow_abi.h include/flow_observation_core.hpp include/route_selection.hpp include/traffic_observation_state.hpp include/net_traffic.h | dirs
	$(CC) $(CXXFLAGS) -pthread -Iinclude -Itests tests/traffic_microbenchmark.cpp -o $@

# BPF map benchmark 在 Linux 链接 libbpf；其他平台仍构建同一 CLI，并明确生成 skipped JSON。
$(BPF_MAP_BENCHMARK): tests/bpf_map_benchmark.cpp tests/benchmark_support.hpp include/flow_abi.h | dirs
ifeq ($(UNAME_S),Linux)
	$(CC) $(CXXFLAGS) -pthread -Iinclude -Itests $(shell pkg-config --cflags libbpf 2>/dev/null) tests/bpf_map_benchmark.cpp -o $@ $(LIBBPF_TEST_LIBS)
else
	$(CC) $(CXXFLAGS) -pthread -Iinclude -Itests tests/bpf_map_benchmark.cpp -o $@
endif

# Linux/Lima live-event driver: it links the real EventManager and GrpcServer,
# while replacing only main() with a bounded benchmark control socket.  Keeping
# it outside the production binary avoids adding a test RPC or changing proto.
ifeq ($(UNAME_S),Linux)
EVENT_PIPELINE_DRIVER_SRCS=$(filter-out src/main.cpp,$(SRC)) tests/event_pipeline_driver.cpp
$(EVENT_PIPELINE_DRIVER): $(EVENT_PIPELINE_DRIVER_SRCS) tests/benchmark_support.hpp $(INC) $(PROTO_SRCS) $(PROTO_HDRS) | dirs
	$(CC) $(CXXFLAGS) $(INCLUDES) -Itests -o $@ $(EVENT_PIPELINE_DRIVER_SRCS) $(PROTO_SRCS) $(LDFLAGS)

benchmark-event-driver: $(EVENT_PIPELINE_DRIVER)
	@echo "event pipeline driver: $(CURDIR)/$(EVENT_PIPELINE_DRIVER)"
else
benchmark-event-driver:
	@echo "ERROR: benchmark-event-driver requires Linux; run it inside Lima on macOS" >&2
	@exit 2
endif

# 细粒度入口允许总编排器指定 PROFILE/OUTPUT；未指定 OUTPUT 时落到 build/benchmarks。
benchmark-traffic-core: $(TRAFFIC_MICROBENCHMARK)
	@mkdir -p "$(BENCHMARK_DIR)"
	@output="$(if $(OUTPUT),$(OUTPUT),$(BENCHMARK_DIR)/traffic-microbenchmark-$(PROFILE).json)"; \
	$(TRAFFIC_MICROBENCHMARK) --profile "$(PROFILE)" --output "$$output"

# Linux ThreadSanitizer 门禁：验证 benchmark 覆盖到的状态发布/读取路径没有数据竞争。
# macOS 当前工具链的 TSan runtime 会在启动期崩溃，因此不把平台故障伪装成通过。
ifeq ($(UNAME_S),Linux)
benchmark-core-tsan: dirs
	$(CC) -std=c++17 -O1 -g -Wall -Wextra -Wpedantic -fno-omit-frame-pointer -fsanitize=thread -pthread -Iinclude -Itests tests/traffic_microbenchmark.cpp -o $(TRAFFIC_TSAN_BENCHMARK)
	@mkdir -p "$(BENCHMARK_DIR)"
	@output="$(if $(OUTPUT),$(OUTPUT),$(BENCHMARK_DIR)/traffic-microbenchmark-tsan-$(PROFILE).json)"; \
	TSAN_OPTIONS=halt_on_error=1:exitcode=66 $(TRAFFIC_TSAN_BENCHMARK) --profile "$(PROFILE)" --output "$$output"
else
benchmark-core-tsan:
	@echo "SKIP: benchmark-core-tsan requires a supported Linux ThreadSanitizer runtime"
endif

benchmark-bpf-maps: $(BPF_MAP_BENCHMARK)
	@mkdir -p "$(BENCHMARK_DIR)"
	@output="$(if $(OUTPUT),$(OUTPUT),$(BENCHMARK_DIR)/bpf-map-benchmark-$(PROFILE).json)"; \
	$(BPF_MAP_BENCHMARK) --profile "$(PROFILE)" --output "$$output"

# 真内核压力只在 Linux root 下运行；负载由 PROFILE 决定
# （standard 约 72k flow，stress 为 300k flow）。其他环境明确 skip，
# 绝不把用户态模拟结果冒充 TC/eBPF 内核路径通过。
ifeq ($(UNAME_S),Linux)
benchmark-kernel-pressure: $(TRAFFIC_KERNEL_TEST)
	@mkdir -p "$(BENCHMARK_DIR)"
	@if [ "$$(id -u)" -ne 0 ]; then \
		echo "SKIP: benchmark-kernel-pressure requires root; rerun with sudo make -C server benchmark-kernel-pressure PROFILE=$(PROFILE)"; \
	else \
		set -e; \
		$(MAKE) --no-print-directory check-bpf-object; \
		output="$(if $(OUTPUT),$(OUTPUT),$(BENCHMARK_DIR)/kernel-pressure-$(PROFILE).json)"; \
		case "$$output" in /*) ;; *) output="$(CURDIR)/$$output" ;; esac; \
		WEAKNET_BENCHMARK_PROFILE="$(PROFILE)" WEAKNET_BENCHMARK_OUTPUT="$$output" \
			tests/run_traffic_kernel_integration.sh; \
	fi
else
benchmark-kernel-pressure:
	@echo "SKIP: benchmark-kernel-pressure requires Linux network namespaces, TC/eBPF and root"
endif

# smoke 保持快速且不启动 namespace；standard/stress 追加各自的
# kernel pressure 档位。组合 target 只做编排，单项结果仍各自落盘 JSON。
benchmark-smoke:
	@$(MAKE) benchmark-traffic-core PROFILE=smoke OUTPUT=$(BENCHMARK_DIR)/traffic-microbenchmark-smoke.json
	@$(MAKE) benchmark-bpf-maps PROFILE=smoke OUTPUT=$(BENCHMARK_DIR)/bpf-map-benchmark-smoke.json

benchmark-standard:
	@$(MAKE) benchmark-traffic-core PROFILE=standard OUTPUT=$(BENCHMARK_DIR)/traffic-microbenchmark-standard.json
	@$(MAKE) benchmark-bpf-maps PROFILE=standard OUTPUT=$(BENCHMARK_DIR)/bpf-map-benchmark-standard.json
	@$(MAKE) benchmark-kernel-pressure PROFILE=standard OUTPUT=$(BENCHMARK_DIR)/kernel-pressure-standard.json

benchmark-stress:
	@$(MAKE) benchmark-traffic-core PROFILE=stress OUTPUT=$(BENCHMARK_DIR)/traffic-microbenchmark-stress.json
	@$(MAKE) benchmark-bpf-maps PROFILE=stress OUTPUT=$(BENCHMARK_DIR)/bpf-map-benchmark-stress.json
	@$(MAKE) benchmark-kernel-pressure PROFILE=stress OUTPUT=$(BENCHMARK_DIR)/kernel-pressure-stress.json

benchmark: benchmark-standard

benchmark-help:
	@echo "Portable smoke:  make -C server benchmark-smoke"
	@echo "Full standard:   sudo make -C server benchmark-standard"
	@echo "Single core:     make -C server benchmark-traffic-core PROFILE=standard OUTPUT=/tmp/core.json"
	@echo "Linux TSan core: make -C server benchmark-core-tsan PROFILE=smoke OUTPUT=/tmp/core-tsan.json"
	@echo "Real BPF maps:   sudo make -C server benchmark-bpf-maps PROFILE=standard OUTPUT=/tmp/maps.json"
	@echo "TC pressure:     sudo make -C server benchmark-kernel-pressure PROFILE=standard OUTPUT=/tmp/kernel.json"
	@echo "Event driver:    make -C server benchmark-event-driver  # Linux/Lima only"

# 删除全部服务端生成产物，下一次构建会重新生成协议和 eBPF 文件。
clean:
	rm -rf $(BIN_DIR) $(BUILD_DIR)

# 使用环境变量指定地址运行服务端，默认仅监听本机 50051 端口。
run: $(TARGET)
	WEAKNET_GRPC_ADDRESS=$${WEAKNET_GRPC_ADDRESS:-127.0.0.1:50051} $(TARGET)
