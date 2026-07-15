# 根构建入口：编排服务端、客户端动态库、测试程序和 Dashboard 相关目标。
# 路径变量统一由 config.mk 提供，便于在仓库根目录执行全部命令。
include config.mk

# C++ 编译器与通用告警、优化选项。
CC=g++
CXXFLAGS=-std=c++17 -O2 -Wall -Wextra -Wpedantic

# 优先通过 pkg-config 获取 gRPC/Protobuf 参数，缺失时使用基础链接回退项。
GRPC_CFLAGS=$(shell pkg-config --cflags grpc++ protobuf 2>/dev/null)
GRPC_LIBS=$(shell pkg-config --libs grpc++ protobuf 2>/dev/null)
GRPC_FALLBACK_LIBS=-lgrpc++ -lprotobuf -lpthread

# 客户端与服务端共用服务端生成的 Protobuf/gRPC C++ 代码。
SERVER_PROTO_GEN_DIR=$(SERVER_DIR)/build/generated
PROTO_SRCS=$(SERVER_PROTO_GEN_DIR)/weaknet.pb.cc $(SERVER_PROTO_GEN_DIR)/weaknet.grpc.pb.cc

# 客户端库和测试程序使用的头文件搜索路径与链接参数。
INCLUDES=$(GRPC_CFLAGS) -I$(SERVER_DIR)/include -I$(CLIENT_DIR) -I$(SERVER_PROTO_GEN_DIR)
LDFLAGS=$(if $(GRPC_LIBS),$(GRPC_LIBS),$(GRPC_FALLBACK_LIBS)) -lglog

# 客户端动态库及其命令行测试程序的源文件集合。
SRC_CLIENT_LIB=client/client.cpp server/src/serializer.cpp $(PROTO_SRCS)
SRC_CLIENT_TEST=client/test_client.cpp

# 默认目标：创建输出目录并构建服务端、客户端库和测试程序。
all: dirs server-client-lib

# 先委托 server/Makefile 构建服务端，再链接客户端动态库与测试程序。
server-client-lib:
	@$(MAKE) -C server
	@echo "Building WeakNet gRPC client shared library..."
	@mkdir -p $(CLIENT_LIB_DIR) $(CLIENT_BIN_DIR)
	$(CC) $(CXXFLAGS) $(INCLUDES) -fPIC -shared -o $(CLIENT_LIB_DIR)/libweaknet.so $(SRC_CLIENT_LIB) $(LDFLAGS)
	@echo "Building WeakNet client test program..."
	$(CC) $(CXXFLAGS) $(INCLUDES) -o $(CLIENT_BIN_DIR)/test-client $(SRC_CLIENT_TEST) -L$(CLIENT_LIB_DIR) -lweaknet $(LDFLAGS)

# 兼容旧目标名，实际复用完整构建流程。
server-client: server-client-lib

# 创建本地构建、二进制和客户端产物目录。
dirs:
	mkdir -p $(BUILD_DIR) $(BIN_DIR) $(CLIENT_BIN_DIR) $(CLIENT_LIB_DIR)

# 压测编排器参数；调用方可从命令行覆盖 Python/Node、组件、输出目录和额外开关。
PYTHON ?= python3
NODE ?= node
STRESS_PROFILE ?= smoke
STRESS_COMPONENTS ?= auto
STRESS_OUTPUT_DIR ?=
STRESS_ARGS ?=
STRESS_OUTPUT_OPTION=$(if $(STRESS_OUTPUT_DIR),--output-dir "$(STRESS_OUTPUT_DIR)",)

# 下列目标名不对应同名文件，始终按命令目标执行。
.PHONY: clean run-server run-client test-client test-lib test-events test-all test-ping test-performance dashboard-install run-dashboard dashboard-build stress-test stress-smoke stress-standard stress-linux-standard

# 清理服务端及客户端生成产物，不删除源码和配置。
clean:
	@$(MAKE) -C server clean
	rm -rf $(CLIENT_BIN_DIR) $(CLIENT_LIB_DIR)
	rm -f *.bin

# 使用环境变量指定地址启动服务端，未设置时监听本机 50051 端口。
run-server: server-client-lib
	WEAKNET_GRPC_ADDRESS=$${WEAKNET_GRPC_ADDRESS:-127.0.0.1:50051} $(BIN_DIR)/weaknet-grpc-server

# 按 COMMAND 参数运行单项或组合客户端测试。
test-client: server-client-lib
	@if [ "$(COMMAND)" = "" ]; then \
		echo "Usage: make test-client COMMAND=[all|get|health|file|ping|check|events|event-types|test-*]"; \
		echo "Examples: make test-client COMMAND=all"; \
		echo "          make test-client COMMAND=get"; \
		echo "          make test-client COMMAND='ping google.com'"; \
		echo "          make test-client COMMAND=test-basic"; \
	else \
		echo "Running client test program: $(COMMAND)"; \
		LD_LIBRARY_PATH=$(CLIENT_LIB_DIR):$$LD_LIBRARY_PATH WEAKNET_GRPC_ADDRESS=$${WEAKNET_GRPC_ADDRESS:-127.0.0.1:50051} $(CLIENT_BIN_DIR)/test-client $(COMMAND); \
	fi

# 验证客户端动态库的基础加载和调用链。
test-lib: server-client-lib
	@echo "Running shared library smoke test..."
	LD_LIBRARY_PATH=$(CLIENT_LIB_DIR):$$LD_LIBRARY_PATH WEAKNET_GRPC_ADDRESS=$${WEAKNET_GRPC_ADDRESS:-127.0.0.1:50051} $(CLIENT_BIN_DIR)/test-client lib-test

# 运行服务端流式事件订阅测试。
test-events: server-client-lib
	@echo "Running event listener test..."
	LD_LIBRARY_PATH=$(CLIENT_LIB_DIR):$$LD_LIBRARY_PATH WEAKNET_GRPC_ADDRESS=$${WEAKNET_GRPC_ADDRESS:-127.0.0.1:50051} $(CLIENT_BIN_DIR)/test-client test-events

# 执行客户端提供的完整 API 验证集合。
test-all: server-client-lib
	@echo "Running full API validation..."
	LD_LIBRARY_PATH=$(CLIENT_LIB_DIR):$$LD_LIBRARY_PATH WEAKNET_GRPC_ADDRESS=$${WEAKNET_GRPC_ADDRESS:-127.0.0.1:50051} $(CLIENT_BIN_DIR)/test-client all

# 执行主动 Ping 功能测试。
test-ping: server-client-lib
	@echo "Running ping test..."
	LD_LIBRARY_PATH=$(CLIENT_LIB_DIR):$$LD_LIBRARY_PATH WEAKNET_GRPC_ADDRESS=$${WEAKNET_GRPC_ADDRESS:-127.0.0.1:50051} $(CLIENT_BIN_DIR)/test-client test-ping

# 执行客户端性能测试。
test-performance: server-client-lib
	@echo "Running performance test..."
	LD_LIBRARY_PATH=$(CLIENT_LIB_DIR):$$LD_LIBRARY_PATH WEAKNET_GRPC_ADDRESS=$${WEAKNET_GRPC_ADDRESS:-127.0.0.1:50051} $(CLIENT_BIN_DIR)/test-client test-performance

# 以前台订阅模式运行测试客户端。
run-client: server-client-lib
	@echo "Running client subscribe mode..."
	LD_LIBRARY_PATH=$(CLIENT_LIB_DIR):$$LD_LIBRARY_PATH WEAKNET_GRPC_ADDRESS=$${WEAKNET_GRPC_ADDRESS:-127.0.0.1:50051} $(CLIENT_BIN_DIR)/test-client subscribe

# 安装 Dashboard 的 Node.js 依赖。
dashboard-install:
	npm --prefix dashboard install

# 启动 Dashboard 开发服务器。
run-dashboard:
	npm --prefix dashboard run dev

# 构建 Dashboard 静态产物。
dashboard-build:
	npm --prefix dashboard run build

# 统一压力测试入口：默认自动选择当前平台可运行的组件并生成 JSON/Markdown 报告。
stress-test:
	"$(PYTHON)" benchmarks/run_stress_suite.py --profile "$(STRESS_PROFILE)" --components "$(STRESS_COMPONENTS)" --python "$(PYTHON)" --node "$(NODE)" $(STRESS_OUTPUT_OPTION) $(STRESS_ARGS)

# macOS/普通开发环境的快速回归档。
stress-smoke:
	@$(MAKE) stress-test STRESS_PROFILE=smoke

# 提交前标准性能基线；具体组件可用 STRESS_COMPONENTS 覆盖。
stress-standard:
	@$(MAKE) stress-test STRESS_PROFILE=standard

# Linux VM 的真 BPF map 与 72k flow 标准档；该快捷目标强制特权和 strict 门禁。
stress-linux-standard:
	@$(MAKE) stress-test STRESS_PROFILE=standard STRESS_COMPONENTS=core,sanitizer,bpf,kernel STRESS_ARGS="$(STRESS_ARGS) --sudo-linux --strict"
