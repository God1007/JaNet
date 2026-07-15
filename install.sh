#!/bin/bash
# WeakNet 安装与验收脚本：检查 Linux 环境、按需安装依赖、构建并执行冒烟测试。
# 脚本还会在仓库根目录生成便捷的服务端启动和客户端测试脚本。

set -e

# 终端颜色转义序列，仅用于提高安装过程的可读性。
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 输出蓝色信息消息。
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

# 输出绿色成功消息。
print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

# 输出黄色警告消息。
print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# 输出红色错误消息。
print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# 检测 root 身份并要求显式确认，避免依赖安装误改系统环境。
check_root() {
    if [ "$EUID" -eq 0 ]; then
        print_warning "检测到root用户，建议使用普通用户运行此脚本"
        read -p "是否继续? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
}

# 从 /etc/os-release 读取发行版名称和版本；无法识别时终止。
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$NAME
        VERSION=$VERSION_ID
    else
        print_error "无法检测操作系统"
        exit 1
    fi
    
    print_info "检测到操作系统: $OS $VERSION"
}

# 根据已识别的发行版安装编译器、gRPC/Protobuf、glog 和 eBPF 依赖。
install_dependencies() {
    print_info "安装系统依赖..."
    
    case "$OS" in
        "Ubuntu"|"Debian GNU/Linux")
            sudo apt-get update
            sudo apt-get install -y \
                build-essential \
                clang \
                llvm \
                pkg-config \
                libgrpc++-dev \
                protobuf-compiler \
                protobuf-compiler-grpc \
                libgoogle-glog-dev \
                libelf-dev \
                zlib1g-dev \
                libcap-dev \
                linux-headers-$(uname -r) \
                libbpf-dev
            ;;
        "CentOS Linux"|"Red Hat Enterprise Linux")
            sudo yum groupinstall -y "Development Tools"
            sudo yum install -y \
                clang \
                llvm \
                pkgconfig \
                grpc-devel \
                protobuf-devel \
                protobuf-compiler \
                glog-devel \
                elfutils-libelf-devel \
                zlib-devel \
                libcap-devel \
                kernel-devel-$(uname -r) \
                libbpf-devel
            ;;
        "Fedora")
            sudo dnf groupinstall -y "Development Tools"
            sudo dnf install -y \
                clang \
                llvm \
                pkgconfig \
                grpc-devel \
                protobuf-devel \
                protobuf-compiler \
                grpc-plugins \
                glog-devel \
                elfutils-libelf-devel \
                zlib-devel \
                libcap-devel \
                kernel-devel-$(uname -r) \
                libbpf-devel
            ;;
        *)
            print_warning "未识别的操作系统: $OS"
            print_info "请手动安装以下依赖:"
            print_info "  - build-essential (或 Development Tools)"
            print_info "  - clang, llvm"
            print_info "  - pkg-config"
            print_info "  - gRPC C++ development package"
            print_info "  - protobuf compiler and grpc_cpp_plugin"
            print_info "  - libglog-dev (或 glog-devel)"
            print_info "  - libelf-dev (或 elfutils-libelf-devel)"
            print_info "  - zlib1g-dev (或 zlib-devel)"
            print_info "  - libcap-dev (或 libcap-devel)"
            print_info "  - linux-headers-$(uname -r) (或 kernel-devel)"
            print_info "  - libbpf-dev (或 libbpf-devel)"
            read -p "是否继续编译? (y/N): " -n 1 -r
            echo
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                exit 1
            fi
            ;;
    esac
    
    print_success "依赖安装完成"
}

# 只读检查构建所需命令和 pkg-config 包；缺项时汇总后终止。
check_dependencies() {
    print_info "检查编译依赖..."
    
    local missing_deps=()
    
    # 检查 C++ 与 eBPF 编译器。
    if ! command -v g++ &> /dev/null; then
        missing_deps+=("g++")
    fi
    
    if ! command -v clang &> /dev/null; then
        missing_deps+=("clang")
    fi
    
    # 检查依赖发现工具和协议代码生成工具。
    if ! command -v pkg-config &> /dev/null; then
        missing_deps+=("pkg-config")
    fi
    
    if ! command -v protoc &> /dev/null; then
        missing_deps+=("protobuf-compiler")
    fi

    if ! command -v grpc_cpp_plugin &> /dev/null; then
        missing_deps+=("grpc_cpp_plugin")
    fi

    # 检查 gRPC、Protobuf 和 glog 开发库。
    if ! pkg-config --exists grpc++; then
        missing_deps+=("grpc++")
    fi

    if ! pkg-config --exists protobuf; then
        missing_deps+=("protobuf")
    fi
    
    if ! pkg-config --exists libglog; then
        missing_deps+=("libglog-dev")
    fi
    
    if [ ${#missing_deps[@]} -ne 0 ]; then
        print_error "缺少以下依赖: ${missing_deps[*]}"
        print_info "请运行: $0 --install-deps"
        exit 1
    fi
    
    print_success "所有依赖检查通过"
}

# 清理旧产物后执行完整构建；任一构建步骤失败即终止脚本。
build_project() {
    print_info "编译WEAK_NET项目..."
    
    # 清理之前的编译产物；首次运行没有产物时允许 clean 失败。
    make clean 2>/dev/null || true
    
    # 构建服务端、客户端动态库及测试程序。
    if make all; then
        print_success "编译成功"
    else
        print_error "编译失败"
        exit 1
    fi
}

# 临时启动服务端并执行 GetInterfaces 冒烟测试，结束后回收子进程。
run_tests() {
    print_info "运行基本测试..."
    
    # 已有服务端运行时避免启动第二个同端口进程。
    if pgrep -f weaknet-grpc-server > /dev/null; then
        print_warning "检测到服务器已在运行，跳过测试"
        return 0
    fi
    
    # 后台启动服务端并记录 PID，地址可由环境变量覆盖。
    print_info "启动服务器进行测试..."
    WEAKNET_GRPC_ADDRESS=${WEAKNET_GRPC_ADDRESS:-127.0.0.1:50051} ./server/bin/weaknet-grpc-server &
    local server_pid=$!
    
    # 为协议监听和初始网络采集预留启动时间，单位秒。
    sleep 3
    
    # 运行一次获取接口列表的基础调用链。
    if make test-client COMMAND=get; then
        print_success "基本功能测试通过"
    else
        print_warning "基本功能测试失败"
    fi
    
    # 结束本函数创建的服务端进程。
    kill $server_pid 2>/dev/null || true
    sleep 1
}

# 生成面向用户的启动与测试包装脚本，并授予执行权限。
create_scripts() {
    print_info "创建启动脚本..."
    
    # 创建固定从仓库根目录启动服务端的包装脚本。
    cat > start-server.sh << 'EOF'
#!/bin/bash
# WeakNet 服务端启动脚本：在仓库根目录启动 gRPC 服务。

cd "$(dirname "$0")"

# 使用环境变量指定监听地址，默认仅监听本机 50051 端口。
echo "启动WEAK_NET服务器..."
WEAKNET_GRPC_ADDRESS=${WEAKNET_GRPC_ADDRESS:-127.0.0.1:50051} ./server/bin/weaknet-grpc-server
EOF

    # 创建先检查服务端进程、再转发测试命令的客户端包装脚本。
    cat > test-client.sh << 'EOF'
#!/bin/bash
# WeakNet 客户端测试脚本：确认服务端存在后执行指定测试命令。

cd "$(dirname "$0")"

# 未检测到服务端进程时立即给出启动提示。
if ! pgrep -f weaknet-grpc-server > /dev/null; then
    echo "错误: 服务器未运行，请先启动服务器"
    echo "运行: ./start-server.sh"
    exit 1
fi

# 未传参数时默认执行完整测试集合。
make test-client COMMAND="${1:-all}"
EOF

    chmod +x start-server.sh test-client.sh
    
    print_success "启动脚本创建完成"
}

# 输出安装完成后的常用启动、测试和构建命令。
show_usage() {
    print_info "WEAK_NET 项目安装完成!"
    echo
    echo "使用方法:"
    echo "  启动服务器: ./start-server.sh"
    echo "  运行测试:   ./test-client.sh [command]"
    echo "  编译项目:   make all"
    echo "  清理项目:   make clean"
    echo
    echo "可用测试命令:"
    echo "  all          - 运行所有测试"
    echo "  get          - 获取网络接口信息"
    echo "  health       - 网络健康检查"
    echo "  events       - 事件监听测试"
    echo "  ping <host>  - Ping测试"
    echo
    echo "更多信息请查看 README.md"
}

# 安装流程入口：可单独安装依赖，默认执行检查、构建、测试和脚本生成。
main() {
    echo "WEAK_NET 项目安装脚本"
    echo "======================"
    
    # --install-deps 只执行系统依赖安装，不继续构建项目。
    if [ "$1" = "--install-deps" ]; then
        check_root
        detect_os
        install_dependencies
        exit 0
    fi
    
    # 确认当前环境已经满足构建条件。
    check_dependencies
    
    # 执行完整项目构建。
    build_project
    
    # 使用临时服务端执行基础冒烟测试。
    run_tests
    
    # 生成后续日常使用的包装脚本。
    create_scripts
    
    # 输出最终使用说明。
    show_usage
}

# 透传调用方参数并执行主流程。
main "$@"
