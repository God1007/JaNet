// 服务端可执行程序入口：把完整进程生命周期交给 start_server 管理。
#include "server.hpp"

// 启动网络诊断服务，并将服务退出码透传给操作系统。
int main() {
    return weaknet_grpc::start_server();
}
