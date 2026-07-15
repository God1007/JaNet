#!/usr/bin/env python3
"""GrpcServer 并发 wait/shutdown/析构的源码级生命周期契约测试。"""

import unittest
from pathlib import Path


SERVER_ROOT = Path(__file__).resolve().parents[1]


class GrpcLifecycleContractTest(unittest.TestCase):
    """用源码结构断言保护 gRPC server 的并发关闭协议。"""

    def test_wait_keeps_shared_server_alive_and_shutdown_wakes_streams_first(self):
        """验证 wait 持有 server，且 shutdown 先唤醒订阅流再关闭 gRPC。"""

        # 这个测试不启动真实端口，而是把生命周期所需的同步原语当作源码契约。
        # 这样即使目标机器缺少可用端口，也能阻止 shared_ptr/mutex/cv 被误删。
        header = (SERVER_ROOT / "include" / "grpc_service.hpp").read_text(encoding="utf-8")
        source = (SERVER_ROOT / "src" / "grpc_service.cpp").read_text(encoding="utf-8")

        # wait() 与 shutdown() 会并发访问 server_；shared ownership 保证 shutdown
        # 清空成员后，已经进入 Wait() 的线程仍持有合法对象。
        self.assertIn("std::shared_ptr<grpc::Server> server_", header)
        self.assertIn("std::mutex lifecycle_mutex_", header)
        self.assertIn("std::condition_variable lifecycle_cv_", header)

        # 截取函数体而不是在整文件搜索，避免同名代码出现在别处造成假通过。
        wait_body = source[source.index("void GrpcServer::wait()") : source.index("void GrpcServer::shutdown()")]
        self.assertIn("std::shared_ptr<grpc::Server> server", wait_body)
        self.assertIn("server = server_", wait_body)
        self.assertIn("server->Wait()", wait_body)

        # 关闭顺序是核心不变量：先使订阅者退出并 notify，再调用 Server::Shutdown；
        # 最后等待并发 shutdown 完成，避免析构线程提前释放生命周期状态。
        shutdown_body = source[source.index("void GrpcServer::shutdown()") : source.index("void GrpcServer::publish")]
        self.assertLess(shutdown_body.index("subscriber->active = false"), shutdown_body.index("server->Shutdown()"))
        self.assertLess(shutdown_body.index("subscriber->cv.notify_all()"), shutdown_body.index("server->Shutdown()"))
        self.assertIn("lifecycle_cv_.wait", shutdown_body)
        self.assertIn("shutdown_complete_ = true", shutdown_body)


if __name__ == "__main__":
    unittest.main()
