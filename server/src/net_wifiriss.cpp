// Wi-Fi RSSI 客户端：通过 wpa_supplicant UNIX 控制套接字执行 SIGNAL_POLL。
// 支持常见控制目录探测，并在必要时尝试拉起 wpa_supplicant。
#include "net_wifiriss.h"

#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <unistd.h>
#include <cstring>
#include <cstdio>
#include <iostream>
#include <vector>
#include <cstdlib>
#include <thread>
#include <chrono>

// 检查控制目录、配置或可执行文件是否存在。
static bool pathExists(const std::string& p) {
    struct stat st{};
    return ::stat(p.c_str(), &st) == 0;
}

// 确保控制目录存在；已有非目录路径视为失败。
static bool ensureDir(const std::string& d) {
    struct stat st{};
    if (::stat(d.c_str(), &st) == 0) return S_ISDIR(st.st_mode);
    return ::mkdir(d.c_str(), 0775) == 0;
}

// 在控制套接字缺失时尝试后台启动 wpa_supplicant，并等待 socket 就绪。
static bool launchWpaSupplicant(const std::string& iface, const std::string& ctrlDir) {
    const char* bin = "/sbin/wpa_supplicant";
    if (!pathExists(bin)) bin = "/usr/sbin/wpa_supplicant";
    if (!pathExists(bin)) return false;
    const char* conf = std::getenv("WPA_SUPPLICANT_CONF");
    if (!conf || !*conf) conf = "/etc/wpa_supplicant/wpa_supplicant.conf";
    if (!pathExists(conf)) return false;
    if (!ensureDir(ctrlDir)) return false;
    // -B 让进程后台运行，-C 明确控制目录；启动依赖系统权限和有效配置。
    std::string cmd = std::string(bin) + " -B -i " + iface + " -c " + conf + " -C " + ctrlDir + " 2>/dev/null";
    int rc = ::system(cmd.c_str());
    if (rc != 0) return false;
    // 等待 socket 文件出现
    const std::string sockPath = ctrlDir + "/" + iface;
    for (int i = 0; i < 20; ++i) {
        if (pathExists(sockPath)) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    return false;
}

std::once_flag WiFiRssiClient::s_onceFlag;
std::shared_ptr<WiFiRssiClient> WiFiRssiClient::s_instance;

// 通过 call_once 创建共享控制客户端，避免并发初始化多个单例对象。
std::shared_ptr<WiFiRssiClient> WiFiRssiClient::getInstance() {
    std::call_once(s_onceFlag, [](){ 
        std::cerr << "[wifi] Creating WiFiRssiClient instance" << std::endl;
        s_instance = std::make_shared<WiFiRssiClient>(); 
        std::cerr << "[wifi] WiFiRssiClient instance created" << std::endl;
    });
    std::cerr << "[wifi] Returning WiFiRssiClient instance" << std::endl;
    return s_instance;
}

// 套接字按 connect 延迟创建，构造阶段不访问系统资源。
WiFiRssiClient::WiFiRssiClient() = default;
// 关闭控制套接字并删除本地临时 socket 路径。
WiFiRssiClient::~WiFiRssiClient() {
    if (sockfd_ != -1) {
        close(sockfd_);
        sockfd_ = -1;
    }
    if (!localSockPath_.empty()) {
        unlink(localSockPath_.c_str());
    }
}

// 为指定接口建立本地 UNIX DGRAM 端点，并依次尝试候选控制目录。
bool WiFiRssiClient::connect(const std::string& ifaceName, const std::string& ctrlDir) {
    std::cerr << "[wifi] connect: starting, iface=" << ifaceName << ", ctrlDir=" << ctrlDir << std::endl;
    iface_ = ifaceName;

    sockfd_ = ::socket(AF_UNIX, SOCK_DGRAM, 0);
    if (sockfd_ < 0) {
        std::cerr << "[wifi] socket() failed" << std::endl;
        return false;
    }
    std::cerr << "[wifi] connect: socket created, fd=" << sockfd_ << std::endl;
    
    if (!bindLocal()) {
        std::cerr << "[wifi] connect: bindLocal() failed" << std::endl;
        return false;
    }
    std::cerr << "[wifi] connect: bindLocal() succeeded" << std::endl;

    // 显式参数优先，其次环境变量，最后回退到两个 Linux 常见目录。
    std::vector<std::string> candidates;
    if (!ctrlDir.empty()) candidates.push_back(ctrlDir);
    const char* envDir = std::getenv("WPA_CTRL_DIR");
    if (envDir && *envDir) candidates.emplace_back(envDir);
    candidates.emplace_back("/run/wpa_supplicant");
    candidates.emplace_back("/var/run/wpa_supplicant");

    std::cerr << "[wifi] connect: trying " << candidates.size() << " candidate directories" << std::endl;
    for (const auto& d : candidates) {
        std::cerr << "[wifi] connect: trying directory " << d << std::endl;
        ctrlDir_ = d;
        if (connectRemote()) {
            std::cerr << "[wifi] connect: connected to " << d << std::endl;
            return true;
        }
        std::cerr << "[wifi] connect: failed to connect to " << d << std::endl;
    }

    // 候选均失败时尝试自动拉起服务；该分支通常需要 root 权限。
    // 优先使用 /run，无法创建时再兼容 /var/run。
    std::string pref = "/run/wpa_supplicant";
    if (!ensureDir(pref)) pref = "/var/run/wpa_supplicant";
    if (ensureDir(pref)) {
        if (launchWpaSupplicant(iface_, pref)) {
            ctrlDir_ = pref;
            if (connectRemote()) {
                return true;
            }
        }
    }

    std::cerr << "[wifi] unable to connect to wpa_supplicant control socket for iface '" << iface_ << "' (auto-start may require root)" << std::endl;
    close(sockfd_);
    sockfd_ = -1;
    if (!localSockPath_.empty()) {
        unlink(localSockPath_.c_str());
        localSockPath_.clear();
    }
    return false;
}

// 以 PID 和接口名生成唯一客户端路径，清理陈旧文件后绑定本地端点。
bool WiFiRssiClient::bindLocal() {
    struct sockaddr_un local{};
    local.sun_family = AF_UNIX;
    char tmp[108]{};
    std::snprintf(tmp, sizeof(tmp), "/tmp/wpa_ctrl_%d_%s", getpid(), iface_.c_str());
    localSockPath_ = tmp;
    std::strncpy(local.sun_path, localSockPath_.c_str(), sizeof(local.sun_path) - 1);

    unlink(local.sun_path);
    if (::bind(sockfd_, reinterpret_cast<struct sockaddr*>(&local), sizeof(local)) < 0) {
        std::cerr << "[wifi] bind() failed: " << local.sun_path << std::endl;
        close(sockfd_);
        sockfd_ = -1;
        return false;
    }
    return true;
}

// 连接 wpa_supplicant 服务端路径，并设置一秒接收超时边界。
bool WiFiRssiClient::connectRemote() {
    struct sockaddr_un dest{};
    dest.sun_family = AF_UNIX;
    std::string destPath = ctrlDir_ + "/" + iface_;
    if (destPath.size() >= sizeof(dest.sun_path)) {
        std::cerr << "[wifi] dest path too long: " << destPath << std::endl;
        return false;
    }
    std::strcpy(dest.sun_path, destPath.c_str());

    // UNIX DGRAM connect 本身通常立即返回，接收超时用于后续命令应答。
    struct timeval tv;
    tv.tv_sec = 1;  // 1秒超时
    tv.tv_usec = 0;
    if (::setsockopt(sockfd_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        std::cerr << "[wifi] setsockopt() failed" << std::endl;
    }

    if (::connect(sockfd_, reinterpret_cast<struct sockaddr*>(&dest), sizeof(dest)) < 0) {
        return false;
    }
    return true;
}

// 发送控制命令并在一秒内读取单个响应，超时或系统调用失败返回空串。
std::string WiFiRssiClient::sendCommand(const std::string& cmd) {
    if (sockfd_ == -1) return {};
    if (::send(sockfd_, cmd.c_str(), cmd.size(), 0) < 0) {
        std::cerr << "[wifi] send() failed" << std::endl;
        return {};
    }
    
    // 每次命令前重申超时，避免外部修改套接字选项后产生无限等待。
    struct timeval tv;
    tv.tv_sec = 1;  // 1秒超时
    tv.tv_usec = 0;
    if (::setsockopt(sockfd_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        std::cerr << "[wifi] setsockopt() failed" << std::endl;
    }
    
    char buf[4096];
    ssize_t n = ::recv(sockfd_, buf, sizeof(buf) - 1, 0);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            std::cerr << "[wifi] recv() timeout" << std::endl;
        } else {
            std::cerr << "[wifi] recv() failed: " << strerror(errno) << std::endl;
        }
        return {};
    }
    buf[n] = '\0';
    return std::string(buf, static_cast<size_t>(n));
}

// 执行 SIGNAL_POLL 并解析 RSSI 字段；失败使用 -1000 作为无效哨兵值。
int WiFiRssiClient::getRssi() {
    std::string resp = sendCommand("SIGNAL_POLL\n");
    if (resp.empty()) return -1000;

    // 解析样例行：RSSI=-42
    size_t pos = resp.find("RSSI=");
    if (pos != std::string::npos) {
        int rssi = 0;
        if (std::sscanf(resp.c_str() + pos, "RSSI=%d", &rssi) == 1) {
            return rssi;
        }
    }
    return -1000;
}
