#include "proxy_server.hpp"

#include <atomic>
#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <signal.h>
#include <string_view>

namespace {

constexpr std::string_view kUsage =
    "Usage: honeypot_proxy [options]\n"
    "\n"
    "Options:\n"
    "  -l, --listen-port <port>   Front-door listen port (default: 2200)\n"
    "  -b, --backend-port <port>  Python SSH backend port (default: 2222)\n"
    "  -h, --backend-host <host>  Python SSH backend host (default: 127.0.0.1)\n"
    "      --dry-run              Initialize the listen socket, print config, and exit\n"
    "      --help                 Show this help and exit\n";

std::atomic<honeypot::ProxyServer*> g_server{nullptr};

extern "C" void handle_signal(int /*signum*/) {
    honeypot::ProxyServer* const server = g_server.load(std::memory_order_acquire);
    if (server != nullptr) {
        server->stop();
    }
}

[[nodiscard]] bool parse_port(const char* text, std::uint16_t& out) {
    if (text == nullptr || *text == '\0') {
        return false;
    }
    char* end = nullptr;
    errno = 0;
    const unsigned long value = std::strtoul(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' || value == 0UL || value > 65535UL) {
        return false;
    }
    out = static_cast<std::uint16_t>(value);
    return true;
}

[[nodiscard]] const char* require_arg(int argc, char** argv, int& index, std::string_view flag) {
    if (index + 1 >= argc) {
        std::cerr << "[honeypot_proxy] missing argument for " << flag << '\n';
        return nullptr;
    }
    ++index;
    return argv[index];
}

void print_config(const honeypot::ProxyConfig& cfg, bool dry_run) {
    std::cout << "[honeypot_proxy]"
              << " bind_host=" << cfg.bind_host
              << " bind_port=" << cfg.bind_port
              << " backend_host=" << cfg.backend_host
              << " backend_port=" << cfg.backend_port
              << " dry_run=" << (dry_run ? "true" : "false")
              << std::endl;
}

[[nodiscard]] bool install_stop_handlers() {
    struct sigaction action {};
    action.sa_handler = handle_signal;
    sigemptyset(&action.sa_mask);
    action.sa_flags = 0;
    if (::sigaction(SIGINT, &action, nullptr) != 0) {
        std::cerr << "[honeypot_proxy] sigaction(SIGINT) failed: " << std::strerror(errno) << '\n';
        return false;
    }
    if (::sigaction(SIGTERM, &action, nullptr) != 0) {
        std::cerr << "[honeypot_proxy] sigaction(SIGTERM) failed: " << std::strerror(errno) << '\n';
        return false;
    }

    struct sigaction ignore_pipe {};
    ignore_pipe.sa_handler = SIG_IGN;
    sigemptyset(&ignore_pipe.sa_mask);
    ignore_pipe.sa_flags = 0;
    if (::sigaction(SIGPIPE, &ignore_pipe, nullptr) != 0) {
        std::cerr << "[honeypot_proxy] sigaction(SIGPIPE) failed: " << std::strerror(errno) << '\n';
        return false;
    }
    return true;
}

}  // namespace

int main(int argc, char** argv) {
    honeypot::ProxyConfig config{};
    bool dry_run = false;

    for (int i = 1; i < argc; ++i) {
        const std::string_view arg = argv[i];
        if (arg == "--help") {
            std::cout << kUsage;
            return 0;
        }
        if (arg == "--dry-run") {
            dry_run = true;
            continue;
        }
        if (arg == "-l" || arg == "--listen-port") {
            const char* const value = require_arg(argc, argv, i, arg);
            if (value == nullptr) {
                return 2;
            }
            if (!parse_port(value, config.bind_port)) {
                std::cerr << "[honeypot_proxy] invalid listen port\n";
                return 2;
            }
            continue;
        }
        if (arg == "-b" || arg == "--backend-port") {
            const char* const value = require_arg(argc, argv, i, arg);
            if (value == nullptr) {
                return 2;
            }
            if (!parse_port(value, config.backend_port)) {
                std::cerr << "[honeypot_proxy] invalid backend port\n";
                return 2;
            }
            continue;
        }
        if (arg == "-h" || arg == "--backend-host") {
            const char* const value = require_arg(argc, argv, i, arg);
            if (value == nullptr) {
                return 2;
            }
            if (*value == '\0') {
                std::cerr << "[honeypot_proxy] invalid backend host\n";
                return 2;
            }
            config.backend_host = value;
            continue;
        }
        std::cerr << "[honeypot_proxy] unknown option: " << arg << '\n';
        std::cerr << kUsage;
        return 2;
    }

    print_config(config, dry_run);

    honeypot::ProxyServer server{std::move(config)};
    if (!server.init()) {
        return 1;
    }

    if (dry_run) {
        std::cout << "[honeypot_proxy] dry-run init ok listening="
                  << (server.listening() ? "true" : "false") << '\n';
        return 0;
    }

    if (!install_stop_handlers()) {
        return 1;
    }
    g_server.store(&server, std::memory_order_release);
    std::cout << "[honeypot_proxy] running (SIGINT/SIGTERM to stop)" << std::endl;
    server.run();
    g_server.store(nullptr, std::memory_order_release);
    std::cout << "[honeypot_proxy] stopped" << std::endl;
    return 0;
}
