#pragma once

#include "rate_limiter.hpp"
#include "socket_utils.hpp"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

namespace honeypot {

struct ProxyConfig {
    std::string bind_host{"0.0.0.0"};
    std::uint16_t bind_port{2200};
    std::string backend_host{"127.0.0.1"};
    std::uint16_t backend_port{2222};
    std::size_t max_connections{1000};
    std::size_t max_per_ip{5};
    std::uint32_t rate_limit{10};
    std::uint32_t rate_burst{15};
    bool send_proxy_protocol{true};
};

enum class SessionState : std::uint8_t {
    Connecting,
    Established,
    Closing,
};

enum class SocketRole : std::uint8_t {
    Client = 0,
    Backend = 1,
};

struct ProxySession {
    UniqueFd client_fd;
    UniqueFd backend_fd;
    std::vector<std::uint8_t> to_backend_buf;
    std::vector<std::uint8_t> to_client_buf;
    std::size_t to_backend_head{0};
    std::size_t to_client_head{0};
    SessionState state{SessionState::Connecting};
    bool client_read_eof{false};
    bool backend_read_eof{false};
    bool client_wr_shutdown{false};
    bool backend_wr_shutdown{false};
    std::uint32_t client_events{0};
    std::uint32_t backend_events{0};
    RateLimiter::Lease lease;
    std::string proxy_header;
};

class ProxyServer {
public:
    explicit ProxyServer(ProxyConfig config);

    ProxyServer(const ProxyServer&) = delete;
    ProxyServer& operator=(const ProxyServer&) = delete;
    ProxyServer(ProxyServer&&) = delete;
    ProxyServer& operator=(ProxyServer&&) = delete;

    ~ProxyServer();

    [[nodiscard]] bool init();
    void run();
    void stop() noexcept;

    [[nodiscard]] const ProxyConfig& config() const noexcept;
    [[nodiscard]] bool listening() const noexcept;

private:
    [[nodiscard]] bool setup_epoll();
    void teardown() noexcept;
    void accept_ready();
    [[nodiscard]] bool spawn_session(
        UniqueFd client_fd,
        std::string client_ip,
        std::string proxy_header);
    void inject_proxy_header(ProxySession& session) const;
    [[nodiscard]] bool open_backend(UniqueFd& out_fd, bool& established);
    void handle_event(std::uint64_t token, std::uint32_t events);
    void handle_session_event(std::uint64_t id, SocketRole role, std::uint32_t events);
    [[nodiscard]] bool finish_connect(std::uint64_t id);
    [[nodiscard]] bool pump_read(std::uint64_t id, SocketRole src);
    [[nodiscard]] bool flush_write(std::uint64_t id, SocketRole dest);
    void on_read_eof(std::uint64_t id, SocketRole src);
    void maybe_complete(std::uint64_t id);
    void destroy_session(std::uint64_t id);
    [[nodiscard]] ProxySession* find_session(std::uint64_t id);
    [[nodiscard]] bool set_watch(
        int fd,
        std::uint64_t token,
        std::uint32_t events,
        std::uint32_t& current);
    void refresh_events(ProxySession& session, std::uint64_t id);
    [[nodiscard]] std::uint32_t desired_events(const ProxySession& session, SocketRole role) const;

    ProxyConfig config_;
    UniqueFd listen_fd_;
    UniqueFd epoll_fd_;
    UniqueFd wakeup_fd_;
    std::atomic<int> wakeup_raw_{-1};
    std::atomic<bool> running_{false};
    std::uint64_t next_session_id_{1};
    RateLimiter rate_limiter_;
    std::unordered_map<std::uint64_t, std::unique_ptr<ProxySession>> sessions_;
};

}  // namespace honeypot
