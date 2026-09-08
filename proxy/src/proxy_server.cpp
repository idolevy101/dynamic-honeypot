#include "proxy_server.hpp"

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <cstddef>
#include <cstring>
#include <iostream>
#include <memory>
#include <string>
#include <utility>

namespace honeypot {
namespace {

constexpr std::size_t kMaxBufferBytes = 64U * 1024U;
constexpr std::size_t kReadChunk = 16U * 1024U;
constexpr std::size_t kCompactThreshold = 8U * 1024U;
constexpr int kMaxEpollEvents = 64;
constexpr int kEpollTimeoutMs = 250;

constexpr std::uint64_t kTokenListen = 0;
constexpr std::uint64_t kTokenWakeup = 1;

constexpr std::uint32_t epoll_bit(int flag) {
    return static_cast<std::uint32_t>(flag);
}

const std::uint32_t kHangupEvents =
    epoll_bit(EPOLLERR) | epoll_bit(EPOLLHUP) | epoll_bit(EPOLLRDHUP);

struct AddrinfoDeleter {
    void operator()(addrinfo* info) const noexcept {
        if (info != nullptr) {
            ::freeaddrinfo(info);
        }
    }
};

void log_sys_error(const char* op) {
    std::cerr << "[honeypot_proxy] " << op << " failed: " << std::strerror(errno) << '\n';
}

[[nodiscard]] std::uint64_t session_token(std::uint64_t id, SocketRole role) {
    return (id << 2U) | (static_cast<std::uint64_t>(role) + 2U);
}

[[nodiscard]] bool decode_session_token(
    std::uint64_t token,
    std::uint64_t& id,
    SocketRole& role) {
    if (token < 2U) {
        return false;
    }
    const std::uint64_t tag = token & 3U;
    if (tag != 2U && tag != 3U) {
        return false;
    }
    id = token >> 2U;
    role = (tag == 2U) ? SocketRole::Client : SocketRole::Backend;
    return id != 0U;
}

[[nodiscard]] std::size_t pending_size(const std::vector<std::uint8_t>& buf, std::size_t head) {
    return buf.size() - head;
}

void compact_buf(std::vector<std::uint8_t>& buf, std::size_t& head) {
    if (head == 0U) {
        return;
    }
    if (head >= buf.size()) {
        buf.clear();
        head = 0;
        return;
    }
    const std::size_t remain = buf.size() - head;
    std::memmove(buf.data(), buf.data() + head, remain);
    buf.resize(remain);
    head = 0;
}

void consume_buf(std::vector<std::uint8_t>& buf, std::size_t& head, std::size_t nbytes) {
    head += nbytes;
    if (head >= buf.size()) {
        buf.clear();
        head = 0;
        return;
    }
    if (head >= kCompactThreshold) {
        compact_buf(buf, head);
    }
}

[[nodiscard]] UniqueFd& fd_for(ProxySession& session, SocketRole role) {
    return role == SocketRole::Client ? session.client_fd : session.backend_fd;
}

[[nodiscard]] std::vector<std::uint8_t>& out_buf(ProxySession& session, SocketRole dest) {
    return dest == SocketRole::Backend ? session.to_backend_buf : session.to_client_buf;
}

[[nodiscard]] std::size_t& out_head(ProxySession& session, SocketRole dest) {
    return dest == SocketRole::Backend ? session.to_backend_head : session.to_client_head;
}

[[nodiscard]] SocketRole peer_of(SocketRole role) {
    return role == SocketRole::Client ? SocketRole::Backend : SocketRole::Client;
}

[[nodiscard]] bool has_read_eof(const ProxySession& session, SocketRole role) {
    return role == SocketRole::Client ? session.client_read_eof : session.backend_read_eof;
}

[[nodiscard]] bool& read_eof_flag(ProxySession& session, SocketRole role) {
    return role == SocketRole::Client ? session.client_read_eof : session.backend_read_eof;
}

[[nodiscard]] bool& wr_shutdown_flag(ProxySession& session, SocketRole role) {
    return role == SocketRole::Client ? session.client_wr_shutdown : session.backend_wr_shutdown;
}

[[nodiscard]] int effective_family(const sockaddr_storage& addr) {
    if (addr.ss_family == AF_INET) {
        return AF_INET;
    }
    if (addr.ss_family == AF_INET6) {
        const auto* sa = reinterpret_cast<const sockaddr_in6*>(&addr);
        if (IN6_IS_ADDR_V4MAPPED(&sa->sin6_addr)) {
            return AF_INET;
        }
        return AF_INET6;
    }
    return AF_UNSPEC;
}

[[nodiscard]] std::uint16_t sock_port(const sockaddr_storage& addr) {
    if (addr.ss_family == AF_INET) {
        return ntohs(reinterpret_cast<const sockaddr_in*>(&addr)->sin_port);
    }
    if (addr.ss_family == AF_INET6) {
        return ntohs(reinterpret_cast<const sockaddr_in6*>(&addr)->sin6_port);
    }
    return 0;
}

[[nodiscard]] std::string peer_ip(const sockaddr_storage& addr) {
    char host[INET6_ADDRSTRLEN]{};
    if (addr.ss_family == AF_INET) {
        const auto* sa = reinterpret_cast<const sockaddr_in*>(&addr);
        if (::inet_ntop(
                AF_INET,
                &sa->sin_addr,
                host,
                static_cast<socklen_t>(sizeof(host))) == nullptr) {
            return "unknown";
        }
        return std::string{host};
    }
    if (addr.ss_family == AF_INET6) {
        const auto* sa = reinterpret_cast<const sockaddr_in6*>(&addr);
        if (IN6_IS_ADDR_V4MAPPED(&sa->sin6_addr)) {
            in_addr v4{};
            std::memcpy(&v4, &sa->sin6_addr.s6_addr[12], sizeof(v4));
            if (::inet_ntop(
                    AF_INET,
                    &v4,
                    host,
                    static_cast<socklen_t>(sizeof(host))) == nullptr) {
                return "unknown";
            }
            return std::string{host};
        }
        if (::inet_ntop(
                AF_INET6,
                &sa->sin6_addr,
                host,
                static_cast<socklen_t>(sizeof(host))) == nullptr) {
            return "unknown";
        }
        return std::string{host};
    }
    return "unknown";
}

[[nodiscard]] std::string format_proxy_v1(
    const sockaddr_storage& src,
    const sockaddr_storage& dst) {
    const std::string src_ip = peer_ip(src);
    const std::string dst_ip = peer_ip(dst);
    const int src_fam = effective_family(src);
    const int dst_fam = effective_family(dst);
    if (src_ip == "unknown" || dst_ip == "unknown") {
        return "PROXY UNKNOWN\r\n";
    }
    const char* family = nullptr;
    if (src_fam == AF_INET && dst_fam == AF_INET) {
        family = "TCP4";
    } else if (src_fam == AF_INET6 && dst_fam == AF_INET6) {
        family = "TCP6";
    } else {
        return "PROXY UNKNOWN\r\n";
    }
    std::string line = "PROXY ";
    line += family;
    line += ' ';
    line += src_ip;
    line += ' ';
    line += dst_ip;
    line += ' ';
    line += std::to_string(sock_port(src));
    line += ' ';
    line += std::to_string(sock_port(dst));
    line += "\r\n";
    return line;
}

[[nodiscard]] std::string make_proxy_v1_header(int client_fd, const sockaddr_storage& client_addr) {
    sockaddr_storage local{};
    socklen_t local_len = static_cast<socklen_t>(sizeof(local));
    if (::getsockname(client_fd, reinterpret_cast<sockaddr*>(&local), &local_len) != 0) {
        return "PROXY UNKNOWN\r\n";
    }
    return format_proxy_v1(client_addr, local);
}

}  // namespace

ProxyServer::ProxyServer(ProxyConfig config)
    : config_(std::move(config)),
      rate_limiter_(
          config_.max_connections,
          config_.max_per_ip,
          config_.rate_limit,
          config_.rate_burst) {}

ProxyServer::~ProxyServer() {
    teardown();
}

bool ProxyServer::init() {
    if (listen_fd_.valid()) {
        return true;
    }

    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_PASSIVE | AI_NUMERICSERV;

    const std::string port = std::to_string(config_.bind_port);
    const char* host = config_.bind_host.empty() ? nullptr : config_.bind_host.c_str();

    addrinfo* raw = nullptr;
    const int gai = ::getaddrinfo(host, port.c_str(), &hints, &raw);
    if (gai != 0) {
        std::cerr << "[honeypot_proxy] getaddrinfo failed: " << ::gai_strerror(gai) << '\n';
        return false;
    }
    const std::unique_ptr<addrinfo, AddrinfoDeleter> addrs(raw);

    int last_errno = 0;
    for (addrinfo* ai = addrs.get(); ai != nullptr; ai = ai->ai_next) {
        UniqueFd fd(::socket(
            ai->ai_family,
            ai->ai_socktype | SOCK_NONBLOCK | SOCK_CLOEXEC,
            ai->ai_protocol));
        if (!fd.valid()) {
            last_errno = errno;
            continue;
        }
        if (!set_reuseaddr(fd.get()) || !set_reuseport(fd.get()) || !set_nonblocking(fd.get())) {
            last_errno = errno;
            continue;
        }
        if (::bind(fd.get(), ai->ai_addr, ai->ai_addrlen) != 0) {
            last_errno = errno;
            continue;
        }
        if (::listen(fd.get(), SOMAXCONN) != 0) {
            last_errno = errno;
            continue;
        }
        listen_fd_ = std::move(fd);
        return true;
    }

    errno = last_errno;
    log_sys_error("listen socket setup");
    return false;
}

bool ProxyServer::setup_epoll() {
    if (epoll_fd_.valid()) {
        return true;
    }

    UniqueFd epoll(::epoll_create1(EPOLL_CLOEXEC));
    if (!epoll.valid()) {
        log_sys_error("epoll_create1");
        return false;
    }

    UniqueFd wakeup(::eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK));
    if (!wakeup.valid()) {
        log_sys_error("eventfd");
        return false;
    }

    epoll_event listen_ev{};
    listen_ev.events = static_cast<std::uint32_t>(EPOLLIN) | kHangupEvents;
    listen_ev.data.u64 = kTokenListen;
    if (::epoll_ctl(epoll.get(), EPOLL_CTL_ADD, listen_fd_.get(), &listen_ev) != 0) {
        log_sys_error("epoll_ctl(listen)");
        return false;
    }

    epoll_event wake_ev{};
    wake_ev.events = static_cast<std::uint32_t>(EPOLLIN);
    wake_ev.data.u64 = kTokenWakeup;
    if (::epoll_ctl(epoll.get(), EPOLL_CTL_ADD, wakeup.get(), &wake_ev) != 0) {
        log_sys_error("epoll_ctl(wakeup)");
        return false;
    }

    epoll_fd_ = std::move(epoll);
    wakeup_fd_ = std::move(wakeup);
    wakeup_raw_.store(wakeup_fd_.get(), std::memory_order_release);
    return true;
}

void ProxyServer::teardown() noexcept {
    sessions_.clear();
    wakeup_raw_.store(-1, std::memory_order_release);
    wakeup_fd_.reset();
    epoll_fd_.reset();
    listen_fd_.reset();
}

void ProxyServer::run() {
    if (!listen_fd_.valid()) {
        return;
    }
    running_.store(true, std::memory_order_release);
    if (!setup_epoll()) {
        running_.store(false, std::memory_order_release);
        return;
    }
    if (!running_.load(std::memory_order_acquire)) {
        teardown();
        return;
    }

    std::array<epoll_event, kMaxEpollEvents> events{};
    while (running_.load(std::memory_order_acquire)) {
        const int n = ::epoll_wait(
            epoll_fd_.get(),
            events.data(),
            kMaxEpollEvents,
            kEpollTimeoutMs);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            log_sys_error("epoll_wait");
            break;
        }
        for (int i = 0; i < n; ++i) {
            handle_event(events[static_cast<std::size_t>(i)].data.u64, events[static_cast<std::size_t>(i)].events);
        }
        rate_limiter_.maybe_sweep();
    }

    running_.store(false, std::memory_order_release);
    teardown();
}

void ProxyServer::stop() noexcept {
    running_.store(false, std::memory_order_release);
    const int fd = wakeup_raw_.load(std::memory_order_acquire);
    if (fd < 0) {
        return;
    }
    const std::uint64_t one = 1;
    const ssize_t wrote = ::write(fd, &one, sizeof(one));
    (void)wrote;
}

const ProxyConfig& ProxyServer::config() const noexcept {
    return config_;
}

bool ProxyServer::listening() const noexcept {
    return listen_fd_.valid();
}

void ProxyServer::handle_event(std::uint64_t token, std::uint32_t events) {
    if (token == kTokenWakeup) {
        if (wakeup_fd_.valid()) {
            std::uint64_t value = 0;
            const ssize_t n = ::read(wakeup_fd_.get(), &value, sizeof(value));
            (void)n;
        }
        return;
    }
    if (token == kTokenListen) {
        if ((events & static_cast<std::uint32_t>(EPOLLIN)) != 0U) {
            accept_ready();
        }
        return;
    }

    std::uint64_t id = 0;
    SocketRole role = SocketRole::Client;
    if (!decode_session_token(token, id, role)) {
        return;
    }
    handle_session_event(id, role, events);
}

void ProxyServer::accept_ready() {
    for (;;) {
        sockaddr_storage addr{};
        socklen_t addr_len = static_cast<socklen_t>(sizeof(addr));
        const int raw = ::accept4(
            listen_fd_.get(),
            reinterpret_cast<sockaddr*>(&addr),
            &addr_len,
            SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (raw < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return;
            }
            if (errno == EINTR) {
                continue;
            }
            if (errno == EMFILE || errno == ENFILE || errno == ENOBUFS || errno == ENOMEM) {
                log_sys_error("accept4");
                return;
            }
            log_sys_error("accept4");
            return;
        }
        UniqueFd client(raw);
        (void)set_nonblocking(client.get());
        (void)set_tcp_nodelay(client.get());
        std::string proxy_header;
        if (config_.send_proxy_protocol) {
            proxy_header = make_proxy_v1_header(client.get(), addr);
        }
        if (!spawn_session(std::move(client), peer_ip(addr), std::move(proxy_header))) {
            continue;
        }
    }
}

bool ProxyServer::spawn_session(
    UniqueFd client_fd,
    std::string client_ip,
    std::string proxy_header) {
    RateLimiter::Lease lease;
    if (!rate_limiter_.try_admit(client_ip, lease)) {
        return false;
    }

    UniqueFd backend_fd;
    bool established = false;
    if (!open_backend(backend_fd, established)) {
        return false;
    }
    (void)set_tcp_nodelay(backend_fd.get());

    auto session = std::make_unique<ProxySession>();
    session->client_fd = std::move(client_fd);
    session->backend_fd = std::move(backend_fd);
    session->state = established ? SessionState::Established : SessionState::Connecting;
    session->lease = std::move(lease);
    session->proxy_header = std::move(proxy_header);
    if (established) {
        inject_proxy_header(*session);
    }
    const std::uint64_t id = next_session_id_++;

    if (!set_watch(
            session->client_fd.get(),
            session_token(id, SocketRole::Client),
            desired_events(*session, SocketRole::Client),
            session->client_events)) {
        return false;
    }
    if (!set_watch(
            session->backend_fd.get(),
            session_token(id, SocketRole::Backend),
            desired_events(*session, SocketRole::Backend),
            session->backend_events)) {
        return false;
    }
    sessions_.emplace(id, std::move(session));
    return true;
}

bool ProxyServer::open_backend(UniqueFd& out_fd, bool& established) {
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_NUMERICSERV;

    const std::string port = std::to_string(config_.backend_port);
    addrinfo* raw = nullptr;
    const int gai = ::getaddrinfo(config_.backend_host.c_str(), port.c_str(), &hints, &raw);
    if (gai != 0) {
        std::cerr << "[honeypot_proxy] backend getaddrinfo failed: " << ::gai_strerror(gai) << '\n';
        return false;
    }
    const std::unique_ptr<addrinfo, AddrinfoDeleter> addrs(raw);

    int last_errno = 0;
    for (addrinfo* ai = addrs.get(); ai != nullptr; ai = ai->ai_next) {
        UniqueFd fd(::socket(
            ai->ai_family,
            SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC,
            ai->ai_protocol));
        if (!fd.valid()) {
            last_errno = errno;
            continue;
        }
        (void)set_nonblocking(fd.get());
        const int rc = ::connect(fd.get(), ai->ai_addr, ai->ai_addrlen);
        if (rc == 0) {
            out_fd = std::move(fd);
            established = true;
            return true;
        }
        if (errno == EINPROGRESS) {
            out_fd = std::move(fd);
            established = false;
            return true;
        }
        last_errno = errno;
    }
    errno = last_errno;
    log_sys_error("backend connect");
    return false;
}

void ProxyServer::handle_session_event(std::uint64_t id, SocketRole role, std::uint32_t events) {
    ProxySession* session = find_session(id);
    if (session == nullptr) {
        return;
    }

    if (session->state == SessionState::Connecting && role == SocketRole::Client) {
        if ((events & (epoll_bit(EPOLLERR) | epoll_bit(EPOLLHUP))) != 0U) {
            destroy_session(id);
            return;
        }
    }

    if (session->state == SessionState::Connecting && role == SocketRole::Backend) {
        if ((events & (epoll_bit(EPOLLERR) | epoll_bit(EPOLLHUP))) != 0U) {
            destroy_session(id);
            return;
        }
        if ((events & epoll_bit(EPOLLOUT)) != 0U) {
            if (!finish_connect(id)) {
                return;
            }
            session = find_session(id);
            if (session == nullptr) {
                return;
            }
        }
    }

    if ((events & epoll_bit(EPOLLERR)) != 0U) {
        destroy_session(id);
        return;
    }

    if ((events & epoll_bit(EPOLLOUT)) != 0U) {
        if (!flush_write(id, role)) {
            return;
        }
    }

    if ((events & (epoll_bit(EPOLLIN) | epoll_bit(EPOLLRDHUP))) != 0U) {
        if (!pump_read(id, role)) {
            return;
        }
    }

    if ((events & epoll_bit(EPOLLHUP)) != 0U) {
        on_read_eof(id, role);
    }
}

bool ProxyServer::finish_connect(std::uint64_t id) {
    ProxySession* session = find_session(id);
    if (session == nullptr) {
        return false;
    }
    int so_error = 0;
    socklen_t len = static_cast<socklen_t>(sizeof(so_error));
    if (::getsockopt(session->backend_fd.get(), SOL_SOCKET, SO_ERROR, &so_error, &len) != 0) {
        destroy_session(id);
        return false;
    }
    if (so_error != 0) {
        errno = so_error;
        log_sys_error("backend SO_ERROR");
        destroy_session(id);
        return false;
    }
    session->state = SessionState::Established;
    inject_proxy_header(*session);
    refresh_events(*session, id);
    return true;
}

void ProxyServer::inject_proxy_header(ProxySession& session) const {
    if (session.proxy_header.empty()) {
        return;
    }
    const auto* data = reinterpret_cast<const std::uint8_t*>(session.proxy_header.data());
    session.to_backend_buf.insert(
        session.to_backend_buf.begin() + static_cast<std::ptrdiff_t>(session.to_backend_head),
        data,
        data + session.proxy_header.size());
    session.proxy_header.clear();
}

bool ProxyServer::pump_read(std::uint64_t id, SocketRole src) {
    ProxySession* session = find_session(id);
    if (session == nullptr) {
        return false;
    }
    if (session->state == SessionState::Connecting || has_read_eof(*session, src)) {
        return true;
    }

    const SocketRole dest = peer_of(src);
    UniqueFd& src_fd = fd_for(*session, src);
    std::array<std::uint8_t, kReadChunk> chunk{};

    for (;;) {
        session = find_session(id);
        if (session == nullptr) {
            return false;
        }
        std::vector<std::uint8_t>& buf = out_buf(*session, dest);
        std::size_t& head = out_head(*session, dest);
        const std::size_t pending = pending_size(buf, head);
        if (pending >= kMaxBufferBytes) {
            refresh_events(*session, id);
            return true;
        }

        const std::size_t space = kMaxBufferBytes - pending;
        const std::size_t want = space < chunk.size() ? space : chunk.size();
        const ssize_t n = ::recv(src_fd.get(), chunk.data(), want, 0);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                refresh_events(*session, id);
                return true;
            }
            if (errno == EINTR) {
                continue;
            }
            destroy_session(id);
            return false;
        }
        if (n == 0) {
            on_read_eof(id, src);
            return find_session(id) != nullptr;
        }

        const auto nbytes = static_cast<std::size_t>(n);
        UniqueFd& dest_fd = fd_for(*session, dest);
        if (pending == 0U) {
            std::size_t offset = 0;
            while (offset < nbytes) {
                const ssize_t sent = ::send(
                    dest_fd.get(),
                    chunk.data() + offset,
                    nbytes - offset,
                    MSG_NOSIGNAL);
                if (sent < 0) {
                    if (errno == EAGAIN || errno == EWOULDBLOCK) {
                        break;
                    }
                    if (errno == EINTR) {
                        continue;
                    }
                    destroy_session(id);
                    return false;
                }
                if (sent == 0) {
                    break;
                }
                offset += static_cast<std::size_t>(sent);
            }
            if (offset < nbytes) {
                buf.insert(buf.end(), chunk.begin() + static_cast<std::ptrdiff_t>(offset),
                           chunk.begin() + static_cast<std::ptrdiff_t>(nbytes));
            }
        } else {
            buf.insert(buf.end(), chunk.begin(), chunk.begin() + static_cast<std::ptrdiff_t>(nbytes));
        }
        refresh_events(*session, id);
    }
}

bool ProxyServer::flush_write(std::uint64_t id, SocketRole dest) {
    ProxySession* session = find_session(id);
    if (session == nullptr) {
        return false;
    }

    std::vector<std::uint8_t>& buf = out_buf(*session, dest);
    std::size_t& head = out_head(*session, dest);
    UniqueFd& dest_fd = fd_for(*session, dest);

    while (pending_size(buf, head) > 0U) {
        const ssize_t sent = ::send(
            dest_fd.get(),
            buf.data() + head,
            pending_size(buf, head),
            MSG_NOSIGNAL);
        if (sent < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                refresh_events(*session, id);
                return true;
            }
            if (errno == EINTR) {
                continue;
            }
            destroy_session(id);
            return false;
        }
        if (sent == 0) {
            refresh_events(*session, id);
            return true;
        }
        consume_buf(buf, head, static_cast<std::size_t>(sent));
    }

    refresh_events(*session, id);
    const SocketRole src = peer_of(dest);
    if (has_read_eof(*session, src) && pending_size(buf, head) == 0U) {
        bool& shut = wr_shutdown_flag(*session, dest);
        if (!shut && dest_fd.valid()) {
            if (::shutdown(dest_fd.get(), SHUT_WR) != 0 && errno != ENOTCONN && errno != EINVAL) {
                destroy_session(id);
                return false;
            }
            shut = true;
        }
    }
    maybe_complete(id);
    return find_session(id) != nullptr;
}

void ProxyServer::on_read_eof(std::uint64_t id, SocketRole src) {
    ProxySession* session = find_session(id);
    if (session == nullptr) {
        return;
    }
    if (has_read_eof(*session, src)) {
        maybe_complete(id);
        return;
    }
    read_eof_flag(*session, src) = true;
    session->state = SessionState::Closing;
    if (!flush_write(id, peer_of(src))) {
        return;
    }
    session = find_session(id);
    if (session == nullptr) {
        return;
    }
    refresh_events(*session, id);
    maybe_complete(id);
}

void ProxyServer::maybe_complete(std::uint64_t id) {
    ProxySession* session = find_session(id);
    if (session == nullptr) {
        return;
    }
    if (!session->client_read_eof || !session->backend_read_eof) {
        return;
    }
    if (pending_size(session->to_backend_buf, session->to_backend_head) != 0U ||
        pending_size(session->to_client_buf, session->to_client_head) != 0U) {
        return;
    }
    destroy_session(id);
}

void ProxyServer::destroy_session(std::uint64_t id) {
    sessions_.erase(id);
}

ProxySession* ProxyServer::find_session(std::uint64_t id) {
    const auto it = sessions_.find(id);
    if (it == sessions_.end()) {
        return nullptr;
    }
    return it->second.get();
}

bool ProxyServer::set_watch(int fd, std::uint64_t token, std::uint32_t events, std::uint32_t& current) {
    if (fd < 0 || !epoll_fd_.valid()) {
        return false;
    }
    if (current == events && current != 0U) {
        return true;
    }
    epoll_event ev{};
    ev.events = events;
    ev.data.u64 = token;
    const int op = current == 0U ? EPOLL_CTL_ADD : EPOLL_CTL_MOD;
    if (::epoll_ctl(epoll_fd_.get(), op, fd, &ev) != 0) {
        log_sys_error("epoll_ctl");
        return false;
    }
    current = events;
    return true;
}

void ProxyServer::refresh_events(ProxySession& session, std::uint64_t id) {
    if (session.client_fd.valid()) {
        (void)set_watch(
            session.client_fd.get(),
            session_token(id, SocketRole::Client),
            desired_events(session, SocketRole::Client),
            session.client_events);
    }
    if (session.backend_fd.valid()) {
        (void)set_watch(
            session.backend_fd.get(),
            session_token(id, SocketRole::Backend),
            desired_events(session, SocketRole::Backend),
            session.backend_events);
    }
}

std::uint32_t ProxyServer::desired_events(const ProxySession& session, SocketRole role) const {
    std::uint32_t events = kHangupEvents;
    const std::size_t outgoing = pending_size(
        role == SocketRole::Backend ? session.to_backend_buf : session.to_client_buf,
        role == SocketRole::Backend ? session.to_backend_head : session.to_client_head);
    const std::size_t incoming_cap = pending_size(
        role == SocketRole::Client ? session.to_backend_buf : session.to_client_buf,
        role == SocketRole::Client ? session.to_backend_head : session.to_client_head);

    if (outgoing > 0U || (session.state == SessionState::Connecting && role == SocketRole::Backend)) {
        events |= epoll_bit(EPOLLOUT);
    }

    if (session.state == SessionState::Connecting && role == SocketRole::Backend) {
        events |= epoll_bit(EPOLLIN);
    } else if (session.state != SessionState::Connecting && !has_read_eof(session, role) &&
               incoming_cap < kMaxBufferBytes) {
        events |= epoll_bit(EPOLLIN);
    }
    return events;
}

}  // namespace honeypot
