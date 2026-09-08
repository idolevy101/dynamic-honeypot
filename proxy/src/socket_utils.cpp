#include "socket_utils.hpp"

#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <utility>

namespace honeypot {

UniqueFd::UniqueFd(int fd) noexcept : fd_(fd) {}

UniqueFd::~UniqueFd() {
    reset();
}

UniqueFd::UniqueFd(UniqueFd&& other) noexcept : fd_(std::exchange(other.fd_, -1)) {}

UniqueFd& UniqueFd::operator=(UniqueFd&& other) noexcept {
    if (this != &other) {
        reset();
        fd_ = std::exchange(other.fd_, -1);
    }
    return *this;
}

int UniqueFd::get() const noexcept {
    return fd_;
}

bool UniqueFd::valid() const noexcept {
    return fd_ >= 0;
}

int UniqueFd::release() noexcept {
    return std::exchange(fd_, -1);
}

void UniqueFd::reset(int fd) noexcept {
    if (fd_ >= 0) {
        const int saved = errno;
        ::close(fd_);
        errno = saved;
    }
    fd_ = fd;
}

void UniqueFd::swap(UniqueFd& other) noexcept {
    std::swap(fd_, other.fd_);
}

bool set_nonblocking(int fd) noexcept {
    const int flags = ::fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        return false;
    }
    return ::fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
}

bool set_cloexec(int fd) noexcept {
    const int flags = ::fcntl(fd, F_GETFD);
    if (flags < 0) {
        return false;
    }
    return ::fcntl(fd, F_SETFD, flags | FD_CLOEXEC) == 0;
}

bool set_reuseaddr(int fd) noexcept {
    const int yes = 1;
    return ::setsockopt(
               fd,
               SOL_SOCKET,
               SO_REUSEADDR,
               &yes,
               static_cast<socklen_t>(sizeof(yes))) == 0;
}

bool set_reuseport(int fd) noexcept {
    const int yes = 1;
    return ::setsockopt(
               fd,
               SOL_SOCKET,
               SO_REUSEPORT,
               &yes,
               static_cast<socklen_t>(sizeof(yes))) == 0;
}

bool set_tcp_nodelay(int fd) noexcept {
    const int yes = 1;
    return ::setsockopt(
               fd,
               IPPROTO_TCP,
               TCP_NODELAY,
               &yes,
               static_cast<socklen_t>(sizeof(yes))) == 0;
}

}  // namespace honeypot
