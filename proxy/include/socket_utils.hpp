#pragma once

namespace honeypot {

class UniqueFd {
public:
    UniqueFd() noexcept = default;
    explicit UniqueFd(int fd) noexcept;
    ~UniqueFd();

    UniqueFd(const UniqueFd&) = delete;
    UniqueFd& operator=(const UniqueFd&) = delete;

    UniqueFd(UniqueFd&& other) noexcept;
    UniqueFd& operator=(UniqueFd&& other) noexcept;

    [[nodiscard]] int get() const noexcept;
    [[nodiscard]] bool valid() const noexcept;

    int release() noexcept;
    void reset(int fd = -1) noexcept;
    void swap(UniqueFd& other) noexcept;

private:
    int fd_{-1};
};

[[nodiscard]] bool set_nonblocking(int fd) noexcept;
[[nodiscard]] bool set_cloexec(int fd) noexcept;
[[nodiscard]] bool set_reuseaddr(int fd) noexcept;
[[nodiscard]] bool set_reuseport(int fd) noexcept;
[[nodiscard]] bool set_tcp_nodelay(int fd) noexcept;

}  // namespace honeypot
