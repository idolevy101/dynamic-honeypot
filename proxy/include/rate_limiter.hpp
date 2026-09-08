#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <unordered_map>

namespace honeypot {

class RateLimiter {
public:
    class Lease {
    public:
        Lease() noexcept = default;
        ~Lease();

        Lease(const Lease&) = delete;
        Lease& operator=(const Lease&) = delete;
        Lease(Lease&& other) noexcept;
        Lease& operator=(Lease&& other) noexcept;

    private:
        friend class RateLimiter;
        Lease(RateLimiter* limiter, std::string ip) noexcept;

        RateLimiter* limiter_{nullptr};
        std::string ip_;
    };

    RateLimiter(
        std::size_t max_connections,
        std::size_t max_per_ip,
        std::uint32_t rate_limit,
        std::uint32_t rate_burst);

    RateLimiter(const RateLimiter&) = delete;
    RateLimiter& operator=(const RateLimiter&) = delete;
    RateLimiter(RateLimiter&&) = delete;
    RateLimiter& operator=(RateLimiter&&) = delete;

    ~RateLimiter() = default;

    [[nodiscard]] bool try_admit(std::string_view ip, Lease& out);
    void maybe_sweep() noexcept;

private:
    struct IpEntry {
        std::size_t active{0};
        double tokens{0.0};
        std::chrono::steady_clock::time_point last_refill{};
        std::chrono::steady_clock::time_point last_seen{};
    };

    void refill(IpEntry& entry, std::chrono::steady_clock::time_point now) const noexcept;
    void sweep_stale(std::chrono::steady_clock::time_point now) noexcept;
    void release(const std::string& ip) noexcept;

    std::size_t max_connections_;
    std::size_t max_per_ip_;
    double tokens_max_;
    double refill_per_sec_;
    std::size_t active_global_{0};
    std::chrono::steady_clock::time_point last_sweep_{};
    std::unordered_map<std::string, IpEntry> entries_;
};

}  // namespace honeypot
