#include "rate_limiter.hpp"

#include <utility>

namespace honeypot {
namespace {

constexpr auto kSweepInterval = std::chrono::seconds(5);
constexpr auto kStaleTtl = std::chrono::seconds(30);

}  // namespace

RateLimiter::Lease::Lease(RateLimiter* limiter, std::string ip) noexcept
    : limiter_(limiter), ip_(std::move(ip)) {}

RateLimiter::Lease::~Lease() {
    if (limiter_ != nullptr) {
        limiter_->release(ip_);
        limiter_ = nullptr;
    }
}

RateLimiter::Lease::Lease(Lease&& other) noexcept
    : limiter_(other.limiter_), ip_(std::move(other.ip_)) {
    other.limiter_ = nullptr;
}

RateLimiter::Lease& RateLimiter::Lease::operator=(Lease&& other) noexcept {
    if (this != &other) {
        if (limiter_ != nullptr) {
            limiter_->release(ip_);
        }
        limiter_ = other.limiter_;
        ip_ = std::move(other.ip_);
        other.limiter_ = nullptr;
    }
    return *this;
}

RateLimiter::RateLimiter(
    std::size_t max_connections,
    std::size_t max_per_ip,
    std::uint32_t rate_limit,
    std::uint32_t rate_burst)
    : max_connections_(max_connections),
      max_per_ip_(max_per_ip),
      tokens_max_(static_cast<double>(rate_burst)),
      refill_per_sec_(static_cast<double>(rate_limit)) {}

bool RateLimiter::try_admit(std::string_view ip, Lease& out) {
    if (active_global_ >= max_connections_) {
        return false;
    }

    const auto now = std::chrono::steady_clock::now();
    const auto [it, inserted] = entries_.try_emplace(std::string(ip));
    IpEntry& entry = it->second;
    if (inserted) {
        entry.tokens = tokens_max_;
        entry.last_refill = now;
    } else {
        refill(entry, now);
    }
    entry.last_seen = now;

    if (entry.active >= max_per_ip_ || entry.tokens < 1.0) {
        return false;
    }

    std::string lease_ip = it->first;
    entry.tokens -= 1.0;
    ++entry.active;
    ++active_global_;
    out = Lease(this, std::move(lease_ip));
    return true;
}

void RateLimiter::maybe_sweep() noexcept {
    const auto now = std::chrono::steady_clock::now();
    if (last_sweep_.time_since_epoch().count() != 0 && now - last_sweep_ < kSweepInterval) {
        return;
    }
    last_sweep_ = now;
    sweep_stale(now);
}

void RateLimiter::refill(IpEntry& entry, std::chrono::steady_clock::time_point now) const noexcept {
    const std::chrono::duration<double> elapsed = now - entry.last_refill;
    double elapsed_sec = elapsed.count();
    if (elapsed_sec < 0.0) {
        elapsed_sec = 0.0;
    }
    entry.tokens += elapsed_sec * refill_per_sec_;
    if (entry.tokens > tokens_max_) {
        entry.tokens = tokens_max_;
    }
    entry.last_refill = now;
}

void RateLimiter::sweep_stale(std::chrono::steady_clock::time_point now) noexcept {
    for (auto it = entries_.begin(); it != entries_.end();) {
        const IpEntry& entry = it->second;
        if (entry.active == 0U && now - entry.last_seen >= kStaleTtl) {
            it = entries_.erase(it);
        } else {
            ++it;
        }
    }
}

void RateLimiter::release(const std::string& ip) noexcept {
    if (active_global_ > 0U) {
        --active_global_;
    }
    const auto it = entries_.find(ip);
    if (it == entries_.end()) {
        return;
    }
    if (it->second.active > 0U) {
        --it->second.active;
    }
    it->second.last_seen = std::chrono::steady_clock::now();
}

}  // namespace honeypot
