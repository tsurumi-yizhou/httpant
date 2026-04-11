export module httpant:caching;

import std;
import :message;

export namespace http {

// ─── Cache-Control directives (RFC 9111 §5.2) ────────────────

enum class directive : std::uint8_t {
    no_store, no_cache, must_revalidate, public_, private_,
    max_age, s_maxage, no_transform, only_if_cached,
    stale_while_revalidate, stale_if_error, immutable
};

struct cache_directive {
    directive type;
    std::optional<std::uint32_t> delta{};
};

struct cache_control {
    std::vector<cache_directive> directives;

    [[nodiscard]] auto has(directive d) const -> bool {
        return std::ranges::any_of(directives, [d](auto& cd) { return cd.type == d; });
    }

    [[nodiscard]] auto max_age() const -> std::optional<std::uint32_t> {
        for (auto& cd : directives)
            if (cd.type == directive::max_age) return cd.delta;
        return std::nullopt;
    }

    [[nodiscard]] auto s_maxage() const -> std::optional<std::uint32_t> {
        for (auto& cd : directives)
            if (cd.type == directive::s_maxage) return cd.delta;
        return std::nullopt;
    }
};

inline auto parse_cache_control(std::string_view value) -> cache_control {
    cache_control cc;
    while (!value.empty()) {
        while (!value.empty() && (value.front() == ' ' || value.front() == ','))
            value.remove_prefix(1);
        if (value.empty()) break;

        auto end = value.find(',');
        auto token = (end != std::string_view::npos) ? value.substr(0, end) : value;
        value = (end != std::string_view::npos) ? value.substr(end + 1) : std::string_view{};

        // Trim trailing whitespace
        while (!token.empty() && token.back() == ' ') token.remove_suffix(1);

        auto eq = token.find('=');
        auto name = (eq != std::string_view::npos) ? token.substr(0, eq) : token;
        while (!name.empty() && name.back() == ' ') name.remove_suffix(1);

        std::optional<std::uint32_t> delta;
        if (eq != std::string_view::npos) {
            auto val = token.substr(eq + 1);
            while (!val.empty() && val.front() == ' ') val.remove_prefix(1);
            std::uint32_t d = 0;
            for (auto c : val) {
                if (c < '0' || c > '9') break;
                d = d * 10 + static_cast<std::uint32_t>(c - '0');
            }
            delta = d;
        }

        if (iequal(name, "no-store"))               cc.directives.push_back({directive::no_store});
        else if (iequal(name, "no-cache"))           cc.directives.push_back({directive::no_cache});
        else if (iequal(name, "must-revalidate"))    cc.directives.push_back({directive::must_revalidate});
        else if (iequal(name, "public"))             cc.directives.push_back({directive::public_});
        else if (iequal(name, "private"))            cc.directives.push_back({directive::private_});
        else if (iequal(name, "no-transform"))       cc.directives.push_back({directive::no_transform});
        else if (iequal(name, "only-if-cached"))     cc.directives.push_back({directive::only_if_cached});
        else if (iequal(name, "immutable"))          cc.directives.push_back({directive::immutable});
        else if (iequal(name, "max-age"))            cc.directives.push_back({directive::max_age, delta});
        else if (iequal(name, "s-maxage"))           cc.directives.push_back({directive::s_maxage, delta});
        else if (iequal(name, "stale-while-revalidate")) cc.directives.push_back({directive::stale_while_revalidate, delta});
        else if (iequal(name, "stale-if-error"))     cc.directives.push_back({directive::stale_if_error, delta});
    }
    return cc;
}

// ─── Cache entry and freshness (RFC 9111 §4) ─────────────────

struct cache_entry {
    http::request  key;
    http::response stored;
    std::chrono::system_clock::time_point request_time;
    std::chrono::system_clock::time_point response_time;
};

// RFC 9111 §4.2.3 — Calculating Age
inline auto current_age(const cache_entry& e) -> std::chrono::seconds {
    using namespace std::chrono;
    auto age_value = seconds{0};
    if (auto a = find_header(e.stored.fields, "age")) {
        std::uint32_t v = 0;
        for (auto c : *a) {
            if (c < '0' || c > '9') break;
            v = v * 10 + static_cast<std::uint32_t>(c - '0');
        }
        age_value = seconds{v};
    }
    auto apparent_age = std::max(seconds{0},
        duration_cast<seconds>(e.response_time - e.request_time));
    auto corrected_age = std::max(apparent_age, age_value);
    auto resident_time = duration_cast<seconds>(
        system_clock::now() - e.response_time);
    return corrected_age + resident_time;
}

// RFC 9111 §4.2.1 — Calculating Freshness Lifetime
inline auto freshness_lifetime(const cache_entry& e) -> std::chrono::seconds {
    auto cc_hdr = find_header(e.stored.fields, "cache-control");
    if (cc_hdr) {
        auto cc = parse_cache_control(*cc_hdr);
        if (auto s = cc.s_maxage()) return std::chrono::seconds{*s};
        if (auto m = cc.max_age())  return std::chrono::seconds{*m};
    }
    // Expires fallback — simplified: treat as zero if unparseable
    if (auto exp = find_header(e.stored.fields, "expires")) {
        // Simplified: if Expires contains a number-like value
        // Full date parsing is out of scope for a pure protocol lib
        return std::chrono::seconds{0};
    }
    return std::chrono::seconds{0};
}

inline auto is_fresh(const cache_entry& e) -> bool {
    return current_age(e) < freshness_lifetime(e);
}

// RFC 9111 §3 — Whether a response is cacheable
inline auto is_cacheable(const http::response& res, const http::request& req) -> bool {
    if (req.method != method::GET && req.method != method::HEAD) return false;
    if (!is_successful(res.status) && res.status != 301 && res.status != 308) return false;
    auto cc_hdr = find_header(res.fields, "cache-control");
    if (cc_hdr) {
        auto cc = parse_cache_control(*cc_hdr);
        if (cc.has(directive::no_store)) return false;
        if (cc.has(directive::private_)) return false;
    }
    return true;
}

// Generate conditional request for revalidation (RFC 9111 §4.3.1)
inline auto make_conditional(const http::request& req, const cache_entry& e) -> http::request {
    auto cond = req;
    if (auto etag_val = find_header(e.stored.fields, "etag"))
        cond.fields.push_back({"if-none-match", std::string(*etag_val)});
    if (auto lm = find_header(e.stored.fields, "last-modified"))
        cond.fields.push_back({"if-modified-since", std::string(*lm)});
    return cond;
}

// Vary-based matching (RFC 9111 §4.1)
inline auto matches_vary(const cache_entry& e, const http::request& req) -> bool {
    auto vary = find_header(e.stored.fields, "vary");
    if (!vary) return true;
    if (*vary == "*") return false;
    // Simplified: check that listed header values match
    auto rest = *vary;
    while (!rest.empty()) {
        while (!rest.empty() && (rest.front() == ' ' || rest.front() == ','))
            rest.remove_prefix(1);
        auto end = rest.find(',');
        auto field = (end != std::string_view::npos) ? rest.substr(0, end) : rest;
        while (!field.empty() && field.back() == ' ') field.remove_suffix(1);
        rest = (end != std::string_view::npos) ? rest.substr(end + 1) : std::string_view{};
        if (field.empty()) continue;
        auto cached_val = find_header(e.key.fields, field);
        auto req_val = find_header(req.fields, field);
        if (cached_val != req_val) return false;
    }
    return true;
}

// ─── Simple in-memory cache store ─────────────────────────────

class cache_store {
public:
    auto lookup(const http::request& req) -> std::optional<cache_entry> {
        for (auto& e : entries_) {
            if (e.key.method == req.method &&
                e.key.target == req.target &&
                e.key.scheme == req.scheme &&
                e.key.authority == req.authority &&
                matches_vary(e, req))
                return e;
        }
        return std::nullopt;
    }

    void store(cache_entry entry) {
        // Replace existing entry for same target/method
        std::erase_if(entries_, [&](auto& e) {
            return e.key.method == entry.key.method &&
                   e.key.target == entry.key.target &&
                   e.key.scheme == entry.key.scheme &&
                   e.key.authority == entry.key.authority;
        });
        entries_.push_back(std::move(entry));
    }

    void invalidate(std::string_view target) {
        std::erase_if(entries_, [&](auto& e) { return e.key.target == target; });
    }

    [[nodiscard]] auto size() const -> std::size_t { return entries_.size(); }

private:
    std::vector<cache_entry> entries_;
};

} // namespace http
