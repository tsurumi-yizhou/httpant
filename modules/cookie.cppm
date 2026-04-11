export module httpant:cookie;

import std;
import :message;

export namespace http {

// ─── Cookie types (RFC 6265 §4, §5) ─────────────────────────

enum class same_site : std::uint8_t { none, lax, strict };

struct cookie {
    std::string name;
    std::string value;
    std::string domain;
    std::string path;
    std::optional<std::chrono::system_clock::time_point> expires;
    bool secure{false};
    bool http_only{false};
    same_site site{same_site::lax};
};

// RFC 6265 §5.2 — Parse a Set-Cookie header
inline auto parse_set_cookie(std::string_view header) -> std::optional<cookie> {
    auto semi = header.find(';');
    auto pair = (semi != std::string_view::npos) ? header.substr(0, semi) : header;

    auto eq = pair.find('=');
    if (eq == std::string_view::npos || eq == 0) return std::nullopt;

    cookie c;
    c.name = std::string(pair.substr(0, eq));
    c.value = std::string(pair.substr(eq + 1));

    // Trim whitespace from name/value
    while (!c.name.empty() && c.name.front() == ' ') c.name.erase(c.name.begin());
    while (!c.name.empty() && c.name.back() == ' ') c.name.pop_back();
    while (!c.value.empty() && c.value.front() == ' ') c.value.erase(c.value.begin());
    while (!c.value.empty() && c.value.back() == ' ') c.value.pop_back();

    if (c.name.empty()) return std::nullopt;

    // Parse attributes
    auto rest = (semi != std::string_view::npos) ? header.substr(semi + 1) : std::string_view{};
    while (!rest.empty()) {
        while (!rest.empty() && rest.front() == ' ') rest.remove_prefix(1);
        auto next = rest.find(';');
        auto attr = (next != std::string_view::npos) ? rest.substr(0, next) : rest;
        rest = (next != std::string_view::npos) ? rest.substr(next + 1) : std::string_view{};
        while (!attr.empty() && attr.back() == ' ') attr.remove_suffix(1);

        auto aeq = attr.find('=');
        auto aname = (aeq != std::string_view::npos) ? attr.substr(0, aeq) : attr;
        auto aval = (aeq != std::string_view::npos) ? attr.substr(aeq + 1) : std::string_view{};
        while (!aname.empty() && aname.back() == ' ') aname.remove_suffix(1);
        while (!aval.empty() && aval.front() == ' ') aval.remove_prefix(1);

        if (iequal(aname, "domain")) {
            c.domain = std::string(aval);
            if (!c.domain.empty() && c.domain.front() == '.')
                c.domain.erase(c.domain.begin());
        } else if (iequal(aname, "path")) {
            c.path = std::string(aval);
        } else if (iequal(aname, "secure")) {
            c.secure = true;
        } else if (iequal(aname, "httponly")) {
            c.http_only = true;
        } else if (iequal(aname, "samesite")) {
            if (iequal(aval, "strict")) c.site = same_site::strict;
            else if (iequal(aval, "none")) c.site = same_site::none;
            else c.site = same_site::lax;
        } else if (iequal(aname, "max-age")) {
            // Convert max-age seconds to absolute time
            std::int64_t secs = 0;
            bool negative = false;
            auto sv = aval;
            if (!sv.empty() && sv.front() == '-') { negative = true; sv.remove_prefix(1); }
            for (auto ch : sv) {
                if (ch < '0' || ch > '9') break;
                secs = secs * 10 + (ch - '0');
            }
            if (negative) secs = -secs;
            c.expires = std::chrono::system_clock::now() + std::chrono::seconds{secs};
        }
        // Expires attribute: simplified (full date parsing out of scope)
    }

    // Default path (RFC 6265 §5.1.4)
    if (c.path.empty()) c.path = "/";

    return c;
}

// RFC 6265 §5.1.3 — Domain matching
inline auto domain_match(std::string_view request_domain, std::string_view cookie_domain) -> bool {
    if (cookie_domain.empty()) return true;
    if (iequal(request_domain, cookie_domain)) return true;
    if (request_domain.size() > cookie_domain.size()) {
        auto suffix = request_domain.substr(request_domain.size() - cookie_domain.size());
        if (iequal(suffix, cookie_domain) &&
            request_domain[request_domain.size() - cookie_domain.size() - 1] == '.')
            return true;
    }
    return false;
}

// RFC 6265 §5.1.4 — Path matching
inline auto path_match(std::string_view request_path, std::string_view cookie_path) -> bool {
    if (cookie_path.empty() || cookie_path == "/") return true;
    if (request_path == cookie_path) return true;
    if (request_path.starts_with(cookie_path)) {
        if (cookie_path.back() == '/') return true;
        if (request_path.size() > cookie_path.size() &&
            request_path[cookie_path.size()] == '/')
            return true;
    }
    return false;
}

// ─── Cookie jar (RFC 6265 §5.3) ─────────────────────────────

class cookie_jar {
public:
    void store(const cookie& c, std::string_view request_domain) {
        auto domain = c.domain.empty() ? std::string(request_domain) : c.domain;

        // Remove existing cookie with same name/domain/path
        std::erase_if(cookies_, [&](auto& existing) {
            return existing.name == c.name &&
                   iequal(existing.domain, domain) &&
                   existing.path == c.path;
        });

        // Don't store expired cookies
        if (c.expires && *c.expires <= std::chrono::system_clock::now()) return;

        auto stored = c;
        if (stored.domain.empty()) stored.domain = std::string(request_domain);
        cookies_.push_back(std::move(stored));
    }

    [[nodiscard]] auto match(std::string_view domain, std::string_view path,
                             bool secure_only = false) const -> std::string {
        std::string result;
        for (auto& c : cookies_) {
            if (c.expires && *c.expires <= std::chrono::system_clock::now()) continue;
            if (secure_only && !c.secure) continue;
            if (!domain_match(domain, c.domain)) continue;
            if (!path_match(path, c.path)) continue;
            if (!result.empty()) result += "; ";
            result += c.name;
            result += '=';
            result += c.value;
        }
        return result;
    }

    void clear() { cookies_.clear(); }

    void remove_expired() {
        auto now = std::chrono::system_clock::now();
        std::erase_if(cookies_, [&](auto& c) {
            return c.expires && *c.expires <= now;
        });
    }

    [[nodiscard]] auto size() const -> std::size_t { return cookies_.size(); }

private:
    std::vector<cookie> cookies_;
};

} // namespace http
