module;

#include <algorithm>
#include <array>
#include <charconv>
#include <chrono>
#include <concepts>
#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

export module httpant:cookie;

import :message;

export namespace http {

namespace detail {

// RFC 6265 §4.1.1 — "cookie-octet = %x21 / %x23-2B / %x2D-3A / %x3C-5B / %x5D-7E"
[[nodiscard]] inline auto is_cookie_octet(char ch) -> bool {
    auto c = static_cast<unsigned char>(ch);
    return c == 0x21 || (c >= 0x23 && c <= 0x2B) || (c >= 0x2D && c <= 0x3A) ||
           (c >= 0x3C && c <= 0x5B) || (c >= 0x5D && c <= 0x7E);
}

[[nodiscard]] inline auto is_digit(char ch) -> bool { return ch >= '0' && ch <= '9'; }

// RFC 6265 §2.2 includes WSP by reference from RFC 5234 Appendix B.1, where
// "WSP = SP / HTAB ; white space".
[[nodiscard]] inline auto is_wsp(char ch) -> bool { return ch == ' ' || ch == '\t'; }

// RFC 6265 §5.1.3 — "The string is a host name (i.e., not an IP address)." — dotted-decimal IPv4
// literals and colon-containing IPv6 literals are IP addresses, so the suffix-matching rule must
// not apply to them.
[[nodiscard]] inline auto is_ip_literal(std::string_view host) -> bool {
    if (host.find(':') != std::string_view::npos) return true;  // IPv6 literal
    // IPv4 literal: exactly four dot-separated components of one to three digits each.
    std::size_t components = 0;
    std::size_t digits = 0;
    for (char ch : host) {
        if (ch == '.') {
            if (digits == 0 || digits > 3) return false;
            ++components;
            digits = 0;
        } else if (is_digit(ch)) {
            if (++digits > 3) return false;
        } else {
            return false;
        }
    }
    return components == 3 && digits > 0;
}

// RFC 6265 §5.1.4 — "The user agent MUST use an algorithm equivalent to the following
// algorithm to compute the default-path of a cookie:"
[[nodiscard]] inline auto default_path(std::string_view uri_path) -> std::string {
    // RFC 6265 §5.1.4 step 2 — "If the uri-path is empty or if the first character of the
    // uri-path is not a %x2F ("/") character, output %x2F ("/") and skip the remaining steps."
    if (uri_path.empty() || uri_path.front() != '/') return "/";
    // RFC 6265 §5.1.4 step 3 — "If the uri-path contains no more than one %x2F ("/") character,
    // output %x2F ("/") and skip the remaining step." (The uri-path starts with "/" at this
    // point, so a right-most "/" at offset 0 means it is the only one.)
    auto last_slash = uri_path.rfind('/');
    if (last_slash == 0) return "/";
    // RFC 6265 §5.1.4 step 4 — "Output the characters of the uri-path from the first character
    // up to, but not including, the right-most %x2F ("/")."
    return std::string(uri_path.substr(0, last_slash));
}

// RFC 6265 §5.1.1 — "time-field = 1*2DIGIT"
[[nodiscard]] inline auto parse_time_field(std::string_view token, std::size_t& i, int& out) -> bool {
    if (i >= token.size() || !is_digit(token[i])) return false;
    int value = 0;
    for (std::size_t n = 0; n < 2 && i < token.size() && is_digit(token[i]); ++n, ++i)
        value = value * 10 + (token[i] - '0');
    out = value;
    return true;
}

// RFC 6265 §5.1.1 — "time = hms-time ( non-digit *OCTET )" and "hms-time = time-field ":" time-
// field ":" time-field" — a date-token whose leading part is hms-time (trailing non-digit
// characters, e.g. the "GMT" in "10:20:30GMT", are permitted and ignored).
[[nodiscard]] inline auto match_time(std::string_view token, int& hour, int& minute, int& second) -> bool {
    std::size_t i = 0;
    int h = 0, m = 0, s = 0;
    if (!parse_time_field(token, i, h)) return false;
    if (i >= token.size() || token[i] != ':') return false;
    ++i;
    if (!parse_time_field(token, i, m)) return false;
    if (i >= token.size() || token[i] != ':') return false;
    ++i;
    if (!parse_time_field(token, i, s)) return false;
    if (i < token.size() && is_digit(token[i])) return false;  // digits after hms-time: no match
    hour = h;
    minute = m;
    second = s;
    return true;
}

// RFC 6265 §5.1.1 — "day-of-month = 1*2DIGIT ( non-digit *OCTET )"
[[nodiscard]] inline auto match_day_of_month(std::string_view token, int& day) -> bool {
    std::size_t n = 0;
    int value = 0;
    while (n < token.size() && n < 2 && is_digit(token[n])) {
        value = value * 10 + (token[n] - '0');
        ++n;
    }
    if (n == 0) return false;
    if (n < token.size() && is_digit(token[n])) return false;
    day = value;
    return true;
}

// RFC 6265 §5.1.1 — "month = ( "jan" / "feb" / "mar" / "apr" / "may" / "jun" / "jul" / "aug" /
// "sep" / "oct" / "nov" / "dec" ) *OCTET" — a date-token whose leading three letters are a
// month name, compared case-insensitively.
[[nodiscard]] inline auto match_month(std::string_view token, int& month) -> bool {
    static constexpr std::array<std::string_view, 12> names{
        "jan", "feb", "mar", "apr", "may", "jun",
        "jul", "aug", "sep", "oct", "nov", "dec"};
    if (token.size() < 3) return false;
    for (std::size_t m = 0; m < names.size(); ++m)
        if (iequal(token.substr(0, 3), names[m])) {
            month = static_cast<int>(m) + 1;
            return true;
        }
    return false;
}

// RFC 6265 §5.1.1 — "year = 2*4DIGIT ( non-digit *OCTET )"
[[nodiscard]] inline auto match_year(std::string_view token, int& year) -> bool {
    std::size_t n = 0;
    int value = 0;
    while (n < token.size() && n < 4 && is_digit(token[n])) {
        value = value * 10 + (token[n] - '0');
        ++n;
    }
    if (n < 2) return false;
    if (n < token.size() && is_digit(token[n])) return false;
    year = value;
    return true;
}

// RFC 6265 §5.1.1 — "The user agent MUST use an algorithm equivalent to the following algorithm
// to parse a cookie-date." Returns the parsed date (UTC), or nullopt when parsing fails.
[[nodiscard]] inline auto parse_cookie_date(std::string_view text) -> std::optional<std::chrono::system_clock::time_point> {
    // RFC 6265 §5.1.1 — "delimiter = %x09 / %x20-2F / %x3B-40 / %x5B-60 / %x7B-7E"
    auto is_delimiter = [](char ch) {
        auto c = static_cast<unsigned char>(ch);
        return c == 0x09 || (c >= 0x20 && c <= 0x2F) || (c >= 0x3B && c <= 0x40) ||
               (c >= 0x5B && c <= 0x60) || (c >= 0x7B && c <= 0x7E);
    };

    // RFC 6265 §5.1.1 step 1 — "Using the grammar below, divide the cookie-date into date-tokens."
    bool found_time = false, found_day = false, found_month = false, found_year = false;
    int day = 0, month = 0, year = 0, hour = 0, minute = 0, second = 0;
    for (std::size_t pos = 0; pos < text.size();) {
        while (pos < text.size() && is_delimiter(text[pos])) ++pos;
        std::size_t start = pos;
        while (pos < text.size() && !is_delimiter(text[pos])) ++pos;
        auto token = text.substr(start, pos - start);
        if (token.empty()) continue;

        // RFC 6265 §5.1.1 steps 2.1-2.4 — "Process each date-token sequentially in the order the
        // date-tokens appear in the cookie-date:" — time, then day-of-month, then month, then
        // year; each production is only matched while its flag is not set, and a match skips the
        // remaining sub-steps.
        if (!found_time && match_time(token, hour, minute, second)) { found_time = true; continue; }
        if (!found_day && match_day_of_month(token, day)) { found_day = true; continue; }
        if (!found_month && match_month(token, month)) { found_month = true; continue; }
        if (!found_year && match_year(token, year)) { found_year = true; continue; }
    }

    // RFC 6265 §5.1.1 step 3 — "If the year-value is greater than or equal to 70 and less than or
    // equal to 99, increment the year-value by 1900."
    if (year >= 70 && year <= 99) year += 1900;
    // RFC 6265 §5.1.1 step 4 — "If the year-value is greater than or equal to 0 and less than or
    // equal to 69, increment the year-value by 2000."
    else if (year >= 0 && year <= 69) year += 2000;

    // RFC 6265 §5.1.1 step 5 — "Abort these steps and fail to parse the cookie-date if:" — all
    // four component flags must be set and every value must be in range.
    if (!found_time || !found_day || !found_month || !found_year) return std::nullopt;
    if (day < 1 || day > 31) return std::nullopt;
    if (year < 1601) return std::nullopt;
    if (hour > 23 || minute > 59 || second > 59) return std::nullopt;

    // RFC 6265 §5.1.1 step 6 — "If no such date exists, abort these steps and fail to parse the
    // cookie-date." — year_month_day::ok() rejects e.g. 30 February.
    auto ymd = std::chrono::year{year} /
               std::chrono::month{static_cast<unsigned>(month)} /
               std::chrono::day{static_cast<unsigned>(day)};
    if (!ymd.ok()) return std::nullopt;

    // RFC 6265 §5.1.1 steps 6-7 — "Let the parsed-cookie-date be the date whose day-of-month,
    // month, year, hour, minute, and second (in UTC) are the day-of-month-value, the month-value,
    // the year-value, the hour-value, the minute-value, and the second-value, respectively." /
    // "Return the parsed-cookie-date as the result of this algorithm."
    // The sum must run in a 64-bit seconds domain: the standard only guarantees 23/29 bits for
    // hours/minutes, and on 32-bit-rep implementations (libstdc++, MSVC) adding minutes to
    // sys_days{9999-12-31} overflows (signed-overflow UB) before the clamp below sees the value;
    // seconds is 64-bit in practice, so sys_time<seconds> arithmetic is exact for every
    // in-grammar cookie-date (years 1601-9999, RFC 6265 §5.1.1 step 5).
    auto parsed_date = std::chrono::sys_time<std::chrono::seconds>{std::chrono::sys_days{ymd}} +
                       std::chrono::seconds{hour * 3600LL + minute * 60LL + second};

    // RFC 6265 §5.2.1 — "If the expiry-time is later than the last date the user agent can
    // represent, the user agent MAY replace the expiry-time with the last representable date."
    // / "If the expiry-time is earlier than the earliest date the user agent can represent,
    // the user agent MAY replace the expiry-time with the earliest representable date." The
    // cookie-date grammar admits years 1601-9999 (§5.1.1 step 5), which can exceed the range
    // of system_clock::duration (a nanosecond-resolution clock holds roughly 1677-2262);
    // clamp instead of letting the implicit conversion to system_clock::time_point overflow,
    // mirroring the Max-Age clamping in accept_cookie.
    auto maximum = std::chrono::time_point_cast<std::chrono::seconds>(
        std::chrono::system_clock::time_point::max());
    auto minimum = std::chrono::time_point_cast<std::chrono::seconds>(
        std::chrono::system_clock::time_point::min());
    if (parsed_date >= maximum) return std::chrono::system_clock::time_point::max();
    if (parsed_date <= minimum) return std::chrono::system_clock::time_point::min();
    return std::chrono::system_clock::time_point{
        std::chrono::duration_cast<std::chrono::system_clock::duration>(
            parsed_date.time_since_epoch())};
}

} // namespace detail

// ─── Cookie types (RFC 6265 §4, §5) ─────────────────────────

enum class same_site : std::uint8_t { none, lax, strict };

struct set_cookie {
    std::string name;
    std::string value;
    std::optional<std::string> domain;
    std::optional<std::string> path;
    std::optional<std::chrono::system_clock::time_point> expires;
    std::optional<std::int64_t> max_age;
    bool secure{false};
    bool http_only{false};
    enum same_site same_site{http::same_site::lax};
};

struct cookie {
    std::string name;
    std::string value;
    std::string domain;
    std::string path;
    std::optional<std::chrono::system_clock::time_point> expires;
    std::chrono::system_clock::time_point creation_time{};
    bool secure{false};
    bool http_only{false};
    bool host_only{true};
    enum same_site same_site{http::same_site::lax};
};

enum class cookie_rejection : std::uint8_t {
    invalid_origin,
    domain_mismatch,
    public_suffix,
    secure_origin_required,
};

struct cookie_request_context {
    std::string_view canonical_host;
    std::string_view request_path;
    bool secure;
    std::chrono::system_clock::time_point now;
};

template <typename Provider>
concept public_suffix_provider = requires(const Provider& provider, std::string_view domain) {
    { provider.is_public_suffix(domain) } -> std::convertible_to<bool>;
};

// RFC 6265 §5.2 — parsing is context-free. Domain acceptance, default path,
// Max-Age's reference time, and the Secure origin rule are applied by accept_cookie.
//
// Deliberately lossy: RFC 6265 §5.2 mandates ignoring a malformed
// set-cookie-string entirely ("...the user agent MUST ... ignore the
// set-cookie-string entirely"), so every parse-level rejection reason
// collapses to nullopt by design; contrast with accept_cookie, where
// contextual rejections carry a typed cookie_rejection.
[[nodiscard]] inline auto parse_set_cookie(std::string_view header) -> std::optional<set_cookie> {
    // RFC 6265 §5.2 — "The name-value-pair string consists of the characters up to, but not
    // including, the first %x3B (";"), and the unparsed-attributes consist of the remainder of
    // the set-cookie-string (including the %x3B (";") in question)."
    auto semi = header.find(';');
    auto pair = (semi != std::string_view::npos) ? header.substr(0, semi) : header;

    // RFC 6265 §5.2 — "If the name-value-pair string lacks a %x3D ("=") character, ignore the
    // set-cookie-string entirely." (An empty name is rejected again after trimming, below.)
    auto eq = pair.find('=');
    if (eq == std::string_view::npos || eq == 0) return std::nullopt;

    // RFC 6265 §5.2 — "The (possibly empty) name string consists of the characters up to, but not
    // including, the first %x3D ("=") character, and the (possibly empty) value string consists
    // of the characters after the first %x3D ("=") character."
    set_cookie parsed;
    parsed.name = std::string(pair.substr(0, eq));
    parsed.value = std::string(pair.substr(eq + 1));

    // RFC 6265 §5.2 — "Remove any leading or trailing WSP characters from the name string and the
    // value string." (Internal whitespace is maintained; WSP is SP or HTAB.) The trimmed range
    // is computed once on a string_view instead of repeatedly erasing from the front.
    auto trim_wsp = [](std::string_view text) {
        while (!text.empty() && detail::is_wsp(text.front())) text.remove_prefix(1);
        while (!text.empty() && detail::is_wsp(text.back())) text.remove_suffix(1);
        return text;
    };
    parsed.name = std::string(trim_wsp(parsed.name));
    parsed.value = std::string(trim_wsp(parsed.value));

    // RFC 6265 §5.2 — "If the name string is empty, ignore the set-cookie-string entirely."
    if (parsed.name.empty()) return std::nullopt;

    // RFC 6265 §4.1.1 — "cookie-name = token" — token is the RFC 9110 §5.6.2 token charset
    // (1*tchar); a name outside that charset is rejected rather than accepted with a semantic
    // mismatch.
    for (char ch : parsed.name)
        if (!detail::is_tchar(static_cast<unsigned char>(ch))) return std::nullopt;

    // RFC 6265 §4.1.1 — "cookie-value = *cookie-octet / ( DQUOTE *cookie-octet DQUOTE )" with
    // "cookie-octet = %x21 / %x23-2B / %x2D-3A / %x3C-5B / %x5D-7E" (excluding CTLs,
    // whitespace, DQUOTE, comma, semicolon, and backslash). The §5.2 parse does not unquote the
    // value (RFC 6265 §5.2 step 6 — "cookie-value is the value string"), so the DQUOTE-wrapped
    // form keeps its surrounding quotes; a bare value must not contain DQUOTE.
    auto value_is_valid = [](std::string_view value) {
        if (value.size() >= 2 && value.front() == '"' && value.back() == '"')
            value = value.substr(1, value.size() - 2);
        for (char ch : value)
            if (!detail::is_cookie_octet(ch)) return false;
        return true;
    };
    if (!value_is_valid(parsed.value)) return std::nullopt;

    // RFC 6265 §5.2 — unparsed-attributes algorithm: "Discard the first character of the
    // unparsed-attributes (which will be a %x3B (";") character)." Then consume each cookie-av
    // up to the next %x3B and split it on the first %x3D ("=") into attribute-name and
    // attribute-value.
    auto rest = (semi != std::string_view::npos) ? header.substr(semi + 1) : std::string_view{};
    while (!rest.empty()) {
        while (!rest.empty() && detail::is_wsp(rest.front())) rest.remove_prefix(1);
        auto next = rest.find(';');
        auto attr = (next != std::string_view::npos) ? rest.substr(0, next) : rest;
        rest = (next != std::string_view::npos) ? rest.substr(next + 1) : std::string_view{};
        while (!attr.empty() && detail::is_wsp(attr.back())) attr.remove_suffix(1);

        // RFC 6265 §5.2 — "If the cookie-av string contains a %x3D ("=") character: The (possibly
        // empty) attribute-name string consists of the characters up to, but not including, the
        // first %x3D ("=") character, and the (possibly empty) attribute-value string consists of
        // the characters after the first %x3D ("=") character."
        auto aeq = attr.find('=');
        auto aname = (aeq != std::string_view::npos) ? attr.substr(0, aeq) : attr;
        auto aval = (aeq != std::string_view::npos) ? attr.substr(aeq + 1) : std::string_view{};
        // RFC 6265 §5.2 — "Remove any leading or trailing WSP characters from the attribute-name
        // string and the attribute-value string."
        while (!aname.empty() && detail::is_wsp(aname.back())) aname.remove_suffix(1);
        while (!aval.empty() && detail::is_wsp(aval.front())) aval.remove_prefix(1);

        // RFC 6265 §5.2 step 6 — "Notice that attributes with unrecognized attribute-names are
        // ignored."
        if (iequal(aname, "domain")) {
            // RFC 6265 §5.2.3 — "If the first character of the attribute-value string is %x2E
            // ("."): Let cookie-domain be the attribute-value without the leading %x2E (".")
            // character."
            std::string domain{aval};
            if (!domain.empty() && domain.front() == '.') domain.erase(domain.begin());
            std::ranges::transform(domain, domain.begin(), [](char character) {
                if (character >= 'A' && character <= 'Z')
                    return static_cast<char>(character - 'A' + 'a');
                return character;
            });
            parsed.domain = std::move(domain);
        } else if (iequal(aname, "path")) {
            parsed.path = std::string(aval);
        } else if (iequal(aname, "secure")) {
            // RFC 6265 §5.2.5 — "If the attribute-name case-insensitively matches the string
            // "Secure", the user agent MUST append an attribute to the cookie-attribute-list with
            // an attribute-name of Secure and an empty attribute-value."
            parsed.secure = true;
        } else if (iequal(aname, "httponly")) {
            // RFC 6265 §5.2.6 — "If the attribute-name case-insensitively matches the string
            // "HttpOnly", the user agent MUST append an attribute to the cookie-attribute-list
            // with an attribute-name of HttpOnly and an empty attribute-value."
            parsed.http_only = true;
        } else if (iequal(aname, "samesite")) {
            // SameSite is not defined by RFC 6265; it was introduced by draft-ietf-httpbis-
            // cookie-same-site and folded into RFC 6265bis, which obsoletes RFC 6265. The
            // value is matched case-insensitively against the draft-ietf-httpbis-rfc6265bis-14
            // §4.1.1 grammar "samesite-value = "Strict" / "Lax" / "None""; anything else takes
            // the default enforcement mode, which §4.1.2.7 describes as "subject to a default
            // enforcement mode that is equivalent to "Lax"" ("If the "SameSite" attribute's
            // value is something other than these three known keywords, the attribute's value
            // will be subject to a default enforcement mode that is equivalent to "Lax"").
            // That mode is modeled here as same_site::lax (the struct's default initializer).
            if (iequal(aval, "strict")) parsed.same_site = same_site::strict;
            else if (iequal(aval, "none")) parsed.same_site = same_site::none;
            else parsed.same_site = same_site::lax;
        } else if (iequal(aname, "max-age")) {
            // RFC 6265 §5.2.2 — "If the first character of the attribute-value is not a DIGIT or
            // a "-" character, ignore the cookie-av."
            bool valid = !aval.empty() &&
                         (detail::is_digit(aval.front()) || aval.front() == '-');
            // RFC 6265 §5.2.2 — "If the remainder of attribute-value contains a non-DIGIT
            // character, ignore the cookie-av." — a malformed value ignores the attribute as a
            // whole rather than accepting its leading digits.
            if (valid)
                for (std::size_t i = 1; i < aval.size(); ++i)
                    if (!detail::is_digit(aval[i])) { valid = false; break; }
            if (valid) {
                // RFC 6265 §5.2.2 — "Let delta-seconds be the attribute-value converted to an
                // integer. If delta-seconds is less than or equal to zero (0), let expiry-time
                // be the earliest representable date and time. Otherwise, let the expiry-time be
                // the current date and time plus delta-seconds seconds."
                std::int64_t secs = 0;
                if (auto [ptr, ec] = std::from_chars(aval.data(), aval.data() + aval.size(), secs);
                    ec == std::errc{}) {
                    parsed.max_age = secs;
                }
            }
        } else if (iequal(aname, "expires")) {
            // RFC 6265 §5.2.1 — "Let the expiry-time be the result of parsing the attribute-value
            // as cookie-date (see Section 5.1.1)." No precedence is decided here: the value is
            // always parsed and kept, and accept_cookie resolves Max-Age over Expires per
            // RFC 6265 §5.3 step 3 — "If the cookie-attribute-list contains an attribute with an
            // attribute-name of "Max-Age": ... Otherwise, if the cookie-attribute-list contains
            // an attribute with an attribute-name of "Expires" (and does not contain an
            // attribute with an attribute-name of "Max-Age")".
            if (auto expiry = detail::parse_cookie_date(aval)) parsed.expires = *expiry;
            // RFC 6265 §5.2.1 — "If the attribute-value failed to parse as a cookie date, ignore
            // the cookie-av." — an unparsable Expires leaves the cookie as a session cookie
            // (no expiry), matching the documented out-of-scope behavior.
        }
    }

    // draft-ietf-httpbis-rfc6265bis-14 §5.6 step 19 (storage model) — "If the cookie's
    // "same-site-flag" is "None", abort these steps and ignore the cookie entirely unless the
    // cookie's secure-only-flag is true." SameSite=None is only meaningful when the same
    // set-cookie-string also carries a Secure attribute; without it the whole string is ignored
    // at parse time. The rule is context-free (it depends only on the attributes present, not
    // on the request environment), so it belongs in parse_set_cookie rather than accept_cookie.
    if (parsed.same_site == same_site::none && !parsed.secure) return std::nullopt;

    return parsed;
}

// RFC 6265 §5.1.3 — Domain matching
[[nodiscard]] inline auto domain_match(std::string_view request_domain, std::string_view cookie_domain) -> bool {
    if (cookie_domain.empty()) return false;
    // RFC 6265 §5.1.3 — "The string is a host name (i.e., not an IP address)." — the
    // suffix-matching rule applies only to host names, so an IP-literal request domain matches
    // only an identical cookie domain.
    if (detail::is_ip_literal(request_domain)) return iequal(request_domain, cookie_domain);
    // RFC 6265 §5.1.3 — "The domain string and the string are identical. (Note that both the
    // domain string and the string will have been canonicalized to lower case at this point.)"
    if (iequal(request_domain, cookie_domain)) return true;
    if (request_domain.size() > cookie_domain.size()) {
        auto suffix = request_domain.substr(request_domain.size() - cookie_domain.size());
        // RFC 6265 §5.1.3 — "The domain string is a suffix of the string." and "The last
        // character of the string that is not included in the domain string is a %x2E (".")
        // character."
        if (iequal(suffix, cookie_domain) &&
            request_domain[request_domain.size() - cookie_domain.size() - 1] == '.')
            return true;
    }
    return false;
}

template <public_suffix_provider Provider>
[[nodiscard]] inline auto accept_cookie(
    const set_cookie& parsed,
    const cookie_request_context& origin,
    const Provider& suffixes) -> std::expected<cookie, cookie_rejection>
{
    if (origin.canonical_host.empty())
        return std::unexpected{cookie_rejection::invalid_origin};
    // draft-ietf-httpbis-rfc6265bis-14 §5.6 step 13 (storage model) — "If the request-uri does
    // not denote a "secure" connection (as defined by the user agent), and the cookie's
    // secure-only-flag is true, then abort these steps and ignore the cookie entirely."
    if (parsed.secure && !origin.secure)
        return std::unexpected{cookie_rejection::secure_origin_required};

    auto domain = std::string{origin.canonical_host};
    auto host_only = true;
    if (parsed.domain && !parsed.domain->empty()) {
        domain = *parsed.domain;
        host_only = false;
        // RFC 6265 §5.3 step 5 — a public suffix Domain is rejected, except
        // when it equals the request host, where it becomes host-only.
        if (suffixes.is_public_suffix(domain)) {
            if (!iequal(domain, origin.canonical_host))
                return std::unexpected{cookie_rejection::public_suffix};
            domain = std::string{origin.canonical_host};
            host_only = true;
        }
        if (!domain_match(origin.canonical_host, domain))
            return std::unexpected{cookie_rejection::domain_mismatch};
    }

    auto path = detail::default_path(origin.request_path);
    if (parsed.path && !parsed.path->empty() && parsed.path->front() == '/')
        path = *parsed.path;

    auto expiry = parsed.expires;
    if (parsed.max_age) {
        // RFC 6265 §5.2.2 — "If delta-seconds is less than or equal to zero
        // (0), let expiry-time be the earliest representable date and time.
        // Otherwise, let the expiry-time be the current date and time plus
        // delta-seconds seconds."
        if (*parsed.max_age <= 0) {
            expiry = std::chrono::system_clock::time_point::min();
        } else {
            // RFC 6265 §5.2.1 — "If the expiry-time is later than the last
            // date the user agent can represent, the user agent MAY replace
            // the expiry-time with the last representable date." — the check
            // runs in the exact integer domain: max_age is compared against
            // the remaining representable span, and the addition only runs
            // when the sum is known to fit the clock.
            auto now_seconds = std::chrono::time_point_cast<std::chrono::seconds>(origin.now);
            auto maximum_seconds = std::chrono::time_point_cast<std::chrono::seconds>(
                std::chrono::system_clock::time_point::max());
            auto remaining = (maximum_seconds - now_seconds).count();
            expiry = *parsed.max_age >= remaining
                ? std::chrono::system_clock::time_point::max()
                : origin.now + std::chrono::seconds{*parsed.max_age};
        }
    }

    return cookie{
        .name = parsed.name,
        .value = parsed.value,
        .domain = std::move(domain),
        .path = std::move(path),
        .expires = expiry,
        .creation_time = origin.now,
        .secure = parsed.secure,
        .http_only = parsed.http_only,
        .host_only = host_only,
        .same_site = parsed.same_site,
    };
}

// RFC 6265 §5.1.4 — Path matching
[[nodiscard]] inline auto path_match(std::string_view request_path, std::string_view cookie_path) -> bool {
    if (cookie_path.empty() || cookie_path == "/") return true;
    // RFC 6265 §5.1.4 — "The cookie-path and the request-path are identical."
    if (request_path == cookie_path) return true;
    if (request_path.starts_with(cookie_path)) {
        // RFC 6265 §5.1.4 — "The cookie-path is a prefix of the request-path, and the last
        // character of the cookie-path is %x2F ("/")."
        if (cookie_path.back() == '/') return true;
        // RFC 6265 §5.1.4 — "The cookie-path is a prefix of the request-path, and the first
        // character of the request-path that is not included in the cookie-path is a %x2F ("/")
        // character."
        if (request_path.size() > cookie_path.size() &&
            request_path[cookie_path.size()] == '/')
            return true;
    }
    return false;
}

// ─── Cookie matching (RFC 6265 §5.4) ─────────────────────────
//
// The library no longer owns a cookie jar: the storage model (§5.3) is
// application coordination (eviction, persistence, public-suffix enforcement).
// Callers keep their own `std::vector<cookie>` and use these stateless helpers
// to select and serialize cookies for a request.

// RFC 6265 §5.4 — compute the Cookie header value for a request. A cookie is
// included when its domain matches the request-host (§5.4 step 1), its path
// path-matches the request path (§5.4 step 1), it is not expired, and it is not
// Secure when the channel is not secure (§5.4 step 1 — "If the cookie's
// secure-only-flag is true, then the request-uri's scheme must denote a
// "secure" protocol"). Serialization follows §5.4 step 4: "Output the cookie's
// name, the %x3D ("=") character, and the cookie's value." / "If there is an
// unprocessed cookie in the cookie-list, output the characters %x3B and %x20
// ("; ")."
[[nodiscard]] inline auto make_cookie_header(
    std::span<const cookie> cookies,
    const cookie_request_context& context) -> std::string {
    std::vector<const cookie*> matched;
    for (const auto& c : cookies) {
        if (c.expires && *c.expires <= context.now) continue;
        // RFC 6265 §5.4 step 1 — a Secure cookie is sent only over a secure
        // channel; a non-secure cookie is sent regardless.
        if (c.secure && !context.secure) continue;
        // RFC 6265 §5.4 step 1 — "Either: The cookie's host-only-flag is true and the
        // canonicalized request-host is identical to the cookie's domain. Or: The cookie's
        // host-only-flag is false and the canonicalized request-host domain-matches the
        // cookie's domain."
        if (c.host_only ? !iequal(context.canonical_host, c.domain)
                        : !domain_match(context.canonical_host, c.domain))
            continue;
        if (!path_match(context.request_path, c.path)) continue;
        matched.push_back(&c);
    }
    // RFC 6265 §5.4 step 2 — "The user agent SHOULD sort the cookie-list in the following
    // order: * Cookies with longer paths are listed before cookies with shorter paths.
    // * Among cookies that have equal-length path fields, cookies with earlier
    // creation-times are listed before cookies with later creation-times."
    std::ranges::stable_sort(matched, [](const cookie* a, const cookie* b) {
        if (a->path.size() != b->path.size()) return a->path.size() > b->path.size();
        return a->creation_time < b->creation_time;
    });
    std::string result;
    for (auto* c : matched) {
        if (!result.empty()) result += "; ";
        result += c->name;
        result += '=';
        result += c->value;
    }
    return result;
}

// SameSite is parsed and retained, but browsing-context classification is an
// application policy and is intentionally not applied by make_cookie_header.

} // namespace http
