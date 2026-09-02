#include <boost/ut.hpp>

#include <chrono>
#include <cstdint>
#include <expected>
#include <ranges>
#include <string_view>
#include <vector>

import httpant;

namespace httpant::testing {

using namespace boost::ut;
using namespace std::literals;

namespace {

constexpr auto instant(std::int64_t seconds) -> std::chrono::system_clock::time_point {
    return std::chrono::system_clock::time_point{std::chrono::seconds{seconds}};
}

struct suffixes {
    std::vector<std::string_view> values;

    [[nodiscard]] auto is_public_suffix(std::string_view domain) const -> bool {
        return std::ranges::find(values, domain) != values.end();
    }
};

auto accept(std::string_view text,
            http::cookie_request_context origin = {
                .canonical_host = "www.example.com",
                .request_path = "/account/page",
                .secure = true,
                .now = instant(1'000),
            }) -> std::expected<http::cookie, http::cookie_rejection>
{
    auto parsed = http::parse_set_cookie(text);
    if (!parsed) return std::unexpected{http::cookie_rejection::invalid_origin};
    return http::accept_cookie(*parsed, origin, suffixes{{"com"}});
}

} // namespace

static suite<"cookie"> cookie_suite = [] {
    "parse_is_context_free"_test = [] {
        // RFC 6265 §5.2 step 6 — "The cookie-name is the name string, and the
        // cookie-value is the value string." Environmental acceptance is a later step.
        auto parsed = http::parse_set_cookie(
            "sid=abc; Domain=.Example.COM; Path=/x; Secure; HttpOnly; SameSite=Strict");
        expect(parsed.has_value());
        expect(parsed->name == "sid"sv);
        expect(parsed->value == "abc"sv);
        expect(parsed->domain == "example.com"sv);
        expect(parsed->path == "/x"sv);
        expect(parsed->secure);
        expect(parsed->http_only);
        expect(parsed->same_site == http::same_site::strict);
    };

    "parse_rejects_invalid_name_and_value"_test = [] {
        // RFC 6265 §4.1.1 — "cookie-name = token" and cookie-value is composed
        // only of cookie-octet characters.
        expect(!http::parse_set_cookie("na me=1").has_value());
        expect(!http::parse_set_cookie("name=a,b").has_value());
        expect(!http::parse_set_cookie("=value").has_value());
    };

    "parse_strips_wsp_from_name_value_and_attributes"_test = [] {
        // RFC 6265 §5.2 step 4 — "Remove any leading or trailing WSP characters
        // from the name string and the value string." WSP is SP / HTAB
        // (RFC 5234 Appendix B.1, included by reference in RFC 6265 §2.2).
        auto parsed = http::parse_set_cookie(" \tsid\t =\t abc \t");
        expect(parsed.has_value());
        expect(parsed->name == "sid"sv);
        expect(parsed->value == "abc"sv);

        // RFC 6265 §5.2 unparsed-attributes step 5 — "Remove any leading or
        // trailing WSP characters from the attribute-name string and the
        // attribute-value string."
        auto attribute = http::parse_set_cookie("sid=1;\tMax-Age\t=\t60\t");
        expect(attribute.has_value());
        expect(attribute->max_age.has_value());
        expect(*attribute->max_age == 60);
    };

    "host_only_acceptance_records_request_host"_test = [] {
        // RFC 6265 §5.3 step 6 — "Set the cookie's host-only-flag to true. Set
        // the cookie's domain to the canonicalized request-host."
        auto cookie = accept("sid=1");
        expect(cookie.has_value());
        expect(cookie->host_only);
        expect(cookie->domain == "www.example.com"sv);
    };

    "empty_domain_falls_back_to_host_only"_test = [] {
        // RFC 6265 §5.2.3 — an empty Domain attribute is undefined and SHOULD be
        // ignored; acceptance therefore uses the host-only branch.
        auto cookie = accept("sid=1; Domain=");
        expect(cookie.has_value());
        expect(cookie->host_only);
        expect(cookie->domain == "www.example.com"sv);
    };

    "domain_acceptance_is_typed"_test = [] {
        // RFC 6265 §5.3 step 6 — "If the canonicalized request-host does not
        // domain-match the domain-attribute: Ignore the cookie entirely."
        auto accepted = accept("sid=1; Domain=example.com");
        expect(accepted.has_value());
        expect(!accepted->host_only);
        auto rejected = accept("sid=1; Domain=other.test");
        expect(!rejected.has_value());
        expect(rejected.error() == http::cookie_rejection::domain_mismatch);
    };

    "public_suffix_is_rejected"_test = [] {
        // RFC 6265 §5.3 step 5 — "If the user agent is configured to reject
        // public suffixes and the domain-attribute is a public suffix: Ignore the
        // cookie entirely" unless it equals the request host.
        auto parsed = http::parse_set_cookie("sid=1; Domain=com");
        auto rejected = http::accept_cookie(
            *parsed,
            http::cookie_request_context{.canonical_host = "example.com", .request_path = "/",
                                         .secure = true, .now = instant(1'000)},
            suffixes{{"com"}});
        expect(!rejected.has_value());
        expect(rejected.error() == http::cookie_rejection::public_suffix);
    };

    "public_suffix_equal_to_host_becomes_host_only"_test = [] {
        // RFC 6265 §5.3 step 5 — when the domain-attribute equals the canonicalized
        // request-host, "Let the domain-attribute be the empty string."
        auto parsed = http::parse_set_cookie("sid=1; Domain=localhost");
        auto cookie = http::accept_cookie(
            *parsed,
            http::cookie_request_context{.canonical_host = "localhost", .request_path = "/",
                                         .secure = true, .now = instant(1'000)},
            suffixes{{"localhost"}});
        expect(cookie.has_value());
        expect(cookie->host_only);
    };

    "default_path_is_computed_during_acceptance"_test = [] {
        // RFC 6265 §5.1.4 step 4 — "Output the characters of the uri-path ...
        // up to, but not including, the right-most %x2F."
        auto cookie = accept("sid=1");
        expect(cookie->path == "/account"sv);
        auto invalid_path = accept("sid=1; Path=relative");
        expect(invalid_path->path == "/account"sv);
    };

    "max_age_uses_explicit_origin_time"_test = [] {
        // RFC 6265 §5.2.2 — "let the expiry-time be the current date and time
        // plus delta-seconds seconds." The supplied origin.now is that time.
        auto cookie = accept("sid=1; Max-Age=60; Expires=Thu, 01 Jan 2035 00:00:00 GMT");
        expect(cookie.has_value());
        expect(cookie->expires == instant(1'060));
        auto deleted = accept("sid=1; Max-Age=-1");
        expect(deleted->expires == std::chrono::system_clock::time_point::min());
    };

    "expires_is_absolute_and_malformed_attribute_is_ignored"_test = [] {
        // RFC 6265 §5.2.1 — "If the attribute-value failed to parse as a cookie
        // date, ignore the cookie-av." A valid Expires value is independent of origin.now.
        auto valid = accept("sid=1; Expires=Thu, 01 Jan 2035 00:00:00 GMT");
        expect(valid.has_value());
        expect(valid->expires.has_value());
        auto invalid = accept("sid=1; Expires=not-a-date");
        expect(invalid.has_value());
        expect(!invalid->expires.has_value());
    };

    "malformed_max_age_is_ignored"_test = [] {
        // RFC 6265 §5.2.2 — "If the remainder of attribute-value contains a
        // non-DIGIT character, ignore the cookie-av."
        auto cookie = accept("sid=1; Max-Age=12seconds");
        expect(cookie.has_value());
        expect(!cookie->expires.has_value());
    };

    "expires_is_clamped_to_the_clock_range"_test = [] {
        // RFC 6265 §5.2.1 — "If the expiry-time is later than the last date the user agent can
        // represent, the user agent MAY replace the expiry-time with the last representable
        // date." / "If the expiry-time is earlier than the earliest date the user agent can
        // represent, the user agent MAY replace the expiry-time with the earliest representable
        // date." Year 9999 and year 1601 are the extremes of the cookie-date grammar
        // (RFC 6265 §5.1.1 — "year = 2*4DIGIT" and "the year-value is less than 1601" fails to
        // parse); whether they fit in system_clock depends on the clock's precision, so the
        // stored expiry must be either the exact date or exactly the clamping bound — never
        // overflowed into an unrelated value. (This platform's microsecond system_clock can
        // represent both dates, so the assertion below exercises the exact-date branch of the
        // invariant; on a coarser clock, e.g. nanoseconds, the clamp branches run instead.)
        auto far_future = accept("sid=1; Expires=Sat, 31 Dec 9999 23:59:59 GMT");
        auto far_past = accept("sid=1; Expires=Mon, 01 Jan 1601 00:00:00 GMT");
        expect(far_future.has_value());
        expect(far_past.has_value());

        // The expected dates are computed independently in a 64-bit seconds domain:
        // std::chrono::hours/minutes reps are only guaranteed to be 23/29 bits, so
        // sys_days{9999-12-31} + hours + minutes overflows on 32-bit-rep standard
        // libraries before any clamp could apply, while sys_time<seconds> (int64)
        // arithmetic is exact for the whole in-grammar year range.
        auto far_exact = std::chrono::sys_time<std::chrono::seconds>{
                             std::chrono::sys_days{std::chrono::year{9999} / 12 / 31}} +
                         std::chrono::seconds{23 * 3600LL + 59 * 60LL + 59};
        auto past_exact = std::chrono::sys_time<std::chrono::seconds>{
            std::chrono::sys_days{std::chrono::year{1601} / 1 / 1}};
        // Invariant: the stored expiry is the exact date when the clock can represent it,
        // and exactly the clock's min()/max() otherwise — never a wrapped intermediate.
        auto expected = [](std::chrono::sys_time<std::chrono::seconds> exact) {
            auto clock_max = std::chrono::time_point_cast<std::chrono::seconds>(
                std::chrono::system_clock::time_point::max());
            auto clock_min = std::chrono::time_point_cast<std::chrono::seconds>(
                std::chrono::system_clock::time_point::min());
            if (exact >= clock_max) return std::chrono::system_clock::time_point::max();
            if (exact <= clock_min) return std::chrono::system_clock::time_point::min();
            return std::chrono::system_clock::time_point{
                std::chrono::duration_cast<std::chrono::system_clock::duration>(
                    exact.time_since_epoch())};
        };
        expect(*far_future->expires == expected(far_exact));
        expect(*far_past->expires == expected(past_exact));
    };

    "samesite_none_requires_secure"_test = [] {
        // SameSite is not defined by RFC 6265; it was introduced by draft-ietf-httpbis-
        // cookie-same-site and folded into RFC 6265bis, which obsoletes RFC 6265.
        // draft-ietf-httpbis-rfc6265bis-14 §5.6 step 19 (storage model) — "If the cookie's
        // "same-site-flag" is "None", abort these steps and ignore the cookie entirely
        // unless the cookie's secure-only-flag is true."
        expect(!http::parse_set_cookie("sid=1; SameSite=None").has_value());
        expect(!http::parse_set_cookie("sid=1; SameSite=none").has_value());
        auto with_secure = http::parse_set_cookie("sid=1; SameSite=None; Secure");
        expect(with_secure.has_value());
        expect(with_secure->same_site == http::same_site::none);
        expect(with_secure->secure);
        // The check covers the whole attribute list, not the attribute order.
        expect(http::parse_set_cookie("sid=1; Secure; SameSite=None").has_value());
    };

    "samesite_mapping_follows_6265bis_defaults"_test = [] {
        // draft-ietf-httpbis-rfc6265bis-14 §4.1.1 — "samesite-value = "Strict" / "Lax" /
        // "None"" with the attribute value matched case-insensitively; §4.1.2.7 — "If the
        // "SameSite" attribute's value is something other than these three known keywords,
        // the attribute's value will be subject to a default enforcement mode that is
        // equivalent to "Lax"." The absent attribute takes the same default (the struct's
        // same_site initializer is lax).
        auto strict = http::parse_set_cookie("sid=1; samesite=StRiCt; Secure");
        expect(strict.has_value());
        expect(strict->same_site == http::same_site::strict);
        auto lax = http::parse_set_cookie("sid=1; SameSite=LAX; Secure");
        expect(lax.has_value());
        expect(lax->same_site == http::same_site::lax);
        auto unknown = http::parse_set_cookie("sid=1; SameSite=Foo; Secure");
        expect(unknown.has_value());
        expect(unknown->same_site == http::same_site::lax);
        auto absent = http::parse_set_cookie("sid=1; Secure");
        expect(absent.has_value());
        expect(absent->same_site == http::same_site::lax);
    };

    "secure_cookie_requires_secure_origin"_test = [] {
        // draft-ietf-httpbis-rfc6265bis-14 §5.6 step 13 (storage model) — "If the
        // request-uri does not denote a "secure" connection (as defined by the user
        // agent), and the cookie's secure-only-flag is true, then abort these steps
        // and ignore the cookie entirely." (§5.7, the retrieval model, governs
        // make_cookie_header instead.)
        auto rejected = accept(
            "sid=1; Secure",
            http::cookie_request_context{.canonical_host = "www.example.com",
                                         .request_path = "/",
                                         .secure = false, .now = instant(1'000)});
        expect(!rejected.has_value());
        expect(rejected.error() == http::cookie_rejection::secure_origin_required);
    };

    "domain_and_path_matching_follow_rfc_rules"_test = [] {
        // RFC 6265 §5.1.3/§5.1.4 — suffix domain matching requires a dot
        // boundary, and path prefix matching requires a slash boundary.
        expect(http::domain_match("sub.example.com", "example.com"));
        expect(!http::domain_match("notexample.com", "example.com"));
        expect(http::path_match("/account/profile", "/account"));
        expect(!http::path_match("/accounting", "/account"));
    };

    "ip_literals_only_domain_match_exactly"_test = [] {
        // RFC 6265 §5.1.3 — the suffix rule requires that "The string is a host
        // name (i.e., not an IP address)."
        expect(http::domain_match("192.0.2.1", "192.0.2.1"));
        expect(!http::domain_match("192.0.2.1", "0.2.1"));
        expect(http::domain_match("2001:db8::1", "2001:db8::1"));
        expect(!http::domain_match("2001:db8::1", "db8::1"));
    };

    "request_context_filters_expired_secure_and_host_only_cookies"_test = [] {
        // RFC 6265 §5.4 step 1 — "The cookie's host-only-flag is true and the
        // canonicalized request-host is identical to the cookie's domain" and "If the
        // cookie's secure-only-flag is true, then the request-uri's scheme must denote
        // a "secure" protocol"; expired cookies are removed by the storage algorithm.
        auto live = *accept("live=1; Path=/");
        auto secure = *accept("secure=1; Path=/; Secure");
        auto expired = *accept("expired=1; Path=/; Max-Age=5");
        std::vector<http::cookie> jar{live, secure, expired};
        auto insecure = http::make_cookie_header(
            jar,
            http::cookie_request_context{.canonical_host = "www.example.com",
                                         .request_path = "/",
                                         .secure = false, .now = instant(1'010)});
        expect(insecure == "live=1"sv);
        auto secure_header = http::make_cookie_header(
            jar,
            http::cookie_request_context{.canonical_host = "www.example.com",
                                         .request_path = "/",
                                         .secure = true, .now = instant(1'010)});
        expect(secure_header == "live=1; secure=1"sv);
    };

    "cookie_header_orders_path_then_creation_time"_test = [] {
        // RFC 6265 §5.4 step 2 — longer paths precede shorter paths; equal paths
        // are ordered by earlier creation-time.
        auto root = *accept("root=1; Path=/");
        auto newer = *accept("newer=1; Path=/account",
            http::cookie_request_context{.canonical_host = "www.example.com",
                                         .request_path = "/account",
                                         .secure = true, .now = instant(1'002)});
        auto older = *accept("older=1; Path=/account",
            http::cookie_request_context{.canonical_host = "www.example.com",
                                         .request_path = "/account",
                                         .secure = true, .now = instant(1'001)});
        std::vector<http::cookie> jar{root, newer, older};
        expect(http::make_cookie_header(
            jar,
            http::cookie_request_context{.canonical_host = "www.example.com",
                                         .request_path = "/account/page", .secure = true,
                                         .now = instant(2'000)}) ==
               "older=1; newer=1; root=1"sv);
    };
};

} // namespace httpant::testing
