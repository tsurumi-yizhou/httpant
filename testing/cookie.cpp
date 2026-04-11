#include <boost/ut.hpp>

import httpant;

namespace httpant::testing {

using namespace boost::ut;
using namespace std::literals;

static suite<"cookie"> cookie_suite = [] {
    "parse_set_cookie_basic"_test = [] {
        auto c = http::parse_set_cookie("sid=abc123; Path=/; HttpOnly");
        expect(c.has_value());
        expect(c->name == "sid"sv);
        expect(c->value == "abc123"sv);
        expect(c->path == "/"sv);
        expect(c->http_only);
    };

    "parse_set_cookie_with_domain"_test = [] {
        auto c = http::parse_set_cookie("id=xyz; Domain=example.com; Path=/; Secure");
        expect(c.has_value());
        expect(c->domain == "example.com"sv);
        expect(c->secure);
    };

    "parse_set_cookie_leading_dot"_test = [] {
        auto c = http::parse_set_cookie("id=xyz; Domain=.example.com");
        expect(c.has_value());
        expect(c->domain == "example.com"sv);
    };

    "parse_set_cookie_samesite"_test = [] {
        auto c = http::parse_set_cookie("id=1; SameSite=Strict");
        expect(c.has_value());
        expect(c->site == http::same_site::strict);
    };

    "parse_set_cookie_max_age"_test = [] {
        auto c = http::parse_set_cookie("id=1; Max-Age=3600");
        expect(c.has_value());
        expect(c->expires.has_value());
    };

    "parse_set_cookie_rejects_empty_name"_test = [] {
        auto c = http::parse_set_cookie("=value");
        expect(!c.has_value());
    };

    "domain_match_exact"_test = [] {
        expect(http::domain_match("example.com", "example.com"));
    };

    "domain_match_subdomain"_test = [] {
        expect(http::domain_match("sub.example.com", "example.com"));
    };

    "domain_match_rejects_unrelated"_test = [] {
        expect(!http::domain_match("evil.com", "example.com"));
    };

    "domain_match_rejects_partial"_test = [] {
        expect(!http::domain_match("notexample.com", "example.com"));
    };

    "path_match_root"_test = [] {
        expect(http::path_match("/anything", "/"));
    };

    "path_match_exact"_test = [] {
        expect(http::path_match("/account", "/account"));
    };

    "path_match_subpath"_test = [] {
        expect(http::path_match("/account/profile", "/account"));
    };

    "path_match_rejects_prefix_collision"_test = [] {
        expect(!http::path_match("/accounting", "/account"));
    };

    "cookie_jar_store_and_match"_test = [] {
        http::cookie_jar jar;
        auto c = http::parse_set_cookie("sid=abc123; Path=/");
        expect(c.has_value());
        jar.store(*c, "example.com");
        expect(jar.size() == 1_u);
        auto header = jar.match("example.com", "/");
        expect(header == "sid=abc123"sv);
    };

    "cookie_jar_domain_scoping"_test = [] {
        http::cookie_jar jar;
        auto c = http::parse_set_cookie("sid=abc; Domain=example.com; Path=/");
        jar.store(*c, "example.com");
        expect(jar.match("sub.example.com", "/") == "sid=abc"sv);
        expect(jar.match("other.com", "/").empty());
    };

    "cookie_jar_path_scoping"_test = [] {
        http::cookie_jar jar;
        auto c = http::parse_set_cookie("sid=abc; Path=/account");
        jar.store(*c, "example.com");
        expect(!jar.match("example.com", "/account/profile").empty());
        expect(jar.match("example.com", "/other").empty());
    };

    "cookie_jar_replaces_duplicates"_test = [] {
        http::cookie_jar jar;
        jar.store(*http::parse_set_cookie("sid=first; Path=/"), "example.com");
        jar.store(*http::parse_set_cookie("sid=second; Path=/"), "example.com");
        expect(jar.size() == 1_u);
        expect(jar.match("example.com", "/") == "sid=second"sv);
    };

    "cookie_jar_multiple_cookies"_test = [] {
        http::cookie_jar jar;
        jar.store(*http::parse_set_cookie("a=1; Path=/"), "example.com");
        jar.store(*http::parse_set_cookie("b=2; Path=/"), "example.com");
        expect(jar.size() == 2_u);
        auto header = jar.match("example.com", "/");
        expect(header.contains("a=1"sv));
        expect(header.contains("b=2"sv));
    };

    "cookie_jar_clear"_test = [] {
        http::cookie_jar jar;
        jar.store(*http::parse_set_cookie("sid=abc; Path=/"), "example.com");
        jar.clear();
        expect(jar.size() == 0_u);
    };
};

} // namespace httpant::testing
