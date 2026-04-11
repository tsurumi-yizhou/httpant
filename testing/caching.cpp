#include <boost/ut.hpp>

#include "test_support.hpp"

namespace httpant::testing {

using namespace boost::ut;
using namespace std::literals;

static suite<"caching"> caching_suite = [] {
    "parse_cache_control_max_age"_test = [] {
        auto cc = http::parse_cache_control("max-age=3600");
        expect(cc.has(http::directive::max_age));
        expect(cc.max_age().has_value());
        expect(*cc.max_age() == 3600_u);
    };

    "parse_cache_control_multiple_directives"_test = [] {
        auto cc = http::parse_cache_control("public, max-age=60, no-transform");
        expect(cc.has(http::directive::public_));
        expect(cc.has(http::directive::max_age));
        expect(cc.has(http::directive::no_transform));
        expect(*cc.max_age() == 60_u);
    };

    "parse_cache_control_no_store"_test = [] {
        auto cc = http::parse_cache_control("no-store");
        expect(cc.has(http::directive::no_store));
        expect(!cc.has(http::directive::max_age));
    };

    "parse_cache_control_s_maxage"_test = [] {
        auto cc = http::parse_cache_control("s-maxage=120, max-age=60");
        expect(*cc.s_maxage() == 120_u);
        expect(*cc.max_age() == 60_u);
    };

    "freshness_lifetime_from_max_age"_test = [] {
        auto now = std::chrono::system_clock::now();
        http::cache_entry entry{
            .key = basic_get("/cached"),
            .stored = http::response{
                .status = 200, .reason = {},
                .fields = {{"cache-control", "max-age=60"}},
                .body = {},
            },
            .request_time = now,
            .response_time = now,
        };
        auto fl = http::freshness_lifetime(entry);
        expect(fl == std::chrono::seconds{60});
    };

    "freshness_lifetime_s_maxage_takes_priority"_test = [] {
        auto now = std::chrono::system_clock::now();
        http::cache_entry entry{
            .key = basic_get("/cached"),
            .stored = http::response{
                .status = 200, .reason = {},
                .fields = {{"cache-control", "s-maxage=120, max-age=60"}},
                .body = {},
            },
            .request_time = now,
            .response_time = now,
        };
        expect(http::freshness_lifetime(entry) == std::chrono::seconds{120});
    };

    "is_cacheable_rejects_no_store"_test = [] {
        auto res = http::response{
            .status = 200, .reason = {},
            .fields = {{"cache-control", "no-store"}},
            .body = {},
        };
        expect(!http::is_cacheable(res, basic_get("/")));
    };

    "is_cacheable_accepts_public_200"_test = [] {
        auto res = http::response{
            .status = 200, .reason = {},
            .fields = {{"cache-control", "public, max-age=60"}},
            .body = {},
        };
        expect(http::is_cacheable(res, basic_get("/")));
    };

    "is_cacheable_rejects_post"_test = [] {
        auto res = http::response{.status = 200, .reason = {}, .fields = {}, .body = {}};
        auto req = http::request{.method = http::method::POST, .target = "/", .fields = {}, .body = {}};
        expect(!http::is_cacheable(res, req));
    };

    "make_conditional_adds_etag"_test = [] {
        auto now = std::chrono::system_clock::now();
        http::cache_entry entry{
            .key = basic_get("/resource"),
            .stored = http::response{
                .status = 200, .reason = {},
                .fields = {{"etag", "\"abc123\""}},
                .body = {},
            },
            .request_time = now,
            .response_time = now,
        };
        auto cond = http::make_conditional(basic_get("/resource"), entry);
        auto inm = http::find_header(cond.fields, "if-none-match");
        expect(inm.has_value());
        expect(*inm == "\"abc123\""sv);
    };

    "make_conditional_adds_last_modified"_test = [] {
        auto now = std::chrono::system_clock::now();
        http::cache_entry entry{
            .key = basic_get("/resource"),
            .stored = http::response{
                .status = 200, .reason = {},
                .fields = {{"last-modified", "Thu, 01 Jan 2024 00:00:00 GMT"}},
                .body = {},
            },
            .request_time = now,
            .response_time = now,
        };
        auto cond = http::make_conditional(basic_get("/resource"), entry);
        auto ims = http::find_header(cond.fields, "if-modified-since");
        expect(ims.has_value());
    };

    "cache_store_lookup_and_store"_test = [] {
        http::cache_store store;
        auto now = std::chrono::system_clock::now();
        http::cache_entry entry{
            .key = basic_get("/data"),
            .stored = http::response{
                .status = 200, .reason = {},
                .fields = {{"cache-control", "max-age=60"}},
                .body = make_body("cached"),
            },
            .request_time = now,
            .response_time = now,
        };
        store.store(entry);
        expect(store.size() == 1_u);
        auto found = store.lookup(basic_get("/data"));
        expect(found.has_value());
        expect(found->stored.status == 200_u);
    };

    "cache_store_invalidate"_test = [] {
        http::cache_store store;
        auto now = std::chrono::system_clock::now();
        store.store(http::cache_entry{
            .key = basic_get("/data"),
            .stored = http::response{.status = 200, .reason = {}, .fields = {}, .body = {}},
            .request_time = now,
            .response_time = now,
        });
        store.invalidate("/data");
        expect(store.size() == 0_u);
    };

    "matches_vary_with_matching_headers"_test = [] {
        auto now = std::chrono::system_clock::now();
        http::cache_entry entry{
            .key = http::request{
                .method = http::method::GET, .target = "/",
                .fields = {{"host", "example.com"}, {"accept-encoding", "gzip"}},
                .body = {},
            },
            .stored = http::response{
                .status = 200, .reason = {},
                .fields = {{"vary", "accept-encoding"}},
                .body = {},
            },
            .request_time = now,
            .response_time = now,
        };
        auto req_matching = http::request{
            .method = http::method::GET, .target = "/",
            .fields = {{"host", "example.com"}, {"accept-encoding", "gzip"}},
            .body = {},
        };
        auto req_different = http::request{
            .method = http::method::GET, .target = "/",
            .fields = {{"host", "example.com"}, {"accept-encoding", "br"}},
            .body = {},
        };
        expect(http::matches_vary(entry, req_matching));
        expect(!http::matches_vary(entry, req_different));
    };

    "only_if_cached_directive_is_parsed"_test = [] {
        auto cc = http::parse_cache_control("only-if-cached");
        expect(cc.has(http::directive::only_if_cached));
    };

    "immutable_directive_is_parsed"_test = [] {
        auto cc = http::parse_cache_control("max-age=31536000, immutable");
        expect(cc.has(http::directive::immutable));
        expect(*cc.max_age() == 31536000_u);
    };
};

} // namespace httpant::testing
