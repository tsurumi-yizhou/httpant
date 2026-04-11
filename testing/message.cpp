#include <boost/ut.hpp>

#include "test_support.hpp"

namespace httpant::testing {

using namespace boost::ut;
using namespace std::literals;

static suite<"message"> message_suite = [] {
    "http_message_types"_test = [] {
        http::request req{
            .method = http::method::GET,
            .target = "/hello",
            .fields = {{"host", "example.com"}},
            .body = {},
        };

        expect(http::to_string(req.method) == "GET"sv);
        expect(req.target == "/hello"sv);

        auto host = http::find_header(req.fields, "Host");
        expect(host.has_value());
        expect(*host == "example.com"sv);
    };

    "http_method_roundtrip"_test = [] {
        for (auto method : {http::method::GET, http::method::HEAD, http::method::POST,
                            http::method::PUT, http::method::DELETE_, http::method::CONNECT,
                            http::method::OPTIONS, http::method::TRACE, http::method::PATCH}) {
            auto token = http::to_string(method);
            auto parsed = http::try_from_string(token);
            expect(parsed.has_value());
            expect(*parsed == method);
        }
    };

    "header_lookup_is_case_insensitive"_test = [] {
        http::headers fields{{"Cache-Control", "max-age=60"}, {"Set-Cookie", "a=b"}};

        auto cache_control = http::find_header(fields, "cache-control");
        auto set_cookie = http::find_header(fields, "set-cookie");

        expect(cache_control.has_value());
        expect(*cache_control == "max-age=60"sv);
        expect(set_cookie.has_value());
        expect(*set_cookie == "a=b"sv);
    };

    "response_reason_phrase_defaults"_test = [] {
        http::response response{
            .status = 404,
            .reason = {},
            .fields = {},
            .body = {},
        };

        auto serialized = bytes_to_string(http::serialize(response));
        expect(serialized.starts_with("HTTP/1.1 404 Not Found\r\n"sv));
    };
};

} // namespace httpant::testing
