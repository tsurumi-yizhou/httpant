#include <boost/ut.hpp>

#include "test_support.hpp"

namespace httpant::testing {

using namespace boost::ut;
using namespace std::literals;

static suite<"connect"> connect_suite = [] {
    "non_connect_requests_do_not_forward_alpn"_test = [] {
        auto serialized = bytes_to_string(http::serialize(http::request{
            .method = http::method::GET,
            .target = "/",
            .fields = {{"host", "example.com"}, {"alpn", "h2"}},
            .body = {},
        }));

        expect(!serialized.contains("alpn: h2\r\n"sv));
    };

    "non_connect_requests_with_alpn_are_rejected"_test = [] {
        pipe c2s, s2c;
        mock_stream transport{.input = c2s, .output = s2c};

        push_text(c2s, "GET / HTTP/1.1\r\nHost: example.com\r\nALPN: h2\r\n\r\n");
        c2s.closed = true;

        http::server_v1<mock_stream> server{transport};
        auto threw = false;
        try {
            static_cast<void>(run_sync(server.receive()));
        } catch (...) {
            threw = true;
        }

        expect(threw);
    };

    "tunnel_alpn_validation_is_enforced"_test = [] {
        pipe c2s, s2c;
        mock_stream transport{.input = c2s, .output = s2c};

        push_text(c2s,
            "CONNECT example.com:443 HTTP/1.1\r\n"
            "Host: example.com:443\r\n"
            "ALPN: h2\r\n\r\n");
        c2s.closed = true;

        http::server_v1<mock_stream> server{transport};
        auto threw = false;
        try {
            auto request = run_sync(server.receive());
            auto alpn = http::find_header(request.fields, "alpn");
            expect(request.method == http::method::CONNECT);
            expect(alpn.has_value());
            if (alpn.has_value()) {
                expect(*alpn == "h2"sv);
            }
        } catch (...) {
            threw = true;
        }

        expect(!threw);
    };

    "successful_connect_responses_do_not_include_content"_test = [] {
        pipe c2s, s2c;
        mock_stream transport{.input = c2s, .output = s2c};

        push_text(c2s, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n");
        c2s.closed = true;

        http::server_v1<mock_stream> server{transport};
        static_cast<void>(run_sync(server.receive()));
        run_sync(server.respond(http::response{
            .status = 200,
            .reason = {},
            .fields = {},
            .body = make_body("tunnel-bytes"),
        }));

        auto wire = bytes_to_string(s2c.buffer);
        expect(!wire.contains("content-length:"sv));
        expect(!wire.contains("tunnel-bytes"sv));
    };

    "connect_targets_use_authority_form"_test = [] {
        pipe c2s, s2c;
        mock_stream transport{.input = c2s, .output = s2c};

        push_text(c2s, "CONNECT /not-authority HTTP/1.1\r\nHost: example.com\r\n\r\n");
        c2s.closed = true;

        http::server_v1<mock_stream> server{transport};
        auto threw = false;
        try {
            static_cast<void>(run_sync(server.receive()));
        } catch (...) {
            threw = true;
        }

        expect(threw);
    };
};

} // namespace httpant::testing
