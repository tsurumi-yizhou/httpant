#include <boost/ut.hpp>

#include "test_support.hpp"

namespace httpant::testing {

using namespace boost::ut;
using namespace std::literals;

static suite<"semantics"> semantics_suite = [] {
    "head_responses_do_not_include_content"_test = [] {
        pipe c2s, s2c;
        mock_stream transport{.input = c2s, .output = s2c};

        push_text(c2s, "HEAD /docs HTTP/1.1\r\nHost: example.com\r\n\r\n");
        c2s.closed = true;

        http::server_v1<mock_stream> server{transport};
        static_cast<void>(run_sync(server.receive()));
        run_sync(server.respond(http::response{
            .status = 200,
            .reason = {},
            .fields = {{"content-type", "text/plain"}},
            .body = make_body("body"),
        }));

        auto wire = bytes_to_string(s2c.buffer);
        expect(!wire.contains("content-length: 4\r\n"sv));
        expect(!wire.ends_with("\r\n\r\nbody"sv));
    };

    "reset_content_responses_do_not_include_content"_test = [] {
        auto wire = bytes_to_string(http::serialize(http::response{
            .status = 205,
            .reason = {},
            .fields = {},
            .body = make_body("reset-me"),
        }));

        expect(!wire.contains("content-length:"sv));
        expect(!wire.ends_with("\r\n\r\nreset-me"sv));
    };

    "trace_requests_do_not_send_content"_test = [] {
        auto wire = bytes_to_string(http::serialize(http::request{
            .method = http::method::TRACE,
            .target = "/trace",
            .fields = {{"host", "example.com"}},
            .body = make_body("payload"),
        }));

        expect(!wire.contains("content-length:"sv));
        expect(!wire.ends_with("\r\n\r\npayload"sv));
    };

    "informational_responses_do_not_end_the_exchange"_test = [] {
        http1_client_fixture fixture;
        fixture.queue_response(
            "HTTP/1.1 100 Continue\r\n\r\n"
            "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nfinal");

        auto response = fixture.issue(basic_get("/upload"));
        expect(response.status == 200_u);
        expect(read_body_text(response.body) == "final"sv);
    };

    "unknown_methods_do_not_downgrade_to_get"_test = [] {
        expect(http::from_string("PROPFIND"sv) != http::method::GET);
    };
};

} // namespace httpant::testing
