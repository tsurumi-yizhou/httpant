#include <boost/ut.hpp>

#include "test_support.hpp"

namespace httpant::testing {

using namespace boost::ut;
using namespace std::literals;

static suite<"wire"> wire_suite = [] {
    "http1_serialize_request_origin_form"_test = [] {
        http::request req{
            .method = http::method::GET,
            .target = "/",
            .fields = {{"host", "localhost"}},
            .body = {},
        };

        auto serialized = bytes_to_string(http::serialize(req));
        expect(serialized.starts_with("GET / HTTP/1.1\r\n"sv));
        expect(serialized.contains("host: localhost\r\n"sv));
        expect(serialized.ends_with("\r\n\r\n"sv));
    };

    "http1_serialize_request_absolute_form"_test = [] {
        http::request req{
            .method = http::method::GET,
            .target = "http://example.com:8080/resource?q=1",
            .fields = {{"host", "example.com:8080"}},
            .body = {},
        };

        auto serialized = bytes_to_string(http::serialize(req));
        expect(serialized.starts_with("GET http://example.com:8080/resource?q=1 HTTP/1.1\r\n"sv));
    };

    "http1_serialize_request_authority_form"_test = [] {
        http::request req{
            .method = http::method::CONNECT,
            .target = "www.example.com:443",
            .fields = {{"host", "www.example.com:443"}, {"alpn", "h2"}},
            .body = {},
        };

        auto serialized = bytes_to_string(http::serialize(req));
        expect(serialized.starts_with("CONNECT www.example.com:443 HTTP/1.1\r\n"sv));
        expect(serialized.contains("alpn: h2\r\n"sv));
    };

    "http1_serialize_request_asterisk_form"_test = [] {
        http::request req{
            .method = http::method::OPTIONS,
            .target = "*",
            .fields = {{"host", "example.com"}},
            .body = {},
        };

        auto serialized = bytes_to_string(http::serialize(req));
        expect(serialized.starts_with("OPTIONS * HTTP/1.1\r\n"sv));
    };

    "http1_request_infers_content_length"_test = [] {
        http::request req{
            .method = http::method::POST,
            .target = "/submit",
            .fields = {{"host", "localhost"}, {"content-type", "text/plain"}},
            .body = make_body("payload"),
        };

        auto serialized = bytes_to_string(http::serialize(req));
        expect(serialized.contains("content-length: 7\r\n"sv));
        expect(serialized.ends_with("\r\n\r\npayload"sv));
    };

    "http1_response_infers_content_length"_test = [] {
        http::response res{
            .status = 200,
            .reason = {},
            .fields = {{"content-type", "text/plain"}},
            .body = make_body("hello"),
        };

        auto serialized = bytes_to_string(http::serialize(res));
        expect(serialized.starts_with("HTTP/1.1 200 OK\r\n"sv));
        expect(serialized.contains("content-length: 5\r\n"sv));
        expect(serialized.ends_with("\r\n\r\nhello"sv));
    };

    "http1_response_omits_body_for_204"_test = [] {
        http::response res{
            .status = 204,
            .reason = {},
            .fields = {{"content-type", "text/plain"}},
            .body = make_body("should-not-be-sent"),
        };

        auto serialized = bytes_to_string(http::serialize(res));
        expect(serialized.starts_with("HTTP/1.1 204 No Content\r\n"sv));
        expect(!serialized.contains("content-length:"sv));
        expect(serialized.ends_with("\r\n\r\n"sv));
        expect(!serialized.contains("should-not-be-sent"sv));
    };

    "http1_client_server_roundtrip"_test = [] {
        pipe c2s, s2c;
        mock_stream client_transport{.input = s2c, .output = c2s};
        mock_stream server_transport{.input = c2s, .output = s2c};

        http::request req{
            .method = http::method::POST,
            .target = "/api/test",
            .fields = {{"host", "localhost"}, {"content-type", "application/json"}},
            .body = {},
        };

        auto request_bytes = http::serialize(req);
        c2s.push(std::span{request_bytes});
        c2s.closed = true;

        http::server_v1<mock_stream> server{server_transport};
        auto parsed_req = run_sync(server.receive());

        expect(parsed_req.method == http::method::POST);
        expect(parsed_req.target == "/api/test"sv);
        auto content_type = http::find_header(parsed_req.fields, "content-type");
        expect(content_type.has_value());
        expect(*content_type == "application/json"sv);

        http::response res{
            .status = 200,
            .reason = {},
            .fields = {{"content-type", "text/plain"}},
            .body = {},
        };
        run_sync(server.respond(res));

        s2c.closed = true;
        auto response_text = bytes_to_string(s2c.buffer);
        expect(response_text.starts_with("HTTP/1.1 200 OK\r\n"sv));
    };

    "http1_body_roundtrip"_test = [] {
        pipe c2s, s2c;
        mock_stream transport{.input = c2s, .output = s2c};

        http::request req{
            .method = http::method::POST,
            .target = "/echo",
            .fields = {{"host", "localhost"}},
            .body = make_body("Hello, World!"),
        };
        auto request_bytes = http::serialize(req);
        c2s.push(std::span{request_bytes});
        c2s.closed = true;

        http::server_v1<mock_stream> server{transport};
        auto parsed = run_sync(server.receive());

        expect(parsed.method == http::method::POST);
        expect(parsed.body.size() == 13_u);
        expect(read_body_text(parsed.body) == "Hello, World!"sv);
    };

    "http1_parses_all_supported_methods"_test = [] {
        using method_case = std::pair<std::string_view, http::method>;
        for (auto [token, expected] : std::array<method_case, 5>{
                 method_case{"GET", http::method::GET},
                 method_case{"HEAD", http::method::HEAD},
                 method_case{"DELETE", http::method::DELETE_},
                 method_case{"OPTIONS", http::method::OPTIONS},
                 method_case{"PATCH", http::method::PATCH},
             }) {
            pipe c2s, s2c;
            mock_stream transport{.input = c2s, .output = s2c};
            auto raw = std::string(token) + " /resource HTTP/1.1\r\nHost: example.com\r\n\r\n";
            push_text(c2s, raw);
            c2s.closed = true;

            http::server_v1<mock_stream> server{transport};
            auto parsed = run_sync(server.receive());
            expect(parsed.method == expected);
        }
    };

    "http1_parses_chunked_request_body"_test = [] {
        pipe c2s, s2c;
        mock_stream transport{.input = c2s, .output = s2c};

        push_text(
            c2s,
            "POST /chunked HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "Transfer-Encoding: chunked\r\n\r\n"
            "4\r\nWiki\r\n"
            "5\r\npedia\r\n"
            "0\r\n\r\n");
        c2s.closed = true;

        http::server_v1<mock_stream> server{transport};
        auto parsed = run_sync(server.receive());

        expect(parsed.target == "/chunked"sv);
        expect(read_body_text(parsed.body) == "Wikipedia"sv);
    };

    "http1_parses_chunked_response_body"_test = [] {
        pipe c2s, s2c;
        mock_stream transport{.input = s2c, .output = c2s};

        push_text(
            s2c,
            "HTTP/1.1 200 OK\r\n"
            "Transfer-Encoding: chunked\r\n\r\n"
            "7\r\nMozilla\r\n"
            "9\r\nDeveloper\r\n"
            "7\r\nNetwork\r\n"
            "0\r\n\r\n");
        s2c.closed = true;

        http::client_v1<mock_stream> client{transport};
        auto response = run_sync(client.request(http::request{
            .method = http::method::GET,
            .target = "/",
            .fields = {{"host", "example.com"}},
            .body = {},
        }));

        expect(response.status == 200_u);
        expect(read_body_text(response.body) == "MozillaDeveloperNetwork"sv);
    };

    "http1_preserves_cookie_and_cache_headers"_test = [] {
        pipe c2s, s2c;
        mock_stream transport{.input = s2c, .output = c2s};

        push_text(
            s2c,
            "HTTP/1.1 200 OK\r\n"
            "Set-Cookie: sid=abc123; Path=/; HttpOnly\r\n"
            "Cache-Control: public, max-age=60\r\n"
            "Age: 10\r\n"
            "Expires: Thu, 01 Dec 1994 16:00:00 GMT\r\n"
            "Content-Length: 0\r\n\r\n");
        s2c.closed = true;

        http::client_v1<mock_stream> client{transport};
        auto response = run_sync(client.request(http::request{
            .method = http::method::GET,
            .target = "/",
            .fields = {{"host", "example.com"}},
            .body = {},
        }));

        expect(http::find_header(response.fields, "set-cookie").has_value());
        expect(http::find_header(response.fields, "cache-control").has_value());
        expect(http::find_header(response.fields, "age").has_value());
        expect(http::find_header(response.fields, "expires").has_value());
    };
};

} // namespace httpant::testing