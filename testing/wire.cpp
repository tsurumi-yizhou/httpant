#include <boost/ut.hpp>

#include "test_support.hpp"

namespace httpant::testing {

using namespace boost::ut;
using namespace std::literals;

static suite<"wire"> wire_suite = [] {
    // RFC 9112 §3.2.1 — "origin-form = absolute-path [ "?" query ]"; a client
    // sends the absolute path as the request-target. RFC 9112 §3.2 — "A client
    // MUST send a Host header field (Section 7.2 of [HTTP]) in all HTTP/1.1
    // request messages."
    "http1_serialize_request_origin_form"_test = [] {
        http::request req{
            .method = http::method::GET,
            .target = "/",
            .fields = {{"host", "localhost"}},
        };

        auto serialized = bytes_to_string(run_sync(http::v1::serialize(req)));
        expect(serialized.starts_with("GET / HTTP/1.1\r\n"sv));
        expect(serialized.contains("host: localhost\r\n"sv));
        expect(serialized.ends_with("\r\n\r\n"sv));
    };

    // RFC 9112 §3.2.2 — "absolute-form = absolute-URI"; a client sends the target
    // URI in absolute-form as the request-target when making a request to a proxy.
    "http1_serialize_request_absolute_form"_test = [] {
        http::request req{
            .method = http::method::GET,
            .target = "http://example.com:8080/resource?q=1",
            .fields = {{"host", "example.com:8080"}},
        };

        auto serialized = bytes_to_string(run_sync(http::v1::serialize(req)));
        expect(serialized.starts_with("GET http://example.com:8080/resource?q=1 HTTP/1.1\r\n"sv));
    };

    // RFC 9112 §3.2.3 — authority-form = uri-host ":" port; a CONNECT request
    // sends only the host and port of the tunnel destination as the request-target.
    // RFC 7639 §2 — "Clients include the ALPN header field in an HTTP CONNECT
    // request to indicate the application-layer protocol that a client intends to
    // use within the tunnel".
    "http1_serialize_request_authority_form"_test = [] {
        http::request req{
            .method = http::method::CONNECT,
            .target = "www.example.com:443",
            .fields = {{"host", "www.example.com:443"}, {"alpn", "h2"}},
        };

        auto serialized = bytes_to_string(run_sync(http::v1::serialize(req)));
        expect(serialized.starts_with("CONNECT www.example.com:443 HTTP/1.1\r\n"sv));
        expect(serialized.contains("alpn: h2\r\n"sv));
    };

    // RFC 9112 §3.2.4 — asterisk-form = "*"; a server-wide OPTIONS request sends
    // only "*" as the request-target.
    "http1_serialize_request_asterisk_form"_test = [] {
        http::request req{
            .method = http::method::OPTIONS,
            .target = "*",
            .fields = {{"host", "example.com"}},
        };

        auto serialized = bytes_to_string(run_sync(http::v1::serialize(req)));
        expect(serialized.starts_with("OPTIONS * HTTP/1.1\r\n"sv));
    };

    // RFC 9110 §8.6 — "A user agent SHOULD send Content-Length in a request when
    // the method defines a meaning for enclosed content and it is not sending
    // Transfer-Encoding."
    "http1_request_infers_content_length"_test = [] {
        http::request req{
            .method = http::method::POST,
            .target = "/submit",
            .fields = {{"host", "localhost"}, {"content-type", "text/plain"}},
        };
        auto body = make_body("payload");

        auto serialized = bytes_to_string(run_sync(http::v1::serialize(req, body)));
        expect(serialized.contains("content-length: 7\r\n"sv));
        expect(serialized.ends_with("\r\n\r\npayload"sv));
    };

    // RFC 9112 §4 — "status-line = HTTP-version SP status-code SP [ reason-phrase ]".
    // RFC 9110 §8.6 — "Aside from the cases defined above, in the absence of
    // Transfer-Encoding, an origin server SHOULD send a Content-Length header field
    // when the content size is known prior to sending the complete header section."
    "http1_response_infers_content_length"_test = [] {
        http::response res{
            .status = 200,
            .reason = {},
            .fields = {{"content-type", "text/plain"}},
        };
        auto body = make_body("hello");

        auto serialized = bytes_to_string(run_sync(http::v1::serialize(res, body)));
        expect(serialized.starts_with("HTTP/1.1 200 OK\r\n"sv));
        expect(serialized.contains("content-length: 5\r\n"sv));
        expect(serialized.ends_with("\r\n\r\nhello"sv));
    };

    // RFC 9110 §8.6 — "A server MUST NOT send a Content-Length header field in
    // any response with a status code of 1xx (Informational) or 204 (No Content)."
    // RFC 9110 §15.3.5 — "A 204 response is terminated by the end of the header
    // section; it cannot contain content or trailers."
    "http1_response_omits_body_for_204"_test = [] {
        http::response res{
            .status = 204,
            .reason = {},
            .fields = {{"content-type", "text/plain"}},
        };
        auto body = make_body("should-not-be-sent");

        auto serialized = bytes_to_string(run_sync(http::v1::serialize(res, body)));
        expect(serialized.starts_with("HTTP/1.1 204 No Content\r\n"sv));
        expect(!serialized.contains("content-length:"sv));
        expect(serialized.ends_with("\r\n\r\n"sv));
        expect(!serialized.contains("should-not-be-sent"sv));
    };

    // RFC 9112 §7.1 — "chunked-body = *chunk last-chunk trailer-section CRLF";
    // "chunk = chunk-size [ chunk-ext ] CRLF chunk-data CRLF" and
    // "last-chunk = 1*("0") [ chunk-ext ] CRLF". The library frames a buffered
    // body as a single chunk followed by the terminating zero chunk (no trailer
    // model), and never adds a Content-Length alongside Transfer-Encoding.
    "http1_serialize_request_chunked_body"_test = [] {
        http::request req{
            .method = http::method::POST,
            .target = "/upload",
            .fields = {{"host", "example.com"}, {"transfer-encoding", "chunked"}},
        };
        auto body = make_body("Wikipedia");

        auto serialized = bytes_to_string(run_sync(http::v1::serialize(req, body)));
        expect(!serialized.contains("content-length:"sv));
        expect(serialized.ends_with("9\r\nWikipedia\r\n0\r\n\r\n"sv));
    };

    // RFC 9112 §7.1 — "chunked-body = *chunk last-chunk trailer-section CRLF";
    // a response body encoded with the final "chunked" transfer coding is framed
    // as chunks terminated by the zero chunk, without a Content-Length.
    "http1_serialize_response_chunked_body"_test = [] {
        http::response res{
            .status = 200,
            .reason = {},
            .fields = {{"transfer-encoding", "chunked"}},
        };
        auto body = make_body("hello");

        auto serialized = bytes_to_string(run_sync(http::v1::serialize(res, body)));
        expect(!serialized.contains("content-length:"sv));
        expect(serialized.ends_with("5\r\nhello\r\n0\r\n\r\n"sv));
    };

    // RFC 9112 §7.1 — "chunked-body = *chunk last-chunk trailer-section CRLF";
    // an empty buffered body is framed as a single terminating zero chunk.
    "http1_serialize_empty_chunked_body"_test = [] {
        http::response res{
            .status = 200,
            .reason = {},
            .fields = {{"transfer-encoding", "chunked"}},
        };

        auto serialized = bytes_to_string(run_sync(http::v1::serialize(res)));
        expect(serialized.ends_with("\r\n\r\n0\r\n\r\n"sv));
    };

    // RFC 9110 §5.1 — "Field names are case-insensitive" (find_header performs
    // case-insensitive lookup). RFC 9112 §4 — "status-line = HTTP-version SP
    // status-code SP [ reason-phrase ]".
    "http1_client_server_roundtrip"_test = [] {
        pipe c2s, s2c;
        mock_stream server_transport{.input = c2s, .output = s2c};

        http::request req{
            .method = http::method::POST,
            .target = "/api/test",
            .fields = {{"host", "localhost"}, {"content-type", "application/json"}},
        };

        auto request_bytes = run_sync(http::v1::serialize(req));
        c2s.push(std::span{request_bytes});
        c2s.closed = true;

        http::v1::server<mock_stream> server{server_transport};
        auto parsed = run_sync(http::coroutine::receive(server));

        expect(parsed.head.method == http::method::POST);
        expect(parsed.head.target == "/api/test"sv);
        auto content_type = http::find_header(parsed.head.fields, "content-type");
        expect(content_type.has_value());
        expect(*content_type == "application/json"sv);
        static_cast<void>(run_sync(drain_body(parsed.body)));

        run_sync(http::coroutine::respond(server, std::move(parsed.token), http::response{
            .status = 200,
            .reason = {},
            .fields = {{"content-type", "text/plain"}},
        }));

        s2c.closed = true;
        auto response_text = bytes_to_string(s2c.buffer);
        expect(response_text.starts_with("HTTP/1.1 200 OK\r\n"sv));
    };

    // RFC 9112 §6.3 — "If a valid Content-Length header field is present without
    // Transfer-Encoding, its decimal value defines the expected message body
    // length in octets."
    "http1_body_roundtrip"_test = [] {
        pipe c2s, s2c;
        mock_stream transport{.input = c2s, .output = s2c};

        http::request req{
            .method = http::method::POST,
            .target = "/echo",
            .fields = {{"host", "localhost"}},
        };
        auto body = make_body("Hello, World!");
        auto request_bytes = run_sync(http::v1::serialize(req, body));
        c2s.push(std::span{request_bytes});
        c2s.closed = true;

        http::v1::server<mock_stream> server{transport};
        auto parsed = run_sync(http::coroutine::receive(server));

        expect(parsed.head.method == http::method::POST);
        auto parsed_body = run_sync(drain_body(parsed.body));
        expect(parsed_body.size() == 13_u);
        expect(read_body_text(parsed_body) == "Hello, World!"sv);
    };

    // RFC 9110 §9.1 — "method = token"; "The method token is case-sensitive ...
    // By convention, standardized methods are defined in all-uppercase US-ASCII
    // letters." (PATCH is registered by RFC 5789.)
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

            http::v1::server<mock_stream> server{transport};
            auto parsed = run_sync(http::coroutine::receive(server));
            expect(parsed.head.method == expected);
        }
    };

    // RFC 9112 §7.1 — "chunked-body = *chunk last-chunk trailer-section CRLF";
    // the body length is determined by reading and decoding the chunked data until
    // the transfer coding indicates the data is complete (RFC 9112 §6.3 step 4).
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

        http::v1::server<mock_stream> server{transport};
        auto parsed = run_sync(http::coroutine::receive(server));

        expect(parsed.head.target == "/chunked"sv);
        auto body = run_sync(drain_body(parsed.body));
        expect(read_body_text(body) == "Wikipedia"sv);
    };

    // RFC 9110 §10.1.1 — "A server that receives a 100-continue expectation in an
    // HTTP/1.1 request ... MUST either send an immediate response ... or send an
    // interim 100 (Continue) response." and RFC 9110 §15.2.1 — the interim response
    // is terminated by the empty line and carries no content. The server sends 100
    // before reading the (chunked) content, then returns the complete request.
    "http1_server_sends_100_continue_before_body"_test = [] {
        pipe c2s, s2c;
        mock_stream transport{.input = c2s, .output = s2c};

        push_text(
            c2s,
            "POST /upload HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "Expect: 100-continue\r\n"
            "Transfer-Encoding: chunked\r\n\r\n"
            "5\r\nhello\r\n"
            "0\r\n\r\n");
        c2s.closed = true;

        http::v1::server<mock_stream> server{transport};
        auto parsed = run_sync(http::coroutine::receive(server));

        expect(parsed.head.target == "/upload"sv);
        auto body = run_sync(drain_body(parsed.body));
        expect(read_body_text(body) == "hello"sv);
        auto interim = bytes_to_string(std::span<const std::byte>{s2c.buffer.data(), s2c.buffer.size()});
        expect(interim.starts_with("HTTP/1.1 100 Continue\r\n\r\n"sv));
    };

    // RFC 9112 §6.3 — "If a message is received with both a Transfer-Encoding and a
    // Content-Length header field, the Transfer-Encoding overrides the Content-Length.
    // Such a message might indicate an attempt to perform request smuggling (Section
    // 11.2) or response splitting (Section 11.1) and ought to be handled as an error."
    "http1_request_with_te_and_cl_is_rejected"_test = [] {
        pipe c2s, s2c;
        mock_stream transport{.input = c2s, .output = s2c};

        push_text(
            c2s,
            "POST /smuggle HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "Transfer-Encoding: chunked\r\n"
            "Content-Length: 4\r\n\r\n"
            "4\r\nWiki\r\n"
            "0\r\n\r\n");
        c2s.closed = true;

        http::v1::server<mock_stream> server{transport};
        auto threw = false;
        try {
            static_cast<void>(run_sync(http::coroutine::receive(server)));
        } catch (...) {
            threw = true;
        }

        expect(threw);
    };

    // RFC 9112 §7.1 — "chunked-body = *chunk last-chunk trailer-section CRLF";
    // the response body is reassembled from multiple chunk-data segments until the
    // terminating zero chunk (RFC 9112 §6.3 step 4).
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

        http::v1::client<mock_stream> client{transport};
        auto received = run_sync(http::coroutine::request(client, http::request{
            .method = http::method::GET,
            .target = "/",
            .fields = {{"host", "example.com"}},
        }));

        expect(received.head.status == 200_u);
        auto body = run_sync(drain_body(received.body));
        expect(read_body_text(body) == "MozillaDeveloperNetwork"sv);
    };

    // RFC 9110 §5.1 — "Field names are case-insensitive"; the response parser
    // preserves the Set-Cookie (RFC 6265 §4.1), Cache-Control (RFC 9111 §5.2),
    // Age (RFC 9111 §5.1), and Expires (RFC 9111 §5.3) fields for later
    // case-insensitive lookup.
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

        http::v1::client<mock_stream> client{transport};
        auto received = run_sync(http::coroutine::request(client, http::request{
            .method = http::method::GET,
            .target = "/",
            .fields = {{"host", "example.com"}},
        }));

        expect(http::find_header(received.head.fields, "set-cookie").has_value());
        expect(http::find_header(received.head.fields, "cache-control").has_value());
        expect(http::find_header(received.head.fields, "age").has_value());
        expect(http::find_header(received.head.fields, "expires").has_value());
    };

    // RFC 9112 §9.3 — "HTTP/1.1 defaults to the use of 'persistent connections',
    // allowing multiple requests and responses to be carried over a single
    // connection."
    "http1_client_reuses_connection_for_multiple_responses"_test = [] {
        http1_client_fixture fixture;
        fixture.queue_response(
            "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\none"
            "HTTP/1.1 204 No Content\r\n\r\n");

        auto first = fixture.issue(basic_get("/first"));
        expect(first.status == 200_u);
        expect(read_body_text(first.body) == "one"sv);
        expect(!fixture.client.should_close());

        auto second = fixture.issue(basic_get("/second"));
        expect(second.status == 204_u);
        expect(!fixture.client.should_close());
    };

    // RFC 9112 §9.3 — "In order to remain persistent, all messages on a
    // connection need to have a self-defined message length (i.e., one not
    // defined by closure of the connection), as described in Section 6." — a
    // body delimited by connection closure cannot be followed by another
    // message, so the connection must close.
    "http1_client_closes_after_eof_delimited_response"_test = [] {
        http1_client_fixture fixture;
        fixture.queue_response(
            "HTTP/1.1 200 OK\r\n\r\nbody-without-length", true);

        auto response = fixture.issue(basic_get("/resource"));
        expect(response.status == 200_u);
        expect(read_body_text(response.body) == "body-without-length"sv);
        expect(fixture.client.should_close());
    };

    // RFC 9112 §9.6 — "A client that receives a 'close' connection option MUST
    // cease sending requests on that connection and close the connection after
    // reading the response message containing the 'close' connection option".
    "http1_client_close_option_ends_the_connection"_test = [] {
        http1_client_fixture fixture;
        fixture.queue_response(
            "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
            true);

        auto response = fixture.issue(basic_get("/"));
        expect(response.status == 200_u);
        expect(fixture.client.should_close());

        auto threw = false;
        try {
            static_cast<void>(fixture.issue(basic_get("/again")));
        } catch (...) {
            threw = true;
        }
        expect(threw);
    };

    // RFC 9112 §9.3 — "A server MAY process a sequence of pipelined requests"
    // (within a single read); a connection that stays open serves both.
    "http1_server_reuses_connection_for_multiple_requests"_test = [] {
        pipe c2s, s2c;
        mock_stream transport{.input = c2s, .output = s2c};

        push_text(
            c2s,
            "GET /first HTTP/1.1\r\nHost: example.com\r\n\r\n"
            "GET /second HTTP/1.1\r\nHost: example.com\r\n\r\n");

        http::v1::server<mock_stream> server{transport};
        auto first = run_sync(http::coroutine::receive(server));
        expect(first.head.target == "/first"sv);
        static_cast<void>(run_sync(drain_body(first.body)));
        // RFC 9112 §9.3 — "In order to remain persistent, all messages on a
        // connection need to have a self-defined message length (i.e., one not
        // defined by closure of the connection)" — the responses carry
        // Content-Length so the connection legitimately persists.
        run_sync(http::coroutine::respond(server, std::move(first.token), http::response{
            .status = 200, .reason = {}, .fields = {{"content-length", "0"}}}));
        expect(!server.should_close());

        auto second = run_sync(http::coroutine::receive(server));
        expect(second.head.target == "/second"sv);
        static_cast<void>(run_sync(drain_body(second.body)));
        run_sync(http::coroutine::respond(server, std::move(second.token), http::response{
            .status = 200, .reason = {}, .fields = {{"content-length", "0"}}}));
        expect(!server.should_close());
    };

    // RFC 9112 §9.3 — "A server MUST read the entire request message body or
    // close the connection after sending its response, since otherwise the
    // remaining data on a persistent connection would be misinterpreted as
    // the next request." An unread body therefore prevents connection reuse.
    "http1_server_rejects_reuse_with_unconsumed_request_body"_test = [] {
        pipe c2s, s2c;
        mock_stream transport{.input = c2s, .output = s2c};
        push_text(c2s,
            "POST /first HTTP/1.1\r\nHost: example.com\r\nContent-Length: 4\r\n\r\n"
            "bodyGET /second HTTP/1.1\r\nHost: example.com\r\n\r\n");

        http::v1::server<mock_stream> server{transport};
        auto first = run_sync(http::coroutine::receive(server));
        expect(first.head.target == "/first"sv);

        auto threw = false;
        try {
            static_cast<void>(run_sync(http::coroutine::receive(server)));
        } catch (const std::runtime_error& error) {
            threw = std::string_view{error.what()}.contains("exchange not complete");
        }
        expect(threw);
    };

    // RFC 9112 §9.3 — "A client MUST read the entire response message body if
    // it intends to reuse the same connection for a subsequent request."
    "http1_client_rejects_reuse_with_unconsumed_response_body"_test = [] {
        pipe c2s, s2c;
        mock_stream transport{.input = s2c, .output = c2s};
        push_text(s2c,
            "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n"
            "bodyHTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");

        http::v1::client<mock_stream> client{transport};
        auto first = run_sync(http::coroutine::request(client, basic_get("/first")));
        expect(first.head.status == 200_u);

        auto threw = false;
        try {
            static_cast<void>(run_sync(
                http::coroutine::request(client, basic_get("/second"))));
        } catch (const std::runtime_error& error) {
            threw = std::string_view{error.what()}.contains("body not consumed");
        }
        expect(threw);
    };

    // RFC 9112 §9.6 — "A server that receives a 'close' connection option MUST
    // initiate closure of the connection (see below) after it sends the final
    // response to the request that contained the 'close' connection option" and
    // "The server SHOULD send a 'close' connection option in its final response
    // on that connection."
    "http1_server_close_option_ends_the_connection"_test = [] {
        pipe c2s, s2c;
        mock_stream transport{.input = c2s, .output = s2c};

        push_text(c2s, "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n");

        http::v1::server<mock_stream> server{transport};
        auto request = run_sync(http::coroutine::receive(server));
        expect(request.head.target == "/"sv);
        static_cast<void>(run_sync(drain_body(request.body)));
        expect(server.should_close());

        run_sync(http::coroutine::respond(server, std::move(request.token), http::response{
            .status = 200, .reason = {}, .fields = {}}));
        auto wire = bytes_to_string(s2c.buffer);
        expect(wire.contains("connection: close\r\n"sv));
        expect(server.should_close());

        auto threw = false;
        try {
            static_cast<void>(run_sync(http::coroutine::receive(server)));
        } catch (...) {
            threw = true;
        }
        expect(threw);
    };

    // RFC 9110 §15.2.2 — "The 101 (Switching Protocols) status code indicates
    // that the server understands and is willing to comply with the client's
    // request, via the Upgrade header field (Section 7.8), for a change in the
    // application protocol being used on this connection." — after a 101 the
    // connection carries the new protocol, not HTTP.
    "http1_client_101_switching_protocols_ends_http_exchange"_test = [] {
        http1_client_fixture fixture;
        fixture.queue_response(
            "HTTP/1.1 101 Switching Protocols\r\n"
            "Connection: Upgrade\r\n"
            "Upgrade: websocket\r\n"
            "\r\n"
            "tunnel-bytes");

        auto response = fixture.issue(http::request{
            .method = http::method::GET,
            .target = "/chat",
            .fields = {{"host", "example.com"}, {"connection", "Upgrade"}, {"upgrade", "websocket"}},
        });
        expect(response.status == 101_u);
        expect(fixture.client.upgraded());
        expect(bytes_to_string(fixture.client.take_pending()) == "tunnel-bytes"sv);
        expect(!fixture.client.should_close());

        auto threw = false;
        try {
            static_cast<void>(fixture.issue(basic_get("/again")));
        } catch (...) {
            threw = true;
        }
        expect(threw);
    };

    // RFC 9110 §9.3.6 — "CONNECT uses a special form of request target" and
    // "Any 2xx (Successful) response indicates that the sender (and all inbound
    // proxies) will switch to tunnel mode immediately after the response header
    // section" — the connection stops being HTTP after the tunnel opens.
    "http1_server_upgrade_request_switches_protocols"_test = [] {
        pipe c2s, s2c;
        mock_stream transport{.input = c2s, .output = s2c};

        push_text(
            c2s,
            "GET /chat HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "Connection: Upgrade\r\n"
            "Upgrade: websocket\r\n\r\n");

        http::v1::server<mock_stream> server{transport};
        auto request = run_sync(http::coroutine::receive(server));
        expect(request.head.target == "/chat"sv);
        static_cast<void>(run_sync(drain_body(request.body)));
        expect(server.upgraded());
        expect(!server.should_close());

        run_sync(http::coroutine::respond(server, std::move(request.token), http::response{
            .status = 101, .reason = {}, .fields = {}}));
        expect(server.should_close());

        auto threw = false;
        try {
            static_cast<void>(run_sync(http::coroutine::receive(server)));
        } catch (...) {
            threw = true;
        }
        expect(threw);
    };

    // RFC 9110 §9.3.2 — "The HEAD method is identical to GET except that the
    // server MUST NOT send content in the response." — a Content-Length in a
    // HEAD response describes the content a GET would have sent, so the
    // exchange ends at the header section and the connection stays reusable.
    "http1_client_head_response_carries_no_body"_test = [] {
        http1_client_fixture fixture;
        fixture.queue_response(
            "HTTP/1.1 200 OK\r\nContent-Length: 123\r\n\r\n"
            "HTTP/1.1 204 No Content\r\n\r\n");

        auto first = fixture.issue(http::request{
            .method = http::method::HEAD,
            .target = "/meta",
            .fields = {{"host", "example.com"}},
        });
        expect(first.status == 200_u);
        expect(first.body.empty());
        expect(http::find_header(first.fields, "content-length").has_value());
        expect(!fixture.client.should_close());

        // The pipelined 204 must parse as the next message, not as 123 bytes
        // of phantom body.
        auto second = fixture.issue(basic_get("/next"));
        expect(second.status == 204_u);
        expect(!fixture.client.should_close());
    };

    // RFC 9110 §9.3.2 — "The server SHOULD send the same header fields in
    // response to a HEAD request as it would have sent if the request method
    // had been GET." — the Content-Length is preserved on the wire while the
    // content itself is suppressed.
    "http1_server_head_response_preserves_content_length"_test = [] {
        pipe c2s, s2c;
        mock_stream transport{.input = c2s, .output = s2c};

        push_text(c2s, "HEAD /resource HTTP/1.1\r\nHost: example.com\r\n\r\n");

        http::v1::server<mock_stream> server{transport};
        auto request = run_sync(http::coroutine::receive(server));
        expect(request.head.method == http::method::HEAD);
        static_cast<void>(run_sync(drain_body(request.body)));

        auto body = make_body("payload");
        run_sync(http::coroutine::respond(server, std::move(request.token), http::response{
            .status = 200,
            .reason = {},
            .fields = {{"content-length", "7"}},
        }, body));

        auto raw = bytes_to_string(s2c.buffer);
        expect(raw.starts_with("HTTP/1.1 200 OK\r\n"sv));
        expect(raw.contains("content-length: 7\r\n"sv));
        expect(!raw.contains("payload"sv));
    };

    // RFC 9112 §6.3 — "A sender MUST NOT send a Content-Length header field in
    // any message that contains a Transfer-Encoding header field."
    "http1_send_rejects_transfer_encoding_with_content_length"_test = [] {
        http::request req{
            .method = http::method::POST,
            .target = "/submit",
            .fields = {
                {"host", "localhost"},
                {"transfer-encoding", "chunked"},
                {"content-length", "7"},
            },
        };
        auto body = make_body("payload");
        auto threw = false;
        try {
            static_cast<void>(run_sync(http::v1::serialize(req, body)));
        } catch (const std::runtime_error&) {
            threw = true;
        }
        expect(threw);
    };

    // RFC 9112 §6.1 — "If a Transfer-Encoding header field is present in a
    // request and the chunked transfer coding is not the final encoding, the
    // message body length cannot be determined reliably" — the library applies
    // no transfer coding other than chunked, so any other coding is rejected
    // instead of being emitted with a silently dropped body.
    "http1_send_rejects_unsupported_transfer_coding"_test = [] {
        http::request req{
            .method = http::method::POST,
            .target = "/submit",
            .fields = {{"host", "localhost"}, {"transfer-encoding", "gzip"}},
        };
        auto body = make_body("payload");
        auto threw = false;
        try {
            static_cast<void>(run_sync(http::v1::serialize(req, body)));
        } catch (const std::runtime_error&) {
            threw = true;
        }
        expect(threw);
    };

    // RFC 9110 §8.6 — "Content-Length = 1*DIGIT"; a value with trailing junk
    // is malformed, not a prefix parse ("5abc" is not 5).
    "http1_send_rejects_trailing_junk_content_length"_test = [] {
        http::request req{
            .method = http::method::POST,
            .target = "/submit",
            .fields = {{"host", "localhost"}, {"content-length", "5abc"}},
        };
        auto body = make_body("12345");
        auto threw = false;
        try {
            static_cast<void>(run_sync(http::v1::serialize(req, body)));
        } catch (const std::runtime_error&) {
            threw = true;
        }
        expect(threw);
    };
    // RFC 9110 §8.6 — conflicting Content-Length field values make the
    // message framing ambiguous. The buffered send path must reject them
    // instead of emitting a body that matches only the first field line.
    "http1_send_rejects_conflicting_content_length_fields"_test = [] {
        http::request req{
            .method = http::method::POST,
            .target = "/submit",
            .fields = {{"host", "localhost"},
                       {"content-length", "1"},
                       {"content-length", "2"}},
        };
        auto body = make_body("x");
        auto threw = false;
        try {
            static_cast<void>(run_sync(http::v1::serialize(req, body)));
        } catch (const std::runtime_error& error) {
            threw = std::string_view{error.what()}.contains("content-length");
        }
        expect(threw);
    };

    // RFC 9110 §15 — "All valid status codes are within the range of 100 to
    // 599, inclusive." A response outside that range must be rejected before
    // it reaches the wire.
    "http1_send_rejects_response_status_outside_100_to_599"_test = [] {
        http::response res{
            .status = 600,
            .reason = {},
            .fields = {{"content-length", "0"}},
        };
        auto threw = false;
        try {
            static_cast<void>(run_sync(http::v1::serialize(res)));
        } catch (const std::runtime_error& error) {
            threw = std::string_view{error.what()}.contains("100-599");
        }
        expect(threw);
    };



    // RFC 9112 §6.3 item 5 — "If a message is received without Transfer-Encoding
    // and with an invalid Content-Length header field, then the message framing
    // is invalid and the recipient MUST treat it as an unrecoverable error,
    // unless the field value can be successfully parsed as a comma-separated
    // list (Section 5.6.1 of [HTTP]), all values in the list are valid, and all
    // values in the list are the same (in which case, the message is processed
    // with that single value used as the Content-Length field value)."
    // Deliberate boundary: the identical-list exception is NOT salvaged — wire
    // parsing is delegated to llhttp, which rejects a comma-list Content-Length
    // outright (PROBLEMS.md). The message is treated as the unrecoverable error
    // the MUST names: 400 and connection close (RFC 9112 §6.3 item 5 — "If the
    // unrecoverable error is in a request message, the server MUST respond
    // with a 400 (Bad Request) status code and then close the connection").
    "http1_identical_comma_list_content_length_is_rejected"_test = [] {
        pipe c2s, s2c;
        mock_stream transport{.input = c2s, .output = s2c};

        push_text(
            c2s,
            "POST /upload HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "Content-Length: 5, 5\r\n\r\n"
            "hello");
        c2s.closed = true;

        http::v1::server<mock_stream> server{transport};
        auto threw = false;
        try {
            static_cast<void>(run_sync(http::coroutine::receive(server)));
        } catch (const http::protocol_error& failure) {
            threw = std::holds_alternative<http::send_response>(failure.action());
        }
        expect(threw);
        auto wire = bytes_to_string(s2c.buffer);
        expect(wire.starts_with("HTTP/1.1 400 Bad Request\r\n"sv));
    };

    // RFC 9110 §5.3 — "A recipient MAY combine multiple field lines ... that
    // have the same field name into one field line, without changing the
    // semantics of the message, by appending each subsequent field line value
    // to the initial field line value ... separated by a comma" — so two
    // identical Content-Length field lines are the list "5, 5" and fall under
    // the same deliberate rejection as the comma-list above.
    "http1_identical_duplicate_content_length_is_rejected"_test = [] {
        pipe c2s, s2c;
        mock_stream transport{.input = c2s, .output = s2c};

        push_text(
            c2s,
            "POST /upload HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "Content-Length: 5\r\n"
            "Content-Length: 5\r\n\r\n"
            "hello");
        c2s.closed = true;

        http::v1::server<mock_stream> server{transport};
        auto threw = false;
        try {
            static_cast<void>(run_sync(http::coroutine::receive(server)));
        } catch (const http::protocol_error& failure) {
            threw = std::holds_alternative<http::send_response>(failure.action());
        }
        expect(threw);
        auto wire = bytes_to_string(s2c.buffer);
        expect(wire.starts_with("HTTP/1.1 400 Bad Request\r\n"sv));
    };

    // RFC 9112 §6.3 item 5 — differing comma-list values are NOT all the same,
    // so the message is not salvaged and must be treated as an unrecoverable
    // framing error: the server MUST respond with 400 and close the connection
    // (RFC 9112 §6.3 item 5 — "If the unrecoverable error is in a request
    // message, the server MUST respond with a 400 (Bad Request) status code
    // and then close the connection").
    "http1_differing_content_length_list_is_rejected"_test = [] {
        pipe c2s, s2c;
        mock_stream transport{.input = c2s, .output = s2c};

        push_text(
            c2s,
            "POST /smuggle HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "Content-Length: 5, 6\r\n\r\n"
            "hello");
        c2s.closed = true;

        http::v1::server<mock_stream> server{transport};
        auto threw = false;
        try {
            static_cast<void>(run_sync(http::coroutine::receive(server)));
        } catch (const http::protocol_error& failure) {
            threw = std::holds_alternative<http::send_response>(failure.action());
        }
        expect(threw);
        auto wire = bytes_to_string(s2c.buffer);
        expect(wire.starts_with("HTTP/1.1 400 Bad Request\r\n"sv));
    };

    // RFC 9112 §6.3 item 4 — "If a Transfer-Encoding header field is present
    // in a request and the chunked transfer coding is not the final encoding,
    // the message body length cannot be determined reliably; the server MUST
    // respond with the 400 (Bad Request) status code and then close the
    // connection." A "gzip, chunked" request (the request-smuggling shape of
    // RFC 9112 §11.2) would be decoded by llhttp as chunked with gzip bytes
    // delivered as the body; this library decodes no transfer coding other
    // than chunked, so the receive side rejects it exactly like the send side.
    // The wire shape below has "chunked" as the final coding of the list —
    // what makes it invalid is the non-chunked member, not the final position.
    "http1_request_with_non_chunked_transfer_encoding_is_rejected_with_400"_test = [] {
        pipe c2s, s2c;
        mock_stream transport{.input = c2s, .output = s2c};

        push_text(
            c2s,
            "POST /smuggle HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "Transfer-Encoding: gzip, chunked\r\n\r\n"
            "5\r\nhello\r\n0\r\n\r\n");
        c2s.closed = true;

        http::v1::server<mock_stream> server{transport};
        auto threw = false;
        try {
            static_cast<void>(run_sync(http::coroutine::receive(server)));
        } catch (const http::protocol_error& failure) {
            threw = std::holds_alternative<http::send_response>(failure.action());
        }
        expect(threw);
        auto wire = bytes_to_string(s2c.buffer);
        expect(wire.starts_with("HTTP/1.1 400 Bad Request\r\n"sv));
    };

    // RFC 9112 §7.1.2 — "A recipient MUST NOT merge a received trailer field
    // into the header section unless its corresponding header field definition
    // explicitly permits and instructs how the trailer field value can be
    // safely merged." The trailer section may span two transport reads — the
    // F_TRAILING flag must be re-latched on every header callback, not just at
    // the first trailer line — so the trailer fields are still fully discarded
    // and cannot reach the header field section.
    "http1_trailer_section_split_across_transport_reads_is_discarded"_test = [] {
        async_pipe c2s{};
        async_pipe s2c{};
        async_mock_stream transport{.input = c2s, .output = s2c};

        http::v1::server<async_mock_stream> server{transport};
        auto receive_task = http::coroutine::receive(server);
        receive_task.start();

        // First read ends inside the trailer section, right after the
        // terminating zero chunk; the trailer field line arrives on a second
        // transport read.
        constexpr std::string_view first_read =
            "POST /upload HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "Transfer-Encoding: chunked\r\n\r\n"
            "5\r\nhello\r\n0\r\n";
        c2s.push(std::as_bytes(std::span{first_read}));
        constexpr std::string_view second_read = "X-Trailer: tval\r\nHost: smuggled.example\r\n\r\n";
        c2s.push(std::as_bytes(std::span{second_read}));
        c2s.closed = true;

        auto parsed = run_sync(std::move(receive_task));
        expect(!http::find_header(parsed.head.fields, "x-trailer").has_value());
        // RFC 9112 §3.2 — exactly one Host is required; the trailer Host must
        // not have been merged into the header section.
        expect(http::find_all_headers(parsed.head.fields, "host").size() == 1_u);
        auto body = run_sync(drain_body(parsed.body));
        expect(read_body_text(body) == "hello"sv);
    };

    // RFC 9110 §5.2 — "field-value = *field-content" — the value of a field
    // line may be empty. llhttp fires on_header_value with a zero-length span
    // for such a line, so the pending-field push must not depend on the value
    // being non-empty; otherwise an empty-valued field in non-final position
    // would be glued to the following field name ("X-AHost").
    "http1_empty_valued_header_in_non_final_position_parses"_test = [] {
        pipe c2s, s2c;
        mock_stream transport{.input = c2s, .output = s2c};

        push_text(
            c2s,
            "GET / HTTP/1.1\r\n"
            "X-A:\r\n"
            "Host: example.com\r\n\r\n");
        c2s.closed = true;

        http::v1::server<mock_stream> server{transport};
        auto parsed = run_sync(http::coroutine::receive(server));
        auto x_a = http::find_header(parsed.head.fields, "x-a");
        expect(x_a.has_value());
        if (x_a) expect(x_a->empty());
        // The empty-valued field must not absorb the following field name.
        expect(http::find_all_headers(parsed.head.fields, "host").size() == 1_u);
    };

    // RFC 9112 §6.3 item 7 — "If this is a request message and none of the
    // above are true, then the message body length is zero (no message body is
    // present)"; RFC 9112 §6.3 — "A user agent that sends a request that
    // contains a message body MUST send either a valid Content-Length header
    // field or use the chunked transfer coding." The streaming send path
    // cannot retroactively add a Content-Length after the head is written, so
    // a body without either framing declaration is refused before the head
    // goes out — matching the buffered path, which infers Content-Length.
    "http1_streaming_request_body_without_framing_is_rejected"_test = [] {
        pipe c2s, s2c;
        mock_stream transport{.input = c2s, .output = s2c};

        http::request req{
            .method = http::method::POST,
            .target = "/submit",
            .fields = {{"host", "localhost"}},
        };
        auto body = make_body("payload");
        http::v1::client<mock_stream> client{transport};
        auto threw = false;
        try {
            static_cast<void>(run_sync(
                http::coroutine::request(client, std::move(req), body)));
        } catch (const std::runtime_error& error) {
            threw = std::string_view{error.what()}.contains(
                "body present without Content-Length or Transfer-Encoding");
        }
        expect(threw);
        expect(c2s.available() == 0);
    };

    // RFC 9112 §6.3 item 8 — "Otherwise, this is a response message without a
    // declared message body length, so the message body length is determined
    // by the number of octets received prior to the server closing the
    // connection." A streaming response with neither Content-Length nor
    // Transfer-Encoding sends the raw body bytes and then closes the
    // connection; the client reads them as the body.
    "http1_streaming_close_delimited_response"_test = [] {
        pipe c2s, s2c;
        mock_stream transport{.input = c2s, .output = s2c};

        push_text(c2s, "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n");

        http::v1::server<mock_stream> server{transport};
        auto request = run_sync(http::coroutine::receive(server));
        auto body = make_body("streamed-body");
        run_sync(http::coroutine::respond(server, std::move(request.token), http::response{
            .status = 200,
            .reason = {},
            .fields = {},
        }, body));

        auto wire = bytes_to_string(s2c.buffer);
        expect(wire.ends_with("streamed-body"sv));
        expect(server.should_close());
    };

    // RFC 9112 §7.1.2 — "A recipient MUST NOT merge a received trailer field
    // into the header section." The message model has no trailer block, so
    // received trailer fields are dropped entirely: they must not appear in
    // response fields and must not be able to smuggle a second Host past
    // request validation.
    "http1_received_trailers_are_not_merged_into_fields"_test = [] {
        pipe c2s, s2c;
        mock_stream transport{.input = c2s, .output = s2c};

        push_text(
            c2s,
            "POST /upload HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "Transfer-Encoding: chunked\r\n\r\n"
            "5\r\nhello\r\n0\r\n"
            "X-Trailer: tval\r\n"
            "Host: smuggled.example\r\n\r\n");
        c2s.closed = true;

        http::v1::server<mock_stream> server{transport};
        auto parsed = run_sync(http::coroutine::receive(server));
        expect(!http::find_header(parsed.head.fields, "x-trailer").has_value());
        // RFC 9112 §3.2 — exactly one Host is required; the trailer Host must
        // not have been merged into the header section.
        expect(http::find_all_headers(parsed.head.fields, "host").size() == 1_u);
        auto body = run_sync(drain_body(parsed.body));
        expect(read_body_text(body) == "hello"sv);
    };

    // RFC 9112 §5.2 — "A user agent that receives an obs-fold in a response
    // message that is not within a 'message/http' container MUST replace each
    // received obs-fold with one or more SP octets prior to interpreting the
    // field value." The client parser admits the folded line and delivers the
    // value with the fold replaced by the continuation's whitespace.
    "http1_client_replaces_obs_fold_with_space"_test = [] {
        http1_client_fixture fixture;
        fixture.queue_response(
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 0\r\n"
            "X-Fold: part-one\r\n"
            "  part-two\r\n\r\n");

        auto response = fixture.issue(basic_get("/"));
        expect(response.status == 200_u);
        auto folded = http::find_header(response.fields, "x-fold");
        expect(folded.has_value());
        if (folded) {
            expect(*folded == "part-one  part-two"sv);
        }
    };

    // RFC 9112 §5.2 — "A server that receives an obs-fold in a request
    // message that is not within a 'message/http' container MUST either reject
    // the message by sending a 400 (Bad Request)" — the server parser stays
    // strict, so a folded request line is answered with 400 and the
    // connection closed.
    "http1_server_rejects_obs_fold_request_with_400"_test = [] {
        pipe c2s, s2c;
        mock_stream transport{.input = c2s, .output = s2c};

        push_text(
            c2s,
            "GET / HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "X-Fold: a\r\n"
            " b\r\n\r\n");

        http::v1::server<mock_stream> server{transport};
        auto threw = false;
        try {
            static_cast<void>(run_sync(http::coroutine::receive(server)));
        } catch (const http::protocol_error& failure) {
            threw = std::holds_alternative<http::send_response>(failure.action());
        }
        expect(threw);
        auto wire = bytes_to_string(s2c.buffer);
        expect(wire.starts_with("HTTP/1.1 400 Bad Request\r\n"sv));
    };

    // RFC 9110 §5.5 — "Field values containing CR, LF, or NUL characters are
    // invalid and dangerous, due to the varying ways that implementations
    // might parse and interpret those characters" — the header-injection
    // surface of RFC 9112 §11.1. Outbound field values are rejected rather
    // than emitted verbatim.
    "http1_send_rejects_crlf_in_field_value"_test = [] {
        http::request req{
            .method = http::method::GET,
            .target = "/",
            .fields = {{"host", "example.com"}, {"x-injected", "safe\r\nX-Evil: 1"}},
        };
        auto threw = false;
        try {
            static_cast<void>(run_sync(http::v1::serialize(req)));
        } catch (const std::runtime_error& error) {
            threw = std::string_view{error.what()}.contains("CR/LF/NUL");
        }
        expect(threw);
    };

    // RFC 9110 §5.5 — CR/LF/NUL in a field value are invalid (quoted above);
    // a NUL in an outbound field value is rejected the same way.
    "http1_send_rejects_nul_in_field_value"_test = [] {
        http::request req{
            .method = http::method::GET,
            .target = "/",
            .fields = {{"host", "example.com"}, {"x-injected", std::string{"a\0b", 3}}},
        };
        auto threw = false;
        try {
            static_cast<void>(run_sync(http::v1::serialize(req)));
        } catch (const std::runtime_error& error) {
            threw = std::string_view{error.what()}.contains("CR/LF/NUL");
        }
        expect(threw);
    };

    // RFC 9110 §15.1 — "reason-phrase = 1*( HTAB / SP / VCHAR / obs-text )"; a
    // CR/LF in the outbound reason phrase would inject a new status line, so
    // it is rejected.
    "http1_send_rejects_crlf_in_reason_phrase"_test = [] {
        http::response res{
            .status = 200,
            .reason = "OK\r\nX-Injected: 1",
            .fields = {},
        };
        auto threw = false;
        try {
            static_cast<void>(run_sync(http::v1::serialize(res)));
        } catch (const std::runtime_error& error) {
            threw = std::string_view{error.what()}.contains("CR/LF/NUL");
        }
        expect(threw);
    };

    // RFC 9112 §3.2 — "A client MUST send a Host header field in all HTTP/1.1
    // request messages." A request without exactly one Host field line is
    // refused on the outbound path.
    "http1_send_rejects_request_without_host"_test = [] {
        http::request req{
            .method = http::method::GET,
            .target = "/",
            .fields = {},
        };
        auto threw = false;
        try {
            static_cast<void>(run_sync(http::v1::serialize(req)));
        } catch (const std::runtime_error& error) {
            threw = std::string_view{error.what()}.contains(
                "exactly one Host header field");
        }
        expect(threw);
    };

    // RFC 9110 §5.3 — "A recipient MAY combine multiple field lines within a
    // field section that have the same field name into one field line, without
    // changing the semantics of the message, by appending each subsequent
    // field line value to the initial field line value in order, separated by
    // a comma" — two Transfer-Encoding field lines combine into one list. RFC
    // 9112 §6.3 item 4 — "If a Transfer-Encoding header field is present in a
    // request and the chunked transfer coding is not the final encoding, the
    // message body length cannot be determined reliably." A response with
    // "Transfer-Encoding: chunked" followed by "Transfer-Encoding: gzip"
    // combines to "chunked, gzip": llhttp only looks at the last field line
    // for its framing flags and accepts it, so the client validates the
    // combined list itself and rejects the response (closing the connection,
    // since the message is unusable).
    "http1_response_with_multi_line_transfer_encoding_is_rejected"_test = [] {
        pipe c2s, s2c;
        mock_stream transport{.input = s2c, .output = c2s};

        push_text(
            s2c,
            "HTTP/1.1 200 OK\r\n"
            "Transfer-Encoding: chunked\r\n"
            "Transfer-Encoding: gzip\r\n\r\n");
        s2c.closed = true;

        http::v1::client<mock_stream> client{transport};
        auto threw = false;
        try {
            static_cast<void>(run_sync(http::coroutine::request(client, basic_get("/"))));
        } catch (const http::protocol_error& failure) {
            threw = failure.info().scope == http::error_scope::connection &&
                std::holds_alternative<http::close_connection>(failure.action());
        }
        expect(threw);
    };

    // RFC 9112 §6.3 item 6 — "If the sender closes the connection or the
    // recipient times out before the indicated number of octets are received,
    // the recipient MUST consider the message to be incomplete and close the
    // connection." A chunked body truncated by EOF is detected by llhttp_finish
    // (HPE_INVALID_EOF_STATE) and must ride the same connection-scoped
    // re-scope as any other body-phase framing error: the failure is
    // delivered as a close_connection protocol_error and the connection is
    // latched closed.
    "http1_chunked_body_truncated_by_eof_closes_connection"_test = [] {
        pipe c2s, s2c;
        mock_stream transport{.input = c2s, .output = s2c};

        push_text(
            c2s,
            "POST /upload HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "Transfer-Encoding: chunked\r\n\r\n"
            "5\r\nhel");
        c2s.closed = true;

        http::v1::server<mock_stream> server{transport};
        auto parsed = run_sync(http::coroutine::receive(server));
        expect(parsed.head.target == "/upload"sv);
        auto threw = false;
        try {
            static_cast<void>(run_sync(drain_body(parsed.body)));
        } catch (const http::protocol_error& failure) {
            threw = failure.info().scope == http::error_scope::connection &&
                std::holds_alternative<http::close_connection>(failure.action());
        }
        expect(threw);
        expect(server.should_close());
    };

    // RFC 9110 §5.5 — "a recipient of CR, LF, or NUL within a field value MUST
    // either reject the message or replace each of those characters with SP
    // before further processing". The lenient client parser admits NUL bytes
    // inside a response field value, so the manual scan rejects the message
    // (the server's strict parser would reject it outright at parse time).
    "http1_lenient_client_rejects_nul_in_response_field_value"_test = [] {
        pipe c2s, s2c;
        mock_stream transport{.input = s2c, .output = c2s};

        constexpr std::string_view head = "HTTP/1.1 200 OK\r\nX-A: b\0d\r\nContent-Length: 0\r\n\r\n";
        push_text(c2s, head);
        c2s.closed = true;

        http::v1::client<mock_stream> client{transport};
        auto threw = false;
        try {
            static_cast<void>(run_sync(http::coroutine::request(client, basic_get("/"))));
        } catch (const http::protocol_error& failure) {
            threw = std::holds_alternative<http::close_connection>(failure.action());
        }
        expect(threw);
    };

    // RFC 9112 §3.2.4 — "asterisk-form = "*""; "The "asterisk-form" of
    // request-target is only used for a server-wide OPTIONS request". RFC 9110
    // §7.1 — "These forms MUST NOT be used with other methods" — so the
    // outbound path refuses to emit an asterisk-form target for a method other
    // than OPTIONS (the receive side rejects the same shape with 400).
    "http1_send_rejects_non_options_asterisk_form_target"_test = [] {
        http::request req{
            .method = http::method::GET,
            .target = "*",
            .fields = {{"host", "example.com"}},
        };
        auto threw = false;
        try {
            static_cast<void>(run_sync(http::v1::serialize(req)));
        } catch (const std::runtime_error& error) {
            threw = std::string_view{error.what()}.contains(
                "asterisk-form request-target requires OPTIONS");
        }
        expect(threw);
    };

    // RFC 9112 §3.2 — "No whitespace is allowed in the request-target." The
    // outbound target is emitted verbatim on the request-line, so SP/HTAB
    // (which no request-target form admits — RFC 9110 §7.1) are rejected
    // alongside the CR/LF/NUL that would inject header lines.
    "http1_send_rejects_whitespace_in_request_target"_test = [] {
        for (auto target : {"/a b"sv, "/a\tb"sv}) {
            http::request req{
                .method = http::method::GET,
                .target = std::string{target},
                .fields = {{"host", "example.com"}},
            };
            auto threw = false;
            try {
                static_cast<void>(run_sync(http::v1::serialize(req)));
            } catch (const std::runtime_error& error) {
                threw = std::string_view{error.what()}.contains("whitespace");
            }
            expect(threw);
        }
    };

    // RFC 9110 §9.1 — "method = token"; RFC 9112 §3 — "request-line = method SP
    // request-target SP HTTP-version" — the method must be a non-empty token.
    // method::UNKNOWN (RFC 9110 §9.1 — "Additional methods, outside the scope of
    // this specification, have been specified for use in HTTP") has no token of
    // its own: serializing it would emit the malformed request-line " / HTTP/1.1",
    // which the library's own server would answer with 400, so the outbound path
    // refuses it.
    "http1_send_rejects_unknown_method"_test = [] {
        http::request req{
            .method = http::method::UNKNOWN,
            .target = "/",
            .fields = {{"host", "example.com"}},
        };
        auto threw = false;
        try {
            static_cast<void>(run_sync(http::v1::serialize(req)));
        } catch (const std::runtime_error& error) {
            threw = std::string_view{error.what()}.contains("unknown method");
        }
        expect(threw);
    };

    // The same contract holds on the streaming send path: the head serializer
    // refuses an UNKNOWN method before any bytes reach the transport.
    "http1_streaming_send_rejects_unknown_method"_test = [] {
        pipe c2s, s2c;
        mock_stream transport{.input = s2c, .output = c2s};
        http::v1::client<mock_stream> client{transport};
        http::request req{
            .method = http::method::UNKNOWN,
            .target = "/",
            .fields = {{"host", "example.com"}},
        };
        auto threw = false;
        try {
            static_cast<void>(run_sync(
                http::coroutine::request(client, std::move(req))));
        } catch (const std::runtime_error& error) {
            threw = std::string_view{error.what()}.contains("unknown method");
        }
        expect(threw);
        expect(c2s.available() == 0);
    };

    // RFC 9110 §9.3.8 — "A client MUST NOT send content in a TRACE request."
    // A TRACE that declares content through a Content-Length greater than zero
    // is refused before the head goes out. Previously the framing lay: the head
    // was emitted with "Content-Length: 5" while the body bytes were dropped,
    // leaving the peer waiting for five octets that never arrive — a framing
    // mismatch on the connection (RFC 9112 §6.3).
    "http1_send_rejects_trace_with_declared_content_length"_test = [] {
        http::request req{
            .method = http::method::TRACE,
            .target = "/trace",
            .fields = {{"host", "example.com"}, {"content-length", "5"}},
        };
        auto body = make_body("hello");
        auto threw = false;
        try {
            static_cast<void>(run_sync(http::v1::serialize(req, body)));
        } catch (const std::runtime_error& error) {
            threw = std::string_view{error.what()}.contains("must not declare content");
        }
        expect(threw);
    };

    // The declared Content-Length alone is the framing lie — an empty buffered
    // body changes nothing, so the same refusal applies.
    "http1_send_rejects_trace_with_declared_content_length_and_no_body_bytes"_test = [] {
        http::request req{
            .method = http::method::TRACE,
            .target = "/trace",
            .fields = {{"host", "example.com"}, {"content-length", "5"}},
        };
        auto threw = false;
        try {
            static_cast<void>(run_sync(http::v1::serialize(req)));
        } catch (const std::runtime_error& error) {
            threw = std::string_view{error.what()}.contains("must not declare content");
        }
        expect(threw);
    };

    // RFC 9110 §9.3.8 — "A client MUST NOT send content in a TRACE request." —
    // a Transfer-Encoding declares content just as Content-Length does and is
    // refused the same way.
    "http1_send_rejects_trace_with_transfer_encoding"_test = [] {
        http::request req{
            .method = http::method::TRACE,
            .target = "/trace",
            .fields = {{"host", "example.com"}, {"transfer-encoding", "chunked"}},
        };
        auto body = make_body("hello");
        auto threw = false;
        try {
            static_cast<void>(run_sync(http::v1::serialize(req, body)));
        } catch (const std::runtime_error& error) {
            threw = std::string_view{error.what()}.contains(
                "must not declare Transfer-Encoding");
        }
        expect(threw);
    };

    // RFC 9110 §9.3.8 — "A client MUST NOT send content in a TRACE request." A
    // Content-Length of 0 declares no content and is acceptable on the wire.
    "http1_send_allows_trace_with_zero_content_length"_test = [] {
        http::request req{
            .method = http::method::TRACE,
            .target = "/trace",
            .fields = {{"host", "example.com"}, {"content-length", "0"}},
        };
        auto serialized = bytes_to_string(run_sync(http::v1::serialize(req)));
        expect(serialized.starts_with("TRACE /trace HTTP/1.1\r\n"sv));
        expect(serialized.contains("content-length: 0\r\n"sv));
        expect(serialized.ends_with("\r\n\r\n"sv));
    };

    // The streaming send path refuses the declared-content shape before the
    // head is written: nothing reaches the transport.
    "http1_streaming_send_rejects_trace_with_declared_content_length"_test = [] {
        pipe c2s, s2c;
        mock_stream transport{.input = s2c, .output = c2s};
        http::v1::client<mock_stream> client{transport};
        http::request req{
            .method = http::method::TRACE,
            .target = "/trace",
            .fields = {{"host", "example.com"}, {"content-length", "5"}},
        };
        auto body = make_body("hello");
        auto threw = false;
        try {
            static_cast<void>(run_sync(
                http::coroutine::request(client, std::move(req), body)));
        } catch (const std::runtime_error& error) {
            threw = std::string_view{error.what()}.contains("must not declare content");
        }
        expect(threw);
        expect(c2s.available() == 0);
    };

    // The streaming send path also accepts a TRACE with Content-Length: 0: the
    // head goes out without content and the exchange proceeds to the response.
    "http1_streaming_send_allows_trace_with_zero_content_length"_test = [] {
        pipe c2s, s2c;
        mock_stream transport{.input = s2c, .output = c2s};
        push_text(s2c, "HTTP/1.1 204 No Content\r\n\r\n");
        http::v1::client<mock_stream> client{transport};
        auto received = run_sync(http::coroutine::request(client, http::request{
            .method = http::method::TRACE,
            .target = "/trace",
            .fields = {{"host", "example.com"}, {"content-length", "0"}},
        }));
        expect(received.head.status == 204_u);
        auto wire = bytes_to_string(c2s.buffer);
        expect(wire.starts_with("TRACE /trace HTTP/1.1\r\n"sv));
        expect(wire.contains("content-length: 0\r\n"sv));
        expect(wire.ends_with("\r\n\r\n"sv));
    };

};

} // namespace httpant::testing
