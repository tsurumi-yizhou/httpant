#include <boost/ut.hpp>

#include "test_support.hpp"

namespace httpant::testing {

using namespace boost::ut;
using namespace std::literals;

static suite<"semantics"> semantics_suite = [] {
    // RFC 9110 §9.3.2 — "The HEAD method is identical to GET except that the
    // server MUST NOT send content in the response." The response is serialized
    // via serialize_head, so no Content-Length and no body appear on the wire.
    "head_responses_do_not_include_content"_test = [] {
        pipe c2s, s2c;
        mock_stream transport{.input = c2s, .output = s2c};

        push_text(c2s, "HEAD /docs HTTP/1.1\r\nHost: example.com\r\n\r\n");
        c2s.closed = true;

        http::v1::server<mock_stream> server{transport};
        auto incoming = run_sync(http::coroutine::receive(server));
        auto body = make_body("body");
        run_sync(http::coroutine::respond(server, std::move(incoming.token), http::response{
            .status = 200,
            .reason = {},
            .fields = {{"content-type", "text/plain"}},
        }, body));

        auto wire = bytes_to_string(s2c.buffer);
        expect(!wire.contains("content-length: 4\r\n"sv));
        expect(!wire.ends_with("\r\n\r\nbody"sv));
    };

    // RFC 9110 §15.3.6 — "Since the 205 status code implies that no additional
    // content will be provided, a server MUST NOT generate content in a 205
    // response." The supplied body is dropped entirely.
    "reset_content_responses_do_not_include_content"_test = [] {
        auto body = make_body("reset-me");
        auto wire = bytes_to_string(run_sync(http::v1::serialize(http::response{
            .status = 205,
            .reason = {},
            .fields = {},
        }, body)));

        expect(!wire.contains("content-length:"sv));
        expect(!wire.ends_with("\r\n\r\nreset-me"sv));
    };

    // RFC 9110 §9.3.8 — "A client MUST NOT send content in a TRACE request."
    // serialize() refuses to emit the body (and thus any Content-Length).
    "trace_requests_do_not_send_content"_test = [] {
        auto body = make_body("payload");
        auto wire = bytes_to_string(run_sync(http::v1::serialize(http::request{
            .method = http::method::TRACE,
            .target = "/trace",
            .fields = {{"host", "example.com"}},
        }, body)));

        expect(!wire.contains("content-length:"sv));
        expect(!wire.ends_with("\r\n\r\npayload"sv));
    };

    // RFC 9110 §15.2 — "A client MUST be able to parse one or more 1xx
    // responses received prior to a final response, even if the client does
    // not expect one." A 100 (Continue) is skipped and the final 200 is the
    // one returned to the caller.
    "informational_responses_do_not_end_the_exchange"_test = [] {
        http1_client_fixture fixture;
        fixture.queue_response(
            "HTTP/1.1 100 Continue\r\n\r\n"
            "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nfinal");

        auto response = fixture.issue(basic_get("/upload"));
        expect(response.status == 200_u);
        expect(read_body_text(response.body) == "final"sv);
    };

    // RFC 9110 §9.1 — "Additional methods, outside the scope of this
    // specification, have been specified for use in HTTP." Unknown methods are
    // preserved as method::UNKNOWN and must never silently become a known
    // method such as GET.
    "unknown_methods_do_not_downgrade_to_get"_test = [] {
        expect(http::from_string("PROPFIND"sv) != http::method::GET);
    };

    // RFC 9112 §9.3 — "A server MUST read the entire request message body or
    // close the connection after sending its response, since otherwise the
    // remaining data on a persistent connection would be misinterpreted as
    // the next request." An early final response that leaves request content
    // unread therefore emits the "close" connection option on the wire (RFC
    // 9112 §9.6 — "The server SHOULD send a 'close' connection option in its
    // final response on that connection") and ends the connection.
    "early_response_with_unconsumed_body_emits_connection_close"_test = [] {
        pipe c2s, s2c;
        mock_stream transport{.input = c2s, .output = s2c};

        push_text(
            c2s,
            "POST /upload HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "Content-Length: 100\r\n\r\n"
            "partial");
        c2s.closed = true;

        http::v1::server<mock_stream> server{transport};
        auto incoming = run_sync(http::coroutine::receive(server));
        run_sync(http::coroutine::respond(server, std::move(incoming.token), http::response{
            .status = 400,
            .reason = {},
            .fields = {},
        }));

        auto wire = bytes_to_string(s2c.buffer);
        expect(wire.contains("connection: close\r\n"sv));
        expect(server.should_close());
    };

    // RFC 9110 §9.3.8 — "A client MUST NOT send content in a TRACE request."
    // A TRACE request that declares content (Content-Length > 0) is rejected
    // with 400 and the connection closed (RFC 9112 §3.2's malformed-request
    // path).
    "trace_request_with_declared_body_is_rejected"_test = [] {
        pipe c2s, s2c;
        mock_stream transport{.input = c2s, .output = s2c};

        push_text(
            c2s,
            "TRACE /trace HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "Content-Length: 5\r\n\r\n"
            "hello");

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

    // RFC 9112 §6.3 item 6 — "If the sender closes the connection or the
    // recipient times out before the indicated number of octets are received,
    // the recipient MUST consider the message to be incomplete and close the
    // connection." A body-phase framing error (an invalid chunk size) is
    // delivered as a connection-scoped protocol_error whose action closes the
    // connection, and the server latches closure instead of reporting the
    // connection usable.
    "body_phase_chunk_error_latches_connection_closure"_test = [] {
        pipe c2s, s2c;
        mock_stream transport{.input = c2s, .output = s2c};

        push_text(
            c2s,
            "POST /upload HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "Transfer-Encoding: chunked\r\n\r\n"
            "ZZ\r\nnot-a-chunk\r\n");
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

    // RFC 9112 §3.2 — "If the authority component is missing or undefined for
    // the target URI, then a client MUST send a Host header field with an
    // empty field value." An empty Host value is therefore a defined form —
    // RFC 9112 §3.2 — "A server MUST respond with a 400 (Bad Request) status
    // code to any HTTP/1.1 request message that lacks a Host header field and
    // to any request message that contains more than one Host header field
    // line or a Host header field with an invalid field value" — but an empty
    // value is not an "invalid field value": it is exactly what a conformant
    // client sends for a target without an authority component, so it is
    // accepted.
    "empty_host_value_is_accepted"_test = [] {
        pipe c2s, s2c;
        mock_stream transport{.input = c2s, .output = s2c};

        push_text(c2s, "GET / HTTP/1.1\r\nHost:\r\n\r\n");
        c2s.closed = true;

        http::v1::server<mock_stream> server{transport};
        auto incoming = run_sync(http::coroutine::receive(server));
        auto host = http::find_header(incoming.head.fields, "host");
        expect(host.has_value());
        if (host) expect(host->empty());
        expect(!server.should_close());
    };

    // RFC 9112 §3.2 — "a Host header field with an invalid field value" must
    // be answered with 400 (quoted above); RFC 9110 §7.2 — "Host = uri-host
    // [ \":\" port ]" — a uri-host (RFC 3986 §3.2.2: IP-literal / IPv4address
    // / reg-name) contains no embedded whitespace, so a value with a space is
    // not a uri-host and is rejected.
    "host_value_with_space_is_rejected"_test = [] {
        pipe c2s, s2c;
        mock_stream transport{.input = c2s, .output = s2c};

        push_text(c2s, "GET / HTTP/1.1\r\nHost: exa mple.com\r\n\r\n");
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

    // RFC 9112 §3.2 — "to any request message that contains more than one Host
    // header field line" — the multiplicity rule is version-unscoped ("any
    // request message"), so it applies to HTTP/1.0 too; only the *presence*
    // requirement stays HTTP/1.1-scoped (RFC 9112 §3.2 — "A client MUST send
    // a Host header field in all HTTP/1.1 request messages").
    "http1_0_request_with_multiple_host_lines_is_rejected"_test = [] {
        pipe c2s, s2c;
        mock_stream transport{.input = c2s, .output = s2c};

        push_text(
            c2s,
            "GET /legacy HTTP/1.0\r\n"
            "Host: a.example\r\n"
            "Host: b.example\r\n\r\n");
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

    // RFC 9112 §3.2.4 — "The 'asterisk-form' of request-target is only used
    // for a server-wide OPTIONS request"; RFC 9110 §7.1 — "These forms MUST
    // NOT be used with other methods." llhttp accepts the wire shape for any
    // method, so a non-OPTIONS request targeting "*" is answered with 400 and
    // the connection closed like the other malformed request heads.
    "asterisk_form_with_non_options_method_is_rejected"_test = [] {
        pipe c2s, s2c;
        mock_stream transport{.input = c2s, .output = s2c};

        push_text(c2s, "GET * HTTP/1.1\r\nHost: example.com\r\n\r\n");
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

    // RFC 9112 §3.2 — "a Host header field with an invalid field value" must
    // be answered with 400 (quoted above); Host is a singleton (RFC 9110 §7.2
    // — "Host = uri-host [ \":\" port ]"), so a comma list cannot be a single
    // uri-host and is rejected.
    "comma_list_host_value_is_rejected"_test = [] {
        pipe c2s, s2c;
        mock_stream transport{.input = c2s, .output = s2c};

        push_text(c2s, "GET / HTTP/1.1\r\nHost: a, b\r\n\r\n");
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

    // RFC 9112 §3.2 — the Host requirement is scoped to HTTP/1.1 — "A client
    // MUST send a Host header field in all HTTP/1.1 request messages" — and
    // the server otherwise supports HTTP/1.0 persistence (RFC 9112 §9.3), so
    // an HTTP/1.0 request without Host is accepted.
    "http1_0_request_without_host_is_accepted"_test = [] {
        pipe c2s, s2c;
        mock_stream transport{.input = c2s, .output = s2c};

        push_text(c2s, "GET /legacy HTTP/1.0\r\n\r\n");
        c2s.closed = true;

        http::v1::server<mock_stream> server{transport};
        auto incoming = run_sync(http::coroutine::receive(server));
        expect(incoming.head.target == "/legacy"sv);
    };

    // RFC 9110 §9.1 — "Additional methods, outside the scope of this
    // specification, have been specified for use in HTTP." An inbound request
    // with an unparseable method must still be deliverable — it arrives as
    // method::UNKNOWN and the exchange completes normally. The send-side
    // refusal of UNKNOWN (serialize_head, make_request_field_block) must not
    // disturb the receive path: the server never serializes the request, it
    // only answers it.
    "unknown_method_request_is_deliverable_on_receive_path"_test = [] {
        pipe c2s, s2c;
        mock_stream transport{.input = c2s, .output = s2c};

        push_text(
            c2s,
            "PROPFIND /resource HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "Content-Length: 0\r\n\r\n");
        c2s.closed = true;

        http::v1::server<mock_stream> server{transport};
        auto incoming = run_sync(http::coroutine::receive(server));
        expect(incoming.head.method == http::method::UNKNOWN);
        expect(incoming.head.target == "/resource"sv);
        static_cast<void>(run_sync(drain_body(incoming.body)));
        run_sync(http::coroutine::respond(server, std::move(incoming.token), http::response{
            .status = 200,
            .reason = {},
            .fields = {{"content-length", "0"}},
        }));
        auto wire = bytes_to_string(s2c.buffer);
        expect(wire.starts_with("HTTP/1.1 200 OK\r\n"sv));
    };
    // RFC 9112 §3.2 — "a Host header field with an invalid field value" must
    // be answered with 400. RFC 9110 §7.2 defines Host as uri-host [ ":" port ],
    // so a path segment or a non-numeric port is outside the grammar even
    // though it contains neither whitespace nor a comma.
    "host_value_with_path_segment_is_rejected"_test = [] {
        pipe c2s, s2c;
        mock_stream transport{.input = c2s, .output = s2c};

        push_text(c2s, "GET / HTTP/1.1\r\nHost: example.com/path\r\n\r\n");
        c2s.closed = true;

        http::v1::server<mock_stream> server{transport};
        auto threw = false;
        try {
            static_cast<void>(run_sync(http::coroutine::receive(server)));
        } catch (const http::protocol_error& failure) {
            threw = std::holds_alternative<http::send_response>(failure.action());
        }
        expect(threw);
        expect(bytes_to_string(s2c.buffer).starts_with("HTTP/1.1 400 Bad Request\r\n"sv));
    };

    "host_value_with_non_numeric_port_is_rejected"_test = [] {
        pipe c2s, s2c;
        mock_stream transport{.input = c2s, .output = s2c};

        push_text(c2s, "GET / HTTP/1.1\r\nHost: example.com:http\r\n\r\n");
        c2s.closed = true;

        http::v1::server<mock_stream> server{transport};
        auto threw = false;
        try {
            static_cast<void>(run_sync(http::coroutine::receive(server)));
        } catch (const http::protocol_error& failure) {
            threw = std::holds_alternative<http::send_response>(failure.action());
        }
        expect(threw);
        expect(bytes_to_string(s2c.buffer).starts_with("HTTP/1.1 400 Bad Request\r\n"sv));
    };

    // RFC 9110 §15 — "All valid status codes are within the range of 100 to
    // 599, inclusive." llhttp accepts any three-digit status, so the client
    // must enforce the semantic bound before delivering the response.
    "http1_response_status_outside_100_to_599_is_rejected"_test = [] {
        pipe c2s, s2c;
        mock_stream transport{.input = s2c, .output = c2s};

        push_text(s2c, "HTTP/1.1 600 What\r\nContent-Length: 0\r\n\r\n");
        s2c.closed = true;

        http::v1::client<mock_stream> client{transport};
        auto threw = false;
        try {
            static_cast<void>(run_sync(http::coroutine::request(
                client, http::request{.target = "/", .fields = {{"host", "example.com"}}})));
        } catch (const http::protocol_error& failure) {
            threw = failure.info().condition == http::error_condition::malformed_message;
        }
        expect(threw);
    };

    // Internal machinery test: a transport write failure mid-request is not
    // RFC behavior. Once the request head has been written, a failing body
    // write desynchronizes the HTTP/1.1 message boundary, so the client must
    // latch the connection closed and the next request() must throw instead of
    // appending a request to the misaligned byte stream.
    "http1_client_body_write_failure_latches_connection_closed"_test = [] {
        pipe c2s{};
        pipe s2c{};
        // The request head write succeeds; the body write fails.
        write_failing_stream transport{
            .input = s2c, .output = c2s, .writes_before_failure = 1};

        http::v1::client<write_failing_stream> client{transport};
        auto body = make_body("payload");
        auto threw = false;
        try {
            static_cast<void>(run_sync(http::coroutine::request(
                client,
                http::request{
                    .method = http::method::POST,
                    .target = "/upload",
                    .fields = {{"host", "example.com"},
                               {"content-length", "7"}},
                },
                body)));
        } catch (const std::runtime_error& failure) {
            expect(std::string_view{failure.what()} ==
                   "write_failing_stream: scripted write failure"sv);
            threw = true;
        }
        expect(threw);

        threw = false;
        try {
            static_cast<void>(run_sync(http::coroutine::request(client, basic_get())));
        } catch (const std::runtime_error& failure) {
            expect(std::string_view{failure.what()} ==
                   "http/1.1: connection closed after previous response"sv);
            threw = true;
        }
        expect(threw);
    };

    // Internal machinery test: a transport write failure on the receive path
    // is not RFC behavior. The interim 100 (Continue) write fails after the
    // request head was read, leaving the byte stream at an unknown position,
    // so the server must latch the connection closed and the next receive()
    // must throw instead of parsing from a desynchronized boundary.
    "http1_server_continue_write_failure_latches_connection_closed"_test = [] {
        pipe c2s{};
        pipe s2c{};
        write_failing_stream transport{.input = c2s, .output = s2c};

        push_text(
            c2s,
            "POST /upload HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "Expect: 100-continue\r\n"
            "Content-Length: 7\r\n\r\n");
        c2s.closed = true;

        http::v1::server<write_failing_stream> server{transport};
        auto threw = false;
        try {
            static_cast<void>(run_sync(http::coroutine::receive(server)));
        } catch (const std::runtime_error& failure) {
            expect(std::string_view{failure.what()} ==
                   "write_failing_stream: scripted write failure"sv);
            threw = true;
        }
        expect(threw);

        threw = false;
        try {
            static_cast<void>(run_sync(http::coroutine::receive(server)));
        } catch (const std::runtime_error& failure) {
            expect(std::string_view{failure.what()} ==
                   "http/1.1: connection closed after previous exchange"sv);
            threw = true;
        }
        expect(threw);
    };



    // Internal machinery test: cancellation of a suspended header-phase read
    // is not HTTP RFC behavior. The transport delivers cancellation by
    // throwing std::system_error{operation_canceled} out of async_read; the
    // receive operation surfaces it untouched.
    "http1_cancelled_header_read_throws_operation_canceled"_test = [] {
        async_pipe c2s{};
        async_pipe s2c{};
        async_mock_stream transport{.input = c2s, .output = s2c};

        http::v1::server<async_mock_stream> server{transport};
        std::stop_source stop;
        auto completions = 0;
        auto cancelled = false;

        auto receive = [&]() -> http::task<void> {
            try {
                static_cast<void>(co_await operation_receive(server, stop.get_token()));
            } catch (const std::system_error& error) {
                cancelled = error.code() == std::errc::operation_canceled;
            }
            ++completions;
        };
        auto pending = receive();
        pending.start();
        expect(!pending.done());

        expect(stop.request_stop());
        expect(pending.done());
        expect(cancelled);
        expect(completions == 1_i);
    };
};

} // namespace httpant::testing
