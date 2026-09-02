#include <boost/ut.hpp>

#include "test_support.hpp"

namespace httpant::testing {

using namespace boost::ut;
using namespace std::literals;

static suite<"connect"> connect_suite = [] {
    // RFC 7639 §2 — "Clients include the ALPN header field in an HTTP CONNECT
    // request to indicate the application-layer protocol that a client intends
    // to use within the tunnel." A non-CONNECT request is not a tunnel request,
    // so ALPN on one is a protocol violation and serialize() refuses it loudly
    // (mirroring the server-side rejection below).
    "non_connect_requests_with_alpn_are_refused"_test = [] {
        auto threw = false;
        try {
            static_cast<void>(run_sync(http::v1::serialize(http::request{
                .method = http::method::GET,
                .target = "/",
                .fields = {{"host", "example.com"}, {"alpn", "h2"}},
            })));
        } catch (const std::runtime_error&) {
            threw = true;
        }
        expect(threw);
    };

    // RFC 7639 §2 — "Clients include the ALPN header field in an HTTP CONNECT
    // request ..." — it has no meaning on a request that is not CONNECT, so a
    // server receiving one on a non-CONNECT request rejects the message.
    "non_connect_requests_with_alpn_are_rejected"_test = [] {
        pipe c2s, s2c;
        mock_stream transport{.input = c2s, .output = s2c};

        push_text(c2s, "GET / HTTP/1.1\r\nHost: example.com\r\nALPN: h2\r\n\r\n");
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

    // RFC 7639 §2.3 — "When used in the ALPN header field, an ALPN identifier
    // is used to identify an entire application protocol stack"; RFC 7639 §2.2
    // — "ALPN = 1#protocol-id; protocol-id = token". A CONNECT request carrying
    // a valid ALPN token is accepted and the token is preserved.
    "tunnel_alpn_validation_is_enforced"_test = [] {
        pipe c2s, s2c;
        mock_stream transport{.input = c2s, .output = s2c};

        push_text(c2s,
            "CONNECT example.com:443 HTTP/1.1\r\n"
            "Host: example.com:443\r\n"
            "ALPN: h2\r\n\r\n");
        c2s.closed = true;

        http::v1::server<mock_stream> server{transport};
        auto threw = false;
        try {
            auto request = run_sync(http::coroutine::receive(server));
            auto alpn = http::find_header(request.head.fields, "alpn");
            expect(request.head.method == http::method::CONNECT);
            expect(alpn.has_value());
            if (alpn.has_value()) {
                expect(*alpn == "h2"sv);
            }
        } catch (...) {
            threw = true;
        }

        expect(!threw);
    };

    // RFC 9110 §9.3.6 — "Any 2xx (Successful) response indicates that the
    // sender (and all inbound proxies) will switch to tunnel mode immediately
    // after the response header section" — so a successful CONNECT response
    // must not carry content (no Content-Length, no body bytes).
    "successful_connect_responses_do_not_include_content"_test = [] {
        pipe c2s, s2c;
        mock_stream transport{.input = c2s, .output = s2c};

        push_text(c2s, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n");
        c2s.closed = true;

        http::v1::server<mock_stream> server{transport};
        auto incoming = run_sync(http::coroutine::receive(server));
        auto body = make_body("tunnel-bytes");
        run_sync(http::coroutine::respond(server, std::move(incoming.token), http::response{
            .status = 200,
            .reason = {},
            .fields = {},
        }, body));

        auto wire = bytes_to_string(s2c.buffer);
        expect(!wire.contains("content-length:"sv));
        expect(!wire.contains("tunnel-bytes"sv));
    };

    // RFC 9110 §9.3.6 — "For CONNECT (Section 9.3.6), the request target is
    // the host name and port number of the tunnel destination, separated by a
    // colon" (authority-form). A target that is not authority-form ("/path")
    // is rejected.
    "connect_targets_use_authority_form"_test = [] {
        pipe c2s, s2c;
        mock_stream transport{.input = c2s, .output = s2c};

        push_text(c2s, "CONNECT /not-authority HTTP/1.1\r\nHost: example.com\r\n\r\n");
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

    // RFC 9112 §3.2.3 — "authority-form = uri-host \":\" port" and RFC 9110
    // §9.3.6 — "A server MUST reject a CONNECT request that targets an empty
    // or invalid port number, typically by responding with a 400 (Bad Request)
    // status code." A CONNECT target without a port ("example.com") is not
    // authority-form and must be rejected.
    "connect_target_without_port_is_rejected"_test = [] {
        pipe c2s, s2c;
        mock_stream transport{.input = c2s, .output = s2c};

        push_text(c2s, "CONNECT example.com HTTP/1.1\r\nHost: example.com\r\n\r\n");
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

    // RFC 9112 §3.2.3 — "authority-form = uri-host \":\" port" — a CONNECT
    // target with a path suffix is not authority-form: the port must be all
    // digits and the target must consist of only the host and port.
    "connect_target_with_path_suffix_is_rejected"_test = [] {
        pipe c2s, s2c;
        mock_stream transport{.input = c2s, .output = s2c};

        push_text(
            c2s,
            "CONNECT example.com:80/foo HTTP/1.1\r\n"
            "Host: example.com:80\r\n\r\n");
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

    // RFC 9112 §6.3 item 2 — "Any 2xx (Successful) response to a CONNECT
    // request implies that the connection will become a tunnel immediately
    // after the empty line that concludes the header fields. A client MUST
    // ignore any Content-Length or Transfer-Encoding header fields received in
    // such a message." A plain 200 CONNECT (without Connection: Upgrade, so
    // llhttp never flags it) switches the client to tunnel mode: the response
    // framing fields are ignored and the bytes after the header section are
    // tunnel data.
    "client_200_connect_starts_tunnel_despite_content_length"_test = [] {
        http1_client_fixture fixture;
        // Content-Length: 10 describes 10 body octets per the framing rules,
        // but a successful CONNECT response becomes a tunnel immediately after
        // the header section, so all remaining bytes are tunnel data.
        fixture.queue_response(
            "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n"
            "tunnel-data-bytes-more-than-ten");

        auto response = fixture.issue(http::request{
            .method = http::method::CONNECT,
            .target = "example.com:443",
            .fields = {{"host", "example.com:443"}},
        });
        expect(response.status == 200_u);
        expect(fixture.client.upgraded());
        expect(bytes_to_string(fixture.client.take_pending()) ==
               "tunnel-data-bytes-more-than-ten"sv);
    };

    // RFC 9110 §9.3.6 — "Any 2xx (Successful) response indicates that the
    // sender (and all inbound proxies) will switch to tunnel mode immediately
    // after the response header section"; RFC 9112 §6.3 item 2 — "A client
    // MUST ignore any Content-Length or Transfer-Encoding header fields
    // received in such a message" — a successful CONNECT response ends the
    // HTTP exchange on the wire, so no further request can be issued on the
    // connection.
    "client_200_connect_ends_http_exchange"_test = [] {
        http1_client_fixture fixture;
        fixture.queue_response(
            "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n"
            "tunnel-data");

        auto response = fixture.issue(http::request{
            .method = http::method::CONNECT,
            .target = "example.com:443",
            .fields = {{"host", "example.com:443"}},
        });
        expect(response.status == 200_u);

        auto threw = false;
        try {
            static_cast<void>(fixture.issue(basic_get("/again")));
        } catch (...) {
            threw = true;
        }
        expect(threw);
    };
};

} // namespace httpant::testing
