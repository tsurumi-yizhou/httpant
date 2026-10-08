import httpant.dependencies.boost.ut;
import std;
import httpant.testing;
import httpant;

namespace httpant::testing {

using namespace boost::ut;
using namespace std::literals;

namespace {

auto request_for(std::string_view target) -> http::request {
    return http::request{
        .method = http::method::POST,
        .target = std::string{target},
        .scheme = "https",
        .authority = "example.com",
    };
}

// HEADERS (0x1) with END_HEADERS | END_STREAM (0x5) on stream 1; HPACK 0x88 is
// the indexed ":status: 200" (RFC 7541 §6.1).
void push_final_h2_response(async_pipe& s2c) {
    const std::vector<std::byte> block{std::byte{0x88}};
    push_http2_frame(s2c, 0x01, 0x05, 1, block);
}

} // namespace

static suite<"fetch"> fetch_suite = [] {
    "alpn_identifiers"_test = [] {
        expect(http::alpn(http::protocol_version::http1).empty());
        expect(http::alpn(http::protocol_version::http2) == "h2"sv);
        expect(http::alpn(http::protocol_version::http3) == "h3"sv);
    };

    // A byte stream runs HTTP/1.1 and HTTP/2; a stream factory runs
    // HTTP/3; the other pairings have no client.
    "client_selection_by_connection_kind_and_version"_test = [] {
        using http::protocol_version;
        expect(std::same_as<http::client_t<mock_stream, protocol_version::http1>,
                            http::v1::client<mock_stream>>);
        expect(std::same_as<http::client_t<mock_stream, protocol_version::http2>,
                            http::v2::client<mock_stream>>);
        expect(std::same_as<http::client_t<mock_stream_factory, protocol_version::http3>,
                            http::v3::client<mock_stream_factory>>);
        expect(!http::has_client<mock_stream, protocol_version::http3>);
        expect(!http::has_client<mock_stream_factory, protocol_version::http1>);
        expect(!http::has_client<mock_stream_factory, protocol_version::http2>);
    };

    // RFC 9112 §3.2 — an HTTP/1.1 request has exactly one Host field; fetch
    // derives it from the authority, adds Content-Length for the body, and
    // reads the Content-Length-framed response to its end.
    "fetch_http1_derives_host_and_reads_the_body"_test = [] {
        pipe c2s, s2c;
        push_text(s2c, "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello");
        mock_stream transport{.input = s2c, .output = c2s};

        const auto payload = std::as_bytes(std::span{"ab", 2});
        auto result = run_sync(http::coroutine::fetch<http::protocol_version::http1>(
            transport, request_for("/order"), payload));

        expect(result.head.status == 200_u);
        expect(result.text() == "hello"sv);
        auto sent = bytes_to_string(c2s.buffer);
        expect(sent.starts_with("POST /order HTTP/1.1\r\n"));
        expect(sent.find("example.com") != std::string::npos);
        expect(sent.find("ontent-") != std::string::npos);
        expect(sent.ends_with("\r\n\r\nab"));
    };

    // The same call over HTTP/2: only the version argument and the connection
    // differ. fetch destroys its client when it returns, and here that happens
    // on the stack of the coroutine the driver woke inline, so this is also the
    // regression test for waking waiters only after the driver has suspended.
    "fetch_http2_and_the_client_dies_inside_the_wakeup"_test = [] {
        async_pipe c2s{};
        async_pipe s2c{};
        async_mock_stream transport{.input = s2c, .output = c2s};
        push_http2_settings_frame(s2c);

        auto pending = http::coroutine::fetch<http::protocol_version::http2>(
            transport, request_for("/h2"));
        pending.start();
        expect(!pending.done());

        push_final_h2_response(s2c);  // wakes the request from inside the reader

        expect(pending.done());
        auto result = run_sync(std::move(pending));
        expect(result.head.status == 200_u);
        expect(result.body.empty());
    };

    // RFC 9110 §7.8 — a 101 switches the connection to the requested protocol;
    // the bytes the server sent after the head already belong to it.
    "upgrade_reports_the_switch_and_the_bytes_after_the_head"_test = [] {
        pipe c2s, s2c;
        push_text(s2c,
                  "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
                  "Connection: Upgrade\r\nX-Probe: 1\r\n\r\nFIRST-BYTES");
        mock_stream transport{.input = s2c, .output = c2s};

        http::request head{.method = http::method::GET,
                           .target = "/ws",
                           .scheme = "https",
                           .authority = "example.com",
                           .fields = {{"upgrade", "websocket"}, {"connection", "Upgrade"}}};
        auto result = run_sync(http::coroutine::upgrade(transport, std::move(head)));

        expect(result.switched);
        expect(result.head.status == 101_u);
        expect(http::find_header(result.head.fields, "x-probe").value_or("") == "1"sv);
        expect(bytes_to_string(result.pending) == "FIRST-BYTES"sv);
        auto sent = bytes_to_string(c2s.buffer);
        expect(sent.starts_with("GET /ws HTTP/1.1\r\n"));
        expect(sent.find("example.com") != std::string::npos);
    };

    // A server that answers with a plain response did not switch: the head
    // says what it answered and no bytes are handed over.
    "upgrade_refused_is_not_a_switch"_test = [] {
        pipe c2s, s2c;
        push_text(s2c, "HTTP/1.1 426 Upgrade Required\r\nContent-Length: 0\r\n\r\n");
        mock_stream transport{.input = s2c, .output = c2s};

        http::request head{.method = http::method::GET,
                           .target = "/ws",
                           .scheme = "https",
                           .authority = "example.com",
                           .fields = {{"upgrade", "websocket"}, {"connection", "Upgrade"}}};
        auto result = run_sync(http::coroutine::upgrade(transport, std::move(head)));

        expect(!result.switched);
        expect(result.head.status == 426_u);
        expect(result.pending.empty());
    };

    // The application destroys the client from the continuation of its own
    // request, which the HTTP/2 reader has just woken.
    "http2_client_destroyed_by_the_coroutine_the_reader_woke"_test = [] {
        async_pipe c2s{};
        async_pipe s2c{};
        async_mock_stream transport{.input = s2c, .output = c2s};
        auto client = std::make_unique<http::v2::client<async_mock_stream>>(transport);
        push_http2_settings_frame(s2c);
        run_sync(http::coroutine::start(*client));

        bool destroyed = false;
        auto app = [&]() -> http::task<void> {
            {
                auto response = co_await http::coroutine::request(*client, basic_get("/x"));
                expect(response.head.status == 200_u);
            }
            client.reset();
            destroyed = true;
        }();
        app.start();
        expect(!destroyed);

        push_final_h2_response(s2c);

        expect(destroyed);
        expect(app.done());
    };
};

} // namespace httpant::testing
