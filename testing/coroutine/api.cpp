#include <boost/ut.hpp>

#include <coroutine>
#include <string>
#include <string_view>
#include <utility>

#include "../test_support.hpp"

namespace httpant::testing::coroutine {

using namespace boost::ut;
using namespace std::literals;

namespace {

using h2_incoming = http::v2::server<async_mock_stream>::incoming_request;

template <typename Client>
concept client_endpoint = requires(
    Client& client,
    http::request request,
    http::buffer_body& body) {
    http::coroutine::start(client);
    http::coroutine::request(client, std::move(request), body);
};

template <typename Server>
concept server_endpoint = requires(
    Server& server,
    typename Server::exchange_token token,
    http::response response,
    http::buffer_body& body) {
    http::coroutine::start(server);
    http::coroutine::receive(server);
    http::coroutine::respond(
        server, std::move(token), std::move(response), body);
};

template <typename Client>
auto request(Client& client, http::request head, http::buffer_body& body) {
    return http::coroutine::request(client, std::move(head), body);
}

template <typename Server>
auto receive(Server& server) {
    return http::coroutine::receive(server);
}

template <typename Server, typename Incoming>
auto respond(
    Server& server,
    Incoming& incoming,
    http::response head,
    http::buffer_body& body) {
    return http::coroutine::respond(
        server, std::move(incoming.token), std::move(head), body);
}

} // namespace

// Coroutine public-API integration suite. These tests drive a complete
// HTTP/1.1 and HTTP/2 exchange using only the free functions in
// `namespace http::coroutine` — never endpoint member operations, and never
// the `http::execution` surface. The transport is a test-only async pipe; no
// RFC-mandated behavior is asserted here beyond what the exchange itself
// requires (correct framing is covered by the wire/conformance suites).
static suite<"coroutine"> tests = [] {
    static_assert(client_endpoint<http::v1::client<async_mock_stream>>);
    static_assert(client_endpoint<http::v2::client<async_mock_stream>>);
    static_assert(client_endpoint<http::v3::client<recording_stream_factory>>);
    static_assert(server_endpoint<http::v1::server<async_mock_stream>>);
    static_assert(server_endpoint<http::v2::server<async_mock_stream>>);
    static_assert(server_endpoint<http::v3::server<recording_stream_factory>>);

    // HTTP/1.1 client and server round-trip through http::coroutine::*.
    // `start` is a documented no-op for H1 (no handshake), so calling it only
    // verifies the public entry point is present and co_await-able.
    "h1_roundtrip"_test = [] {
        async_pipe c2s{};
        async_pipe s2c{};
        async_mock_stream client_transport{.input = s2c, .output = c2s};
        async_mock_stream server_transport{.input = c2s, .output = s2c};

        http::v1::client<async_mock_stream> client{client_transport};
        http::v1::server<async_mock_stream> server{server_transport};

        run_sync(http::coroutine::start(client));
        run_sync(http::coroutine::start(server));

        auto server_receive = receive(server);
        server_receive.start();

        http::buffer_body request_body;
        auto client_request = request(client, basic_get("/index.html"), request_body);
        client_request.start();

        auto incoming = run_sync(std::move(server_receive));
        expect(incoming.head.target == "/index.html"sv);
        expect(incoming.head.method == http::method::GET);
        static_cast<void>(run_sync(drain_body(incoming.body)));

        // The streaming H1 write path does not infer Content-Length (that is
        // only done by the buffered serialize_response helper), so the response
        // declares it explicitly; without it the client would treat the body as
        // close-delimited and wait for EOF that never comes.
        auto response_body = make_body("<html/>");
        run_sync(respond(
            server,
            incoming,
            http::response{
                .status = 200,
                .reason = {},
                .fields = {
                    {"content-type", "text/html"},
                    {"content-length", "7"},
                },
            },
            response_body));

        auto response = run_sync(std::move(client_request));
        expect(response.head.status == 200_u);
        expect(read_body_text(response.body) == "<html/>"sv);
    };

    // HTTP/2 client and server round-trip through http::coroutine::*.
    // `start` maps to the H2 handshake; receive/respond are the token-correlated
    // exchange operations.
    "h2_roundtrip"_test = [] {
        async_pipe c2s{};
        async_pipe s2c{};
        async_mock_stream client_transport{.input = s2c, .output = c2s};
        async_mock_stream server_transport{.input = c2s, .output = s2c};

        http::v2::client<async_mock_stream> client{client_transport};
        http::v2::server<async_mock_stream> server{server_transport};

        auto server_accept = [&]() -> http::task<h2_incoming> {
            co_await http::coroutine::start(server);
            co_return co_await receive(server);
        };
        auto server_task = server_accept();
        server_task.start();
        run_sync(http::coroutine::start(client));

        http::buffer_body request_body;
        auto client_request = request(client, basic_get("/index.html"), request_body);
        client_request.start();

        auto incoming = run_sync(std::move(server_task));
        expect(incoming.head.target == "/index.html"sv);
        static_cast<void>(run_sync(drain_body(incoming.body)));

        auto response_body = make_body("<html/>");
        run_sync(respond(
            server,
            incoming,
            http::response{
                .status = 200,
                .reason = {},
                .fields = {{"content-type", "text/html"}},
            },
            response_body));

        auto response = run_sync(std::move(client_request));
        expect(response.head.status == 200_u);
        expect(read_body_text(response.body) == "<html/>"sv);
    };

    // The same generic request/receive/respond helpers also drive HTTP/3;
    // transport routing below only models the QUIC backend boundary.
    "h3_roundtrip"_test = [] {
        recording_stream_factory client_transport{true};
        recording_stream_factory server_transport{false};
        http::v3::client<recording_stream_factory> client{client_transport};
        http::v3::server<recording_stream_factory> server{server_transport};

        run_sync(http::coroutine::start(client));
        route_writes_to(client_transport, server_transport);
        run_sync(http::coroutine::start(server));
        route_writes_to(server_transport, client_transport);

        http::buffer_body request_body;
        auto client_request = request(client, basic_get("/index.html"), request_body);
        client_request.start();
        route_writes_to(client_transport, server_transport);

        auto incoming = run_sync(receive(server));
        expect(incoming.head.target == "/index.html"sv);
        static_cast<void>(run_sync(drain_body(incoming.body)));

        auto response_body = make_body("<html/>");
        run_sync(respond(
            server,
            incoming,
            http::response{.status = 200, .reason = {}, .fields = {}},
            response_body));
        route_writes_to(server_transport, client_transport);

        auto response = run_sync(std::move(client_request));
        expect(response.head.status == 200_u);
        expect(read_body_text(response.body) == "<html/>"sv);
    };
};

} // namespace httpant::testing::coroutine
