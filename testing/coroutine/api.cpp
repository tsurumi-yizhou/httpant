import httpant.dependencies.boost.ut;
import std;
import httpant;
import httpant.testing;

namespace httpant::testing::coroutine {

    using namespace boost::ut;
    using namespace std::literals;

    namespace {

        using h2_incoming = http::v2::server<async_mock_stream>::incoming_request;

        template <typename Client>
        concept client_endpoint = requires(Client& client, http::request request, http::buffer_body& body) {
            http::coroutine::start(client);
            http::coroutine::request(client, std::move(request), body);
        };

        template <typename Server>
        concept server_endpoint = requires(Server& server, typename Server::exchange_token token, http::response response, http::buffer_body& body) {
            http::coroutine::start(server);
            http::coroutine::receive(server);
            http::coroutine::respond(server, std::move(token), std::move(response), body);
        };

        template <typename Client> auto request(Client& client, http::request head, http::buffer_body& body) {
            return http::coroutine::request(client, std::move(head), body);
        }

        template <typename Server> auto receive(Server& server) { return http::coroutine::receive(server); }

        template <typename Server, typename Incoming> auto respond(Server& server, Incoming& incoming, http::response head, http::buffer_body& body) {
            return http::coroutine::respond(server, std::move(incoming.token), std::move(head), body);
        }

        struct borrowing_client {
            template <http::body_stream Body> auto request(const http::request& head, Body&) -> http::detail::operation<std::string> { co_return head.target; }
        };
        struct borrowing_server {
            int observed_token = 0;
            std::string observed_reason;
            template <http::body_stream Body> auto respond(const int& token, const http::response& head, Body&) -> http::detail::operation<void> {
                observed_token = token;
                observed_reason = head.reason;
                co_return;
            }
        };

        struct overloaded_client {
            bool borrowed = false;
            template <http::body_stream Body> auto request(http::request head, Body&) -> http::detail::operation<std::string> { co_return head.target; }
            auto request(http::request&& head, http::buffer_body&) -> http::detail::operation<std::string> {
                borrowed = true;
                co_return head.target;
            }
        };
        struct overloaded_server {
            bool borrowed = false;
            std::string observed_reason;
            template <http::body_stream Body> auto respond(int, http::response head, Body&) -> http::detail::operation<void> {
                observed_reason = head.reason;
                co_return;
            }
            auto respond(int&&, http::response&& head, http::buffer_body&) -> http::detail::operation<void> {
                borrowed = true;
                observed_reason = head.reason;
                co_return;
            }
        };

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

        "generic_endpoints_keep_borrowed_message_arguments_alive"_test = [] {
            http::buffer_body body;
            borrowing_client client;
            std::string target = "/" + std::string(128, 'q');
            auto request = http::coroutine::request(client, http::request{.target = target}, body);
            expect(run_sync(std::move(request)) == target);
            borrowing_server server;
            std::string reason(128, 'r');
            auto response = http::coroutine::respond(server, 73, http::response{.reason = reason}, body);
            run_sync(std::move(response));
            expect(server.observed_token == 73_i);
            expect(server.observed_reason == reason);
        };

        "the_adopted_member_is_the_value_taking_overload"_test = [] {
            http::buffer_body body;
            overloaded_client client;
            std::string target = "/" + std::string(128, 'v');
            expect(run_sync(http::coroutine::request(client, http::request{.target = target}, body)) == target);
            expect(!client.borrowed);
            overloaded_server server;
            std::string reason(128, 'v');
            run_sync(http::coroutine::respond(server, 73, http::response{.reason = reason}, body));
            expect(!server.borrowed && server.observed_reason == reason);
        };

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
            // declares it; without it the client would treat the body as
            // close-delimited and wait for EOF that never comes.
            auto response_body = make_body("<html/>");
            run_sync(respond(server, incoming,
                             http::response{
                                 .status = 200,
                                 .reason = {},
                                 .fields =
                                     {
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

            http::v2::client<async_mock_stream, http::queues::locked> client{client_transport};
            http::v2::server<async_mock_stream, http::queues::locked> server{server_transport};

            std::weak_ptr<http::v2::detail::stream_data<http::queues::locked>> completed;
            {
                auto server_accept = [&]() -> http::task<typename decltype(server)::incoming_request> {
                    co_await http::coroutine::start(server);
                    co_return co_await receive(server);
                };
                auto server_task = server_accept();
                server_task.start();
                run_sync(http::coroutine::start(client));

                http::buffer_body request_body;
                auto client_request = request(client, basic_get("/index.html?lang=en&next=%2F"), request_body);
                client_request.start();

                auto incoming = run_sync(std::move(server_task));
                completed = incoming.token.handle();
                expect(incoming.head.target == "/index.html?lang=en&next=%2F"sv);
                static_cast<void>(run_sync(drain_body(incoming.body)));

                auto response_body = make_body("<html/>");
                run_sync(respond(server, incoming,
                                 http::response{
                                     .status = 200,
                                     .reason = {},
                                     .fields = {{"content-type", "text/html"}},
                                 },
                                 response_body));

                auto response = run_sync(std::move(client_request));
                expect(response.head.status == 200_u);
                expect(read_body_text(response.body) == "<html/>"sv);
                run_sync(http::coroutine::close(client));
                run_sync(http::coroutine::close(server));
            }
            expect(completed.expired());
        };

        // The same generic request/receive/respond helpers also drive HTTP/3;
        // transport routing below only models the QUIC backend boundary.
        "h3_roundtrip"_test = [] {
            recording_stream_factory client_transport{true};
            recording_stream_factory server_transport{false};
            http::v3::client<recording_stream_factory, http::queues::locked> client{client_transport};
            http::v3::server<recording_stream_factory, http::queues::locked> server{server_transport};

            run_sync(http::coroutine::start(client));
            route_writes_to(client_transport, server_transport);
            run_sync(http::coroutine::start(server));
            route_writes_to(server_transport, client_transport);

            http::buffer_body request_body;
            auto client_request = request(client, basic_get("/index.html?lang=en&next=%2F"), request_body);
            client_request.start();
            route_writes_to(client_transport, server_transport);

            auto incoming = run_sync(receive(server));
            expect(incoming.head.target == "/index.html?lang=en&next=%2F"sv);
            static_cast<void>(run_sync(drain_body(incoming.body)));

            auto response_body = make_body("<html/>");
            run_sync(respond(server, incoming, http::response{.status = 200, .reason = {}, .fields = {}}, response_body));
            route_writes_to(server_transport, client_transport);

            auto response = run_sync(std::move(client_request));
            expect(response.head.status == 200_u);
            expect(read_body_text(response.body) == "<html/>"sv);
        };
    };

} // namespace httpant::testing::coroutine
