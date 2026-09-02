#include <boost/ut.hpp>

#include <stdexec/execution.hpp>

#include <stop_token>
#include <stdexcept>
#include <string>
#include <tuple>
#include <type_traits>
#include <utility>
#include <variant>

#include "../test_support.hpp"

namespace httpant::testing::execution {

using namespace boost::ut;

namespace {

template <typename Client>
concept client_endpoint = requires(
    Client& client,
    http::request request,
    http::buffer_body& body) {
    { http::execution::start(client) } -> stdexec::sender;
    { http::execution::request(client, std::move(request), body) } -> stdexec::sender;
};

template <typename Server>
concept server_endpoint = requires(
    Server& server,
    typename Server::exchange_token token,
    http::response response,
    http::buffer_body& body) {
    { http::execution::start(server) } -> stdexec::sender;
    { http::execution::receive(server) } -> stdexec::sender;
    { http::execution::respond(
        server, std::move(token), std::move(response), body) } -> stdexec::sender;
};

template <typename Value>
struct sender_state {
    std::optional<Value> value{};
    std::exception_ptr error{};
    bool stopped{false};
};

template <>
struct sender_state<void> {
    bool completed{false};
    std::exception_ptr error{};
    bool stopped{false};
};

template <typename Value>
struct sender_receiver {
    using receiver_concept = stdexec::receiver_t;
    sender_state<Value>& state;

    void set_value(Value value) noexcept {
        state.value.emplace(std::move(value));
    }
    void set_error(std::exception_ptr error) noexcept {
        state.error = std::move(error);
    }
    void set_stopped() noexcept { state.stopped = true; }
    auto get_env() const noexcept {
        return stdexec::prop{stdexec::get_stop_token, std::stop_token{}};
    }
};

template <>
struct sender_receiver<void> {
    using receiver_concept = stdexec::receiver_t;
    sender_state<void>& state;

    void set_value() noexcept { state.completed = true; }
    void set_error(std::exception_ptr error) noexcept {
        state.error = std::move(error);
    }
    void set_stopped() noexcept { state.stopped = true; }
    auto get_env() const noexcept {
        return stdexec::prop{stdexec::get_stop_token, std::stop_token{}};
    }
};

template <typename Sender, typename Value>
class started_sender {
public:
    explicit started_sender(Sender sender) {
        operation_ = std::unique_ptr<operation_type>{new operation_type{
            stdexec::connect(std::move(sender), sender_receiver<Value>{state_})}};
        operation_->start();
    }

    started_sender(const started_sender&) = delete;
    auto operator=(const started_sender&) -> started_sender& = delete;

    [[nodiscard]] auto done() const noexcept -> bool {
        if constexpr (std::is_void_v<Value>)
            return state_.completed || state_.error || state_.stopped;
        else
            return state_.value.has_value() || state_.error || state_.stopped;
    }

    auto take() -> Value requires (!std::is_void_v<Value>) {
        if (state_.error)
            std::rethrow_exception(state_.error);
        if (!state_.value)
            throw std::runtime_error("execution test operation did not complete");
        return std::move(*state_.value);
    }

    void take() requires std::is_void_v<Value> {
        if (state_.error)
            std::rethrow_exception(state_.error);
        if (!state_.completed)
            throw std::runtime_error("execution test operation did not complete");
    }

private:
    using operation_type = decltype(stdexec::connect(
        std::declval<Sender>(), std::declval<sender_receiver<Value>>()));
    sender_state<Value> state_{};
    std::unique_ptr<operation_type> operation_{};
};

template <typename Sender>
struct sender_value;

template <typename Value>
struct sender_value<http::task<Value>> {
    using type = Value;
};

template <typename Sender>
using sender_value_t = typename sender_value<std::remove_cvref_t<Sender>>::type;

template <typename Sender>
auto launch(Sender sender) -> started_sender<Sender, sender_value_t<Sender>> {
    return started_sender<Sender, sender_value_t<Sender>>{std::move(sender)};
}

struct no_route {
    void operator()() const noexcept {}
};

template <typename Client, typename Server, typename RouteRequest, typename RouteResponse>
auto exchange(
    Client& client,
    Server& server,
    RouteRequest route_request,
    RouteResponse route_response) -> std::string
{
    auto server_start = launch(http::execution::start(server));
    auto client_start = launch(http::execution::start(client));
    route_request();
    route_response();
    server_start.take();
    client_start.take();

    auto receive = launch(http::execution::receive(server));
    auto request_body = http::buffer_body{};
    auto request = launch(
        http::execution::request(client, basic_get("/generic"), request_body));
    route_request();

    auto incoming = receive.take();
    static_cast<void>(run_sync(drain_body(incoming.body)));
    auto response_body = make_body("generic-body");
    auto response = launch(http::execution::respond(
        server,
        std::move(incoming.token),
        http::response{.status = 200, .reason = {}, .fields = {
            {"content-length", "12"}}},
        response_body));
    route_response();
    response.take();

    auto received = request.take();
    return read_body_text(received.body);
}

struct task_client {
    friend auto operation_start(task_client&) -> http::task<void> {
        co_return;
    }

    friend auto operation_request(
        task_client&,
        http::request head,
        http::buffer_body&) -> http::task<int> {
        if (head.target == "/error")
            throw std::runtime_error("request failed");
        co_return 42;
    }
};

struct counting_client {
    int& calls;

    friend auto operation_request(
        counting_client& client,
        http::request,
        http::buffer_body&) -> http::task<int> {
        ++client.calls;
        co_return 42;
    }
};

struct increment {
    auto operator()(int value) const noexcept -> int { return value + 1; }
};

struct add {
    auto operator()(int left, int right) const noexcept -> int {
        return left + right;
    }
};

struct task_server {
    struct token {};

    friend auto operation_receive(task_server&) -> http::task<int> {
        co_return 7;
    }

    friend auto operation_respond(
        task_server& server,
        token,
        http::response,
        http::buffer_body&) -> http::task<void> {
        server.responded = true;
        co_return;
    }

    bool responded{false};
};

} // namespace

static suite<"execution"> tests = [] {
    static_assert(client_endpoint<http::v1::client<async_mock_stream>>);
    static_assert(client_endpoint<http::v2::client<async_mock_stream>>);
    static_assert(client_endpoint<http::v3::client<recording_stream_factory>>);
    static_assert(server_endpoint<http::v1::server<async_mock_stream>>);
    static_assert(server_endpoint<http::v2::server<async_mock_stream>>);
    static_assert(server_endpoint<http::v3::server<recording_stream_factory>>);

    // Internal machinery test: the public execution surface returns senders and
    // does not expose the task-to-sender conversion boundary.
    "public_request_is_sender_and_sync_waits"_test = [] {
        task_client client;
        http::buffer_body body;
        auto operation = http::execution::request(
            client, http::request{.target = "/"}, body);

        static_assert(stdexec::sender<decltype(operation)>);
        auto result = stdexec::sync_wait(std::move(operation));
        expect(result.has_value());
        expect(std::get<0>(*result) == 42_i);
    };

    // Internal machinery test: the sender advertises accurate completion
    // signatures — one set_value(int), set_error(exception_ptr), set_stopped.
    "public_request_completion_signatures"_test = [] {
        task_client client;
        http::buffer_body body;
        using sender_t = decltype(http::execution::request(
            client, http::request{.target = "/"}, body));

        static_assert(stdexec::sender<sender_t>);
        static_assert(stdexec::sends_stopped<sender_t>);
        static_assert(std::same_as<
                      stdexec::value_types_of_t<sender_t>,
                      std::variant<std::tuple<int>>>);
        static_assert(std::same_as<
                      stdexec::error_types_of_t<sender_t>,
                      std::variant<std::exception_ptr>>);
    };

    // Internal machinery test: senders are move-only and single-consumer, and
    // their operation state is a distinct, non-copyable type.
    "public_request_is_single_consumer"_test = [] {
        task_client client;
        http::buffer_body body;
        using sender_t = decltype(http::execution::request(
            client, http::request{.target = "/"}, body));

        static_assert(!std::copy_constructible<sender_t>);
        static_assert(std::movable<sender_t>);
    };

    // Internal machinery test: building the sender does not start the shared
    // coroutine operation. The client request body only runs once the sender
    // is connected and started.
    "public_request_is_lazy"_test = [] {
        int calls = 0;
        counting_client client{calls};
        http::buffer_body body;
        {
            auto operation = http::execution::request(
                client, http::request{.target = "/"}, body);
            expect(calls == 0_i);
        }
        expect(calls == 0_i);
    };

    // Internal machinery test: standard sender adaptors compose directly with
    // the public execution API.
    "public_request_composes_with_then"_test = [] {
        task_client client;
        http::buffer_body body;
        auto operation = stdexec::then(
            http::execution::request(
                client, http::request{.target = "/"}, body),
            increment{});

        auto result = stdexec::sync_wait(std::move(operation));
        expect(result.has_value());
        expect(std::get<0>(*result) == 43_i);
    };

    // Internal machinery test: when_all concatenates the value channels of the
    // two composed senders, which only works if the public API returns real
    // senders rather than awaitables.
    "public_request_composes_with_when_all"_test = [] {
        task_client client;
        http::buffer_body body;
        auto operation = stdexec::when_all(
            http::execution::request(
                client, http::request{.target = "/"}, body),
            http::execution::request(
                client, http::request{.target = "/"}, body));
        auto summed = stdexec::then(std::move(operation), add{});

        auto result = stdexec::sync_wait(std::move(summed));
        expect(result.has_value());
        expect(std::get<0>(*result) == 84_i);
    };

    // Internal machinery test: exceptions from the shared coroutine operation
    // are delivered through the sender error channel and rethrown by sync_wait.
    "public_request_propagates_error"_test = [] {
        task_client client;
        http::buffer_body body;
        auto threw = false;
        try {
            static_cast<void>(stdexec::sync_wait(http::execution::request(
                client, http::request{.target = "/error"}, body)));
        } catch (const std::runtime_error& error) {
            threw = std::string{error.what()} == "request failed";
        }
        expect(threw);
    };

    // Internal machinery test: the receiver environment's stop token reaches
    // the shared operation. A token that is already requested completes with
    // set_stopped (sync_wait returns a disengaged optional) before the
    // coroutine body ever runs.
    "public_request_stop_token_yields_stopped"_test = [] {
        task_client client;
        http::buffer_body body;
        std::stop_source source;
        source.request_stop();

        auto operation = http::execution::request(
            client, http::request{.target = "/"}, body);
        auto with_stop = stdexec::write_env(
            std::move(operation),
            stdexec::prop{stdexec::get_stop_token, source.get_token()});

        auto result = stdexec::sync_wait(std::move(with_stop));
        expect(!result.has_value());
    };

    // Internal machinery test: endpoints without a handshake capability receive
    // the documented no-op start sender.
    "public_start_no_op_sync_waits"_test = [] {
        task_client client;
        auto operation = http::execution::start(client);
        static_assert(stdexec::sender<decltype(operation)>);
        auto result = stdexec::sync_wait(std::move(operation));
        expect(result.has_value());
    };

    // Internal machinery test: receive and token-correlated respond are exposed
    // through the same public sender surface.
    "public_server_operations_sync_wait"_test = [] {
        task_server server;
        http::buffer_body body;

        auto incoming = stdexec::sync_wait(http::execution::receive(server));
        expect(incoming.has_value());
        expect(std::get<0>(*incoming) == 7_i);

        auto responded = stdexec::sync_wait(http::execution::respond(
            server, task_server::token{}, http::response{.status = 204}, body));
        expect(responded.has_value());
        expect(server.responded);
    };

    // One generic sender driver performs an equivalent exchange for every
    // HTTP generation. Only the transport routing policy varies.
    "generic_exchange_covers_h1_h2_h3"_test = [] {
        {
            async_pipe c2s{};
            async_pipe s2c{};
            async_mock_stream client_transport{.input = s2c, .output = c2s};
            async_mock_stream server_transport{.input = c2s, .output = s2c};
            http::v1::client<async_mock_stream> client{client_transport};
            http::v1::server<async_mock_stream> server{server_transport};
            expect(exchange(
                client, server, no_route{}, no_route{}) == "generic-body"sv);
        }
        {
            async_pipe c2s{};
            async_pipe s2c{};
            async_mock_stream client_transport{.input = s2c, .output = c2s};
            async_mock_stream server_transport{.input = c2s, .output = s2c};
            http::v2::client<async_mock_stream> client{client_transport};
            http::v2::server<async_mock_stream> server{server_transport};
            expect(exchange(
                client, server, no_route{}, no_route{}) == "generic-body"sv);
        }
        {
            recording_stream_factory client_transport{true};
            recording_stream_factory server_transport{false};
            http::v3::client<recording_stream_factory> client{client_transport};
            http::v3::server<recording_stream_factory> server{server_transport};
            auto request_route = [&] {
                route_writes_to(client_transport, server_transport);
            };
            auto response_route = [&] {
                route_writes_to(server_transport, client_transport);
            };
            expect(exchange(
                client, server, request_route, response_route) == "generic-body"sv);
        }
    };
};

} // namespace httpant::testing::execution
