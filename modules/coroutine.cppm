export module httpant:coroutine;

import std;
import :trait;
import :message;

// The coroutine stack: every operation is an http::task, run by resumption.
// Awaiting it from another task hands down that task's stop token, so a stop
// request reaches every transport and body operation beneath it.
export namespace http::coroutine {

    namespace detail {
        // A borrowed message requires storage through completion of the member task.
        template <typename T, typename Function> auto invoke_owned(Function function) -> task<T> { co_return co_await function(); }
    } // namespace detail

    template <typename Endpoint>
        requires requires(Endpoint& endpoint) {
            { endpoint.start() } -> http::detail::awaitable;
        }
    auto start(Endpoint& endpoint) -> task<void> {
        if constexpr (std::convertible_to<decltype(endpoint.start()), task<void>>)
            return endpoint.start();
        else
            return detail::invoke_owned<void>([&endpoint] { return endpoint.start(); });
    }

    // Stops what the endpoint runs beside the application (the HTTP/2 and HTTP/3
    // drivers) and waits for it to finish. An endpoint that was started must be
    // closed before it is destroyed.
    template <typename Endpoint>
        requires requires(Endpoint& endpoint) {
            { endpoint.close() } -> http::detail::awaitable;
        }
    auto close(Endpoint& endpoint) -> task<void> {
        if constexpr (std::convertible_to<decltype(endpoint.close()), task<void>>)
            return endpoint.close();
        else
            return detail::invoke_owned<void>([&endpoint] { return endpoint.close(); });
    }

    // Runs body(endpoint) between start and close, so whatever the endpoint runs
    // beside the application lives exactly as long as this coroutine: close runs
    // whether start or the body returned, threw or was stopped, and their failure
    // wins over close's.
    template <typename Endpoint, typename Body>
        requires requires(Endpoint& endpoint, Body& body) {
            coroutine::start(endpoint);
            coroutine::close(endpoint);
            typename std::invoke_result_t<Body&, Endpoint&>::value_type;
            { body(endpoint) } -> http::detail::awaitable;
        }
    auto scoped(Endpoint& endpoint, Body body) -> task<typename std::invoke_result_t<Body&, Endpoint&>::value_type> {
        using value = typename std::invoke_result_t<Body&, Endpoint&>::value_type;
        auto run_session = [&endpoint, body = std::move(body)]() mutable -> task<value> {
            co_await coroutine::start(endpoint);
            if constexpr (std::is_void_v<value>)
                co_await body(endpoint);
            else
                co_return co_await body(endpoint);
        };
        return http::detail::finally(std::move(run_session), [&endpoint] { return coroutine::close(endpoint); });
    }

    // Runs body(scope) with a task_scope for the children it spawns. When the
    // body finishes — returned, threw or was stopped — the children still running
    // are stopped and joined before this coroutine completes, so none outlives
    // it. The body's failure wins over a child's; otherwise the first child
    // failure is rethrown.
    template <typename Body>
        requires requires(Body& body, http::task_scope& scope) {
            typename std::invoke_result_t<Body&, http::task_scope&>::value_type;
            { body(scope) } -> http::detail::awaitable;
        }
    auto with_scope(Body body) -> task<typename std::invoke_result_t<Body&, http::task_scope&>::value_type> {
        http::task_scope scope;
        auto stop_children = [&]() -> task<void> {
            scope.request_stop();
            co_await scope.join();
        };
        co_return co_await http::detail::finally([&] { return body(scope); }, std::move(stop_children));
    }

    template <typename Client, http::body_stream Body>
        requires requires(Client& client, http::request head, Body& body) {
            { client.request(std::move(head), body) } -> http::detail::awaitable;
        }
    auto request(Client& client, http::request head, Body& body) -> task<typename decltype(client.request(std::move(head), body))::value_type> {
        using operation = decltype(client.request(std::move(head), body));
        using value = typename operation::value_type;
        if constexpr (std::convertible_to<operation, task<value>> && requires { static_cast<operation (Client::*)(http::request, Body&)>(&Client::request); }) {
            constexpr auto member = static_cast<operation (Client::*)(http::request, Body&)>(&Client::request);
            return (client.*member)(std::move(head), body);
        } else {
            return detail::invoke_owned<value>([&client, &body, head = std::move(head)]() mutable { return client.request(std::move(head), body); });
        }
    }

    // A request without content: the empty body lives in this coroutine's frame.
    template <typename Client>
        requires requires(Client& client, http::request head, http::buffer_body& body) {
            { client.request(std::move(head), body) } -> http::detail::awaitable;
        }
    auto request(Client& client, http::request head)
        -> task<typename decltype(client.request(std::move(head), std::declval<http::buffer_body&>()))::value_type> {
        http::buffer_body empty;
        co_return co_await client.request(std::move(head), empty);
    }

    template <typename Server>
        requires requires(Server& server) {
            { server.receive() } -> http::detail::awaitable;
        }
    auto receive(Server& server) -> task<typename decltype(server.receive())::value_type> {
        using operation = decltype(server.receive());
        using value = typename operation::value_type;
        if constexpr (std::convertible_to<operation, task<value>>)
            return server.receive();
        else
            return detail::invoke_owned<value>([&server] { return server.receive(); });
    }

    template <typename Server, typename Token, http::body_stream Body>
        requires requires(Server& server, Token token, http::response head, Body& body) {
            { server.respond(std::move(token), std::move(head), body) } -> http::detail::awaitable;
        }
    auto respond(Server& server, Token token, http::response head, Body& body) -> task<void> {
        using operation = decltype(server.respond(std::move(token), std::move(head), body));
        if constexpr (std::convertible_to<operation, task<void>> &&
                      requires { static_cast<operation (Server::*)(Token, http::response, Body&)>(&Server::respond); }) {
            constexpr auto member = static_cast<operation (Server::*)(Token, http::response, Body&)>(&Server::respond);
            return (server.*member)(std::move(token), std::move(head), body);
        } else {
            return detail::invoke_owned<void>([&server, &body, token = std::move(token), head = std::move(head)]() mutable {
                return server.respond(std::move(token), std::move(head), body);
            });
        }
    }

    template <typename Server, typename Token>
        requires requires(Server& server, Token token, http::response head, http::buffer_body& body) {
            { server.respond(std::move(token), std::move(head), body) } -> http::detail::awaitable;
        }
    auto respond(Server& server, Token token, http::response head) -> task<void> {
        http::buffer_body empty;
        co_await server.respond(std::move(token), std::move(head), empty);
    }

    template <http::body_stream Body> auto read(Body& body, std::span<std::byte> buffer) -> task<std::size_t> {
        co_return co_await body.async_read(buffer, co_await current_stop_token());
    }

} // namespace http::coroutine
