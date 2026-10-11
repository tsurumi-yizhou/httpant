export module httpant:coroutine;

import std;
import :trait;
import :message;

export namespace http::detail {

// Awaits work(), then cleanup() however the work ended (returned, threw or was
// stopped). The work's failure wins over the cleanup's; otherwise the
// cleanup's failure, then the work's value, is the outcome. Both callables
// live in this frame, so a coroutine lambda's captures outlive its await.
template <typename Work, typename Cleanup>
auto finally(Work work, Cleanup cleanup) -> task<typename std::invoke_result_t<Work&>::value_type> {
    using value = typename std::invoke_result_t<Work&>::value_type;
    std::conditional_t<std::is_void_v<value>, bool, std::optional<value>> result{};
    std::exception_ptr failure;
    try {
        if constexpr (std::is_void_v<value>)
            co_await work();
        else
            result.emplace(co_await work());
    } catch (...) {
        failure = std::current_exception();
    }
    try {
        co_await cleanup();
    } catch (...) {
        if (!failure)
            failure = std::current_exception();
    }
    if (failure)
        std::rethrow_exception(failure);
    if constexpr (!std::is_void_v<value>)
        co_return std::move(*result);
}

} // namespace http::detail

// The coroutine stack: every operation is an http::task, run by resumption.
// Awaiting it from another task hands down that task's stop token, so a stop
// request reaches every transport and body operation beneath it.
export namespace http::coroutine {

template <typename Endpoint>
    requires requires(Endpoint& endpoint) {
        { operation_start(endpoint) } -> std::same_as<task<void>>;
    }
auto start(Endpoint& endpoint) -> task<void> {
    return operation_start(endpoint);
}

// Stops what the endpoint runs beside the application (the HTTP/2 and HTTP/3
// drivers) and waits for it to finish. An endpoint that was started must be
// closed before it is destroyed.
template <typename Endpoint>
    requires requires(Endpoint& endpoint) {
        { operation_close(endpoint) } -> std::same_as<task<void>>;
    }
auto close(Endpoint& endpoint) -> task<void> {
    return operation_close(endpoint);
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
auto scoped(Endpoint& endpoint, Body body)
    -> task<typename std::invoke_result_t<Body&, Endpoint&>::value_type> {
    using value = typename std::invoke_result_t<Body&, Endpoint&>::value_type;
    return http::detail::finally(
        [&endpoint, body = std::move(body)]() mutable -> task<value> {
            co_await coroutine::start(endpoint);
            if constexpr (std::is_void_v<value>)
                co_await body(endpoint);
            else
                co_return co_await body(endpoint);
        },
        [&endpoint] { return coroutine::close(endpoint); });
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
auto with_scope(Body body)
    -> task<typename std::invoke_result_t<Body&, http::task_scope&>::value_type> {
    http::task_scope scope;
    co_return co_await http::detail::finally(
        [&] { return body(scope); },
        [&]() -> task<void> {
            scope.request_stop();
            co_await scope.join();
        });
}

template <typename Client, http::body_stream Body>
    requires requires(Client& client, http::request head, Body& body) {
        { operation_request(client, std::move(head), body) } -> http::detail::awaitable;
    }
auto request(Client& client, http::request head, Body& body)
    -> decltype(operation_request(client, std::move(head), body)) {
    return operation_request(client, std::move(head), body);
}

// A request without content: the empty body lives in this coroutine's frame.
template <typename Client>
    requires requires(Client& client, http::request head, http::buffer_body& body) {
        { operation_request(client, std::move(head), body) } -> http::detail::awaitable;
    }
auto request(Client& client, http::request head)
    -> decltype(operation_request(
        client, std::move(head), std::declval<http::buffer_body&>())) {
    http::buffer_body empty;
    co_return co_await operation_request(client, std::move(head), empty);
}

template <typename Server>
    requires requires(Server& server) {
        { operation_receive(server) } -> http::detail::awaitable;
    }
auto receive(Server& server) -> decltype(operation_receive(server)) {
    return operation_receive(server);
}

template <typename Server, typename Token, http::body_stream Body>
    requires requires(Server& server, Token token, http::response head, Body& body) {
        { operation_respond(server, std::move(token), std::move(head), body) }
            -> http::detail::awaitable;
    }
auto respond(Server& server, Token token, http::response head, Body& body)
    -> decltype(operation_respond(server, std::move(token), std::move(head), body)) {
    return operation_respond(server, std::move(token), std::move(head), body);
}

template <typename Server, typename Token>
    requires requires(
        Server& server, Token token, http::response head, http::buffer_body& body) {
        { operation_respond(server, std::move(token), std::move(head), body) }
            -> http::detail::awaitable;
    }
auto respond(Server& server, Token token, http::response head) -> task<void> {
    http::buffer_body empty;
    co_await operation_respond(server, std::move(token), std::move(head), empty);
}

} // namespace http::coroutine
