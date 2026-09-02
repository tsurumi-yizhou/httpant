module;

#include <utility>

export module httpant:execution;

import :trait;
import :message;

export namespace http::execution {

template <typename Endpoint>
    requires requires(Endpoint& endpoint) {
        { operation_start(endpoint) } -> http::detail::awaitable;
    }
auto start(Endpoint& endpoint) -> decltype(operation_start(endpoint)) {
    return operation_start(endpoint);
}

template <typename Client, http::body_stream Body>
    requires requires(Client& client, http::request head, Body& body) {
        { operation_request(client, std::move(head), body) }
            -> http::detail::awaitable;
    }
auto request(Client& client, http::request head, Body& body)
    -> decltype(operation_request(client, std::move(head), body)) {
    return operation_request(client, std::move(head), body);
}

template <typename Client>
    requires requires(Client& client, http::request head, http::buffer_body& body) {
        { operation_request(client, std::move(head), body) }
            -> http::detail::awaitable;
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
    -> decltype(operation_respond(
        server, std::move(token), std::move(head), body)) {
    return operation_respond(
        server, std::move(token), std::move(head), body);
}


template <typename Server, typename Token>
    requires requires(
        Server& server,
        Token token,
        http::response head,
        http::buffer_body& body) {
        { operation_respond(server, std::move(token), std::move(head), body) }
            -> http::detail::awaitable;
    }
auto respond(Server& server, Token token, http::response head)
    -> decltype(operation_respond(
        server,
        std::move(token),
        std::move(head),
        std::declval<http::buffer_body&>())) {
    http::buffer_body empty;
    co_await operation_respond(
        server, std::move(token), std::move(head), empty);
}

} // namespace http::execution
