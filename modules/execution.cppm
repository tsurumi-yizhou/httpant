export module httpant:execution;

import std;
import :trait;
import :message;
import :coroutine;

// The execution stack: every operation is a lazy P2300 sender. Calling one
// only captures its arguments; connect and start run it, with the stop token
// of the receiver's environment. References an operation takes (the endpoint,
// a body) must outlive the operation, as with any sender.
export namespace http::execution {

template <typename Endpoint>
    requires requires(Endpoint& endpoint) { coroutine::start(endpoint); }
auto start(Endpoint& endpoint) {
    return http::defer([&endpoint] { return coroutine::start(endpoint); });
}

template <typename Endpoint>
    requires requires(Endpoint& endpoint) { coroutine::close(endpoint); }
auto close(Endpoint& endpoint) {
    return http::defer([&endpoint] { return coroutine::close(endpoint); });
}

template <typename Client, http::body_stream Body>
    requires requires(Client& client, http::request head, Body& body) {
        coroutine::request(client, std::move(head), body);
    }
auto request(Client& client, http::request head, Body& body) {
    return http::defer([&client, &body, head = std::move(head)]() mutable {
        return coroutine::request(client, std::move(head), body);
    });
}

template <typename Client>
    requires requires(Client& client, http::request head) {
        coroutine::request(client, std::move(head));
    }
auto request(Client& client, http::request head) {
    return http::defer([&client, head = std::move(head)]() mutable {
        return coroutine::request(client, std::move(head));
    });
}

template <typename Server>
    requires requires(Server& server) { coroutine::receive(server); }
auto receive(Server& server) {
    return http::defer([&server] { return coroutine::receive(server); });
}

template <typename Server, typename Token, http::body_stream Body>
    requires requires(Server& server, Token token, http::response head, Body& body) {
        coroutine::respond(server, std::move(token), std::move(head), body);
    }
auto respond(Server& server, Token token, http::response head, Body& body) {
    return http::defer(
        [&server, &body, token = std::move(token), head = std::move(head)]() mutable {
            return coroutine::respond(server, std::move(token), std::move(head), body);
        });
}

template <typename Server, typename Token>
    requires requires(Server& server, Token token, http::response head) {
        coroutine::respond(server, std::move(token), std::move(head));
    }
auto respond(Server& server, Token token, http::response head) {
    return http::defer([&server, token = std::move(token), head = std::move(head)]() mutable {
        return coroutine::respond(server, std::move(token), std::move(head));
    });
}

} // namespace http::execution
