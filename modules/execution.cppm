export module httpant:execution;

import std;
import httpant.dependencies.stdexec;
import :trait;
import :message;

export namespace http::execution {
namespace detail {

template <typename Operation, typename Resource>
struct bound_operation : stdexec::sender_adaptor_closure<bound_operation<Operation, Resource>> {
    Resource* resource;
    explicit bound_operation(Resource& value) noexcept : resource(&value) {}
    template <stdexec::sender Sender>
    auto operator()(Sender&& sender) const {
        return Operation{}(std::forward<Sender>(sender), *resource);
    }
};

template <typename Client, typename Body>
concept requestable = http::body_stream<Body> && requires(Client& client, http::request head, Body& body) {
    client.request(std::move(head), body);
};

template <typename Server, typename Token, typename Body>
concept respondable = http::body_stream<Body> && requires(Server& server, Token token, http::response head, Body& body) {
    server.respond(std::move(token), std::move(head), body);
};

} // namespace detail

// P2762's direct-factory and upstream-sender forms. A resource with a required
// input also has a bound, pipeable form. Protocol state stays in the endpoint;
// each sender owns only the arguments and lifetime of its one operation.
struct start_t {
    template <typename Endpoint>
        requires requires(Endpoint& endpoint) { endpoint.start(); }
    auto operator()(Endpoint& endpoint) const {
        return http::defer([&endpoint] { return endpoint.start(); });
    }
    template <stdexec::sender Sender, typename Endpoint>
    auto operator()(Sender&& sender, Endpoint& endpoint) const {
        return stdexec::let_value(std::forward<Sender>(sender), [&endpoint] { return start_t{}(endpoint); });
    }
};
inline constexpr start_t start{};

struct close_t {
    template <typename Endpoint>
        requires requires(Endpoint& endpoint) { endpoint.close(); }
    auto operator()(Endpoint& endpoint) const {
        return http::defer([&endpoint] { return endpoint.close(); });
    }
    template <stdexec::sender Sender, typename Endpoint>
    auto operator()(Sender&& sender, Endpoint& endpoint) const {
        return stdexec::let_value(std::forward<Sender>(sender), [&endpoint] { return close_t{}(endpoint); });
    }
};
inline constexpr close_t close{};

struct request_t {
    template <typename Client, http::body_stream Body>
        requires detail::requestable<Client, Body>
    auto operator()(Client& client, http::request head, Body& body) const {
        return http::defer([&client, &body, head = std::move(head)]() mutable {
            return client.request(std::move(head), body);
        });
    }
    template <typename Client>
        requires detail::requestable<Client, http::buffer_body>
    auto operator()(Client& client, http::request head) const {
        return http::defer([&client, head = std::move(head), body = http::buffer_body{}]() mutable {
            return client.request(std::move(head), body);
        });
    }
    template <typename Client>
        requires detail::requestable<Client, http::buffer_body>
    auto operator()(Client& client) const { return detail::bound_operation<request_t, Client>{client}; }
    template <stdexec::sender Sender, typename Client>
    auto operator()(Sender&& sender, Client& client) const {
        return stdexec::let_value(std::forward<Sender>(sender), [&client](http::request& head, auto&... body) {
            return request_t{}(client, std::move(head), body...);
        });
    }
};
inline constexpr request_t request{};

struct receive_t {
    template <typename Server>
        requires requires(Server& server) { server.receive(); }
    auto operator()(Server& server) const {
        return http::defer([&server] { return server.receive(); });
    }
    template <stdexec::sender Sender, typename Server>
    auto operator()(Sender&& sender, Server& server) const {
        return stdexec::let_value(std::forward<Sender>(sender), [&server] { return receive_t{}(server); });
    }
};
inline constexpr receive_t receive{};

struct respond_t {
    template <typename Server, typename Token, http::body_stream Body>
        requires detail::respondable<Server, Token, Body>
    auto operator()(Server& server, Token token, http::response head, Body& body) const {
        return http::defer([&server, &body, token = std::move(token), head = std::move(head)]() mutable {
            return server.respond(std::move(token), std::move(head), body);
        });
    }
    template <typename Server, typename Token>
        requires detail::respondable<Server, Token, http::buffer_body>
    auto operator()(Server& server, Token token, http::response head) const {
        return http::defer([&server, token = std::move(token), head = std::move(head), body = http::buffer_body{}]() mutable {
            return server.respond(std::move(token), std::move(head), body);
        });
    }
    template <typename Server>
    auto operator()(Server& server) const { return detail::bound_operation<respond_t, Server>{server}; }
    template <stdexec::sender Sender, typename Server>
    auto operator()(Sender&& sender, Server& server) const {
        return stdexec::let_value(std::forward<Sender>(sender), [&server](auto& token, http::response& head, auto&... body) {
            return respond_t{}(server, std::move(token), std::move(head), body...);
        });
    }
};
inline constexpr respond_t respond{};

struct read_t {
    template <http::body_stream Body>
    auto operator()(Body& body, std::span<std::byte> buffer) const {
        return http::defer([&body, buffer]() -> http::detail::operation<std::size_t> {
            co_return co_await body.async_read(buffer, co_await http::current_stop_token());
        });
    }
    template <http::body_stream Body>
    auto operator()(Body& body) const { return detail::bound_operation<read_t, Body>{body}; }
    template <stdexec::sender Sender, http::body_stream Body>
    auto operator()(Sender&& sender, Body& body) const {
        return stdexec::let_value(std::forward<Sender>(sender), [&body](auto& buffer) { return read_t{}(body, buffer); });
    }
};
inline constexpr read_t read{};

} // namespace http::execution
