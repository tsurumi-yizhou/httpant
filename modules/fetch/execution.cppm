export module httpant:fetch.execution;

import std;
import httpant.dependencies.stdexec;
import :trait;
import :message;
import :fetch;
import :execution;

export namespace http::execution {

struct fetch_t {
    template <client_endpoint Client, body_stream Body>
    auto operator()(Client& client, http::request head, Body& body, fetch_options options = {}) const {
        return http::defer([&client, &body, head = std::move(head), options]() mutable {
            return http::detail::fetch_streaming(client, std::move(head), body, options);
        });
    }
    template <client_endpoint Client>
    auto operator()(Client& client, http::request head, fetch_options options = {}) const {
        return http::defer([&client, head = std::move(head), options]() mutable {
            return http::detail::fetch_owned(client, std::move(head), {}, options);
        });
    }
    template <client_endpoint Client>
    auto operator()(Client& client, http::request head, std::span<const std::byte> body, fetch_options options = {}) const {
        return http::defer([&client, head = std::move(head), options,
                            bytes = std::vector<std::byte>{body.begin(), body.end()}]() mutable {
            return http::detail::fetch_owned(client, std::move(head), std::move(bytes), options);
        });
    }
    template <client_endpoint Client>
    auto operator()(Client& client, http::request head, std::string_view body, fetch_options options = {}) const {
        return (*this)(client, std::move(head), std::as_bytes(std::span{body}), options);
    }
    template <client_endpoint Client>
    struct closure : stdexec::sender_adaptor_closure<closure<Client>> {
        Client* client;
        fetch_options options;
        closure(Client& endpoint, fetch_options configuration) noexcept : client(&endpoint), options(configuration) {}
        template <stdexec::sender Sender>
        auto operator()(Sender&& sender) const {
            return fetch_t{}(std::forward<Sender>(sender), *client, options);
        }
    };
    template <client_endpoint Client>
    auto operator()(Client& client, fetch_options options = {}) const { return closure<Client>{client, options}; }
    template <stdexec::sender Sender, client_endpoint Client>
    auto operator()(Sender&& sender, Client& client, fetch_options options = {}) const {
        return stdexec::let_value(std::forward<Sender>(sender), [&client, options](http::request& head, auto&... body) {
            return fetch_t{}(client, std::move(head), body..., options);
        });
    }
};
inline constexpr fetch_t fetch{};

struct upgrade_t {
    template <upgradeable_client Client>
    auto operator()(Client& client, http::request head, fetch_options options = {}) const {
        return http::defer([&client, head = std::move(head), options]() mutable {
            return http::detail::upgrade_connection(client, std::move(head), options);
        });
    }
    template <upgradeable_client Client>
    auto operator()(Client& client) const { return detail::bound_operation<upgrade_t, Client>{client}; }
    template <stdexec::sender Sender, upgradeable_client Client>
    auto operator()(Sender&& sender, Client& client) const {
        return stdexec::let_value(std::forward<Sender>(sender), [&client](http::request& head) {
            return upgrade_t{}(client, std::move(head));
        });
    }
};
inline constexpr upgrade_t upgrade{};

} // namespace http::execution
