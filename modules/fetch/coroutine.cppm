export module httpant:fetch.coroutine;

import std;
import :trait;
import :message;
import :fetch;
import :coroutine;

export namespace http::coroutine {

    template <client_endpoint Client, body_stream Body>
    auto fetch(Client& client, http::request head, Body& body, fetch_options options = {}) -> task<fetched> {
        return http::detail::fetch_streaming(client, std::move(head), body, options);
    }

    template <client_endpoint Client> auto fetch(Client& client, http::request head, fetch_options options = {}) -> task<fetched> {
        return http::detail::fetch_owned(client, std::move(head), {}, options);
    }

    // The copy happens before returning the lazy task.
    template <client_endpoint Client>
    auto fetch(Client& client, http::request head, std::span<const std::byte> body, fetch_options options = {}) -> task<fetched> {
        return http::detail::fetch_owned(client, std::move(head), std::vector<std::byte>{body.begin(), body.end()}, options);
    }

    template <client_endpoint Client> auto fetch(Client& client, http::request head, std::string_view body, fetch_options options = {}) -> task<fetched> {
        return fetch(client, std::move(head), std::as_bytes(std::span{body}), options);
    }

    template <upgradeable_client Client> auto upgrade(Client& client, http::request head, fetch_options options = {}) -> task<upgraded> {
        return http::detail::upgrade_connection(client, std::move(head), options);
    }

} // namespace http::coroutine
