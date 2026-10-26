export module httpant:fetch;

import std;
import :trait;
import :message;
import :error;

export namespace http {

// ─── Where a request goes ────────────────────────────────────

// The host and port to connect to for a request.
struct origin {
    std::string host{};      // without the brackets of an IPv6 literal
    std::uint16_t port{0};
};

// Derive the origin from the request alone: the authority (an :authority, an
// absolute-form target, or a Host field, in that order of precedence) gives
// host and optional port, and the request's scheme gives the default port.
// RFC 3986 §3.2: a userinfo component is ignored, an IPv6 literal is
// bracketed. Returns nullopt when the request names no host, the port is not a
// number, or there is neither a port nor a scheme to take one from.
[[nodiscard]] inline auto request_origin(const request& req) -> std::optional<origin> {
    auto authority = request_authority(req);
    if (!authority) return std::nullopt;
    std::string_view rest = *authority;
    if (auto at = rest.rfind('@'); at != std::string_view::npos)
        rest.remove_prefix(at + 1);

    std::string_view host = rest;
    std::string_view port_text;
    if (!rest.empty() && rest.front() == '[') {
        auto close = rest.find(']');
        if (close == std::string_view::npos) return std::nullopt;
        host = rest.substr(1, close - 1);
        auto tail = rest.substr(close + 1);
        if (!tail.empty()) {
            if (tail.front() != ':') return std::nullopt;
            port_text = tail.substr(1);
        }
    } else if (auto colon = rest.rfind(':'); colon != std::string_view::npos) {
        host = rest.substr(0, colon);
        port_text = rest.substr(colon + 1);
    }
    if (host.empty()) return std::nullopt;

    origin result{.host = std::string{host}};
    if (!port_text.empty()) {
        unsigned value = 0;
        auto [end, ec] = std::from_chars(port_text.data(), port_text.data() + port_text.size(), value);
        if (ec != std::errc{} || end != port_text.data() + port_text.size() || value > 65535)
            return std::nullopt;
        result.port = static_cast<std::uint16_t>(value);
        return result;
    }
    auto scheme = request_scheme(req);
    if (!scheme) return std::nullopt;
    auto port = default_port(*scheme);
    if (!port) return std::nullopt;
    result.port = *port;
    return result;
}

// A response with its body read to the end.
struct fetched {
    response head{};
    std::vector<std::byte> body{};

    [[nodiscard]] auto text() const noexcept -> std::string_view {
        return {reinterpret_cast<const char*>(body.data()), body.size()};
    }
};

// What a request needs besides what the caller set: HTTP/1.1 requires exactly
// one Host field, derived here from the authority (HTTP/2 and HTTP/3 take
// :authority from the same place), and a body of known size needs its length.
// Whether the host belongs in a field is the client's own constant.
template <typename Client>
void complete_request(request& head, std::optional<std::size_t> body_size) {
    if constexpr (Client::uses_host_field) {
        if (!find_header(head.fields, "host"))
            if (auto authority = request_authority(head))
                head.fields.push_back({"host", std::string{*authority}});
    }
    if (body_size && *body_size != 0 && !find_header(head.fields, "content-length"))
        head.fields.push_back({"content-length", std::to_string(*body_size)});
}

inline constexpr std::size_t default_fetch_limit = 64 * 1024 * 1024;
struct fetch_options {
    std::size_t body_limit = default_fetch_limit;
};

// A protocol switch leaves any bytes after the head with the application.
struct upgraded {
    response head{};
    bool switched{false};
    std::vector<std::byte> pending{};
    std::vector<std::byte> body{};
};

template <typename Client>
concept client_endpoint = requires(Client& client, http::request head, buffer_body& body) {
    { Client::uses_host_field } -> std::convertible_to<bool>;
    client.request(std::move(head), body);
};

template <typename Client>
concept upgradeable_client = client_endpoint<Client> && requires(Client& client) {
    { client.upgraded() } -> std::convertible_to<bool>;
    client.take_pending();
};

namespace detail {

// Shared response buffering for a plain exchange or a refused upgrade.
template <body_stream Body>
auto read_response_body(Body& body, fetch_options options) -> operation<std::vector<std::byte>> {
    std::vector<std::byte> result;
    auto& stop = co_await current_stop_token();
    std::array<std::byte, 4096> buffer;
    while (auto n = co_await body.async_read(buffer, stop)) {
        if (n > options.body_limit - result.size())
            throw protocol_error{
                error_info{
                    .scope = error_scope::message,
                    .condition = error_condition::resource_limit,
                    .exchange_identity = std::nullopt,
                    .library_code = std::nullopt,
                },
                no_action{},
                std::format("fetch: response body exceeds {} bytes", options.body_limit)};
        result.insert(result.end(), buffer.data(), buffer.data() + n);
    }
    co_return result;
}

// Endpoint lifetime belongs to the caller; one connection can serve many fetches.
template <client_endpoint Client, body_stream Body>
auto fetch_streaming(Client& client, request head, Body& body, fetch_options options,
                     std::optional<std::size_t> body_size = std::nullopt) -> operation<fetched> {
    complete_request<Client>(head, body_size);
    auto received = co_await client.request(std::move(head), body);
    co_return fetched{.head = std::move(received.head), .body = co_await read_response_body(received.body, options)};
}

template <client_endpoint Client>
auto fetch_owned(Client& client, request head, std::vector<std::byte> body, fetch_options options) -> operation<fetched> {
    auto size = body.size();
    http::buffer_body request_body{std::move(body)};
    co_return co_await fetch_streaming(client, std::move(head), request_body, options, size);
}

template <upgradeable_client Client>
auto upgrade_connection(Client& client, http::request head, fetch_options options) -> operation<upgraded> {
    complete_request<Client>(head, 0);
    http::buffer_body empty;
    auto received = co_await client.request(std::move(head), empty);
    upgraded result{.head = std::move(received.head), .switched = client.upgraded()};
    if (result.switched)
        result.pending = client.take_pending();
    else
        result.body = co_await read_response_body(received.body, options);
    co_return result;
}

} // namespace detail
} // namespace http
