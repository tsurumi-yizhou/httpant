export module httpant:fetch;

import std;
import :trait;
import :message;
import :error;
import :client.llhttp;
import :client.nghttp2;
import :client.nghttp3;
import :coroutine;

export namespace http {

// ─── Where a request goes ────────────────────────────────────

// The scheme's default port (RFC 9110 §4.2.1 and §4.2.2).
constexpr auto default_port(std::string_view scheme) -> std::optional<std::uint16_t> {
    auto equals = [](std::string_view a, std::string_view b) {
        return std::ranges::equal(a, b, [](char x, char y) {
            return (x >= 'A' && x <= 'Z' ? char(x + 32) : x) == y;
        });
    };
    if (equals(scheme, "https")) return 443;
    if (equals(scheme, "http")) return 80;
    return std::nullopt;
}

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

// ─── Version selection ───────────────────────────────────────

// The ALPN protocol identifier a TLS connection offers for a version (RFC 7301;
// RFC 9113 §3.1 "h2"; RFC 9114 §3.1 "h3"). HTTP/1.1 is the default when no
// ALPN is negotiated, so it offers none.
constexpr auto alpn(protocol_version version) -> std::string_view {
    switch (version) {
        case protocol_version::http1: return "";
        case protocol_version::http2: return "h2";
        case protocol_version::http3: return "h3";
    }
    std::unreachable();
}

// The client that speaks `Version` over `Connection`: a byte stream runs
// HTTP/1.1 or HTTP/2, a QUIC stream factory runs HTTP/3. Other pairings
// have no client.
template <typename Connection, protocol_version Version>
struct client_for;

template <byte_stream C>
struct client_for<C, protocol_version::http1> {
    using type = v1::client<C>;
};

template <byte_stream C>
struct client_for<C, protocol_version::http2> {
    using type = v2::client<C>;
};

template <stream_factory F>
struct client_for<F, protocol_version::http3> {
    using type = v3::client<F>;
};

template <typename Connection, protocol_version Version>
concept has_client = requires { typename client_for<Connection, Version>::type; };

template <typename Connection, protocol_version Version>
    requires has_client<Connection, Version>
using client_t = typename client_for<Connection, Version>::type;

// ─── One-shot exchange ───────────────────────────────────────

// A response with its body read to the end.
struct fetched {
    response head{};
    std::vector<std::byte> body{};

    [[nodiscard]] auto text() const noexcept -> std::string_view {
        return {reinterpret_cast<const char*>(body.data()), body.size()};
    }
};

namespace detail {

// What a request needs besides what the caller set: HTTP/1.1 requires exactly
// one Host field, derived here from the authority (HTTP/2 and HTTP/3 take
// :authority from the same place), and a body of known size needs its length.
template <protocol_version Version>
void complete_request(request& head, std::optional<std::size_t> body_size) {
    if constexpr (Version == protocol_version::http1) {
        if (!find_header(head.fields, "host"))
            if (auto authority = request_authority(head))
                head.fields.push_back({"host", std::string{*authority}});
    }
    if (body_size && *body_size != 0 && !find_header(head.fields, "content-length"))
        head.fields.push_back({"content-length", std::to_string(*body_size)});
}

template <protocol_version Version, typename Connection, body_stream Body>
auto fetch_streaming(Connection& connection, request head, Body& body, std::stop_token stop)
    -> task<fetched> {
    client_t<Connection, Version> client{connection};
    co_await operation_start(client);
    auto received = co_await operation_request(client, std::move(head), body);

    fetched result;
    result.head = std::move(received.head);
    std::array<std::byte, 4096> buffer;
    while (auto n = co_await received.body.async_read(buffer, stop))
        result.body.insert(result.body.end(), buffer.data(), buffer.data() + n);
    co_return result;
}

// The task is lazy, so a body given as a span or string is copied when fetch is
// called and owned by the task: the caller's buffer need not outlive the call.
template <protocol_version Version, typename Connection>
auto fetch_owned(Connection& connection, request head, std::vector<std::byte> body,
                 std::stop_token stop) -> task<fetched> {
    complete_request<Version>(head, body.size());
    http::buffer_body request_body{std::move(body)};
    co_return co_await fetch_streaming<Version>(connection, std::move(head), request_body, stop);
}

} // namespace detail

// The outcome of asking an HTTP/1.1 connection to switch protocols.
struct upgraded {
    response head{};
    // True when the server switched (101, or a tunnel): the connection now
    // runs the new protocol. False when it answered as a plain
    // response (for example 200 or 426), and `head` says what it answered.
    bool switched{false};
    // Bytes the server sent after the response head. When `switched`, they are
    // the first bytes of the new protocol and belong to the caller.
    std::vector<std::byte> pending{};
};

// ─── fetch: one request, one buffered response ───────────────
//
// The connection stays the caller's (a byte stream for HTTP/1.1 and HTTP/2, a
// stream factory for HTTP/3) and is not closed. The request is the same for
// every version: give it a scheme and an authority (or a Host field). fetch
// adds what the version needs (see detail::complete_request), runs the
// exchange on a client it creates and destroys, and reads the response body to
// its end. The body argument is a span or string of bytes (Content-Length is
// added), or any body_stream (the caller frames it, with Content-Length or
// Transfer-Encoding). `stop` cancels the response body reads.

namespace coroutine {

template <protocol_version Version, typename Connection, body_stream Body>
    requires has_client<Connection, Version>
auto fetch(Connection& connection, http::request head, Body& body, std::stop_token stop = {})
    -> task<fetched> {
    detail::complete_request<Version>(head, std::nullopt);
    return detail::fetch_streaming<Version>(connection, std::move(head), body, stop);
}

template <protocol_version Version, typename Connection>
    requires has_client<Connection, Version>
auto fetch(Connection& connection, http::request head, std::span<const std::byte> body = {},
           std::stop_token stop = {}) -> task<fetched> {
    return detail::fetch_owned<Version>(
        connection, std::move(head), std::vector<std::byte>{body.begin(), body.end()}, stop);
}

template <protocol_version Version, typename Connection>
    requires has_client<Connection, Version>
auto fetch(Connection& connection, http::request head, std::string_view body,
           std::stop_token stop = {}) -> task<fetched> {
    return fetch<Version>(connection, std::move(head), std::as_bytes(std::span{body}), stop);
}

// RFC 9110 §7.8: send an HTTP/1.1 request with an Upgrade field (the caller
// supplies Upgrade, Connection and any protocol-specific fields) and report
// whether the server switched protocols. On a switch, the connection belongs
// to the new protocol from here on and `pending` holds the bytes the server
// already sent after its 101. The HTTP client is gone when upgrade returns, so
// nothing of HTTP/1.1 framing remains on the connection.
template <byte_stream Connection>
auto upgrade(Connection& connection, http::request head) -> task<upgraded> {
    detail::complete_request<protocol_version::http1>(head, 0);

    v1::client<Connection> client{connection};
    co_await start(client);

    upgraded result;
    {
        auto received = co_await request(client, std::move(head));
        result.head = std::move(received.head);
    }
    result.switched = client.upgraded();
    if (result.switched)
        result.pending = client.take_pending();
    co_return result;
}

} // namespace coroutine

// The same operations on the P2300 surface: the returned task is a sender.
namespace execution {

template <protocol_version Version, typename Connection, typename... Rest>
    requires requires(Connection& c, http::request h, Rest&&... rest) {
        coroutine::fetch<Version>(c, std::move(h), std::forward<Rest>(rest)...);
    }
auto fetch(Connection& connection, http::request head, Rest&&... rest) -> task<fetched> {
    return coroutine::fetch<Version>(connection, std::move(head), std::forward<Rest>(rest)...);
}

template <byte_stream Connection>
auto upgrade(Connection& connection, http::request head) -> task<upgraded> {
    return coroutine::upgrade(connection, std::move(head));
}

} // namespace execution

// Per-version entry points: the connection kind and the namespace name the
// version, so no template argument is needed.
namespace v1 {
template <byte_stream S, typename... Rest>
auto fetch(S& stream, http::request head, Rest&&... rest) {
    return coroutine::fetch<protocol_version::http1>(stream, std::move(head), std::forward<Rest>(rest)...);
}
template <byte_stream S>
auto upgrade(S& stream, http::request head) {
    return coroutine::upgrade(stream, std::move(head));
}
} // namespace v1

namespace v2 {
template <byte_stream S, typename... Rest>
auto fetch(S& stream, http::request head, Rest&&... rest) {
    return coroutine::fetch<protocol_version::http2>(stream, std::move(head), std::forward<Rest>(rest)...);
}
} // namespace v2

namespace v3 {
template <stream_factory F, typename... Rest>
auto fetch(F& factory, http::request head, Rest&&... rest) {
    return coroutine::fetch<protocol_version::http3>(factory, std::move(head), std::forward<Rest>(rest)...);
}
} // namespace v3

} // namespace http
