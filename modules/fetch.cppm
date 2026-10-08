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
// :authority from the same place), and a non-empty body needs its length.
template <protocol_version Version>
void complete_request(request& head, std::size_t body_size) {
    if constexpr (Version == protocol_version::http1) {
        if (!find_header(head.fields, "host"))
            if (auto authority = request_authority(head))
                head.fields.push_back({"host", std::string{*authority}});
    }
    if (body_size != 0 && !find_header(head.fields, "content-length"))
        head.fields.push_back({"content-length", std::to_string(body_size)});
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

namespace coroutine {

// One request/response exchange on an established connection, over whichever
// version the connection type and `Version` select. The request is the same
// for every version: give it a scheme and an authority (or a Host field).
// fetch adds what the version needs (see detail::complete_request). The
// response body is read to its end. Nothing is reused afterwards: the client,
// and with it the connection's protocol state, is destroyed when fetch
// returns.
template <protocol_version Version, typename Connection>
    requires has_client<Connection, Version>
auto fetch(Connection& connection, http::request head, std::span<const std::byte> body = {})
    -> task<fetched> {
    detail::complete_request<Version>(head, body.size());

    client_t<Connection, Version> client{connection};
    co_await start(client);

    http::buffer_body request_body{std::vector<std::byte>{body.begin(), body.end()}};
    auto received = co_await request(client, std::move(head), request_body);

    fetched result;
    result.head = std::move(received.head);
    std::array<std::byte, 4096> buffer;
    while (auto n = co_await received.body.async_read(buffer, std::stop_token{}))
        result.body.insert(result.body.end(), buffer.data(), buffer.data() + n);
    co_return result;
}

// RFC 9110 §7.8: send an HTTP/1.1 request with an Upgrade field (the
// caller supplies Upgrade, Connection and any protocol-specific fields) and
// report whether the server switched protocols. On a switch, the connection
// belongs to the new protocol from here on and `pending` holds the bytes the
// server already sent after its 101. The HTTP client is gone when upgrade
// returns, so nothing of HTTP/1.1 framing remains on the connection.
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

} // namespace http
