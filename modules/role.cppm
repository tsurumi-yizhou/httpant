module;

#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

export module httpant:role;

import :message;

// Version-free server-role machinery shared by the HTTP/1.1 (llhttp), HTTP/2
// (nghttp2), and HTTP/3 (nghttp3) engines: the exchange-token ownership guard,
// the incoming-request aggregate, and the response body-suppression predicate.
// Each engine server aliases the token and the aggregate as its public nested
// `exchange_token` / `incoming_request` names and keeps engine-specific
// payloads in the token handle; the predicate is the single implementation of
// a suppression rule all three respond paths share.
export namespace http {

// Whether a response to |method| with |status| may carry content on the wire.
// The three version-free suppression rules:
// RFC 9110 §9.3.2 — "The HEAD method is identical to GET except that the
// server MUST NOT send content in the response."
// RFC 9110 §9.3.6 — a successful CONNECT response must not carry content (the
// connection becomes a tunnel, RFC 9112 §9.6).
// RFC 9110 §15.2 / §15.3.5 / §15.3.6 / §15.4.5 — 1xx, 204, 205, and 304
// responses are terminated by the end of the header section and cannot
// contain content (status_allows_body).
[[nodiscard]] constexpr auto response_carries_body(method m, status s) -> bool {
    return m != method::HEAD && !(m == method::CONNECT && is_successful(s)) &&
           status_allows_body(s);
}

namespace detail {

// ─── Server exchange-token shell ─────────────────────────────

// The move-only ownership guard every server's public exchange_token is built
// on: it binds an engine-specific handle payload (v1's per-exchange lifecycle
// record, the v2/v3 stream_data) to the server instance that minted it, so a
// token from one connection can never respond on another. The engines alias
// this core as their nested public `exchange_token`; respond() funnels the
// null-handle and wrong-owner checks through the core's members and consumes
// the handle (take_handle) so a second respond with the same token fails.
template <typename Owner, typename Handle>
class exchange_token {
public:
    exchange_token(exchange_token&&) noexcept = default;
    auto operator=(exchange_token&&) noexcept -> exchange_token& = default;
    exchange_token(const exchange_token&) = delete;
    auto operator=(const exchange_token&) -> exchange_token& = delete;

    // Minted by the owning server, which passes itself. The handle moves out
    // of the token in respond(), so a consumed token is invalid.
    exchange_token(Owner& owner, Handle handle)
        : owner_(&owner), handle_(std::move(handle)) {}

    // A consumed token — its handle already moved out by respond() — must not
    // be reused.
    [[nodiscard]] auto valid() const noexcept -> bool { return handle_ != nullptr; }

    // The engine payload, readable without consuming the token (the v2 push
    // path reads the associated stream id).
    [[nodiscard]] auto handle() const noexcept -> const Handle& { return handle_; }

    // Move the payload out, consuming the token; check_owner must have passed
    // first.
    auto take_handle() -> Handle { return std::exchange(handle_, {}); }

    // The uniform wrong-owner rejection: a token minted by another server must
    // not respond on this connection. Each engine passes its protocol error
    // prefix ("http/1.1: " / "http/2: " / "http/3: ") so the local-misuse
    // error matches the engine's own wording.
    void check_owner(const Owner& expected, std::string_view prefix) const {
        if (owner_ != &expected)
            throw std::runtime_error(
                std::string(prefix) + "exchange token does not belong to server");
    }

private:
    Owner* owner_{};
    Handle handle_{};
};

// ─── Server incoming-request aggregate ───────────────────────

// A completed request delivered by receive(): the request head, its lazy body
// reader, and the exchange token that atomically correlates the response with
// this request. Engines alias this as their public nested `incoming_request`.
template <typename Body, typename Token>
struct incoming_request {
    http::request head;
    Body body;
    Token token;
};

} // namespace detail

} // namespace http
