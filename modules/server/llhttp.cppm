module;

#include <llhttp.h>

#include <cstddef>
#include <coroutine>
#include <memory>
#include <optional>
#include <span>
#include <stdexcept>
#include <stop_token>
#include <string_view>
#include <utility>
#include <vector>

export module httpant:server.llhttp;

import :trait;
import :message;
import :role;
import :error;
import :validate.llhttp;
import :parse.llhttp;
import :serialize.llhttp;

export namespace http::v1 {

// ─── HTTP/1.1 server (RFC 9112) ──────────────────────────────

template <byte_stream S>
class server {
public:
    explicit server(S& transport) : transport_(transport) {}

    using request_body = body_reader<HTTP_REQUEST, S>;

private:
    // The token's engine payload (v1 keeps the request lifecycle here): the
    // shared per-exchange record the token and the server's active-exchange
    // latch both reference, so respond() can enforce single-response and
    // ordering invariants.
    struct exchange_state {
        method request_method;
        std::shared_ptr<typename request_body::lifecycle> body;
        bool responded{false};
    };

public:
    using exchange_token =
        http::detail::exchange_token<server, std::shared_ptr<exchange_state>>;
    using incoming_request = http::detail::incoming_request<request_body, exchange_token>;

private:
    // Read the request head and return it plus a lazy body reader.
    auto operation_receive(std::stop_token stop = {}) -> task<incoming_request> {
        // RFC 9112 §9.6 — no further requests once the connection closed.
        if (closed_ || close_requested_ || parser_.connection_closed())
            throw std::runtime_error("http/1.1: connection closed after previous exchange");
        if (active_exchange_ &&
            (!active_exchange_->body->consumed || !active_exchange_->responded))
            throw std::runtime_error("http/1.1: previous exchange not complete");

        parser_.begin_message();
        // A malformed request head must be answered with 400 and the connection
        // closed (RFC 9112 §3.2 / §6.3). co_await is not allowed inside a catch
        // handler, so the candidate failure is captured and the response write
        // happens after the try block.
        std::optional<protocol_error> malformed{};
        try {
            co_await parser_.read_headers(transport_, stop);

            // RFC 9110 §10.1.1 — a 100-continue expectation requires an interim
            // 100 (Continue) before the content is read.
            if (parser_.paused_for_continue()) {
                static constexpr std::string_view continue_response = "HTTP/1.1 100 Continue\r\n\r\n";
                auto bytes = std::as_bytes(std::span<const char>{continue_response.data(), continue_response.size()});
                co_await http::detail::write_all(
                    transport_, std::span<const std::byte>{bytes.data(), bytes.size()}, stop);
                parser_.resume_after_continue();
            }

            auto& st = parser_.state();
            if (st.headers_done)
                detail::validate_request(st);
        } catch (const protocol_error& failure) {
            // RFC 9112 §3.2 — "A server MUST respond with a 400 (Bad Request)
            // status code to any HTTP/1.1 request message that lacks a Host
            // header field and to any request message that contains more than
            // one Host header field line." §6.3 — "The server MUST respond with
            // the 400 (Bad Request) status code and then close the connection"
            // for a message with an invalid framing combination. A malformed
            // request head therefore produces a 400 response and closes the
            // connection; the typed error is rethrown so the application still
            // sees the protocol violation.
            if (failure.info().version == protocol_version::http1 &&
                failure.info().condition == error_condition::malformed_message) {
                malformed.emplace(
                    failure.info(),
                    send_response{static_cast<http::status>(400), true},
                    failure.what());
            } else {
                throw;
            }
        } catch (...) {
            // A transport failure while reading the request head — or while
            // writing the interim 100 (Continue) — leaves the byte stream at
            // an unknown position: the peer may consider part of the exchange
            // delivered that never reached the parser. The next request head
            // would be parsed from a misaligned boundary, so the connection is
            // latched closed (RFC 9112 §9.6).
            closed_ = true;
            throw;
        }

        if (malformed) {
            // RFC 9112 §6.3 — "...and then close the connection" — the 400
            // answer is terminal whether or not its write succeeds, so the
            // latch is taken before the write: a transport failure while
            // emitting the 400 must not leave the connection reusable at a
            // misaligned boundary.
            closed_ = true;
            static constexpr std::string_view bad_request =
                "HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
            auto bytes = std::as_bytes(std::span<const char>{bad_request.data(), bad_request.size()});
            co_await http::detail::write_all(
                transport_, std::span<const std::byte>{bytes.data(), bytes.size()}, stop);
            throw std::move(*malformed);
        }

        auto& st = parser_.state();

        // RFC 9112 §9.6 — a request carrying "close" requests connection closure
        // after the response. Requests are always self-framed, so keep-alive is
        // known at the headers boundary.
        if (!parser_.should_keep_alive())
            close_requested_ = true;

        auto head = http::request{
            .method = st.req_method,
            .target = std::move(st.url),
            .fields = std::move(st.fields),
        };

        auto body_lifecycle = std::make_shared<typename request_body::lifecycle>();
        body_lifecycle->consumed = parser_.complete();
        auto exchange = std::make_shared<exchange_state>(st.req_method, body_lifecycle);
        active_exchange_ = exchange;
        co_return incoming_request{
            .head = std::move(head),
            .body = request_body{transport_, parser_, std::move(body_lifecycle)},
            .token = exchange_token{*this, std::move(exchange)},
        };
    }

    // Stream the response head and body. For HEAD or a successful CONNECT the
    // body is suppressed on the wire (no content is sent).
    template <body_stream Body>
    auto operation_respond(
        exchange_token token,
        http::response head,
        Body& body,
        std::stop_token stop = {}) -> task<void> {
        // RFC 9112 §9.6 — no response once the connection is finished. The
        // parser's connection_closed_ latch is not consulted here: it is set
        // whenever a request completed with "Connection: close", which is
        // exactly the exchange this respond() must still serve.
        if (closed_)
            throw std::runtime_error("http/1.1: connection closed after previous exchange");
        if (!token.valid())
            throw std::runtime_error("http/1.1: invalid exchange token");
        // A token minted by another server must not respond on this
        // connection; responding consumes the token (the exchange record moves
        // out), so a second respond with the same token fails the check above.
        token.check_owner(*this, "http/1.1: ");
        auto exchange = token.take_handle();
        if (active_exchange_ != exchange || exchange->responded)
            throw std::runtime_error("http/1.1: exchange token does not belong to server");

        // RFC 9112 §9.6 — reflect the client's "close" request with a "close"
        // connection option in the final response.
        if (close_requested_ && !detail::has_close_option(head.fields))
            head.fields.push_back({"connection", "close"});

        // RFC 9112 §9.3 — "A server MUST read the entire request message body
        // or close the connection after sending its response, since otherwise
        // the remaining data on a persistent connection would be
        // misinterpreted as the next request." An early final response that
        // leaves request content unread therefore emits the "close" connection
        // option on the wire (RFC 9112 §9.6 — "The server SHOULD send a
        // 'close' connection option in its final response on that connection"),
        // which also latches the connection closed below.
        if (!exchange->body->consumed && !detail::has_close_option(head.fields))
            head.fields.push_back({"connection", "close"});

        // RFC 9110 §9.3.2 — HEAD responses never carry content; RFC 9110 §9.3.6
        // — a successful CONNECT response must not carry content; RFC 9110
        // §15.2/§15.3.5/§15.3.6/§15.4.5 — 1xx/204/205/304 responses never carry
        // content. The shared predicate decides suppression.
        bool suppress_body = !http::response_carries_body(exchange->request_method, head.status);
        // RFC 9112 §6.3 item 8 — a response that carries neither Content-Length
        // nor Transfer-Encoding is close-delimited: its body runs until the
        // server closes the connection, so the connection must not be reused
        // after the response.
        bool close_delimited = !suppress_body &&
            !find_header(head.fields, "content-length") &&
            !find_header(head.fields, "transfer-encoding");
        try {
            if (suppress_body) {
                co_await detail::write_response_head(transport_, head, stop);
            } else {
                co_await detail::write_response(transport_, head, body, stop);
            }
        } catch (...) {
            // The response head (and possibly part of the body) has already
            // been written. The next request would begin at a misaligned
            // frame boundary, so the connection must never be reused.
            closed_ = true;
            throw;
        }

        // RFC 9112 §9.6 — close after a "close" option, a 101 switch
        // (RFC 9110 §15.2.2), a successful CONNECT tunnel (RFC 9110 §9.3.6), or
        // a close-delimited response (RFC 9112 §6.3 item 8).
        bool switched = parser_.connection_upgraded() &&
            (head.status == 101 ||
             (exchange->request_method == method::CONNECT && is_successful(head.status)));
        if (close_requested_ || switched || close_delimited || detail::has_close_option(head.fields))
            closed_ = true;
        exchange->responded = true;
    }

    friend auto operation_start(server&) -> task<void> {
        co_return;
    }

    friend auto operation_receive(server& endpoint, std::stop_token stop = {})
        -> task<incoming_request> {
        co_return co_await endpoint.operation_receive(stop);
    }

    template <body_stream Body>
    friend auto operation_respond(
        server& endpoint,
        exchange_token token,
        http::response head,
        Body& body,
        std::stop_token stop = {}) -> task<void> {
        co_await endpoint.operation_respond(
            std::move(token), std::move(head), body, stop);
    }

public:

    [[nodiscard]] auto should_close() const noexcept -> bool {
        return close_requested_ || closed_ || parser_.connection_closed();
    }

    [[nodiscard]] auto upgraded() const noexcept -> bool {
        return parser_.connection_upgraded();
    }

    [[nodiscard]] auto take_pending() -> std::vector<std::byte> {
        return parser_.take_pending();
    }

private:
    S& transport_;
    detail::message_parser<HTTP_REQUEST> parser_;
    std::shared_ptr<exchange_state> active_exchange_{};
    bool close_requested_{false};
    bool closed_{false};
};

} // namespace http::v1
