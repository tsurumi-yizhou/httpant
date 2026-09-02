module;

#include <llhttp.h>

#include <array>
#include <coroutine>
#include <cstddef>
#include <exception>
#include <memory>
#include <optional>
#include <span>
#include <stdexcept>
#include <stop_token>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

export module httpant:client.llhttp;

import :trait;
import :message;
import :error;
import :validate.llhttp;
import :parse.llhttp;
import :serialize.llhttp;

export namespace http::v1 {

// ─── HTTP/1.1 client (RFC 9112) ──────────────────────────────

template <byte_stream S>
class client {
public:
    explicit client(S& transport) : transport_(transport) {}

    using response_body = body_reader<HTTP_RESPONSE, S>;

    // Send the head, stream the body, and return the response head plus a lazy
    // body reader. Pass an http::buffer_body (or any body_stream) for the body;
    // omit it for a request without content.
private:
    template <body_stream Body>
    auto operation_request(http::request head, Body& body, std::stop_token stop = {})
        -> task<http::received<http::response, body_reader<HTTP_RESPONSE, S>>> {
        // RFC 9112 §9.6 — a client must not send further requests on a closed
        // connection, and a 101 switches the connection to another protocol.
        if (closed_ || parser_.connection_closed())
            throw std::runtime_error("http/1.1: connection closed after previous response");
        if (parser_.connection_upgraded())
            throw std::runtime_error(
                "http/1.1: connection switched protocols (101 or CONNECT tunnel)");
        if (response_lifecycle_ && !response_lifecycle_->consumed)
            throw std::runtime_error("http/1.1: previous response body not consumed");

        try {
            co_await detail::write_request(transport_, head, body, stop);
        } catch (...) {
            // write_request validates the head before the first byte leaves and
            // then streams head and body; both stages land here. Once any part
            // of the request has been written, a failure corrupts the HTTP/1.1
            // message boundary on this connection, so it is marked closed
            // unconditionally — a later request() must not append another
            // request to an already-misaligned byte stream (RFC 9112 §9.6 /
            // request-smuggling shape).
            closed_ = true;
            throw;
        }

        parser_.begin_message();
        // RFC 9110 §15.2 — a client MUST parse one or more 1xx responses before
        // the final response; each 1xx is terminated by the header section.
        try {
            for (;;) {
                co_await parser_.read_headers(transport_, stop);
                auto status = parser_.state().status_code;
                // RFC 9110 §15 — "All valid status codes are within the range
                // of 100 to 599, inclusive." llhttp accepts any three-digit
                // status, so the semantic bound is enforced here before the
                // response can reach the application.
                if (!http::detail::is_valid_status(status))
                    throw detail::protocol_violation(
                        "http/1.1: response status outside 100-599");
                // RFC 9110 §9.3.2 — a HEAD response ends at the header section;
                // RFC 9112 §6.3 item 2 — a successful CONNECT response — "A
                // client MUST ignore any Content-Length or Transfer-Encoding
                // header fields received in such a message"; RFC 9110 §15.2.2 —
                // a 101 switches protocols. None of these frame a body, so
                // their Transfer-Encoding is not decoded and not validated.
                bool tunnel = head.method == method::CONNECT && is_successful(status);
                bool bodyless = head.method == method::HEAD || tunnel || parser_.upgraded();
                if (!is_informational(status) && !bodyless)
                    detail::validate_response_transfer_encoding(parser_.state().fields);
                if (parser_.upgraded() || !is_informational(status))
                    break;
                // Skip the (empty) 1xx body to reach the next message.
                std::array<std::byte, 1024> scratch;
                while (co_await parser_.read_body(
                    transport_, scratch, stop) != 0) {}
                parser_.begin_message();
            }
        } catch (const protocol_error& failure) {
            // RFC 9112 §6.3 — "If the sender closes the connection or the
            // recipient times out before the indicated number of octets are
            // received, the recipient MUST consider the message to be incomplete
            // and close the connection." A malformed response leaves the
            // connection unusable, so the action is an unconditional close.
            if (failure.info().version == protocol_version::http1 &&
                failure.info().condition == error_condition::malformed_message) {
                closed_ = true;
                // The malformed response leaves the connection unusable, so
                // the failure is re-scoped from message to connection.
                auto info = failure.info();
                info.scope = error_scope::connection;
                throw protocol_error{
                    info,
                    close_connection{std::nullopt},
                    failure.what()};
            }
            throw;
        } catch (...) {
            // A non-protocol failure (transport EOF, I/O error) while reading
            // the response leaves the parser at an unknown offset inside the
            // message; the connection can never be reframed, so it is latched
            // closed exactly like the malformed-message path above.
            closed_ = true;
            throw;
        }

        auto head_out = http::response{
            .status = parser_.state().status_code,
            .reason = std::move(parser_.state().status_text),
            .fields = std::move(parser_.state().fields),
        };

        response_lifecycle_ = std::make_shared<typename response_body::lifecycle>();
        // RFC 9110 §9.3.2 — "the server MUST NOT send content in such a
        // response" (HEAD); a Content-Length field describes the content a GET
        // would have sent. llhttp cannot know the request method, so the
        // exchange completes at the header section: the body reader is born
        // consumed and persistence is already known from the received fields.
        if (head.method == method::HEAD) {
            response_lifecycle_->consumed = true;
            if (!parser_.should_keep_alive())
                closed_ = true;
        } else if (head.method == method::CONNECT && is_successful(head_out.status)) {
            // RFC 9112 §6.3 item 2 — "Any 2xx (Successful) response to a
            // CONNECT request implies that the connection will become a tunnel
            // immediately after the empty line that concludes the header
            // fields. A client MUST ignore any Content-Length or
            // Transfer-Encoding header fields received in such a message."
            // llhttp's upgrade flag is only set for Connection: Upgrade / 101 —
            // a plain 2xx CONNECT response is never flagged because a response
            // parser does not know the request method — so the tunnel is
            // latched here: the exchange ends at the header section, the
            // response framing fields are ignored, and the bytes retained
            // after the header section (take_pending) are tunnel data, never
            // a body or the next message.
            response_lifecycle_->consumed = true;
            parser_.mark_connect_tunnel();
        } else {
            response_lifecycle_->consumed = parser_.complete();
        }
        co_return http::received<http::response, response_body>{
            .head = std::move(head_out),
            .body = response_body{transport_, parser_, response_lifecycle_},
        };
    }

    friend auto operation_start(client&) -> task<void> {
        co_return;
    }

    template <body_stream Body>
    friend auto operation_request(client& endpoint, http::request head, Body& body,
                                  std::stop_token stop = {})
        -> task<http::received<http::response, response_body>> {
        co_return co_await endpoint.operation_request(std::move(head), body, stop);
    }

public:

    // RFC 9112 §9.6 — whether the connection is finished after the current
    // exchange (the peer sent "close", or the response body was close-delimited).
    [[nodiscard]] auto should_close() const noexcept -> bool {
        return parser_.connection_closed();
    }

    // RFC 9110 §15.2.2 / §9.3.6 — whether the last response switched the
    // connection to another protocol: a 101 (Switching Protocols), or a 2xx
    // response to a CONNECT request opening the tunnel. The connection now
    // carries the upgraded protocol and tunnel bytes are available via
    // take_pending().
    [[nodiscard]] auto upgraded() const noexcept -> bool {
        return parser_.connection_upgraded();
    }

    [[nodiscard]] auto take_pending() -> std::vector<std::byte> {
        return parser_.take_pending();
    }

private:
    S& transport_;
    detail::message_parser<HTTP_RESPONSE> parser_;
    std::shared_ptr<typename response_body::lifecycle> response_lifecycle_{};
    // A malformed response forces the connection closed (RFC 9112 §6.3); this
    // mirrors the server's `closed_` latch.
    bool closed_{false};
};

} // namespace http::v1
