module;

#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <variant>

export module httpant:error;

import :message;

export namespace http {

enum class protocol_version : std::uint8_t {
    http1 = 1,
    http2 = 2,
    http3 = 3,
};

// RFC 9113 §5.4 — "HTTP/2 framing permits two classes of errors" —
// connection errors and errors in an individual stream are represented
// separately; message and implementation scopes cover library-side failures
// that do not themselves define an HTTP/2 or HTTP/3 wire action.
enum class error_scope : std::uint8_t {
    message,
    stream,
    connection,
    implementation,
};

enum class error_condition : std::uint16_t {
    malformed_message,
    malformed_frame,
    peer_closed,
    stream_reset,
    goaway_rejected,
    compression_failure,
    timeout,
    resource_limit,
    library_failure,
    transport_contract_violation,
};

// error_info describes what happened. The wire action the RFCs require is a
// separate concept (protocol_action) so a protocol error never has to guess
// its protocol's error semantics from a raw integer.
struct error_info {
    protocol_version version;
    error_scope scope;
    error_condition condition;
    std::optional<std::uint64_t> exchange_identity;
    // Backend library return codes are diagnostic values in the separate
    // library_code field and must never be reinterpreted as wire codes.
    std::optional<int> library_code;
    bool retryable;
};

// RFC 9113 §7 — "Error codes are 32-bit fields that are used in RST_STREAM and
// GOAWAY frames to convey the reasons for the stream or connection error."
// HTTP/2 wire error codes live in their own 32-bit space.
namespace v2 {

struct error_code {
    std::uint32_t value;
};

} // namespace v2

// RFC 9114 §8.1 — "The following error codes are defined for use when abruptly
// terminating streams, aborting reading of streams, or immediately closing
// HTTP/3 connections." HTTP/3 application error codes live in the 62-bit
// registry managed by Section 11.2.3.
namespace v3 {

struct error_code {
    std::uint64_t value;
};

} // namespace v3

// The protocol code algebra is type-safe: HTTP/2 and HTTP/3 codes belong to
// different spaces and cannot be interchanged, and HTTP/1.1 has no integer
// error code at all, so no protocol_code exists for it.
using protocol_code = std::variant<v2::error_code, v3::error_code>;

// ─── RFC-required wire actions ──────────────────────────────

// No additional wire action is required: local misuse, a pure implementation
// failure, or a peer that already terminated the exchange.
struct no_action {};

// RFC 9112 — a server that receives a malformed request must respond and then
// close the connection (e.g. §3.2 "MUST respond with a 400 (Bad Request)
// status code"). The library performs no I/O beyond the transport it is given,
// so the response is sent by the application; close_after records whether the
// response must close the connection.
struct send_response {
    http::status status;
    bool close_after;
};

// RFC 9113 §5.4.2 — "An endpoint that detects a stream error sends a RST_STREAM
// frame (Section 6.4) that contains the stream identifier of the stream where
// the error occurred" — and RFC 9114 §8 — "QUIC allows the application to
// abruptly terminate (reset) that stream and communicate a reason." The code
// must belong to the protocol's own error space.
struct reset_stream {
    protocol_code code;
};

// RFC 9113 §5.4.1 — "An endpoint that encounters a connection error SHOULD
// first send a GOAWAY frame ... with an error code (Section 7)"; RFC 9114 §8 —
// "terminate the QUIC connection ... using an error code from Section 8.1";
// RFC 9112 §6.3 — an incomplete message requires closing the connection.
// HTTP/1.1 carries no integer error code, so code is empty for it.
struct close_connection {
    std::optional<protocol_code> code;
};

using protocol_action = std::variant<no_action, send_response, reset_stream, close_connection>;

namespace detail {

template <typename... Ts>
struct overloaded : Ts... {
    using Ts::operator()...;
};
template <typename... Ts>
overloaded(Ts...) -> overloaded<Ts...>;

// Construction-time invariants, enforced in one place so protocol
// implementations cannot attach a mismatched version, scope, or code.
inline void validate_action(const error_info& info, const protocol_action& action) {
    // An HTTP/2 code is only meaningful for an HTTP/2 failure and an HTTP/3
    // code only for an HTTP/3 failure; HTTP/1.1 has no integer error code.
    auto require_code_version = [&](const protocol_code& code) {
        std::visit(overloaded{
            [&](const v2::error_code&) {
                if (info.version != protocol_version::http2)
                    throw std::invalid_argument("v2::error_code requires protocol_version::http2");
            },
            [&](const v3::error_code&) {
                if (info.version != protocol_version::http3)
                    throw std::invalid_argument("v3::error_code requires protocol_version::http3");
            },
        }, code);
    };
    std::visit(overloaded{
        [&](const no_action&) {},
        [&](const send_response&) {
            if (info.version != protocol_version::http1)
                throw std::invalid_argument("send_response requires protocol_version::http1");
        },
        [&](const reset_stream& reset) {
            // RFC 9113 §5.4.2 / RFC 9114 §8 — a stream reset terminates one
            // stream; it is only meaningful at stream scope.
            if (info.scope != error_scope::stream)
                throw std::invalid_argument("reset_stream requires stream scope");
            require_code_version(reset.code);
        },
        [&](const close_connection& close) {
            // RFC 9113 §5.4.1 / RFC 9114 §8 — closing the connection is only
            // meaningful at connection scope; a message or stream failure
            // carries its own narrower action.
            if (info.scope != error_scope::connection)
                throw std::invalid_argument("close_connection requires connection scope");
            if (close.code)
                require_code_version(*close.code);
            else if (info.version != protocol_version::http1)
                throw std::invalid_argument("http2/http3 connection close requires a protocol code");
        },
    }, action);
}

} // namespace detail

class protocol_error final : public std::runtime_error {
public:
    protocol_error(error_info info, protocol_action action, std::string message)
        : std::runtime_error(std::move(message)),
          info_(std::move(info)),
          action_(std::move(action)) {
        detail::validate_action(info_, action_);
    }

    [[nodiscard]] auto info() const noexcept -> const error_info& {
        return info_;
    }

    [[nodiscard]] auto action() const noexcept -> const protocol_action& {
        return action_;
    }

private:
    error_info info_;
    protocol_action action_;
};

} // namespace http
