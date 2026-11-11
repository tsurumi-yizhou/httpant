export module httpant:error;
import httpant.exception;

import std;
import :message;

export namespace http {

// RFC 9113 §5.4 — "HTTP/2 framing permits two classes of errors" —
// connection errors and errors in an individual stream are represented
// separately; message and implementation scopes cover library-side failures
// that do not themselves define a protocol action.
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
};

// RFC 9114 §8.1 — "The following error codes are defined for use when abruptly
// terminating streams, aborting reading of streams, or immediately closing
// HTTP/3 connections"; the codes live in one 62-bit space (Section 11.2.3).
// That space is the library's only error-code space: an engine submits the low
// bits its own frame format defines (RST_STREAM and GOAWAY take 32 of them), and
// nothing re-checks a code against a protocol — the engine's type already says
// which protocol it is. HTTP/1.1 has no integer error code at all.
using error_code = std::uint64_t;

// error_info describes what happened. The wire action the RFCs require is a
// separate concept (protocol_action) so a protocol error never has to guess
// its protocol's error semantics from a raw integer.
struct error_info {
    // Written by protocol_error's constructor when the action implies a scope,
    // and kept as given when the failure has no protocol action of its own.
    error_scope scope;
    error_condition condition;
    std::optional<std::uint64_t> exchange_identity;
    // Backend library return codes are diagnostic values in the separate
    // library_code field and must never be reinterpreted as wire codes.
    std::optional<int> library_code;
};

// Whether repeating the request on a new exchange can succeed. RFC 9114
// §4.1.1 — a request whose stream was reset "MAY be retried... on a new
// stream"; RFC 9113 §6.8 — a stream above the peer's GOAWAY last-stream-id was
// not processed. Whether a retry is appropriate for a non-idempotent request
// is the caller's decision; this only reports what the protocol said about the
// exchange.
[[nodiscard]] constexpr auto retryable(const error_info& info) noexcept -> bool {
    return info.condition == error_condition::goaway_rejected ||
           info.condition == error_condition::stream_reset;
}

// ─── RFC-required wire actions ──────────────────────────────

// No additional wire action is required: a pure implementation failure, or a
// peer that already terminated the exchange.
struct no_action {};

// RFC 9113 §5.4.2 — "An endpoint that detects a stream error sends a RST_STREAM
// frame (Section 6.4) that contains the stream identifier of the stream where
// the error occurred" — and RFC 9114 §4.1.2 — a reset terminates one stream and
// "communicates a reason" as an application error code. A reset is stream
// scoped by definition.
struct reset_stream {
    error_code code;
};

// RFC 9113 §5.4.1 — "An endpoint that encounters a connection error SHOULD
// first send a GOAWAY frame ... with an error code (Section 7)"; RFC 9114 §5.2 —
// "terminate the QUIC connection ... using an error code from Section 8.1";
// RFC 9112 §6.3 — an incomplete message requires closing the connection, and
// RFC 9112 §3.2 / §6.3 — after a malformed request the server answers 400
// (which the HTTP/1.1 server writes itself) and then closes the connection.
// HTTP/1.1 has no integer error code, so code is empty for it. A close is
// connection scoped by definition.
struct close_connection {
    std::optional<error_code> code;
};

using protocol_action = std::variant<no_action, reset_stream, close_connection>;

class protocol_error : public std::runtime_error, public http::exceptions::exception_capture {
public:
    auto capture() const noexcept -> std::exception_ptr override { return http::exceptions::capture(*this); }

    // The action decides the scope, so no construction site can hand a stream
    // reset a connection scope (or the reverse): the type of the action is the
    // invariant. no_action keeps the scope the failure names, since a failure
    // with no protocol action still knows whether it affected one message, one
    // stream or the connection.
    protocol_error(error_info info, no_action, std::string message)
        : std::runtime_error(std::move(message)),
          info_(info),
          action_(no_action{}) {}

    protocol_error(error_info info, reset_stream action, std::string message)
        : std::runtime_error(std::move(message)),
          info_(info),
          action_(action) {
        info_.scope = error_scope::stream;
    }

    protocol_error(error_info info, close_connection action, std::string message)
        : std::runtime_error(std::move(message)),
          info_(info),
          action_(action) {
        info_.scope = error_scope::connection;
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
