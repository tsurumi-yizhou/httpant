module;

#include <nghttp2/nghttp2.h>

#include <array>
#include <coroutine>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <exception>
#include <format>
#include <functional>
#include <memory>
#include <optional>
#include <ranges>
#include <span>
#include <stdexcept>
#include <stop_token>
#include <string>
#include <string_view>
#include <system_error>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

export module httpant:session.nghttp2;

import :trait;
import :message;
import :error;
import :session.core;

export namespace http::v2 {

// RFC 9113 §6.5.2 — SETTINGS identifiers are stable 16-bit wire values.
enum class setting_name : std::uint16_t {
    header_table_size = 0x01,
    enable_push = 0x02,
    maximum_concurrent_streams = 0x03,
    initial_window_size = 0x04,
    maximum_frame_size = 0x05,
    maximum_field_section_size = 0x06,
};

struct setting {
    setting_name name;
    std::uint32_t value;
};

struct settings_ticket {
    std::uint64_t sequence;

    auto operator<=>(const settings_ticket&) const = default;
};

struct hpack_configuration {
    std::uint32_t decoder_capacity{4096};
    std::size_t encoder_capacity{4096};
};

struct configuration {
    hpack_configuration compression{};
    std::uint32_t maximum_concurrent_streams{100};
    std::uint32_t maximum_field_section_size{64 * 1024};
    bool enable_push{true};
};

struct hpack_state {
    std::uint32_t decoder_capacity;
    std::size_t decoder_size;
    std::uint32_t peer_decoder_capacity;
    std::size_t encoder_capacity;
    std::size_t encoder_size;
};

struct pushed_exchange {
    request promised_request{};
    response pushed_response{};
    // HTTP/2 pushes are delivered atomically by take_push. Wire stream
    // identity remains endpoint-owned and is not part of the application API.
    std::vector<std::byte> body{};
};

namespace detail {

inline constexpr std::size_t io_buffer_size = 16 * 1024;

struct callbacks_deleter {
    void operator()(nghttp2_session_callbacks* callbacks) const noexcept {
        nghttp2_session_callbacks_del(callbacks);
    }
};

struct option_deleter {
    void operator()(nghttp2_option* option) const noexcept {
        nghttp2_option_del(option);
    }
};

struct session_deleter {
    void operator()(nghttp2_session* session) const noexcept {
        nghttp2_session_del(session);
    }
};

using callbacks_handle =
    http::detail::engine_handle<nghttp2_session_callbacks, callbacks_deleter>;
using option_handle =
    http::detail::engine_handle<nghttp2_option, option_deleter>;
using session_handle =
    http::detail::engine_handle<nghttp2_session, session_deleter>;

inline auto make_error(std::string_view op, int rc) -> std::runtime_error {
    return std::runtime_error(std::format("http/2: {} failed ({})", op, rc));
}

inline void check(int rc, std::string_view op) {
    if (rc != 0) throw make_error(op, rc);
}

// RFC 9113 §6.8 — streams above the peer's GOAWAY boundary were not
// processed and can be retried on a different connection. GOAWAY itself is
// already the wire signal, so rejecting the local operation needs no action.
inline auto make_goaway_rejection(std::optional<std::uint64_t> exchange)
    -> protocol_error
{
    return http::detail::make_goaway_rejection(
        protocol_version::http2, exchange, "http/2: ");
}

[[nodiscard]] inline auto wire_code_from_library_code(int code) -> std::uint32_t {
    switch (code) {
        case NGHTTP2_ERR_FRAME_SIZE_ERROR: return NGHTTP2_FRAME_SIZE_ERROR;
        case NGHTTP2_ERR_HEADER_COMP: return NGHTTP2_COMPRESSION_ERROR;
        case NGHTTP2_ERR_FLOW_CONTROL: return NGHTTP2_FLOW_CONTROL_ERROR;
        case NGHTTP2_ERR_SETTINGS_EXPECTED:
        case NGHTTP2_ERR_TOO_MANY_SETTINGS:
        case NGHTTP2_ERR_PROTO: return NGHTTP2_PROTOCOL_ERROR;
        case NGHTTP2_ERR_FLOODED: return NGHTTP2_ENHANCE_YOUR_CALM;
        default: return NGHTTP2_INTERNAL_ERROR;
    }
}

// The typed condition matching a wire error code (RFC 9113 §7): compression
// failures and rate-limit rejections are distinguished from generic frame
// violations.
[[nodiscard]] inline auto condition_from_wire_code(std::uint32_t code) -> error_condition {
    switch (code) {
        case NGHTTP2_COMPRESSION_ERROR: return error_condition::compression_failure;
        case NGHTTP2_ENHANCE_YOUR_CALM: return error_condition::resource_limit;
        default: return error_condition::malformed_frame;
    }
}

// Parse a :status pseudo-header value through the shared non-throwing parser
// (http::detail::parse_status); wire input is untrusted (RFC 9113 §8.3.2). A
// malformed or out-of-range value yields nullopt so the callback can reset the
// stream instead of letting an exception escape through the nghttp2 C callback
// boundary. RFC 9110 §15 — "All valid status codes are within the range of 100
// to 599, inclusive." and "Values outside the range 100..599 are invalid." —
// nghttp2 only checks the three-digit shape (and rejects 101), so a well-formed
// but out-of-range value (e.g. "700" or "000") is rejected here like any other
// invalid :status.
inline auto parse_status(std::string_view value) -> std::optional<std::uint16_t> {
    return http::detail::parse_status(value);
}


inline auto check_stream_id(int id, std::string_view op) -> int {
    if (id < 0) throw make_error(op, id);
    return id;
}

// A request/response stream. The body is streamed: on_data_chunk_recv appends to
// a staging buffer; the body reader drains it via async_read. complete marks the
// receipt of END_STREAM; aborted marks an RST_STREAM before END_STREAM. The
// shared stream_state_core holds the lifecycle flags, decoded fields, and the
// three waiter slots; the body storage, credit bookkeeping, and reset-code pair
// are engine-specific and stay here.
struct stream_data {
    http::detail::stream_state_core<std::int32_t> core{};
    http::detail::byte_cursor body{};
    // Flow-control credit for buffered body bytes is returned exactly once:
    // either as the application consumes (body_reader) or — for bytes never
    // consumed — when the stream closes.
    bool credit_settled{false};
    // RFC 9113 §6.4 — "RST_STREAM (type=0x3) ... contains a single unsigned,
    // 32-bit integer identifying the error code (Section 7)" — the code the peer
    // carried when it reset the stream before its message completed. nullopt
    // when the abort was local or the stream completed normally; the value
    // drives RFC 9113 §8.7 retry semantics for REFUSED_STREAM.
    std::optional<std::uint32_t> peer_reset_code{};
    // The code this endpoint submitted when it reset a stream it aborted itself
    // (e.g. RST_STREAM PROTOCOL_ERROR for a malformed peer message — RFC 9113
    // §8.1.1), so the local abort surfaces as a typed stream error carrying the
    // wire code instead of a bare runtime_error. nullopt when the abort (if
    // any) was the peer's (peer_reset_code).
    std::optional<std::uint32_t> local_reset_code{};
    // An abort this endpoint initiated (e.g. a malformed peer :status reset with
    // RST_STREAM PROTOCOL_ERROR). Distinct from a peer RST_STREAM: the code this
    // endpoint submitted is recorded separately (local_reset_code) rather than
    // attributed to the peer, and on_stream_close_callback keeps the abort
    // sticky when END_STREAM raced with the local reset.
    bool locally_aborted{false};
};

// Throw the typed abort for a stream that closed before its message
// completed: the peer's RST_STREAM code when the peer reset it, the code this
// endpoint submitted when it reset the stream itself, or — when neither is
// recorded — a bare runtime_error for a plain incomplete close. The messages
// distinguish request/response streams from pushed ones.
[[noreturn]] inline void throw_reset_failure(
    std::int32_t stream_id,
    const std::optional<std::uint32_t>& peer_reset_code,
    const std::optional<std::uint32_t>& local_reset_code,
    std::string_view peer_reset_message,
    std::string_view local_reset_message,
    std::string_view incomplete_message) {
    if (peer_reset_code) {
        auto code = *peer_reset_code;
        throw http::detail::make_protocol_error(
            error_info{
                .version = protocol_version::http2,
                .scope = error_scope::stream,
                .condition = error_condition::stream_reset,
                .exchange_identity = static_cast<std::uint64_t>(stream_id),
                .library_code = std::nullopt,
                // RFC 9113 §8.7 — "The REFUSED_STREAM error code can be included
                // in a RST_STREAM frame to indicate that the stream is being
                // closed prior to any processing having occurred. Any request
                // that was sent on the reset stream can be safely retried."
                .retryable = code == NGHTTP2_REFUSED_STREAM,
            },
            reset_stream{error_code{code}},
            "http/2: ",
            peer_reset_message);
    }
    if (local_reset_code) {
        auto code = *local_reset_code;
        throw http::detail::make_protocol_error(
            error_info{
                .version = protocol_version::http2,
                .scope = error_scope::stream,
                .condition = error_condition::malformed_message,
                .exchange_identity = static_cast<std::uint64_t>(stream_id),
                .library_code = std::nullopt,
                .retryable = false,
            },
            reset_stream{error_code{code}},
            "http/2: ",
            local_reset_message);
    }
    throw std::runtime_error(std::string{incomplete_message});
}

// Surface an aborted stream to the application. RFC 9113 §6.4 — "RST_STREAM
// (type=0x3) ... contains a single unsigned, 32-bit integer identifying the
// error code (Section 7)" — a reset by the peer before the message completed is
// delivered as a typed stream error carrying the peer's code, so the application
// can apply RFC 9113 §8.7 retry semantics. A stream this endpoint aborted itself
// (e.g. a malformed peer message reset with RST_STREAM PROTOCOL_ERROR per
// RFC 9113 §8.1.1) is equally typed, carrying the code that went on the wire —
// mirroring the RFC 9114 §4.1.2 malformed-message treatment in v3.
[[noreturn]] inline void throw_stream_abort(const stream_data& stream) {
    throw_reset_failure(
        stream.core.id,
        stream.peer_reset_code,
        stream.local_reset_code,
        "stream reset by peer",
        "stream closed before complete message",
        "http/2: stream closed before complete message");
}

// A synchronous, type-erased body source consumed by nghttp2's data provider.
// The exchange coroutine owns the body_bridge and refills it between flushes;
// read_outbound_body drains it. std::nullopt means the body is deferred until
// the next refill; read_outbound_body maps it to NGHTTP2_ERR_DEFERRED at the C
// boundary. deferred mirrors nghttp2's deferral state:
// nghttp2_session_resume_data fails with NGHTTP2_ERR_INVALID_ARGUMENT when no
// deferred data exists, so a resume is only issued while the provider has
// actually deferred.
struct outbound_body_state {
    std::function<std::optional<std::size_t>(std::uint8_t*, std::size_t, bool&)> read{};
    bool deferred{false};
};

// Forward declaration (definition in the serialize partition): the nghttp2
// data-provider callback drains an outbound_body_state.
auto read_outbound_body(
    nghttp2_session*,
    std::int32_t,
    std::uint8_t*,
    std::size_t,
    std::uint32_t*,
    nghttp2_data_source*,
    void*) -> nghttp2_ssize;

struct push_data {
    std::int32_t promised_stream_id{0};
    std::int32_t associated_stream_id{0};
    bool complete{false};
    bool closed{false};
    bool aborted{false};
    // An abort this endpoint initiated (e.g. a malformed :status reset with
    // RST_STREAM PROTOCOL_ERROR — RFC 9113 §8.1.1). Distinct from a peer
    // RST_STREAM: the code this endpoint submitted is recorded separately
    // (local_reset_code) rather than attributed to the peer. Mirrors
    // stream_data.
    bool locally_aborted{false};
    http::detail::decoded_fields request{};
    http::status status_code{0};
    http::detail::decoded_fields response{};
    std::vector<std::byte> body{};
    // RFC 9113 §6.4 — "RST_STREAM (type=0x3) ... contains a single unsigned,
    // 32-bit integer identifying the error code (Section 7)" — the code the
    // peer carried when it reset the promised stream before its response
    // completed. nullopt when the abort was local or the stream completed
    // normally; the value drives RFC 9113 §8.7 retry semantics for
    // REFUSED_STREAM.
    std::optional<std::uint32_t> peer_reset_code{};
    // The code this endpoint submitted when it reset a promised stream whose
    // response was malformed (e.g. a bad :status), so the local abort surfaces
    // as a typed stream error carrying the wire code. nullopt when the abort
    // (if any) was the peer's (peer_reset_code).
    std::optional<std::uint32_t> local_reset_code{};
};

inline auto make_pushed_exchange(const push_data& push) -> v2::pushed_exchange {
    return v2::pushed_exchange{
        .promised_request = http::request{
            .method = from_string(push.request.method_token),
            .target = push.request.path,
            .scheme = push.request.scheme,
            .authority = push.request.authority,
            .fields = push.request.regular,
        },
        .pushed_response = http::response{
            .status = push.status_code,
            .reason = {},
            .fields = push.response.regular,
        },
        .body = push.body,
    };
}

struct completed_push {
    std::int32_t stream_id{0};
    v2::pushed_exchange exchange{};
};

// A promised stream that closed without delivering a pushed exchange, queued
// for take_push() to surface as a typed protocol_error. The record carries the
// reset code and stream identity only; the buffered response is discarded with
// the push_data at close time.
struct aborted_push {
    std::int32_t stream_id{0};
    std::optional<std::uint32_t> peer_reset_code{};
    std::optional<std::uint32_t> local_reset_code{};
};

// Surface an aborted push to the application. RFC 9113 §6.4 — "RST_STREAM
// (type=0x3) ... contains a single unsigned, 32-bit integer identifying the
// error code (Section 7)" — a promised stream the peer reset before its
// response completed is delivered as a typed stream error carrying the peer's
// code, so the application can apply RFC 9113 §8.7 retry semantics. A push
// this endpoint aborted itself (a malformed pushed response reset with
// RST_STREAM PROTOCOL_ERROR per RFC 9113 §8.1.1) is equally typed, carrying
// the code that went on the wire — mirroring throw_stream_abort for
// request/response streams.
[[noreturn]] inline void throw_push_abort(const aborted_push& push) {
    throw_reset_failure(
        push.stream_id,
        push.peer_reset_code,
        push.local_reset_code,
        "pushed stream reset by peer",
        "pushed stream closed before complete response",
        "http/2: pushed stream closed before complete response");
}

struct session_context {
    // The shared connection core holds the per-stream / per-outbound-body
    // registries, the server receive queue, the GOAWAY flag and boundary, the
    // connection-error latch, the callback-failure slot, and the receive()
    // waiter. Engine-specific state (push machinery, settings generations,
    // GOAWAY richness, the output buffer, the handshake waiter) stays here.
    http::detail::connection_core<std::int32_t, stream_data, outbound_body_state> core{};
    std::unordered_map<std::int32_t, std::shared_ptr<push_data>> pushed_streams{};
    std::vector<std::byte> outbuf{};
    std::deque<completed_push> completed_pushes{};
    std::deque<aborted_push> aborted_pushes{};
    // RFC 9113 §6.5 — "ACK (0x01): When set, the ACK flag indicates that this frame
    // acknowledges receipt and application of the peer's SETTINGS frame." The peer's
    // initial non-ACK SETTINGS and the ACK of our local SETTINGS are distinct states.
    bool peer_initial_settings_received{false};
    std::uint64_t next_settings_sequence{1};
    std::uint64_t acknowledged_settings_sequence{0};
    std::deque<settings_ticket> unsent_settings{};
    std::deque<settings_ticket> pending_settings{};
    std::int32_t goaway_last_stream_id{0};
    // RFC 9113 §6.8 — the error code the peer's GOAWAY carried; it diagnoses
    // why the connection is being closed when the transport reaches EOF.
    std::uint32_t goaway_error_code{0};
    // The error code of the last GOAWAY this endpoint sent; nghttp2 terminates
    // the session itself on a peer connection error (e.g. RFC 9113 §4.3 —
    // header decompression failure is COMPRESSION_ERROR) without mem_recv2
    // returning a negative code, so the code is captured as the frame goes out.
    std::optional<std::uint32_t> sent_goaway_error_code{};
    std::optional<int> library_error_code{};
    // RFC 9113 §6.8 — "Endpoints MUST NOT increase the value they send in the last stream
    // identifier" across multiple GOAWAY frames; the most recent value sent is tracked here.
    std::optional<std::int32_t> goaway_sent_last_stream_id{};
    // Highest peer-initiated stream whose exchange has actually crossed the
    // public delivery boundary. GOAWAY must describe application processing,
    // not merely parser activity, and the application must never choose raw IDs.
    std::int32_t last_processed_peer_stream_id{0};
    // Push IDs the client has rejected (RFC 9113 §8.4) with RST_STREAM; their promise and
    // response streams must be ignored thereafter.
    std::unordered_set<std::int32_t> rejected_pushes{};
    // RFC 9113 §8.4 — "The server MUST include a value in the ":authority" pseudo-header field
    // for which the server is authoritative ... A client MUST treat a PUSH_PROMISE for which the
    // server is not authoritative as a stream error ... of type PROTOCOL_ERROR." The client
    // records the origin of the first request it sends on this connection (RFC 9110 §4.3: a
    // connection carries requests for a single origin, absent CONNECT tunneling); pushed
    // requests are then checked against it.
    std::optional<std::string> origin_scheme{};
    std::optional<std::string> origin_authority{};
    // Single-waiter slot (waiter_slot): at most one coroutine may park on it;
    // parking a second throws std::logic_error (asserted at the awaiter).
    http::detail::waiter_slot handshake_waiter{};
};

inline auto reserve_settings_ticket(session_context& ctx) -> settings_ticket {
    auto ticket = settings_ticket{ctx.next_settings_sequence++};
    ctx.unsent_settings.push_back(ticket);
    return ticket;
}

inline void rethrow_connection_error(const session_context& ctx) {
    if (ctx.core.connection_error)
        std::rethrow_exception(ctx.core.connection_error);
}

inline void notify_waiters(session_context& ctx) noexcept {
    if (ctx.peer_initial_settings_received || ctx.core.connection_error)
        ctx.handshake_waiter.resume();
    if (!ctx.core.receive_queue_empty() || ctx.core.connection_error)
        ctx.core.receive_waiter.resume();
    for (auto& stream : ctx.core.streams | std::views::values) {
        // RFC 9113 §6.8 — "If the receiver of the GOAWAY has sent data on
        // streams with a higher stream identifier than what is indicated in
        // the GOAWAY frame, those streams are not or will not be processed." —
        // a suspended exchange above the boundary must wake and fail instead
        // of hanging until the transport closes.
        bool goaway_rejected = ctx.core.goaway_received &&
            stream->core.id > ctx.goaway_last_stream_id;
        http::detail::wake_stream_conditions(
            stream->core,
            !stream->body.empty(),
            goaway_rejected,
            ctx.core.connection_error != nullptr);
    }
}

struct handshake_awaiter {
    session_context& context;
    bool await_ready() const noexcept {
        return context.peer_initial_settings_received ||
               context.core.connection_error != nullptr;
    }
    void await_suspend(std::coroutine_handle<> handle) {
        context.handshake_waiter.park(handle);
    }
    // v3-style error delivery: the caller re-checks the connection state after
    // the wake instead of the awaiter rethrowing.
    void await_resume() const noexcept {}
};

struct request_awaiter {
    session_context& context;
    std::shared_ptr<stream_data> stream;
    bool await_ready() const noexcept {
        return stream->core.headers_done || stream->core.aborted ||
               context.core.connection_error != nullptr;
    }
    void await_suspend(std::coroutine_handle<> handle) {
        stream->core.headers_waiter.park(handle);
    }
    void await_resume() const noexcept {}
};

// Parks the body reader until DATA or a terminal stream event arrives
// (notify_waiters). The wait also honors the user stop token carried by
// body_reader::async_read: the stop callback claims the single waiter slot with
// the same exchange the normal wakeup uses, so whichever side loses the race
// observes an empty slot and never resumes a second time. Cancellation is
// delivered from await_resume as std::system_error{operation_canceled} — the
// same convention a transport uses for a cancelled read.
struct body_awaiter {
    session_context& context;
    std::shared_ptr<stream_data> stream;
    std::stop_token stop;
    bool cancelled{false};

    struct on_stop {
        body_awaiter* self;
        void operator()() const noexcept {
            // Exchange-claim: normal completion and this callback race for the
            // single waiter slot; the loser must not resume a second time. When
            // the slot is still empty the stop raced the registration in
            // await_suspend, which then refuses to park.
            self->cancelled = true;
            if (auto handle = self->stream->core.body_waiter.take(); handle)
                handle.resume();
        }
    };

    bool await_ready() const noexcept {
        return !stream->body.empty() || stream->core.complete ||
               stream->core.aborted ||
               context.core.connection_error != nullptr ||
               stop.stop_requested();
    }
    auto await_suspend(std::coroutine_handle<> handle) -> bool {
        if (stop.stop_possible())
            cancel.emplace(stop, on_stop{this});
        if (cancelled)
            return false;
        stream->core.body_waiter.park(handle);
        return true;
    }
    void await_resume() const {
        if (cancelled || stop.stop_requested())
            throw std::system_error(
                std::make_error_code(std::errc::operation_canceled));
    }

    std::optional<std::stop_callback<on_stop>> cancel{};
};

// Suspends an outbound body driver while the peer's send window is exhausted
// (RFC 9113 §6.9). The readiness check lives at the call site (the window is
// nghttp2 state, not stream_data state); every received frame batch wakes the
// waiter so a WINDOW_UPDATE restarts the send.
struct window_awaiter {
    session_context& context;
    std::shared_ptr<stream_data> stream;
    bool await_ready() const noexcept { return false; }
    void await_suspend(std::coroutine_handle<> handle) {
        stream->core.capacity_waiter.park(handle);
    }
    void await_resume() const noexcept {}
};

struct receive_awaiter {
    session_context& context;
    bool await_ready() const noexcept {
        return !context.core.receive_queue_empty() ||
               context.core.connection_error != nullptr;
    }
    void await_suspend(std::coroutine_handle<> handle) {
        context.core.receive_waiter.park(handle);
    }
    void await_resume() const noexcept {}
};

} // namespace detail
} // namespace http::v2
