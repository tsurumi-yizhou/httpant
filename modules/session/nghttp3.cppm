module;

#include <nghttp3/nghttp3.h>

#include <coroutine>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <exception>
#include <format>
#include <memory>
#include <optional>
#include <stop_token>
#include <string>
#include <string_view>
#include <system_error>
#include <unordered_map>
#include <utility>
#include <variant>
#include <vector>

export module httpant:session.nghttp3;

import :trait;
import :message;
import :error;
import :session.core;

export namespace http::v3 {

// RFC 9000 §16 — QUIC variable-length integers encode at most 62 bits.
inline constexpr std::uint64_t maximum_varint =
    (std::uint64_t{1} << 62) - 1;

struct qpack_configuration {
    std::size_t decoder_capacity{0};
    std::size_t blocked_streams{0};
    std::size_t encoder_capacity{4096};
};

// RFC 9204 §3.2.3 — "For clients using 0-RTT data in HTTP/3, the server's
// maximum table capacity is the remembered value of the setting or zero if
// the value was not previously sent. ... If the remembered value is non-zero,
// the server MUST send the same non-zero value in its SETTINGS frame." The
// public API has no remembered-settings input, so 0-RTT resumption is out of
// scope: every connection starts with a fresh handshake where the encoder's
// dynamic-table capacity is 0 until SETTINGS_QPACK_MAX_TABLE_CAPACITY
// arrives (RFC 9204 §3.2.3), which is the compliant behavior for non-0-RTT
// usage.
struct configuration {
    qpack_configuration compression{};
    std::uint64_t maximum_field_section_size{maximum_varint};
};

struct qpack_state {
    std::size_t decoder_capacity{0};
    std::size_t blocked_streams{0};
    std::size_t encoder_capacity{4096};
    std::size_t peer_decoder_capacity{0};
    std::size_t peer_blocked_streams{0};
};

namespace detail {

inline constexpr std::size_t io_buffer_size = 16 * 1024;
inline constexpr std::size_t body_buffer_limit = io_buffer_size;
inline constexpr std::size_t field_entry_overhead = 32;
inline constexpr std::uint64_t cancel_push_frame_type = 0x03;
inline constexpr std::uint64_t settings_frame_type = 0x04;
inline constexpr std::uint64_t push_promise_frame_type = 0x05;
inline constexpr std::uint64_t goaway_frame_type = 0x07;
inline constexpr std::uint64_t max_push_id_frame_type = 0x0d;

inline constexpr std::uint64_t control_stream_type = 0x00;
inline constexpr std::uint64_t push_stream_type = 0x01;
inline constexpr std::uint64_t qpack_encoder_stream_type = 0x02;
inline constexpr std::uint64_t qpack_decoder_stream_type = 0x03;

enum class stream_kind {
    request,
    control,
    qpack,
    ignored,
};

inline auto make_error(std::string_view op, int rc) -> protocol_error {
    return protocol_error{
        error_info{
            .version = protocol_version::http3,
            .scope = error_scope::implementation,
            .condition = error_condition::library_failure,
            .exchange_identity = std::nullopt,
            .library_code = rc,
            .retryable = false,
        },
        no_action{},
        std::format("http/3: {} failed ({})", op, rc)};
}

inline void check(int rc, std::string_view op) {
    if (rc != 0) throw make_error(op, rc);
}

struct stream_data {
    http::detail::stream_state_core<std::int64_t> core{};
    std::deque<std::vector<std::byte>> body{};
    std::size_t body_offset{0};
    std::size_t buffered_body_size{0};
    std::uint64_t field_section_size{0};
    std::uint64_t close_error_code{0};
    // Set when a suspended body read is cancelled through its stop token; the
    // read's await_resume consumes the flag and throws operation_canceled.
    bool body_read_cancelled{false};
};

struct outbound_body_state {
    std::vector<std::byte> data{};
    std::size_t acknowledged{0};
    bool offered{false};
    bool eof{false};
    std::coroutine_handle<> ack_waiter{};

    void resume_ack_waiter() noexcept {
        if (ack_waiter)
            std::exchange(ack_waiter, {}).resume();
    }
};

// serialize/nghttp3.cppm's outbound pump takes endpoint_runtime<S>&; the
// definition lives in endpoint/nghttp3.cppm, which imports this partition.
template <stream_factory S>
class endpoint_runtime;

struct stream_input_state {
    stream_kind kind{stream_kind::request};
    bool stream_type_known{false};
    bool settings_seen{false};
    std::uint64_t stream_type{0};
    std::vector<std::byte> buffer{};
    bool closed{false};
};

struct conn_context {
    http::detail::connection_core<std::int64_t, stream_data, outbound_body_state> core{};
    // RFC 9114 §8 — stream-scoped failures of server request streams (e.g. a
    // malformed request, H3_MESSAGE_ERROR) are delivered to receive() one at
    // a time instead of failing the connection; the connection and its other
    // exchanges keep running.
    std::deque<std::exception_ptr> server_stream_failures{};

    bool is_client{false};
    std::int64_t local_control_stream_id{-1};
    std::optional<std::int64_t> remote_control_stream_id{};
    std::optional<std::int64_t> remote_qpack_encoder_stream_id{};
    std::optional<std::int64_t> remote_qpack_decoder_stream_id{};
    std::optional<std::uint64_t> peer_max_push_id{};
    std::unordered_map<std::int64_t, stream_input_state> inputs{};
    std::unordered_map<std::int64_t, std::size_t> deferred_consumption{};
    configuration local_configuration{};
    std::size_t peer_decoder_capacity{0};
    std::size_t peer_blocked_streams{0};
    // The peer's advertised SETTINGS_MAX_FIELD_SECTION_SIZE (RFC 9114
    // §7.2.4.1 — "The default value is unlimited"); honored on outbound field
    // sections (RFC 9114 §4.2.2).
    std::uint64_t peer_max_field_section_size{maximum_varint};

    // RFC 9114 §8 — error handling: H3 error codes are recorded here so the
    // upper layer can carry them on connection shutdown / exception. 0 means
    // no connection error has been recorded.
    std::uint64_t connection_error_code{0};

    bool connection_close_started{false};
};

// RFC 9114 §8 — "If an entire connection needs to be terminated, QUIC
// similarly provides mechanisms to communicate a reason ... an HTTP/3
// implementation can terminate a QUIC connection and communicate the reason
// using an error code from Section 8.1."
// libnghttp3 has no "close with an application error code" call; the
// application error code is supplied by the QUIC layer when it closes the
// connection. We therefore record the H3 error code here and start connection
// shutdown on the nghttp3 side; the typed protocol_action on the thrown
// exception carries the code to the caller.
// nghttp3_conn_shutdown requires the control stream to be bound first
// (asserted inside the library), so it is only invoked once handshake has
// bound it.
inline void record_connection_error(conn_context& ctx, nghttp3_conn* conn, std::uint64_t wire_code) {
    if (ctx.connection_error_code == 0)
        ctx.connection_error_code = wire_code;
    if (conn != nullptr && ctx.local_control_stream_id >= 0)
        static_cast<void>(nghttp3_conn_shutdown(conn));
}

// RFC 9114 §8 — "When a stream cannot be completed successfully, QUIC allows
// the application to abruptly terminate (reset) that stream and communicate a
// reason ... This is referred to as a 'stream error'." Stream errors are
// signaled with the QUIC stream reset carrying the H3 error code from
// Section 8.1; nghttp3 models this as nghttp3_conn_close_stream.
inline void record_stream_error(conn_context& ctx, nghttp3_conn* conn, std::int64_t stream_id, std::uint64_t wire_code) {
    if (auto it = ctx.core.streams.find(stream_id); it != ctx.core.streams.end())
        it->second->close_error_code = wire_code;
    if (conn != nullptr)
        static_cast<void>(nghttp3_conn_close_stream(conn, stream_id, wire_code));
}

// Marks an outbound body terminal and wakes its ACK waiter. A
// pump_outbound_body parked on the ACK wait must wake to a terminal state
// (retained chunk dropped, eof set — mirroring the stream-reset treatment in
// flush_output) so it co_returns instead of re-parking on a state the map no
// longer holds, which nothing would ever resume again. The caller then
// surfaces the stream/connection error as it already does.
inline void terminate_outbound_body(outbound_body_state& body) {
    body.data.clear();
    body.acknowledged = 0;
    body.offered = false;
    body.eof = true;
    body.resume_ack_waiter();
}

// Marks a stream terminal and wakes its waiters. Used for streams the peer
// reset before nghttp3 ever saw them, where nghttp3_conn_close_stream cannot
// deliver the stream_close callback.
inline void mark_stream_closed(conn_context& ctx, std::int64_t stream_id, std::uint64_t app_error_code) {
    if (auto it = ctx.core.streams.find(stream_id); it != ctx.core.streams.end()) {
        auto& stream = *it->second;
        stream.close_error_code = app_error_code;
        stream.core.closed = true;
        // A closed stream is aborted iff its message never completed; a
        // completion that raced a close wins (end_stream is the message's
        // final signal).
        stream.core.aborted = !stream.core.complete;
        http::detail::wake_stream_conditions(stream.core, false, false, false);
    }
    if (auto it = ctx.core.outbound_bodies.find(stream_id); it != ctx.core.outbound_bodies.end()) {
        // Erase before resuming: terminate_outbound_body resumes the
        // exchange's pump synchronously, and the operation erases its own
        // outbound-bodies entry when the pump returns — erasing |it| after
        // that nested resume would dereference a dangling iterator.
        auto body = std::move(it->second);
        ctx.core.outbound_bodies.erase(it);
        terminate_outbound_body(*body);
    }
}

// Exception-path cleanup for the exchange registrations an operation makes
// before its first throwing suspension (fill_outbound_body, the submit calls,
// pump_outbound_body). Without it, a throw leaks the inserted entries until
// connection teardown: reap_closed_streams only reclaims streams the endpoint
// driver marked closed, and these never are. The guard erases exactly what
// the operation inserted and, once the stream was submitted to nghttp3,
// closes it at the sole protocol owner (mirroring the reset paths, RFC 9114
// §8) so a late peer frame cannot recreate the erased state through
// begin_headers. The original exception propagates unchanged.
template <typename StreamMap>
struct exchange_registration {
    conn_context& ctx;
    nghttp3_conn* conn;
    StreamMap* open_streams{nullptr};
    std::int64_t stream_id{0};
    bool submitted{false};
    bool armed{true};

    explicit exchange_registration(
        conn_context& context,
        nghttp3_conn* connection,
        std::int64_t id,
        StreamMap* streams = nullptr)
        : ctx(context), conn(connection), open_streams(streams), stream_id(id) {}
    exchange_registration(const exchange_registration&) = delete;
    auto operator=(const exchange_registration&) -> exchange_registration& = delete;

    ~exchange_registration() {
        if (!armed) return;
        ctx.core.outbound_bodies.erase(stream_id);
        if (open_streams == nullptr) return;
        ctx.core.streams.erase(stream_id);
        open_streams->erase(stream_id);
        // RFC 9114 §8.1 — H3_REQUEST_CANCELLED: "used when the request or its
        // response (including pushed response) is cancelled."
        if (submitted)
            static_cast<void>(nghttp3_conn_close_stream(
                conn, stream_id, NGHTTP3_H3_REQUEST_CANCELLED));
    }

    void disarm() noexcept { armed = false; }
};

// RFC 9114 §8 — a connection-level protocol violation records the H3 error
// code (Section 8.1), starts connection shutdown on the nghttp3 side, and is
// reported as a protocol_error whose action is close_connection carrying the
// same code. Because the library performs no I/O, the actual QUIC close is the
// transport's job; the action is delivered to the caller through the typed
// exception rather than a polled accessor.
inline auto make_frame_error(conn_context& ctx, nghttp3_conn* conn, std::uint64_t wire_code, std::string_view detail) -> protocol_error {
    record_connection_error(ctx, conn, wire_code);
    return http::detail::make_protocol_error(
        error_info{
            .version = protocol_version::http3,
            .scope = error_scope::connection,
            .condition = error_condition::malformed_frame,
            .exchange_identity = std::nullopt,
            .library_code = std::nullopt,
            .retryable = false,
        },
        close_connection{error_code{wire_code}},
        "http/3: ",
        detail);
}

// RFC 9114 §5.2 — requests rejected by GOAWAY were not processed and can be
// retried on another connection. The peer already sent the required signal,
// so no additional wire action belongs to this failure.
inline auto make_goaway_rejection(std::optional<std::uint64_t> exchange)
    -> protocol_error
{
    return http::detail::make_goaway_rejection(
        protocol_version::http3, exchange, "http/3: ");
}

// RFC 9114 §6.1 — "HTTP/3 does not use server-initiated bidirectional streams,
// though an extension could define a use for these streams. Clients MUST treat
// receipt of a server-initiated bidirectional stream as a connection error of
// type H3_STREAM_CREATION_ERROR unless such an extension has been negotiated."
// Peer-initiated streams are classified by the transport-declared access of
// the accepted handle, not by guessing from the numeric stream ID: a
// receive-only stream carries a unidirectional stream header (RFC 9114 §6.2);
// a bidirectional stream is a request stream, which only a server may receive.
// An accepted send-only stream violates the stream_accepting contract.
inline auto accepted_stream_is_unidirectional(conn_context& ctx, nghttp3_conn* conn, stream_access access) -> bool {
    switch (access) {
        case stream_access::receive_only:
            return true;
        case stream_access::bidirectional:
            if (ctx.is_client)
                throw make_frame_error(ctx, conn, NGHTTP3_H3_STREAM_CREATION_ERROR, "server-initiated bidirectional stream");
            return false;
        case stream_access::send_only:
            break;
    }
    throw protocol_error{
        error_info{
            .version = protocol_version::http3,
            .scope = error_scope::connection,
            .condition = error_condition::transport_contract_violation,
            .exchange_identity = std::nullopt,
            .library_code = std::nullopt,
            .retryable = false,
        },
        no_action{},
        "http/3: stream factory accepted a send-only stream"};
}

// RFC 9114 §4.1.2 — "Malformed requests or responses that are detected MUST
// be treated as a stream error of type H3_MESSAGE_ERROR." Records the stream
// error (reset at the sole nghttp3 owner) and returns the typed stream-scoped
// failure. |wire_code| is the H3 application error code the stream is reset
// with — H3_MESSAGE_ERROR for malformed messages, H3_REQUEST_INCOMPLETE for a
// request stream that terminated without a complete request (RFC 9114 §4.1).
// |liberr| is the nghttp3 library code when the malformed message was
// detected by nghttp3 itself, and nullopt when the library's own validation
// (RFC 9110 §15 status range, local frame truncation) rejected the message.
inline auto make_stream_message_error(conn_context& ctx, nghttp3_conn* conn,
                                      std::int64_t stream_id,
                                      std::uint64_t wire_code,
                                      std::optional<int> liberr,
                                      std::string_view detail) -> protocol_error {
    record_stream_error(ctx, conn, stream_id, wire_code);
    return http::detail::make_protocol_error(
        error_info{
            .version = protocol_version::http3,
            .scope = error_scope::stream,
            .condition = error_condition::malformed_message,
            .exchange_identity = static_cast<std::uint64_t>(stream_id),
            .library_code = liberr,
            .retryable = false,
        },
        reset_stream{error_code{wire_code}},
        "http/3: ",
        detail);
}

// RFC 9114 §4.1 — "If a client-initiated stream terminates without enough of
// the HTTP message to provide a complete response, the server SHOULD abort
// its response stream with the error code H3_REQUEST_INCOMPLETE." A stream
// that reaches FIN at a frame boundary without a complete message never
// carried a fully formed request/response: the server aborts its response
// stream with H3_REQUEST_INCOMPLETE; the client's incomplete response is a
// malformed message (RFC 9114 §4.1.2 — "Malformed requests or responses that
// are detected MUST be treated as a stream error of type H3_MESSAGE_ERROR").
// This is distinct from a last frame truncated by FIN, which RFC 9114 §7.1 —
// "When a stream terminates cleanly, if the last frame on the stream was
// truncated, this MUST be treated as a connection error of type
// H3_FRAME_ERROR" — makes a connection error; see process_request_stream.
// nghttp3 reports the frame-boundary case as H3_FRAME_UNEXPECTED (FIN before
// any frame starts) and the truncated-frame case as H3_FRAME_ERROR.
inline auto make_incomplete_message_error(conn_context& ctx, nghttp3_conn* conn,
                                          std::int64_t stream_id,
                                          int liberr) -> protocol_error {
    return make_stream_message_error(
        ctx, conn, stream_id,
        ctx.is_client ? NGHTTP3_H3_MESSAGE_ERROR : NGHTTP3_H3_REQUEST_INCOMPLETE,
        liberr,
        std::format("stream terminated without a complete message ({})",
                    nghttp3_strerror(liberr)));
}

// Marks every in-flight stream aborted, records the failure, and wakes all
// waiters so no operation hangs once the driver has stopped. The stream_factory
// concept requires driver and reader completions to resume serially.
inline void fail_connection(conn_context& ctx, std::exception_ptr failure) {
    if (ctx.core.connection_error)
        return;
    for (auto& [_, stream] : ctx.core.streams)
        stream->core.aborted = true;
    // Move the map out before waking anybody: terminate_outbound_body resumes
    // each exchange's pump synchronously, and the operation erases its own
    // outbound-bodies entry when the pump returns — erasing from a map while
    // iterating it is undefined behavior.
    auto outbound_bodies = std::exchange(ctx.core.outbound_bodies, {});
    for (auto& [_, body] : outbound_bodies)
        terminate_outbound_body(*body);
    http::detail::fail_connection(ctx.core, std::move(failure));
}

[[nodiscard]] inline auto reset_code(const std::exception_ptr& failure)
    -> std::optional<std::uint64_t>
{
    try {
        std::rethrow_exception(failure);
    } catch (const protocol_error& error) {
        if (!std::holds_alternative<reset_stream>(error.action()))
            return std::nullopt;
        const auto& reset = std::get<reset_stream>(error.action());
        if (!std::holds_alternative<error_code>(reset.code))
            return std::nullopt;
        return std::get<error_code>(reset.code).value;
    } catch (...) {
        return std::nullopt;
    }
}

// The transport's stream identity is opaque to the application; the H3 layer
// converts it to the wire stream ID (RFC 9114 §4.1 — request/response streams
// are identified by their QUIC stream ID).
[[nodiscard]] inline auto to_stream_id(http::stream_identifier identifier) -> std::int64_t {
    return static_cast<std::int64_t>(identifier.value);
}

struct body_data_awaiter {
    std::shared_ptr<stream_data> stream;
    std::stop_token stop;

    // Claims the waiter slot exactly once: normal completion
    // (resume_body_waiter) and the stop callback race for the single slot,
    // and whoever exchanges the handle out owns the resumption, so the
    // coroutine resumes exactly once. The loser finds an empty slot and does
    // nothing.
    struct stop_claim {
        std::shared_ptr<stream_data> stream;
        void operator()() const noexcept {
            if (auto handle = stream->core.body_waiter.take(); handle) {
                stream->body_read_cancelled = true;
                handle.resume();
            }
        }
    };

    [[nodiscard]] auto await_ready() const noexcept -> bool {
        return !stream->body.empty() || stream->core.complete ||
               stream->core.aborted;
    }
    auto await_suspend(std::coroutine_handle<> handle) -> bool {
        stream->core.body_waiter.park(handle);
        if (stop.stop_requested()) {
            // Stop raced with the suspension: claim the slot and complete
            // inline. Registering a std::stop_callback here instead would
            // fire reentrantly inside its constructor.
            static_cast<void>(stream->core.body_waiter.take());
            stream->body_read_cancelled = true;
            return false;
        }
        if (stop.stop_possible())
            callback.emplace(stop, stop_claim{stream});
        return true;
    }
    void await_resume() const {
        if (stream->body_read_cancelled) {
            stream->body_read_cancelled = false;
            throw std::system_error(
                std::make_error_code(std::errc::operation_canceled));
        }
    }

    std::optional<std::stop_callback<stop_claim>> callback{};
};

struct headers_awaiter {
    std::shared_ptr<stream_data> stream;

    [[nodiscard]] auto await_ready() const noexcept -> bool {
        return stream->core.headers_done || stream->core.aborted;
    }
    void await_suspend(std::coroutine_handle<> handle) {
        stream->core.headers_waiter.park(handle);
    }
    void await_resume() const noexcept {}
};

struct body_capacity_awaiter {
    std::shared_ptr<stream_data> stream;

    [[nodiscard]] auto await_ready() const noexcept -> bool {
        return stream->buffered_body_size < body_buffer_limit ||
               stream->core.complete || stream->core.aborted;
    }
    void await_suspend(std::coroutine_handle<> handle) {
        stream->core.capacity_waiter.park(handle);
    }
    void await_resume() const noexcept {}
};

struct connection_deleter {
    void operator()(nghttp3_conn* connection) const noexcept {
        nghttp3_conn_del(connection);
    }
};

using connection_handle =
    http::detail::engine_handle<nghttp3_conn, connection_deleter>;

} // namespace detail

} // namespace http::v3
