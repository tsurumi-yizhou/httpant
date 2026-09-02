module;

#include <nghttp3/nghttp3.h>

#include <algorithm>
#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <exception>
#include <format>
#include <memory>
#include <optional>
#include <span>
#include <stdexcept>
#include <stop_token>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

export module httpant:parse.nghttp3;

import :trait;
import :message;
import :error;
import :session.nghttp3;

export namespace http::v3 {

namespace detail {

inline void rethrow_callback_failure(conn_context& ctx) {
    if (!ctx.core.pending_callback_failure) return;
    auto failure = std::exchange(ctx.core.pending_callback_failure, {});
    std::rethrow_exception(failure);
}

// Parse a :status pseudo-header value through the shared non-throwing parser
// (httpant:message) — wire input is untrusted (RFC 9114 §4.3.2), and the
// throwing wrapper keeps this call site's error channel unchanged.
// RFC 9110 §15 — "All valid status codes are within the range of 100 to 599,
// inclusive." nghttp3 already pre-validates the three-digit form and rejects
// 101 for HTTP/3 (RFC 9114 §4.5 — "HTTP/3 does not support the HTTP Upgrade
// mechanism ... or the 101 (Switching Protocols) informational status code"),
// so this range check is a local backstop;
// an out-of-range code is a malformed message (RFC 9114 §4.1.2), not a
// connection error. The shared parser is stricter than the local copy it
// replaced: trailing garbage after the digits is rejected as well.
inline auto parse_status(std::string_view value) -> std::uint16_t {
    auto parsed = http::detail::parse_status(value);
    if (!parsed)
        throw std::runtime_error("http/3: malformed :status pseudo-header");
    return *parsed;
}

inline auto rcbuf_to_string(nghttp3_rcbuf* buf) -> std::string {
    auto vec = nghttp3_rcbuf_get_buf(buf);
    return std::string(reinterpret_cast<const char*>(vec.base), vec.len);
}

inline auto span_bytes(const std::vector<std::byte>& bytes) -> std::span<const std::byte> {
    return {bytes.data(), bytes.size()};
}

inline void append_bytes(std::vector<std::byte>& dst, std::span<const std::byte> src) {
    dst.insert(dst.end(), src.begin(), src.end());
}

// RFC 9000 §16 — QUIC variable-length integers are encoded with a 2-bit
// prefix of the first byte selecting the length. Decoding delegates to the
// public nghttp3 varint API (nghttp3_get_uvarintlen / nghttp3_get_uvarint,
// public since nghttp3 1.17). The nghttp3 getters assume a valid, complete
// buffer, so the length check against the span size stays here: a buffer too
// short to hold the full varint returns false without decoding.
inline auto try_decode_varint(std::span<const std::byte> src, std::size_t& consumed, std::uint64_t& value) -> bool {
    if (src.empty()) return false;

    auto first = std::to_integer<std::uint8_t>(src.front());
    auto length = nghttp3_get_uvarintlen(&first);
    if (src.size() < length) return false;

    auto raw = reinterpret_cast<const uint8_t*>(src.data());
    std::uint64_t decoded = 0;
    const auto* end = nghttp3_get_uvarint(&decoded, raw);
    // The getters read exactly |length| bytes (RFC 9000 §16), so the returned
    // end pointer lands past the encoded integer.
    assert(end == raw + length);
    value = decoded;
    consumed = length;
    return true;
}

// RFC 9114 §7.1 — "A frame payload that contains additional bytes after the identified fields or a frame payload that terminates before the end of the identified fields MUST be treated as a connection error of type H3_FRAME_ERROR."
inline auto decode_exact_varint(conn_context& ctx, nghttp3_conn* conn, std::span<const std::byte> src, std::string_view what) -> std::uint64_t {
    std::size_t consumed = 0;
    std::uint64_t value = 0;
    if (!try_decode_varint(src, consumed, value) || consumed != src.size())
        throw make_frame_error(ctx, conn, NGHTTP3_H3_FRAME_ERROR, std::string("malformed ") + std::string(what));
    return value;
}

// RFC 9114 §7.1 — "All frames have the following format: HTTP/3 Frame Format { Type (i), Length (i), Frame Payload (..) }"
struct parsed_frame {
    std::uint64_t type{0};
    std::vector<std::byte> payload{};
    std::vector<std::byte> raw{};
};

inline auto try_pop_frame(std::vector<std::byte>& buffer, parsed_frame& frame) -> bool {
    std::size_t type_len = 0;
    std::uint64_t type = 0;
    if (!try_decode_varint(span_bytes(buffer), type_len, type)) return false;

    std::size_t length_len = 0;
    std::uint64_t payload_length = 0;
    auto rest = span_bytes(buffer).subspan(type_len);
    if (!try_decode_varint(rest, length_len, payload_length)) return false;

    auto frame_length = type_len + length_len + static_cast<std::size_t>(payload_length);
    if (buffer.size() < frame_length) return false;

    frame.type = type;
    frame.raw.assign(buffer.begin(), buffer.begin() + frame_length);
    frame.payload.assign(buffer.begin() + type_len + length_len, buffer.begin() + frame_length);
    buffer.erase(buffer.begin(), buffer.begin() + frame_length);
    return true;
}

// Forwards bytes on |stream_id| into the nghttp3 conn and returns the number
// of bytes nghttp3 reports as consumed. nghttp3_conn_read_stream's return
// value is the amount the application may grant as QUIC flow-control credit,
// and it deliberately excludes DATA-frame payload bytes (those reach the
// application through the recv_data callback instead).
//
// RFC 9114 §4.1.2 — "Malformed requests or responses that are detected MUST
// be treated as a stream error of type H3_MESSAGE_ERROR." nghttp3 reports
// malformed messages as NGHTTP3_ERR_MALFORMED_HTTP_HEADER /
// NGHTTP3_ERR_MALFORMED_HTTP_MESSAGING, whose mapped application code is
// H3_MESSAGE_ERROR (0x010e); those and other stream-scoped HTTP/3 errors are
// closed on the offending stream only, so the connection and its concurrent
// exchanges keep running. Only errors that affect the whole connection
// (nghttp3_err_is_fatal, plus connection-wide states like QPACK corruption)
// escalate to a connection error.
inline auto forward_stream_input(conn_context& ctx, nghttp3_conn* conn, std::int64_t stream_id, std::span<const std::byte> data, bool fin) -> std::size_t {
    static constexpr std::array<std::byte, 1> empty{std::byte{0}};
    auto bytes = data.empty() ? std::span<const std::byte>{empty.data(), 0} : data;
    auto consumed = nghttp3_conn_read_stream(
        conn,
        stream_id,
        reinterpret_cast<const uint8_t*>(bytes.data()),
        bytes.size(),
        fin ? 1 : 0);
    if (consumed < 0) {
        rethrow_callback_failure(ctx);
        auto liberr = static_cast<int>(consumed);
        auto wire_code = nghttp3_err_infer_quic_app_error_code(liberr);
        if (liberr == NGHTTP3_ERR_MALFORMED_HTTP_HEADER ||
            liberr == NGHTTP3_ERR_MALFORMED_HTTP_MESSAGING) {
            // RFC 9114 §4.1.2 — "Malformed requests or responses that are
            // detected MUST be treated as a stream error of type
            // H3_MESSAGE_ERROR." nghttp3 reports a malformed message with
            // these codes, whose mapped application code is H3_MESSAGE_ERROR;
            // RFC 9114 §8 — "QUIC allows the application to abruptly
            // terminate (reset) that stream and communicate a reason."
            // Only the offending stream is reset (verified against the
            // reference backend: the connection keeps serving its other
            // exchanges), so concurrent exchanges survive.
            throw make_stream_message_error(
                ctx, conn, stream_id, NGHTTP3_H3_MESSAGE_ERROR, liberr,
                std::format("malformed message on stream {} ({})",
                            stream_id, nghttp3_strerror(liberr)));
        }
        if (fin && liberr == NGHTTP3_ERR_H3_FRAME_UNEXPECTED) {
            // RFC 9114 §7.1 — "When a stream terminates cleanly, if the last
            // frame on the stream was truncated, this MUST be treated as a
            // connection error of type H3_FRAME_ERROR." httpant forwards only
            // complete frames to nghttp3 (process_request_stream pops frames
            // from its local buffer first), so nghttp3 never observes a last
            // frame truncated by FIN here — that case is intercepted locally
            // and already closes the connection with H3_FRAME_ERROR. The
            // remaining fin-time frame error is H3_FRAME_UNEXPECTED, which
            // nghttp3 reports when FIN arrives before any frame starts: the
            // stream terminates at a frame boundary without a complete
            // message and keeps the §4.1 / §4.1.2 stream errors (see
            // make_incomplete_message_error). A mid-stream frame violation is
            // reported with fin == false and stays a connection error
            // (RFC 9114 §4.1 — "Receipt of an invalid sequence of frames MUST
            // be treated as a connection error of type H3_FRAME_UNEXPECTED").
            throw make_incomplete_message_error(ctx, conn, stream_id, liberr);
        }
        // RFC 9114 §8 — any other negative return means the whole connection
        // must be closed; map the library error to its H3 application error
        // code (Section 8.1) and record it so the upper layer can carry it on
        // the QUIC CONNECTION_CLOSE.
        record_connection_error(ctx, conn, wire_code);
        auto condition = liberr == NGHTTP3_ERR_QPACK_DECOMPRESSION_FAILED ||
                liberr == NGHTTP3_ERR_QPACK_ENCODER_STREAM_ERROR ||
                liberr == NGHTTP3_ERR_QPACK_DECODER_STREAM_ERROR
            ? error_condition::compression_failure
            : error_condition::library_failure;
        throw protocol_error{
            error_info{
                .version = protocol_version::http3,
                .scope = error_scope::connection,
                .condition = condition,
                .exchange_identity = std::nullopt,
                .library_code = liberr,
                .retryable = false,
            },
            close_connection{error_code{wire_code}},
            std::format("http/3: read_stream failed ({})", nghttp3_strerror(liberr))};
    }
    rethrow_callback_failure(ctx);
    return static_cast<std::size_t>(consumed);
}

inline auto process_control_stream(conn_context& ctx, nghttp3_conn* conn, std::int64_t stream_id, stream_input_state& input) -> std::size_t {
    std::vector<std::byte> forward;
    std::size_t consumed = 0;
    while (true) {
        parsed_frame frame;
        if (!try_pop_frame(input.buffer, frame)) break;

        // RFC 9114 §6.2.1 — "If the first frame of the control stream is any other frame type, this MUST be treated as a connection error of type H3_MISSING_SETTINGS."
        if (!input.settings_seen) {
            if (frame.type != settings_frame_type)
                throw make_frame_error(ctx, conn, NGHTTP3_H3_MISSING_SETTINGS, "control stream is missing initial SETTINGS frame");
            input.settings_seen = true;
        // RFC 9114 §7.2.4 — "If an endpoint receives a second SETTINGS frame on the control stream, the endpoint MUST respond with a connection error of type H3_FRAME_UNEXPECTED."
        } else if (frame.type == settings_frame_type) {
            throw make_frame_error(ctx, conn, NGHTTP3_H3_FRAME_UNEXPECTED, "duplicate SETTINGS frame on control stream");
        }

        switch (frame.type) {
            case settings_frame_type:
                append_bytes(forward, frame.raw);
                break;
            case goaway_frame_type: {
                auto id = decode_exact_varint(ctx, conn, span_bytes(frame.payload), "GOAWAY payload");
                // RFC 9114 §5.2 — "Receiving a GOAWAY containing a larger identifier than previously received MUST be treated as a connection error of type H3_ID_ERROR."
                if (ctx.core.goaway_id && id > *ctx.core.goaway_id)
                    throw make_frame_error(ctx, conn, NGHTTP3_H3_ID_ERROR, "GOAWAY identifier increased");
                append_bytes(forward, frame.raw);
                break;
            }
            case max_push_id_frame_type: {
                // RFC 9114 §7.2.7 — "A server MUST NOT send a MAX_PUSH_ID frame. A client MUST treat the receipt of a MAX_PUSH_ID frame as a connection error of type H3_FRAME_UNEXPECTED."
                if (ctx.is_client)
                    throw make_frame_error(ctx, conn, NGHTTP3_H3_FRAME_UNEXPECTED, "server sent MAX_PUSH_ID on control stream");
                auto id = decode_exact_varint(ctx, conn, span_bytes(frame.payload), "MAX_PUSH_ID payload");
                // RFC 9114 §7.2.7 — "A MAX_PUSH_ID frame cannot reduce the maximum push ID; receipt of a MAX_PUSH_ID frame that contains a smaller value than previously received MUST be treated as a connection error of type H3_ID_ERROR."
                if (ctx.peer_max_push_id && id < *ctx.peer_max_push_id)
                    throw make_frame_error(ctx, conn, NGHTTP3_H3_ID_ERROR, "peer reduced MAX_PUSH_ID");
                ctx.peer_max_push_id = id;
                // This frame is consumed by the library (not forwarded to
                // nghttp3), so its bytes count as consumed for flow-control
                // credit purposes.
                consumed += frame.raw.size();
                break;
            }
            case cancel_push_frame_type: {
                static_cast<void>(decode_exact_varint(
                    ctx, conn, span_bytes(frame.payload), "CANCEL_PUSH payload"));
                if (!ctx.is_client) {
                    // RFC 9114 §7.2.3 — "If a server receives a CANCEL_PUSH
                    // frame for a push ID that has not yet been mentioned by a
                    // PUSH_PROMISE frame, this MUST be treated as a connection
                    // error of type H3_ID_ERROR." httpant never sends
                    // PUSH_PROMISE, so every push ID is unmentioned here.
                    throw make_frame_error(
                        ctx, conn, NGHTTP3_H3_ID_ERROR,
                        "CANCEL_PUSH for unknown push ID");
                }
                // RFC 9114 §7.2.3 — "If the client receives a CANCEL_PUSH
                // frame, that frame might identify a push ID that has not yet
                // been mentioned by a PUSH_PROMISE frame due to reordering."
                // The client therefore tolerates the cancellation: httpant
                // never advertises MAX_PUSH_ID and never promises pushes, so
                // there is no push state to update. The frame is consumed
                // (its bytes count as consumed for flow-control credit below).
                consumed += frame.raw.size();
                break;
            }
            default:
                append_bytes(forward, frame.raw);
                break;
        }
    }

    if (input.closed) {
        // RFC 9114 §7.1 — "When a stream terminates cleanly, if the last frame on the stream was truncated, this MUST be treated as a connection error of type H3_FRAME_ERROR."
        if (!input.buffer.empty())
            throw make_frame_error(ctx, conn, NGHTTP3_H3_FRAME_ERROR, "truncated control stream frame");
        if (!forward.empty())
            consumed += forward_stream_input(ctx, conn, stream_id, span_bytes(forward), false);
        // RFC 9114 §6.2.1 — "If either control stream is closed at any point, this MUST be treated as a connection error of type H3_CLOSED_CRITICAL_STREAM."
        // The closure is reported before forwarding fin so the accurate typed
        // H3 error is recorded instead of a generic backend failure.
        throw make_frame_error(ctx, conn, NGHTTP3_H3_CLOSED_CRITICAL_STREAM, "control stream was closed");
    }

    if (!forward.empty())
        consumed += forward_stream_input(ctx, conn, stream_id, span_bytes(forward), false);
    return consumed;
}

inline auto process_request_stream(conn_context& ctx, nghttp3_conn* conn, std::int64_t stream_id, stream_input_state& input) -> std::size_t {
    std::vector<std::byte> forward;
    std::size_t consumed = 0;
    while (true) {
        parsed_frame frame;
        if (!try_pop_frame(input.buffer, frame)) break;

        if (!ctx.is_client) {
            // RFC 9114 §7.2.5 — "A client MUST NOT send a PUSH_PROMISE frame. A server MUST treat the receipt of a PUSH_PROMISE frame as a connection error of type H3_FRAME_UNEXPECTED."
            if (frame.type == push_promise_frame_type)
                throw make_frame_error(ctx, conn, NGHTTP3_H3_FRAME_UNEXPECTED, "client sent PUSH_PROMISE on request stream");
            append_bytes(forward, frame.raw);
            continue;
        }

        if (frame.type == push_promise_frame_type) {
            std::size_t push_id_len = 0;
            std::uint64_t push_id = 0;
            if (!try_decode_varint(span_bytes(frame.payload), push_id_len, push_id))
                throw make_frame_error(ctx, conn, NGHTTP3_H3_FRAME_ERROR, "malformed PUSH_PROMISE payload");
            static_cast<void>(push_id_len);
            static_cast<void>(push_id);
            // RFC 9114 §7.2.5 — this endpoint never advertises MAX_PUSH_ID;
            // therefore every promised push exceeds the permitted push ID.
            throw make_frame_error(
                ctx, conn, NGHTTP3_H3_ID_ERROR,
                "received PUSH_PROMISE without MAX_PUSH_ID");
        }

        append_bytes(forward, frame.raw);
    }

    if (input.closed && !input.buffer.empty()) {
        // RFC 9114 §7.1 — "When a stream terminates cleanly, if the last frame
        // on the stream was truncated, this MUST be treated as a connection
        // error of type H3_FRAME_ERROR." A partial frame left buffered at FIN
        // is a last frame truncated by the clean stream termination; the rule
        // is generic over streams, so a request/response stream closes the
        // connection too — unlike a frame-boundary termination, which keeps
        // the §4.1 H3_REQUEST_INCOMPLETE / §4.1.2 H3_MESSAGE_ERROR stream
        // errors (see make_incomplete_message_error). The control/QPACK
        // streams apply the same §7.1 rule above.
        throw make_frame_error(
            ctx, conn, NGHTTP3_H3_FRAME_ERROR,
            ctx.is_client ? "truncated response frame"
                          : "truncated request frame");
    }

    if (!forward.empty() || input.closed)
        consumed += forward_stream_input(ctx, conn, stream_id, span_bytes(forward), input.closed);
    return consumed;
}

// Consumes |data| on |stream_id| and returns the number of bytes the library
// has consumed, i.e. the amount the caller may grant as QUIC flow-control
// credit for this stream. This is the sum of:
//   - bytes nghttp3_conn_read_stream reported as consumed for frames forwarded
//     to the nghttp3 conn (its return value excludes DATA-frame payload, which
//     reaches the application through the recv_data callback), plus
//   - bytes of control frames the library parsed itself.
// The caller must NOT grant credit for the raw input size, or the peer's flow
// control would be inflated (RFC 9114 §6.1 / [QUIC-TRANSPORT] §4.1).
// |unidirectional| is the direction declared by the stream handle's access()
// (accepted_stream_is_unidirectional), not a guess from the numeric stream ID.
inline auto process_input(conn_context& ctx, nghttp3_conn* conn, std::int64_t stream_id, bool unidirectional, std::span<const std::byte> data, bool fin) -> std::size_t {
    auto& input = ctx.inputs[stream_id];
    append_bytes(input.buffer, data);
    input.closed = input.closed || fin;
    std::size_t consumed = 0;

    if (unidirectional && !input.stream_type_known) {
        std::size_t type_len = 0;
        std::uint64_t stream_type = 0;
        if (!try_decode_varint(span_bytes(input.buffer), type_len, stream_type)) {
            if (input.closed)
                throw make_frame_error(ctx, conn, NGHTTP3_H3_FRAME_ERROR, "truncated unidirectional stream type");
            return consumed;
        }

        input.stream_type_known = true;
        input.stream_type = stream_type;

        switch (stream_type) {
            case control_stream_type:
                input.kind = stream_kind::control;
                // RFC 9114 §6.2.1 — "Only one control stream per peer is permitted; receipt of a second stream claiming to be a control stream MUST be treated as a connection error of type H3_STREAM_CREATION_ERROR."
                if (ctx.remote_control_stream_id && *ctx.remote_control_stream_id != stream_id)
                    throw make_frame_error(ctx, conn, NGHTTP3_H3_STREAM_CREATION_ERROR, "received duplicate control stream");
                ctx.remote_control_stream_id = stream_id;
                break;
            case push_stream_type:
                // RFC 9114 §4.6 — no MAX_PUSH_ID is advertised while H3 push
                // is unavailable, so every received push stream is invalid.
                throw make_frame_error(
                    ctx,
                    conn,
                    ctx.is_client ? NGHTTP3_H3_ID_ERROR
                                  : NGHTTP3_H3_STREAM_CREATION_ERROR,
                    "received push stream while server push is disabled");
            case qpack_encoder_stream_type:
                // RFC 9204 §4.2 — "Each endpoint MUST initiate, at most, one encoder stream and, at most, one decoder stream. Receipt of a second instance of either stream type MUST be treated as a connection error of type H3_STREAM_CREATION_ERROR."
                if (ctx.remote_qpack_encoder_stream_id)
                    throw make_frame_error(ctx, conn, NGHTTP3_H3_STREAM_CREATION_ERROR, "duplicate QPACK encoder stream");
                ctx.remote_qpack_encoder_stream_id = stream_id;
                input.kind = stream_kind::qpack;
                break;
            case qpack_decoder_stream_type:
                if (ctx.remote_qpack_decoder_stream_id)
                    throw make_frame_error(ctx, conn, NGHTTP3_H3_STREAM_CREATION_ERROR, "duplicate QPACK decoder stream");
                ctx.remote_qpack_decoder_stream_id = stream_id;
                input.kind = stream_kind::qpack;
                break;
            default:
                input.kind = stream_kind::ignored;
                break;
        }

        if (input.kind == stream_kind::control || input.kind == stream_kind::qpack) {
            auto prefix = std::vector<std::byte>{input.buffer.begin(), input.buffer.begin() + static_cast<std::ptrdiff_t>(type_len)};
            consumed += forward_stream_input(ctx, conn, stream_id, span_bytes(prefix), false);
        } else {
            consumed += type_len;
        }
        input.buffer.erase(input.buffer.begin(), input.buffer.begin() + static_cast<std::ptrdiff_t>(type_len));
    }

    if (!unidirectional)
        input.kind = stream_kind::request;

    switch (input.kind) {
        case stream_kind::request:
            consumed += process_request_stream(ctx, conn, stream_id, input);
            break;
        case stream_kind::control:
            consumed += process_control_stream(ctx, conn, stream_id, input);
            break;
        case stream_kind::qpack: {
            // RFC 9114 §4.2.1 — the peer's QPACK encoder/decoder stream carries
            // dynamic-table updates and insert-count acknowledgements. The
            // nghttp3 connection is the sole QPACK owner and sole reader of
            // both unidirectional streams.
            if (!input.buffer.empty()) {
                auto buffered = std::move(input.buffer);
                input.buffer.clear();
                consumed += forward_stream_input(ctx, conn, stream_id, span_bytes(buffered), false);
            }
            // RFC 9204 §4.2 — "The sender MUST NOT close either of these streams, and the receiver MUST NOT request that the sender close either of these streams. Closure of either unidirectional stream type MUST be treated as a connection error of type H3_CLOSED_CRITICAL_STREAM."
            // The closure is reported before forwarding fin so the accurate
            // typed H3 error is recorded instead of a generic backend failure.
            if (input.closed)
                throw make_frame_error(ctx, conn, NGHTTP3_H3_CLOSED_CRITICAL_STREAM, "QPACK stream was closed");
            break;
        }
        // RFC 9114 §6.2 — "Recipients of unknown stream types MUST either abort reading of the stream or discard incoming data without further processing."
        case stream_kind::ignored: {
            // httpant discards: the stream-type bytes were credited above and
            // every subsequent chunk is dropped and credited immediately
            // instead of being buffered to FIN, so memory is bounded and the
            // peer's flow-control window keeps advancing (RFC 9114 §6.2
            // "discard incoming data without further processing").
            consumed += input.buffer.size();
            input.buffer.clear();
            break;
        }
    }
    return consumed;
}

inline auto make_callbacks() -> nghttp3_callbacks {
    nghttp3_callbacks cbs{};

    cbs.stream_close = [](nghttp3_conn*, std::int64_t stream_id,
                          std::uint64_t app_error_code,
                          void* ud, void*) -> int {
        auto& ctx = *static_cast<conn_context*>(ud);
        return http::detail::callback_boundary(ctx, NGHTTP3_ERR_CALLBACK_FAILURE, [&] {
            mark_stream_closed(ctx, stream_id, app_error_code);
        });
    };

    cbs.acked_stream_data = [](nghttp3_conn*, std::int64_t stream_id,
                               std::uint64_t datalen, void* ud, void*) -> int {
        auto& ctx = *static_cast<conn_context*>(ud);
        return http::detail::callback_boundary(ctx, NGHTTP3_ERR_CALLBACK_FAILURE, [&] {
            auto it = ctx.core.outbound_bodies.find(stream_id);
            if (it == ctx.core.outbound_bodies.end())
                return;
            auto& state = *it->second;
            if (datalen > state.data.size() - state.acknowledged)
                throw std::runtime_error("http/3: acknowledgement exceeds retained body data");
            state.acknowledged += static_cast<std::size_t>(datalen);
            if (state.acknowledged == state.data.size()) {
                state.data.clear();
                state.acknowledged = 0;
                state.offered = false;
                state.resume_ack_waiter();
            }
        });
    };

    cbs.recv_settings2 = [](
        nghttp3_conn*,
        const nghttp3_proto_settings* settings,
        void* ud) -> int {
        auto& ctx = *static_cast<conn_context*>(ud);
        return http::detail::callback_boundary(ctx, NGHTTP3_ERR_CALLBACK_FAILURE, [&] {
            ctx.peer_decoder_capacity = settings->qpack_max_dtable_capacity;
            ctx.peer_blocked_streams = settings->qpack_blocked_streams;
            ctx.peer_max_field_section_size = settings->max_field_section_size;
        });
    };

    cbs.shutdown = [](nghttp3_conn*, std::int64_t id, void* ud) -> int {
        auto& ctx = *static_cast<conn_context*>(ud);
        return http::detail::callback_boundary(ctx, NGHTTP3_ERR_CALLBACK_FAILURE, [&] {
            ctx.core.goaway_received = true;
            auto identifier = static_cast<std::uint64_t>(id);
            if (!ctx.core.goaway_id || identifier < *ctx.core.goaway_id)
                ctx.core.goaway_id = identifier;
            // RFC 9114 §5.2 — "Upon receipt of a GOAWAY frame, if the client
            // has already sent requests with a stream ID greater than or equal
            // to the identifier contained in the GOAWAY frame, those requests
            // will not be processed. Clients can safely retry unprocessed
            // requests on a different HTTP connection." Wake the header
            // waiters of streams at/above the boundary so a parked request
            // re-evaluates the GOAWAY check and fails with the retryable
            // rejection instead of hanging until the connection fails
            // (mirrors v2's notify_waiters after each driver cycle).
            for (auto& [stream_id, stream] : ctx.core.streams)
                if (static_cast<std::uint64_t>(stream_id) >= *ctx.core.goaway_id)
                    stream->core.resume_waiter();
        });
    };

    cbs.recv_header = [](nghttp3_conn* conn, std::int64_t stream_id,
                         std::int32_t, nghttp3_rcbuf* name,
                         nghttp3_rcbuf* value, std::uint8_t,
                         void* ud, void*) -> int {
        auto& ctx = *static_cast<conn_context*>(ud);
        return http::detail::callback_boundary(ctx, NGHTTP3_ERR_CALLBACK_FAILURE, [&] {
            auto it = ctx.core.streams.find(stream_id);
            if (it == ctx.core.streams.end()) return;
            auto n = rcbuf_to_string(name);
            auto v = rcbuf_to_string(value);
            // RFC 9114 §4.2.2 — field-section size is the sum of each field's
            // name length, value length, and 32 bytes of overhead.
            auto entry_size = static_cast<std::uint64_t>(
                n.size() + v.size() + field_entry_overhead);
            auto maximum = ctx.local_configuration.maximum_field_section_size;
            if (entry_size > maximum ||
                it->second->field_section_size > maximum - entry_size) {
                record_stream_error(
                    ctx, conn, stream_id, NGHTTP3_H3_EXCESSIVE_LOAD);
                throw protocol_error{
                    error_info{
                        .version = protocol_version::http3,
                        .scope = error_scope::stream,
                        .condition = error_condition::resource_limit,
                        .exchange_identity = static_cast<std::uint64_t>(stream_id),
                        .library_code = std::nullopt,
                        .retryable = false,
                    },
                    reset_stream{error_code{NGHTTP3_H3_EXCESSIVE_LOAD}},
                    "http/3: field section exceeds configured maximum"};
            }
            it->second->field_section_size += entry_size;
            if (n == ":status") {
                try {
                    it->second->core.status_code =
                        static_cast<http::status>(parse_status(v));
                } catch (const std::runtime_error&) {
                    // RFC 9114 §4.1.2 — a :status outside the 100-599 range
                    // (RFC 9110 §15 — "All valid status codes are within the
                    // range of 100 to 599, inclusive") makes the response
                    // malformed; treat it as a stream error of type
                    // H3_MESSAGE_ERROR rather than a connection error.
                    throw make_stream_message_error(
                        ctx, conn, stream_id, NGHTTP3_H3_MESSAGE_ERROR,
                        std::nullopt,
                        "malformed :status pseudo-header");
                }
            } else
                static_cast<void>(
                    it->second->core.decoded.append(std::move(n), std::move(v)));
        });
    };

    cbs.end_headers = [](nghttp3_conn* conn, std::int64_t stream_id,
                         int, void* ud, void*) -> int {
        auto& ctx = *static_cast<conn_context*>(ud);
        return http::detail::callback_boundary(ctx, NGHTTP3_ERR_CALLBACK_FAILURE, [&] {
            auto it = ctx.core.streams.find(stream_id);
            if (it == ctx.core.streams.end())
                return;
            auto& stream = *it->second;
            // RFC 9114 §4.1 — "An HTTP request/response exchange fully consumes a
            // client-initiated bidirectional QUIC stream." combined with RFC 9110
            // §15.2: informational (1xx) header blocks precede the final response
            // on the same stream and are not the final response, so they are
            // discarded and the wait for the final header block continues.
            // method_token is only set on request streams (server side), where
            // :status never appears, so this check is client-response specific.
            if (stream.core.decoded.method_token.empty() &&
                http::is_informational(stream.core.status_code)) {
                stream.core.decoded = {};
                stream.core.status_code = http::status{0};
                return;
            }
            // RFC 9114 §4.3.1 — "An OPTIONS request that does not include a
            // path component includes the value * (ASCII 0x2a) for the :path
            // pseudo-header field." Asterisk-form targets are defined only
            // for OPTIONS; RFC 9110 §7.1 — "These forms MUST NOT be used with
            // other methods." nghttp3 enforces this only for http/https
            // schemes (its path check exempts other schemes), so a non-OPTIONS
            // method with ':path: *' under any other scheme would otherwise
            // slip through; it is malformed (RFC 9114 §4.1.2 — "Malformed
            // requests or responses that are detected MUST be treated as a
            // stream error of type H3_MESSAGE_ERROR") and must never be
            // delivered to the application.
            if (!stream.core.decoded.method_token.empty() &&
                stream.core.decoded.path == "*" &&
                stream.core.decoded.method_token != "OPTIONS") {
                throw make_stream_message_error(
                    ctx, conn, stream_id, NGHTTP3_H3_MESSAGE_ERROR,
                    std::nullopt,
                    "asterisk-form :path with non-OPTIONS method");
            }
            // RFC 9114 §4.3.1 — "If both fields are present, they MUST contain
            // the same value." nghttp3 validates pseudo-header presence but
            // does not compare Host with :authority; the check shares the
            // same-origin comparison with HTTP/2 (RFC 9113 §8.3.1 — scheme/host
            // case-insensitive, default port omitted) so a mismatched request
            // is a typed H3_MESSAGE_ERROR, not a delivered request with
            // ambiguous authority.
            if (!stream.core.decoded.method_token.empty() &&
                !stream.core.decoded.authority.empty()) {
                if (auto host = http::find_header(stream.core.decoded.regular, "host")) {
                    if (!http::detail::same_origin(
                            stream.core.decoded.scheme,
                            stream.core.decoded.authority,
                            stream.core.decoded.scheme,
                            *host)) {
                        throw make_stream_message_error(
                            ctx, conn, stream_id, NGHTTP3_H3_MESSAGE_ERROR,
                            std::nullopt,
                            "Host header does not match :authority");
                    }
                }
            }
            stream.core.headers_done = true;
            if (!stream.core.decoded.method_token.empty() &&
                !stream.core.delivered) {
                stream.core.delivered = true;
                ctx.core.receive_queue_push(it->second);
                ctx.core.receive_waiter.resume();
            }
            stream.core.resume_waiter();
        });
    };

    cbs.recv_data = [](nghttp3_conn*, std::int64_t stream_id,
                       const uint8_t* data, std::size_t len,
                       void* ud, void*) -> int {
        auto& ctx = *static_cast<conn_context*>(ud);
        return http::detail::callback_boundary(ctx, NGHTTP3_ERR_CALLBACK_FAILURE, [&] {
            auto it = ctx.core.streams.find(stream_id);
            if (it != ctx.core.streams.end()) {
                auto bytes = std::as_bytes(std::span{data, len});
                it->second->body.emplace_back(bytes.begin(), bytes.end());
                it->second->buffered_body_size += len;
                it->second->core.resume_body_waiter();
            }
        });
    };

    cbs.deferred_consume = [](nghttp3_conn*, std::int64_t stream_id,
                              std::size_t consumed, void* ud, void*) -> int {
        auto& ctx = *static_cast<conn_context*>(ud);
        return http::detail::callback_boundary(ctx, NGHTTP3_ERR_CALLBACK_FAILURE, [&] {
            ctx.deferred_consumption[stream_id] += consumed;
        });
    };

    cbs.end_stream = [](nghttp3_conn*, std::int64_t stream_id,
                        void* ud, void*) -> int {
        auto& ctx = *static_cast<conn_context*>(ud);
        return http::detail::callback_boundary(ctx, NGHTTP3_ERR_CALLBACK_FAILURE, [&] {
            if (auto it = ctx.core.streams.find(stream_id); it != ctx.core.streams.end()) {
                it->second->core.complete = true;
                it->second->core.resume_waiter();
                it->second->core.resume_body_waiter();
            }
        });
    };

    cbs.begin_headers = [](nghttp3_conn*, std::int64_t stream_id,
                           void* ud, void*) -> int {
        auto& ctx = *static_cast<conn_context*>(ud);
        return http::detail::callback_boundary(ctx, NGHTTP3_ERR_CALLBACK_FAILURE, [&] {
            if (!ctx.core.streams.contains(stream_id)) {
                auto sd = std::make_shared<stream_data>();
                sd->core.id = stream_id;
                ctx.core.streams[stream_id] = sd;
            }
            ctx.core.streams.at(stream_id)->field_section_size = 0;
        });
    };

    return cbs;
}

} // namespace detail

template <stream_factory S>
class body_reader {
public:
    body_reader() = default;
    body_reader(
        std::shared_ptr<detail::stream_data> stream,
        std::shared_ptr<typename S::stream_type> transport,
        detail::conn_context& context)
        : stream_(std::move(stream)), transport_(std::move(transport)), context_(&context) {}
    body_reader(const body_reader&) = delete;
    auto operator=(const body_reader&) -> body_reader& = delete;
    body_reader(body_reader&& other) noexcept
        : stream_(std::move(other.stream_)),
          transport_(std::move(other.transport_)),
          context_(std::exchange(other.context_, nullptr)) {}
    auto operator=(body_reader&& other) noexcept -> body_reader& {
        if (this != &other) {
            release();
            stream_ = std::move(other.stream_);
            transport_ = std::move(other.transport_);
            context_ = std::exchange(other.context_, nullptr);
        }
        return *this;
    }
    ~body_reader() { release(); }

    auto async_read(
        std::span<std::byte> output,
        std::stop_token stop) -> task<std::size_t>
    {
        if (!stream_ || !transport_)
            co_return 0;
        while (stream_->body.empty() && !stream_->core.complete &&
               !stream_->core.aborted) {
            if (stop.stop_requested())
                throw std::system_error(std::make_error_code(std::errc::operation_canceled));
            co_await detail::body_data_awaiter{stream_, stop};
        }
        if (stream_->core.aborted) {
            if (stream_->close_error_code != 0) {
                // RFC 9114 §8 — a peer reset or a stream-scoped protocol error
                // recorded its application error code on this stream; surface
                // it as the typed stream action, matching the client-side
                // aborted-request path. The connection keeps running.
                throw protocol_error{
                    error_info{
                        .version = protocol_version::http3,
                        .scope = error_scope::stream,
                        .condition = error_condition::stream_reset,
                        .exchange_identity =
                            static_cast<std::uint64_t>(stream_->core.id),
                        .library_code = std::nullopt,
                        .retryable = false,
                    },
                    reset_stream{error_code{stream_->close_error_code}},
                    std::format("http/3: body stream aborted (0x{:x})",
                                stream_->close_error_code)};
            }
            throw std::runtime_error(
                "http/3: stream closed before body completed");
        }
        if (stream_->body.empty()) {
            release();
            co_return 0;
        }

        auto& chunk = stream_->body.front();
        auto remaining = chunk.size() - stream_->body_offset;
        auto size = std::min(output.size(), remaining);
        std::copy_n(chunk.data() + stream_->body_offset, size, output.data());
        stream_->body_offset += size;
        stream_->buffered_body_size -= size;
        transport_->consume(size);
        if (stream_->body_offset == chunk.size()) {
            stream_->body.pop_front();
            stream_->body_offset = 0;
        }
        stream_->core.resume_capacity_waiter();
        co_return size;
    }

private:
    void release() noexcept {
        if (!stream_)
            return;
        if (!stream_->core.complete && !stream_->core.aborted && transport_) {
            transport_->shutdown(
                stream_side::receiving,
                application_error{NGHTTP3_H3_REQUEST_CANCELLED});
        }
        if (context_)
            context_->core.streams.erase(stream_->core.id);
        stream_.reset();
        transport_.reset();
        context_ = nullptr;
    }

    std::shared_ptr<detail::stream_data> stream_{};
    std::shared_ptr<typename S::stream_type> transport_{};
    detail::conn_context* context_{nullptr};

};

} // namespace http::v3
