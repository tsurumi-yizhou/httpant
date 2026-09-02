module;

#include <nghttp2/nghttp2.h>

#include <algorithm>
#include <array>
#include <coroutine>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <format>
#include <memory>
#include <optional>
#include <ranges>
#include <span>
#include <stdexcept>
#include <stop_token>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

export module httpant:endpoint.nghttp2;

import :session.nghttp2;
import :parse.nghttp2;
import :serialize.nghttp2;
import :trait;
import :message;
import :error;

export namespace http::v2 {

namespace detail {

enum class endpoint_role {
    client,
    server,
};

inline auto create_session(
    endpoint_role role,
    session_context& context,
    const configuration& configuration) -> session_handle
{
    auto callbacks = create_callbacks();

    nghttp2_option* raw_option = nullptr;
    check(nghttp2_option_new(&raw_option), "option_new");
    auto option = option_handle{raw_option};
    nghttp2_option_set_max_deflate_dynamic_table_size(
        option.get(), configuration.compression.encoder_capacity);
    // RFC 9113 §6.9 — flow control "provides protection against denial of
    // service ... and ensures that ... resources are not consumed" by a sender
    // outrunning the receiver: automatic WINDOW_UPDATE is disabled so credit
    // returns only as the application consumes body bytes (body_reader), which
    // bounds the per-stream staging buffer by the advertised window.
    nghttp2_option_set_no_auto_window_update(option.get(), 1);

    nghttp2_session* raw_session = nullptr;
    auto result = role == endpoint_role::client
        ? nghttp2_session_client_new2(
            &raw_session, callbacks.get(), &context, option.get())
        : nghttp2_session_server_new2(
            &raw_session, callbacks.get(), &context, option.get());
    auto session = session_handle{raw_session};
    check(result, role == endpoint_role::client
        ? "session_client_new2"
        : "session_server_new2");

    // RFC 9113 §6.5.2 — advertise the receive-side limits common to both
    // endpoint roles. ENABLE_PUSH is client-only; a server MUST NOT send it.
    std::vector<nghttp2_settings_entry> settings{
        {NGHTTP2_SETTINGS_HEADER_TABLE_SIZE,
         configuration.compression.decoder_capacity},
        {NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS,
         configuration.maximum_concurrent_streams},
        {NGHTTP2_SETTINGS_MAX_HEADER_LIST_SIZE,
         configuration.maximum_field_section_size},
    };
    if (role == endpoint_role::client && !configuration.enable_push)
        settings.push_back({NGHTTP2_SETTINGS_ENABLE_PUSH, 0});

    check(nghttp2_submit_settings(
        session.get(), NGHTTP2_FLAG_NONE, settings.data(), settings.size()),
        "submit_settings");
    static_cast<void>(reserve_settings_ticket(context));
    return session;
}

inline void flush_output(nghttp2_session* session, session_context& ctx) {
    const uint8_t* data = nullptr;
    for (;;) {
        auto len = nghttp2_session_mem_send2(session, &data);
        if (len < 0) throw make_error("mem_send", static_cast<int>(len));
        if (len == 0) break;
        auto bytes = std::as_bytes(std::span{data, static_cast<std::size_t>(len)});
        ctx.outbuf.insert(ctx.outbuf.end(), bytes.begin(), bytes.end());
    }
}

inline auto write_and_clear(auto& transport, session_context& ctx) -> task<void> {
    if (!ctx.outbuf.empty()) {
        // Remove the batch from connection state before awaiting transport I/O.
        // A synchronous adapter can deliver a peer response immediately and
        // re-enter the endpoint driver; that nested flush must not resend this
        // already-accepted batch.
        auto batch = std::exchange(ctx.outbuf, {});
        co_await http::detail::write_all(
            transport,
            std::span<const std::byte>{batch.data(), batch.size()});
    }
}

template <byte_stream S>
class endpoint_runtime {
public:
    endpoint_runtime(
        S& transport,
        session_handle& session,
        session_context& context)
        : transport_(transport), session_(session), context_(context) {}

    endpoint_runtime(const endpoint_runtime&) = delete;
    auto operator=(const endpoint_runtime&) -> endpoint_runtime& = delete;

    ~endpoint_runtime() { stop(); }

    auto start() -> task<void> {
        if (started_)
            co_return;
        started_ = true;
        try {
            co_await flush();
        } catch (...) {
            // A failed initial flush (e.g. the transport rejects the connection
            // preface write) is terminal: the read driver never launches, so no
            // peer SETTINGS can ever arrive. Latch the failure into the session
            // context exactly as read_loop does and wake the waiters, so a
            // parked or later handshake()/request() fails fast with this error
            // instead of hanging. started_ stays true: a retry must neither
            // relaunch the driver nor silently succeed.
            context_.core.connection_error = std::current_exception();
            notify_waiters(context_);
            throw;
        }
        driver_ = read_loop();
        driver_.start();
    }

    // RFC 9113 §3.4 — "The SETTINGS frames received from a peer as part of the
    // connection preface MUST be acknowledged (see Section 6.5.3) after sending
    // the connection preface." Both endpoint roles wait for the peer's initial
    // SETTINGS before the connection is usable (nghttp2 acknowledges the peer's
    // SETTINGS automatically; the wait is for the peer's frame itself), and
    // §3.4 — "Clients and servers MUST treat an invalid connection preface as
    // a connection error (Section 5.4.1) of type PROTOCOL_ERROR" is enforced by
    // nghttp2 before that frame can arrive.
    auto handshake() -> task<void> {
        while (!context_.peer_initial_settings_received) {
            // The driver latched a connection failure (e.g. EOF before the
            // peer's initial SETTINGS, RFC 9113 §3.4 — "Clients and servers
            // MUST treat an invalid connection preface as a connection error
            // (Section 5.4.1)"); surface it instead of parking forever.
            if (context_.core.connection_error)
                std::rethrow_exception(context_.core.connection_error);
            co_await handshake_awaiter{context_};
        }
    }

    auto flush() -> task<void> {
        flush_output(session_.get(), context_);
        co_await write_and_clear(transport_, context_);
        if (context_.core.pending_callback_failure)
            std::rethrow_exception(
                std::exchange(context_.core.pending_callback_failure, {}));
        rethrow_connection_error(context_);
    }

    // Flush queued control frames (WINDOW_UPDATE) produced by body_reader
    // credit return. Unlike flush(), a recorded connection error is not
    // surfaced here: buffered body bytes must stay readable after the
    // connection died, and returning credit to a dead peer is pointless.
    auto flush_credit() -> task<void> {
        if (context_.core.connection_error)
            co_return;
        flush_output(session_.get(), context_);
        co_await write_and_clear(transport_, context_);
    }

    // RFC 9113 §6.9 — return flow-control credit as the application consumes
    // body bytes. nghttp2_session_consume cannot fail here: the stream id is
    // nonzero and automatic WINDOW_UPDATE is disabled (create_session).
    auto return_credit(std::int32_t stream_id, std::size_t n) -> task<void> {
        static_cast<void>(nghttp2_session_consume(session_.get(), stream_id, n));
        co_await flush_credit();
    }

    // RFC 9113 §6.7 — "The PING frame (type=0x06) is a mechanism for measuring a minimal
    // round-trip time from the sender, as well as determining whether an idle connection is
    // still functional." RFC 9113 §6.7 — "In addition to the frame header, PING frames MUST
    // contain 8 octets of opaque data in the frame payload." — the payload is
    // application-chosen; nghttp2 acknowledges PING frames received from the peer
    // automatically (§6.7, "Receivers of a PING frame that does not include an ACK flag MUST
    // send a PING frame with the ACK flag set in response, with an identical frame payload.").
    auto ping() -> task<void> {
        std::array<std::uint8_t, 8> opaque{};
        check(nghttp2_submit_ping(
            session_.get(), NGHTTP2_FLAG_NONE, opaque.data()), "submit_ping");
        co_await flush();
    }

    // RFC 9113 §9.1 — "When either endpoint chooses to close the transport-layer
    // TCP connection, the terminating endpoint SHOULD first send a GOAWAY
    // (Section 6.8) frame so that both endpoints can reliably determine whether
    // previously sent frames have been processed and gracefully complete or
    // terminate any necessary remaining tasks." The last-stream-id is the
    // highest peer-initiated stream whose exchange crossed the public delivery
    // boundary (last_processed_peer_stream_id): public push delivery is that
    // boundary on a client, request delivery on a server. RFC 9113 §6.8 —
    // "Endpoints MUST NOT increase the value they send in the last stream
    // identifier, since the peers might already have retried unprocessed
    // requests on another connection." — the processed value is clamped to the
    // smallest last-stream-id already sent on this connection (if any), then
    // recorded, so repeated GOAWAYs stay monotone.
    auto shutdown() -> task<void> {
        auto processed = context_.last_processed_peer_stream_id;
        auto send = std::min(
            processed, context_.goaway_sent_last_stream_id.value_or(processed));
        context_.goaway_sent_last_stream_id = send;
        check(nghttp2_submit_goaway(
            session_.get(), NGHTTP2_FLAG_NONE, send, NGHTTP2_NO_ERROR,
            nullptr, 0), "submit_goaway");
        co_await flush();
    }

    auto update_settings(std::span<const setting> settings)
        -> task<settings_ticket>
    {
        auto entries = make_settings(settings);
        check(nghttp2_submit_settings(
            session_.get(), NGHTTP2_FLAG_NONE, entries.data(), entries.size()),
            "submit_settings");
        auto ticket = reserve_settings_ticket(context_);
        co_await flush();
        co_return ticket;
    }

    [[nodiscard]] auto acknowledged(settings_ticket ticket) const noexcept -> bool {
        return ticket.sequence <= context_.acknowledged_settings_sequence;
    }

    [[nodiscard]] auto compression_state(
        const hpack_configuration& configuration) const -> hpack_state
    {
        return {
            .decoder_capacity = configuration.decoder_capacity,
            .decoder_size = nghttp2_session_get_hd_inflate_dynamic_table_size(session_.get()),
            .peer_decoder_capacity = nghttp2_session_get_remote_settings(
                session_.get(), NGHTTP2_SETTINGS_HEADER_TABLE_SIZE),
            .encoder_capacity = configuration.encoder_capacity,
            .encoder_size = nghttp2_session_get_hd_deflate_dynamic_table_size(session_.get()),
        };
    }

    // RFC 9113 §5.2 — "Flow control is directional with overall control
    // provided by the receiver." — these accessors expose the current
    // send-side windows tracked by nghttp2.
    [[nodiscard]] auto remote_window_size() const -> std::int32_t {
        return nghttp2_session_get_remote_window_size(session_.get());
    }

    [[nodiscard]] auto local_window_size() const -> std::int32_t {
        return nghttp2_session_get_local_window_size(session_.get());
    }

    void expire(settings_ticket ticket) {
        if (ticket.sequence <= context_.acknowledged_settings_sequence)
            return;
        auto pending = std::ranges::any_of(
            context_.pending_settings,
            [ticket](settings_ticket candidate) {
                return candidate.sequence == ticket.sequence;
            });
        if (!pending)
            return;

        // RFC 9113 §6.5.3 — "If the sender of a SETTINGS frame does not
        // receive an acknowledgment within a reasonable amount of time, it
        // MAY issue a connection error (Section 5.4.1) of type
        // SETTINGS_TIMEOUT." The external timer decides when this hook fires.
        auto code = static_cast<std::uint32_t>(NGHTTP2_SETTINGS_TIMEOUT);
        check(
            nghttp2_session_terminate_session(session_.get(), code),
            "terminate_session");
        flush_output(session_.get(), context_);
        context_.core.connection_error = std::make_exception_ptr(protocol_error{
            error_info{
                .version = protocol_version::http2,
                .scope = error_scope::connection,
                .condition = error_condition::timeout,
                .exchange_identity = std::nullopt,
                .library_code = std::nullopt,
                .retryable = false,
            },
            close_connection{error_code{code}},
            "http/2: SETTINGS acknowledgment timed out"});
        notify_waiters(context_);
    }

    // Expire an unacknowledged SETTINGS generation (expire) and flush the
    // resulting GOAWAY. The protocol library owns no clock; an external timer
    // calls this with the ticket whose deadline elapsed.
    auto expire_settings(settings_ticket ticket) -> task<void> {
        expire(ticket);
        co_await flush();
    }

    void stop() noexcept {
        stop_source_.request_stop();
        driver_ = {};
    }

private:
    auto read_loop() -> task<void> {
        try {
            std::array<std::byte, io_buffer_size> buffer;
            while (!stop_source_.stop_requested()) {
                auto size = co_await transport_.async_read(
                    std::span{buffer}, stop_source_.get_token());
                if (size == 0) {
                    // The transport reached EOF. RFC 9113 §6.8 — "A server that
                    // is attempting to gracefully shut down a connection SHOULD
                    // send an initial GOAWAY frame"; without one the fate of
                    // in-flight exchanges is unknown. The error is typed so the
                    // application does not have to parse a bare runtime_error.
                    auto code = context_.core.goaway_received
                        ? context_.goaway_error_code
                        : static_cast<std::uint32_t>(NGHTTP2_NO_ERROR);
                    throw protocol_error{
                        error_info{
                            .version = protocol_version::http2,
                            .scope = error_scope::connection,
                            .condition = error_condition::peer_closed,
                            .exchange_identity = std::nullopt,
                            .library_code = std::nullopt,
                            .retryable = !context_.core.goaway_received,
                        },
                        close_connection{error_code{code}},
                        "http/2: connection closed by peer"};
                }

                auto result = nghttp2_session_mem_recv2(
                    session_.get(),
                    reinterpret_cast<const std::uint8_t*>(buffer.data()),
                    size);
                if (context_.core.pending_callback_failure)
                    std::rethrow_exception(
                        std::exchange(context_.core.pending_callback_failure, {}));
                if (result < 0) {
                    // A fatal library return maps directly to the wire code for
                    // the GOAWAY we answer with — never to a stale recorded one.
                    auto wire_code = wire_code_from_library_code(
                        static_cast<int>(result));
                    static_cast<void>(
                        nghttp2_session_terminate_session(
                            session_.get(), wire_code));
                    co_await flush();
                    throw protocol_error(error_info{
                        .version = protocol_version::http2,
                        .scope = error_scope::connection,
                        .condition = condition_from_wire_code(wire_code),
                        .exchange_identity = std::nullopt,
                        .library_code = static_cast<int>(result),
                        .retryable = false,
                    }, close_connection{error_code{wire_code}},
                        std::format("http/2: mem_recv failed ({})", result));
                }
                co_await flush();
                notify_waiters(context_);
                if (!nghttp2_session_want_read(session_.get())) {
                    // nghttp2 terminates the session itself — answering with
                    // GOAWAY — when the peer commits a connection error (e.g.
                    // RFC 9113 §4.3 — a header decompression failure is a
                    // connection error of type COMPRESSION_ERROR); mem_recv2
                    // does not return a negative code for that path. Surface
                    // the termination with the code that went on the wire.
                    auto code = context_.sent_goaway_error_code.value_or(
                        NGHTTP2_PROTOCOL_ERROR);
                    throw protocol_error{
                        error_info{
                            .version = protocol_version::http2,
                            .scope = error_scope::connection,
                            .condition = condition_from_wire_code(code),
                            .exchange_identity = std::nullopt,
                            .library_code = context_.library_error_code,
                            .retryable = false,
                        },
                        close_connection{error_code{code}},
                        "http/2: connection terminated after peer protocol violation"};
                }
            }
        } catch (...) {
            if (!stop_source_.stop_requested()) {
                context_.core.connection_error = std::current_exception();
                notify_waiters(context_);
            }
        }
    }

    S& transport_;
    session_handle& session_;
    session_context& context_;
    std::stop_source stop_source_{};
    task<void> driver_{};
    bool started_{false};
};

// RFC 9113 §6.9 — "Flow control is directional with overall control provided
// by the receiver." DATA can be sent only while both the connection-level and
// the stream-level send window are open.
[[nodiscard]] inline auto send_window_available(nghttp2_session* session, std::int32_t stream_id) -> bool {
    return nghttp2_session_get_remote_window_size(session) > 0 &&
           nghttp2_session_get_stream_remote_window_size(session, stream_id) > 0;
}

// Drive an outbound body through nghttp2's data provider: refill the bridge,
// requeue the stream when the provider deferred, and flush until the body is
// exhausted. While the peer's send window is exhausted the coroutine suspends
// until a WINDOW_UPDATE (or a terminal stream event) arrives — resume_data
// only requeues a *deferred* stream, so without the wait the flush would spin
// without progress. When the peer closes the stream mid-body the driver either
// throws (client requests) or returns quietly (server responses).
template <byte_stream S, body_stream Body>
inline auto stream_outbound_body(
    endpoint_runtime<S>& runtime,
    nghttp2_session* session,
    session_context& ctx,
    std::int32_t stream_id,
    std::shared_ptr<stream_data> sd,
    outbound_body_state& outbound,
    body_bridge<Body>& bridge,
    bool fail_on_close) -> task<void> {
    for (;;) {
        auto body_eof = co_await bridge.refill();
        while (!body_eof && !send_window_available(session, stream_id)) {
            if (!ctx.core.outbound_bodies.contains(stream_id)) {
                if (fail_on_close)
                    throw_stream_abort(*sd);
                co_return;
            }
            // The connection failure is re-checked after the window wait
            // (v3-style delivery): the driver latched it and aborted the
            // stream, so a suspended sender fails fast with the typed error.
            if (ctx.core.connection_error)
                std::rethrow_exception(ctx.core.connection_error);
            co_await window_awaiter{ctx, sd};
        }
        if (!ctx.core.outbound_bodies.contains(stream_id)) {
            if (fail_on_close)
                throw_stream_abort(*sd);
            co_return;
        }
        if (outbound.deferred) {
            outbound.deferred = false;
            check(nghttp2_session_resume_data(session, stream_id),
                "session_resume_data");
        }
        co_await runtime.flush();
        if (!ctx.core.outbound_bodies.contains(stream_id) && !body_eof) {
            if (fail_on_close)
                throw_stream_abort(*sd);
            co_return;
        }
        if (body_eof)
            co_return;
    }
}

} // namespace detail
} // namespace http::v2
