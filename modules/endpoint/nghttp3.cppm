module;

#include <nghttp3/nghttp3.h>

#include <algorithm>
#include <array>
#include <coroutine>
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
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

export module httpant:endpoint.nghttp3;

import :trait;
import :error;
import :session.nghttp3;
import :parse.nghttp3;

export namespace http::v3 {

namespace detail {

enum class endpoint_role {
    client,
    server,
};

inline auto make_settings(const configuration& config) -> nghttp3_settings {
    nghttp3_settings settings;
    nghttp3_settings_default(&settings);
    settings.max_field_section_size = config.maximum_field_section_size;
    settings.qpack_max_dtable_capacity = config.compression.decoder_capacity;
    settings.qpack_encoder_max_dtable_capacity = config.compression.encoder_capacity;
    settings.qpack_blocked_streams = config.compression.blocked_streams;
    settings.qpack_indexing_strat = NGHTTP3_QPACK_INDEXING_STRAT_EAGER;
    return settings;
}

inline auto create_connection(
    endpoint_role role,
    conn_context& context,
    const configuration& config) -> connection_handle
{
    auto callbacks = make_callbacks();
    auto settings = make_settings(config);
    nghttp3_conn* raw_connection = nullptr;
    auto result = role == endpoint_role::client
        ? nghttp3_conn_client_new(
              &raw_connection,
              &callbacks,
              &settings,
              nghttp3_mem_default(),
              &context)
        : nghttp3_conn_server_new(
              &raw_connection,
              &callbacks,
              &settings,
              nghttp3_mem_default(),
              &context);
    if (result != 0) {
        connection_handle cleanup{raw_connection};
        throw make_error(
            role == endpoint_role::client ? "conn_client_new" : "conn_server_new",
            result);
    }
    context.is_client = role == endpoint_role::client;
    context.local_configuration = config;
    return connection_handle{raw_connection};
}

[[nodiscard]] inline auto compression_state(const conn_context& context)
    -> qpack_state
{
    return qpack_state{
        .decoder_capacity = context.local_configuration.compression.decoder_capacity,
        .blocked_streams = context.local_configuration.compression.blocked_streams,
        .encoder_capacity = context.local_configuration.compression.encoder_capacity,
        .peer_decoder_capacity = context.peer_decoder_capacity,
        .peer_blocked_streams = context.peer_blocked_streams,
    };
}

// Flushes each nghttp3_conn_writev_stream batch. Only bytes the transport
// accepted advance the nghttp3 write offset — a partially accepting
// backend retries the remainder instead of nghttp3 losing track of unsent
// data. Buffer release is awaited before the caller's span can change;
// acknowledgement advances nghttp3's ACK offset and releases retained body
// chunks through acked_stream_data.
template <typename StreamMap>
inline auto flush_output(
    conn_context& ctx,
    nghttp3_conn* conn,
    StreamMap& open_streams,
    std::stop_token stop) -> task<void>
{
    std::int64_t sid = -1;
    int fin = 0;
    nghttp3_vec vec[8];
    for (;;) {
        auto n = nghttp3_conn_writev_stream(conn, &sid, &fin, vec, 8);
        if (n < 0) {
            rethrow_callback_failure(ctx);
            // RFC 9114 §8 — the negative code means the connection must be
            // closed; infer the H3 application error code (Section 8.1) and
            // record it for the upper layer to carry on CONNECTION_CLOSE.
            auto wire_code = nghttp3_err_infer_quic_app_error_code(static_cast<int>(n));
            record_connection_error(ctx, conn, wire_code);
            throw protocol_error{
                error_info{
                    .version = protocol_version::http3,
                    .scope = error_scope::connection,
                    .condition = error_condition::malformed_frame,
                    .exchange_identity = std::nullopt,
                    .library_code = static_cast<int>(n),
                    .retryable = false,
                },
                close_connection{error_code{wire_code}},
                std::format("http/3: writev_stream failed ({})", n)};
        }
        rethrow_callback_failure(ctx);
        if (n == 0 && fin == 0) break;

        auto it = open_streams.find(sid);
        if (it == open_streams.end())
            throw std::runtime_error("http/3: write on an unknown stream");
        auto& stream = *it->second;

        // The read_data contract keeps each vec's bytes owned by the caller
        // until acked; they are copied into one stable buffer per batch.
        std::vector<std::byte> data;
        auto count = static_cast<std::size_t>(n);
        for (std::size_t i = 0; i < count; ++i) {
            auto bytes = std::as_bytes(std::span{
                reinterpret_cast<const char*>(vec[i].base), vec[i].len});
            data.insert(data.end(), bytes.begin(), bytes.end());
        }

        if (data.empty()) {
            // FIN-only batch: the nghttp3 contract reports a zero-byte write
            // offset once the FIN has been handed to the transport.
            auto result = co_await stream.async_write(std::span<const std::byte>{}, fin != 0, stop);
            co_await std::move(result.buffer_release);
            auto acknowledged = co_await std::move(result.acknowledgement);
            static_cast<void>(result.accepted);
            check(nghttp3_conn_add_write_offset(conn, sid, 0), "add_write_offset");
            check(nghttp3_conn_add_ack_offset(conn, sid, acknowledged), "add_ack_offset");
            continue;
        }

        try {
            auto remaining = std::span<const std::byte>{data};
            // FIN is deliberately kept off the data-bearing writes. If a
            // transport accepts a partial write, the FIN would otherwise be
            // delivered before the final byte, closing the send side early.
            // Data is drained first, then a zero-length FIN-only write is
            // emitted exactly once when nghttp3 requested stream finalization.
            while (!remaining.empty()) {
                auto result = co_await stream.async_write(remaining, false, stop);
                co_await std::move(result.buffer_release);
                auto acknowledged = co_await std::move(result.acknowledgement);
                if (result.accepted == 0)
                    throw std::runtime_error("http/3: stream write made no progress");
                if (result.accepted > remaining.size())
                    throw std::runtime_error("http/3: stream write accepted too many bytes");
                if (acknowledged > result.accepted)
                    throw std::runtime_error("http/3: stream write acknowledged too many bytes");
                check(
                    nghttp3_conn_add_write_offset(conn, sid, static_cast<nghttp3_ssize>(result.accepted)),
                    "add_write_offset");
                check(nghttp3_conn_add_ack_offset(conn, sid, acknowledged), "add_ack_offset");
                remaining = remaining.subspan(result.accepted);
            }
            if (fin != 0) {
                auto result = co_await stream.async_write(std::span<const std::byte>{}, true, stop);
                co_await std::move(result.buffer_release);
                auto acknowledged = co_await std::move(result.acknowledgement);
                if (result.accepted != 0)
                    throw std::runtime_error("http/3: FIN-only write accepted bytes");
                if (acknowledged != 0)
                    throw std::runtime_error("http/3: FIN-only write acknowledged bytes");
                check(nghttp3_conn_add_write_offset(conn, sid, 0), "add_write_offset");
                check(nghttp3_conn_add_ack_offset(conn, sid, acknowledged), "add_ack_offset");
            }
        } catch (const http::stream_reset& reset) {
            // RFC 9114 §4.1.1 — the peer abandoned this one stream
            // (STOP_SENDING); close it at the sole protocol owner and keep
            // flushing the other streams. Abandon the retained body chunk so
            // a pump_outbound_body parked on ACK wakes and exits instead of
            // waiting for an ACK that can no longer arrive.
            if (auto it = ctx.core.outbound_bodies.find(sid); it != ctx.core.outbound_bodies.end()) {
                auto& state = *it->second;
                state.data.clear();
                state.acknowledged = 0;
                state.offered = false;
                state.eof = true;
                state.resume_ack_waiter();
            }
            if (nghttp3_conn_close_stream(conn, sid, reset.error_code.value) != 0)
                mark_stream_closed(ctx, sid, reset.error_code.value);
            open_streams.erase(sid);
        }
    }
}

// Serializes flush_output so only one coroutine may be inside
// nghttp3_conn_writev_stream / async_write / add_write_offset at a time.
// nghttp3 does not advance its write offset until add_write_offset, so a
// second flush entering while the first is suspended in async_write would
// receive the same unsent batch and duplicate bytes on the wire.
// Waiters are released only by the holder's unlock(), so a holder stuck
// forever inside a transport write would strand the queue. The transport
// contract covers this: every stream_factory operation takes a stop token and
// must complete — with an error once the connection has failed — so the
// holder always reaches unlock() and the queue drains. This gate relies on
// that contract.
struct flush_gate {
    bool locked{false};
    std::deque<std::coroutine_handle<>> waiters{};

    struct lock_awaiter {
        flush_gate& gate;

        [[nodiscard]] bool await_ready() const noexcept { return false; }
        auto await_suspend(std::coroutine_handle<> handle) noexcept -> bool {
            if (!gate.locked) {
                gate.locked = true;
                return false;
            }
            gate.waiters.push_back(handle);
            return true;
        }
        void await_resume() const noexcept {}
    };

    [[nodiscard]] auto lock() noexcept -> lock_awaiter { return {*this}; }

    void unlock() noexcept {
        if (waiters.empty()) {
            locked = false;
            return;
        }
        auto handle = waiters.front();
        waiters.pop_front();
        handle.resume();
    }
};

template <stream_factory S>
class endpoint_runtime {
public:
    using stream_pointer = std::shared_ptr<typename S::stream_type>;
    using stream_map = std::unordered_map<std::int64_t, stream_pointer>;

    endpoint_runtime(
        S& transport,
        nghttp3_conn* connection,
        conn_context& context,
        stream_map& streams)
        : transport_(transport), connection_(connection), context_(context), streams_(streams) {}

    endpoint_runtime(const endpoint_runtime&) = delete;
    auto operator=(const endpoint_runtime&) -> endpoint_runtime& = delete;

    ~endpoint_runtime() { stop(); }

    auto start(std::stop_token stop = {}) -> task<void> {
        if (started_)
            co_return;
        started_ = true;
        external_stop_.emplace(stop, stop_forward{&stop_source_});

        auto control = co_await transport_.async_open_unidirectional(stop_source_.get_token());
        auto encoder = co_await transport_.async_open_unidirectional(stop_source_.get_token());
        auto decoder = co_await transport_.async_open_unidirectional(stop_source_.get_token());
        auto control_id = to_stream_id(control.identifier());
        auto encoder_id = to_stream_id(encoder.identifier());
        auto decoder_id = to_stream_id(decoder.identifier());
        streams_[control_id] = std::make_shared<typename S::stream_type>(std::move(control));
        streams_[encoder_id] = std::make_shared<typename S::stream_type>(std::move(encoder));
        streams_[decoder_id] = std::make_shared<typename S::stream_type>(std::move(decoder));
        bound_streams_ = {control_id, encoder_id, decoder_id};

        check(nghttp3_conn_bind_control_stream(connection_, control_id), "bind_control");
        check(
            nghttp3_conn_bind_qpack_streams(connection_, encoder_id, decoder_id),
            "bind_qpack");
        context_.local_control_stream_id = control_id;
        co_await flush();
        driver_ = accept_loop();
        driver_.start();
    }

    auto flush() -> task<void> {
        co_await flush_gate_.lock();
        try {
            co_await flush_output(
                context_, connection_, streams_, stop_source_.get_token());
            reap_closed_streams();
        } catch (...) {
            flush_gate_.unlock();
            throw;
        }
        flush_gate_.unlock();
    }

    auto shutdown() -> task<void> {
        check(nghttp3_conn_submit_shutdown_notice(connection_), "submit_shutdown_notice");
        check(nghttp3_conn_shutdown(connection_), "shutdown");
        co_await flush();
        if (!context_.connection_close_started) {
            context_.connection_close_started = true;
            // RFC 9114 §8.1 — H3_NO_ERROR indicates a graceful connection
            // close after the GOAWAY bytes have been accepted by the transport.
            co_await transport_.async_close(
                application_error{NGHTTP3_H3_NO_ERROR});
        }
        stop();
    }

    [[nodiscard]] auto stop_token() const noexcept -> std::stop_token {
        return stop_source_.get_token();
    }

    void read(stream_pointer stream, bool peer_initiated = true) {
        auto stream_id = to_stream_id(stream->identifier());
        streams_[stream_id] = stream;
        readers_.push_back(read_stream_guarded(std::move(stream), peer_initiated));
        readers_.back().start();
    }

    void stop() noexcept {
        stop_source_.request_stop();
        readers_.clear();
        driver_ = {};
    }

private:
    struct stop_forward {
        std::stop_source* source;
        void operator()() const noexcept { source->request_stop(); }
    };

    auto accept_loop() -> task<void> {
        try {
            while (!stop_source_.stop_requested()) {
                auto stream = co_await transport_.async_accept(stop_source_.get_token());
                std::erase_if(readers_, [](const auto& reader) { return reader.done(); });
                auto shared_stream =
                    std::make_shared<typename S::stream_type>(std::move(stream));
                read(std::move(shared_stream));
            }
        } catch (...) {
            if (!stop_source_.stop_requested())
                fail_connection(context_, std::current_exception());
        }
    }

    auto read_stream_guarded(stream_pointer stream, bool peer_initiated) -> task<void> {
        auto stream_id = to_stream_id(stream->identifier());
        std::exception_ptr failure;
        try {
            co_await read_stream(stream, peer_initiated);
            co_return;
        } catch (const http::stream_reset& reset) {
            // RFC 9114 §4.1.1 — "Stream errors are expressed as ... resets;
            // they do not affect other streams or the connection." Inform the
            // sole protocol owner so the stream reaches its terminal state
            // (nghttp3 delivers stream_close, which wakes the stream's
            // waiters); when nghttp3 never saw the stream, mark it directly.
            // The connection and its other in-flight streams keep running.
            if (nghttp3_conn_close_stream(connection_, stream_id, reset.error_code.value) != 0)
                mark_stream_closed(context_, stream_id, reset.error_code.value);
            streams_.erase(stream_id);
            context_.inputs.erase(stream_id);
            co_return;
        } catch (...) {
            failure = std::current_exception();
        }

        if (stop_source_.stop_requested())
            co_return;

        if (auto code = reset_code(failure)) {
            // RFC 9204 §2.2.2.2 — "When a stream is reset or reading is
            // abandoned, the decoder emits a Stream Cancellation instruction."
            // nghttp3_conn_close_stream has already updated the sole QPACK
            // owner; execute the typed QUIC stream action and flush any
            // resulting decoder-stream instruction.
            try {
                stream->shutdown(
                    stream_side::both,
                    application_error{*code});
                co_await flush();
            } catch (...) {
                failure = std::current_exception();
                record_connection_error(
                    context_, connection_, NGHTTP3_H3_INTERNAL_ERROR);
            }
            if (context_.connection_error_code == 0) {
                // RFC 9114 §8 — "Stream errors are expressed as ... resets;
                // they do not affect other streams or the connection." The
                // typed stream action was executed; the connection and its
                // other exchanges keep running. A server-side request-stream
                // failure is surfaced to receive() so the application sees
                // the typed error; a client-side failure wakes its own
                // request through mark_stream_closed (delivered by
                // nghttp3_conn_close_stream in record_stream_error).
                if (!context_.is_client) {
                    // The failed request stream is never delivered to
                    // receive() (it rethrows the queued failure), so no
                    // body_reader will ever release its stream_data: drop the
                    // ctx.streams entry (and its buffered body / decoded
                    // fields) here. The transport handle stays in streams_
                    // and is reaped by reap_closed_streams once the stream
                    // closes, preserving that function's early-release
                    // behavior for the handle.
                    context_.core.streams.erase(stream_id);
                    context_.server_stream_failures.push_back(failure);
                    context_.core.receive_waiter.resume();
                }
                co_return;
            }
        }

        if (context_.connection_error_code != 0 &&
            !context_.connection_close_started) {
            context_.connection_close_started = true;
            try {
                // RFC 9114 §8 — the protocol layer selects the typed H3/QPACK
                // application error; the factory only performs QUIC close.
                co_await transport_.async_close(
                    application_error{context_.connection_error_code});
            } catch (...) {
                // The protocol action was selected and attempted; failure of
                // the transport action is now the terminal error and must not
                // be swallowed behind the original protocol violation.
                failure = std::current_exception();
            }
        }
        fail_connection(context_, std::move(failure));
    }

    auto read_stream(stream_pointer stream, bool peer_initiated) -> task<void> {
        auto stream_id = to_stream_id(stream->identifier());
        auto unidirectional = peer_initiated
            ? accepted_stream_is_unidirectional(
                  context_, connection_, stream->access())
            : false;
        std::array<std::byte, io_buffer_size> buffer;
        for (;;) {
            if (auto it = context_.core.streams.find(stream_id);
                it != context_.core.streams.end() &&
                it->second->buffered_body_size >= body_buffer_limit) {
                co_await body_capacity_awaiter{it->second};
                continue;
            }
            auto capacity = body_buffer_limit;
            if (auto it = context_.core.streams.find(stream_id); it != context_.core.streams.end())
                capacity -= it->second->buffered_body_size;
            auto size = co_await stream->async_read(
                std::span{buffer}.first(capacity), stop_source_.get_token());
            // The transport signals fin by returning zero bytes, so the fin
            // flag passed to process_input is exactly "no bytes this read"; a
            // partial frame left at fin therefore accumulated from earlier
            // reads and is the stream's truncated last frame (RFC 9114 §7.1).
            auto consumed = process_input(
                context_, connection_, stream_id, unidirectional,
                std::span<const std::byte>{buffer.data(), static_cast<std::size_t>(size)},
                size == 0);
            stream->consume(static_cast<std::size_t>(consumed));
            for (auto it = context_.deferred_consumption.begin();
                 it != context_.deferred_consumption.end();) {
                if (auto handle = streams_.find(it->first); handle != streams_.end())
                    handle->second->consume(it->second);
                it = context_.deferred_consumption.erase(it);
            }
            if (size == 0) {
                if (auto it = context_.core.streams.find(stream_id); it != context_.core.streams.end())
                    it->second->core.resume_waiter();
                // RFC 9114 §4.1 — "If a client-initiated stream terminates
                // without enough of the HTTP message to provide a complete
                // response, the server SHOULD abort its response stream with
                // the error code H3_REQUEST_INCOMPLETE." The frame-level
                // truncations nghttp3 reports are handled as stream errors in
                // process_request_stream / forward_stream_input; a request
                // stream that reaches FIN while its QPACK field section is
                // still blocked is consumed silently by nghttp3 (the FIN is
                // buffered until unblocking), so httpant cannot distinguish it
                // from a still-decoding stream and delivers EOF without a
                // reset.
                co_return;
            }
            co_await flush();
        }
    }

    // Reaps transport handles and input parsers whose exchange has fully
    // ended: the stream closed at the protocol layer, or (client side) the
    // completed exchange was released by the body_reader. The bound control /
    // QPACK streams and the peer's control / QPACK streams live until
    // connection teardown, so they are never reaped here.
    void reap_closed_streams() {
        auto connection_lifetime = [this](std::int64_t id) {
            return bound_streams_.contains(id) ||
                   context_.remote_control_stream_id == id ||
                   context_.remote_qpack_encoder_stream_id == id ||
                   context_.remote_qpack_decoder_stream_id == id;
        };
        std::erase_if(streams_, [&](const auto& entry) {
            if (connection_lifetime(entry.first))
                return false;
            auto it = context_.core.streams.find(entry.first);
            if (it != context_.core.streams.end() && !it->second->core.closed)
                return false;
            // A server request stream whose state was released early keeps its
            // handle: the response may still be written through it.
            if (it == context_.core.streams.end() && !context_.is_client)
                return false;
            context_.inputs.erase(entry.first);
            return true;
        });
    }

    S& transport_;
    nghttp3_conn* connection_;
    conn_context& context_;
    stream_map& streams_;
    std::unordered_set<std::int64_t> bound_streams_{};
    std::stop_source stop_source_{};
    std::optional<std::stop_callback<stop_forward>> external_stop_{};
    flush_gate flush_gate_{};
    task<void> driver_{};
    std::vector<task<void>> readers_{};
    bool started_{false};
};

} // namespace detail

} // namespace http::v3
