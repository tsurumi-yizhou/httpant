module;

#include <nghttp3/nghttp3.h>

#include <cstddef>
#include <cstdint>
#include <coroutine>
#include <deque>
#include <exception>
#include <format>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

export module httpant:server.nghttp3;

import :trait;
import :message;
import :role;
import :error;
import :session.nghttp3;
import :serialize.nghttp3;
import :parse.nghttp3;
import :endpoint.nghttp3;

export namespace http::v3 {

template <stream_factory S>
class server {
public:
    explicit server(S& transport, configuration config = {})
        : transport_(transport),
          conn_(detail::create_connection(
              detail::endpoint_role::server, ctx_, config)),
          runtime_(transport_, conn_.get(), ctx_, open_streams_) {}

    server(const server&) = delete;
    server& operator=(const server&) = delete;

    // The token's engine payload: the request stream record. The shared core
    // carries the owning-server pointer, so a token minted by one connection
    // cannot be used to respond on another (checked in operation_respond).
    using exchange_token =
        http::detail::exchange_token<server, std::shared_ptr<detail::stream_data>>;
    using incoming_request = http::detail::incoming_request<body_reader<S>, exchange_token>;

    // RFC 9114 §6.2.1 — "Each side MUST initiate a single control stream at
    // the beginning of the connection and send its SETTINGS frame as the first
    // frame on this stream." See client::start for the stream-factory
    // driven creation of the control/QPACK unidirectional streams.
private:
    auto operation_start() -> task<void> {
        co_await runtime_.start();
    }

    // RFC 9114 §4.1 — "A server sends ... responses on the same stream as the
    // request"; the opaque move-only token carries that association atomically
    // with the completed request. Suspends until the endpoint driver has
    // completed the next request stream (headers + request body + FIN).
    auto operation_receive() -> http::task<incoming_request> {
        struct receive_awaiter {
            detail::conn_context& ctx;

            [[nodiscard]] auto await_ready() const noexcept -> bool {
                return !ctx.core.receive_queue_empty() ||
                       !ctx.server_stream_failures.empty() ||
                       ctx.core.connection_error;
            }
            void await_suspend(std::coroutine_handle<> handle) {
                ctx.core.receive_waiter.park(handle);
            }
            void await_resume() const noexcept {}
        };

        for (;;) {
            // RFC 9114 §8 — once the connection has failed, every server
            // operation surfaces the typed connection error instead of
            // hanging or returning stale state.
            if (ctx_.core.connection_error)
                std::rethrow_exception(ctx_.core.connection_error);
            if (!ctx_.core.receive_queue_empty())
                break;
            // RFC 9114 §8 — a stream error on a request stream is delivered
            // as a typed stream-scoped failure of receive(); the connection
            // itself keeps running (RFC 9114 §4.1.2 — malformed requests are
            // stream errors of type H3_MESSAGE_ERROR).
            if (!ctx_.server_stream_failures.empty()) {
                auto failure = std::move(ctx_.server_stream_failures.front());
                ctx_.server_stream_failures.pop_front();
                std::rethrow_exception(failure);
            }
            co_await receive_awaiter{ctx_};
        }

        auto stream = std::move(ctx_.core.receive_queue_front());
        ctx_.core.receive_queue_pop();
        // A stream reset between header completion and delivery must not be
        // handed to the application as if it were live: fail it exactly like
        // the client-side aborted-stream path in operation_request.
        if (stream->core.aborted) {
            if (stream->close_error_code != 0) {
                // RFC 9114 §8 — "QUIC allows the application to abruptly
                // terminate (reset) that stream and communicate a reason."
                throw protocol_error{
                    error_info{
                        .version = protocol_version::http3,
                        .scope = error_scope::stream,
                        .condition = error_condition::stream_reset,
                        .exchange_identity =
                            static_cast<std::uint64_t>(stream->core.id),
                        .library_code = std::nullopt,
                        .retryable = false,
                    },
                    reset_stream{error_code{stream->close_error_code}},
                    std::format("http/3: request stream aborted (0x{:x})",
                                stream->close_error_code)};
            }
            throw std::runtime_error("http/3: stream closed before complete request");
        }
        // The transport handle of a stream the driver marked complete is an
        // internal invariant, so a missing entry is a plain internal failure,
        // not a wire-level protocol error.
        auto transport = open_streams_.find(stream->core.id);
        if (transport == open_streams_.end())
            throw std::runtime_error(
                "http/3: completed request stream has no transport handle");
        auto head = http::request{
            .method = from_string(stream->core.decoded.method_token),
            .target = std::move(stream->core.decoded.path),
            .scheme = std::move(stream->core.decoded.scheme),
            .authority = std::move(stream->core.decoded.authority),
            .fields = std::move(stream->core.decoded.regular),
        };
        co_return incoming_request{
            .head = std::move(head),
            .body = body_reader<S>{
                stream, transport->second, ctx_},
            .token = exchange_token{*this, stream},
        };
    }

    template <body_stream Body>
    auto operation_respond(
        exchange_token token,
        http::response res,
        Body& body) -> task<void> {
        if (!token.valid())
            throw std::runtime_error("http/3: invalid exchange token");
        // A token minted by another server must not respond on this
        // connection; responding consumes the token (the stream handle moves
        // out), so a second respond with the same token fails the check above.
        token.check_owner(*this, "http/3: ");
        auto stream = token.take_handle();
        // RFC 9110 §15 — "All valid status codes are within the range of 100
        // to 599, inclusive." — an out-of-range status would be emitted as an
        // invalid ':status' value (RFC 9114 §4.3.2 — "This pseudo-header
        // field MUST be included in all responses ... otherwise, the response
        // is malformed"), so the send path rejects it locally before any
        // frame is submitted, mirroring the inbound parse_status check.
        if (res.status < 100 || res.status > 599)
            throw std::runtime_error("http/3: response status outside 100-599");
        if (ctx_.core.connection_error)
            std::rethrow_exception(ctx_.core.connection_error);
        auto stream_id = stream->core.id;

        // RFC 9110 §9.3.2 — "The HEAD method is identical to GET except that
        // the server MUST NOT send content in the response." RFC 9110 §9.3.6 —
        // a successful CONNECT response must not carry content. RFC 9110 §15.2 /
        // §15.3.5 / §15.3.6 / §15.4.5 — "A 1xx response is terminated by the
        // end of the header section; it cannot contain content or trailers."
        // (likewise 204/205/304). RFC 9114 §4.1 — message content is sent as
        // DATA frames, so such a response ends at the header section: the
        // body is dropped and the outbound body is already at eof, which
        // submits no data reader and emits no DATA frames.
        auto request_method = from_string(stream->core.decoded.method_token);
        auto allows_body = http::response_carries_body(request_method, res.status);

        auto nva = detail::nv_block{res.fields.size() + 1};
        nva.push(":status", std::to_string(res.status));
        for (auto& h : res.fields) nva.push(h.name, h.value);
        detail::check_outbound_field_section(ctx_, nva);

        auto outbound_body = std::make_shared<detail::outbound_body_state>();
        // Only the outbound-body registration is new here: the stream state
        // belongs to the received exchange, so the guard must not touch it.
        detail::exchange_registration<typename detail::endpoint_runtime<S>::stream_map>
            guard{ctx_, conn_.get(), stream_id};
        if (allows_body)
            co_await detail::fill_outbound_body(body, *outbound_body, runtime_.stop_token());
        else
            outbound_body->eof = true;
        nghttp3_data_reader reader{.read_data = &detail::read_outbound_body};
        detail::check(nghttp3_conn_submit_response(conn_.get(), stream_id,
            nva.fields.data(), nva.fields.size(),
            outbound_body->eof ? nullptr : &reader), "submit_response");
        if (!outbound_body->eof) {
            ctx_.core.outbound_bodies[stream_id] = outbound_body;
            // RFC 9114 §4.1 — response content is sent as DATA frames on the
            // request stream; nghttp3's data callback therefore needs the body
            // state bound to that exact stream.
            detail::check(nghttp3_conn_set_stream_user_data(
                conn_.get(), stream_id, outbound_body.get()), "set_stream_user_data");
        }
        co_await detail::pump_outbound_body(
            body, *outbound_body, stream_id, conn_.get(), runtime_);
        ctx_.core.outbound_bodies.erase(stream_id);
        guard.disarm();
    }

    friend auto operation_start(server& endpoint) -> task<void> {
        co_await endpoint.operation_start();
    }

    friend auto operation_receive(server& endpoint) -> task<incoming_request> {
        co_return co_await endpoint.operation_receive();
    }

    template <body_stream Body>
    friend auto operation_respond(
        server& endpoint,
        exchange_token token,
        http::response head,
        Body& body) -> task<void> {
        co_await endpoint.operation_respond(
            std::move(token), std::move(head), body);
    }

public:
    auto shutdown() -> task<void> {
        co_await runtime_.shutdown();
    }

    [[nodiscard]] auto goaway_received() const -> bool { return ctx_.core.goaway_received; }

    [[nodiscard]] auto compression_state() const -> qpack_state {
        return detail::compression_state(ctx_);
    }

private:
    S& transport_;
    detail::conn_context ctx_{};
    detail::connection_handle conn_{};
    typename detail::endpoint_runtime<S>::stream_map open_streams_{};
    detail::endpoint_runtime<S> runtime_;
};

} // namespace http::v3
