module;

#include <nghttp3/nghttp3.h>

#include <cstddef>
#include <cstdint>
#include <exception>
#include <format>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

export module httpant:client.nghttp3;

import :trait;
import :message;
import :error;
import :session.nghttp3;
import :serialize.nghttp3;
import :parse.nghttp3;
import :endpoint.nghttp3;

export namespace http::v3 {

template <stream_factory S>
class client {
public:
    explicit client(S& transport, configuration config = {})
        : transport_(transport),
          conn_(detail::create_connection(
              detail::endpoint_role::client, ctx_, config)),
          runtime_(transport_, conn_.get(), ctx_, open_streams_) {}

    client(const client&) = delete;
    client& operator=(const client&) = delete;

    // RFC 9114 §6.2.1 — "Each side MUST initiate a single control stream at
    // the beginning of the connection and send its SETTINGS frame as the first
    // frame on this stream." The control and QPACK encoder/decoder
    // unidirectional streams are created through the stream factory (no
    // application-supplied stream IDs), bound, and flushed. The endpoint-owned
    // driver then accepts peer-initiated streams and feeds them into the
    // nghttp3 connection.
private:
    auto operation_start() -> task<void> {
        co_await runtime_.start();
    }

private:
    template <body_stream Body>
    auto operation_request(http::request req, Body& body)
        -> task<http::received<http::response, body_reader<S>>> {
        // RFC 9114 §5.2 — "Endpoints MUST NOT initiate new requests or promise new pushes on the connection after receipt of a GOAWAY frame from the peer."
        if (ctx_.core.goaway_received)
            throw detail::make_goaway_rejection(std::nullopt);
        if (ctx_.core.connection_error)
            std::rethrow_exception(ctx_.core.connection_error);

        // RFC 9114 §4.3.1 / §4.4 — HTTP/2 and HTTP/3 share the same
        // pseudo-field completeness, ordering, CONNECT, and Host rules.
        auto fields = http::detail::make_request_field_block(req);
        if (!fields)
            throw std::runtime_error(
                std::string{"http/3: "} +
                std::string{http::detail::request_field_error_name(fields.error())});

        auto nva = detail::nv_block{fields->size()};
        for (const auto& field : *fields)
            nva.push(field.name, field.value);
        detail::check_outbound_field_section(ctx_, nva);

        // RFC 9114 §4.1 — the request stream is opened through the factory with
        // an explicit direction; the identity is consumed by the H3 layer and
        // never surfaced to the application.
        auto stream = co_await transport_.async_open_bidirectional(runtime_.stop_token());
        auto stream_id = detail::to_stream_id(stream.identifier());
        auto shared_stream =
            std::make_shared<typename S::stream_type>(std::move(stream));
        open_streams_[stream_id] = shared_stream;
        detail::exchange_registration guard{
            ctx_, conn_.get(), stream_id, &open_streams_};

        auto sd = std::make_shared<detail::stream_data>();
        sd->core.id = stream_id;
        ctx_.core.streams[stream_id] = sd;

        auto outbound_body = std::make_shared<detail::outbound_body_state>();
        co_await detail::fill_outbound_body(body, *outbound_body, runtime_.stop_token());
        nghttp3_data_reader reader{.read_data = &detail::read_outbound_body};
        if (!outbound_body->eof)
            ctx_.core.outbound_bodies[stream_id] = outbound_body;

        detail::check(nghttp3_conn_submit_request(conn_.get(), stream_id,
            nva.fields.data(), nva.fields.size(),
            outbound_body->eof ? nullptr : &reader,
            outbound_body->eof ? nullptr : outbound_body.get()), "submit_request");
        guard.submitted = true;

        co_await detail::pump_outbound_body(
            body, *outbound_body, stream_id, conn_.get(), runtime_);
        ctx_.core.outbound_bodies.erase(stream_id);
        guard.disarm();

        runtime_.read(shared_stream, false);
        // Cancellation boundary: connection stop only. request() exposes no
        // user stop token, so this header wait cannot be cancelled directly
        // (matching the boundary buffer_body documents for its always-ready
        // reads). The wait ends when the endpoint driver resumes sd's headers
        // waiter — on end_headers, on stream_close/abort, or on connection
        // failure (fail_connection). The runtime's stop_source_ only cancels
        // the driver's own transport reads; it does not resume this wait.
        while (!sd->core.headers_done && !sd->core.aborted) {
            if (ctx_.core.goaway_received && ctx_.core.goaway_id &&
                static_cast<std::uint64_t>(stream_id) >= *ctx_.core.goaway_id)
                throw detail::make_goaway_rejection(
                    static_cast<std::uint64_t>(stream_id));
            co_await detail::headers_awaiter{sd};
        }

        if (ctx_.core.connection_error)
            std::rethrow_exception(ctx_.core.connection_error);
        if (sd->core.aborted) {
            if (sd->close_error_code != 0) {
                // RFC 9114 §8 — "QUIC allows the application to abruptly
                // terminate (reset) that stream and communicate a reason."
                // A peer reset or a stream-scoped protocol error recorded its
                // application error code on this stream; surface it as the
                // typed stream action (e.g. H3_MESSAGE_ERROR for a malformed
                // response, RFC 9114 §4.1.2). The connection and its other
                // exchanges keep running.
                throw protocol_error{
                    error_info{
                        .version = protocol_version::http3,
                        .scope = error_scope::stream,
                        .condition = error_condition::stream_reset,
                        .exchange_identity =
                            static_cast<std::uint64_t>(stream_id),
                        .library_code = std::nullopt,
                        .retryable = false,
                    },
                    reset_stream{error_code{sd->close_error_code}},
                    std::format("http/3: request stream aborted (0x{:x})",
                                sd->close_error_code)};
            }
            throw std::runtime_error("http/3: stream closed before complete response");
        }

        auto head = http::response{
            .status = sd->core.status_code,
            .reason = {},
            .fields = std::move(sd->core.decoded.regular),
        };
        co_return http::received<http::response, body_reader<S>>{
            .head = std::move(head),
            .body = body_reader<S>{sd, shared_stream, ctx_},
        };
    }

    friend auto operation_start(client& endpoint) -> task<void> {
        co_await endpoint.operation_start();
    }

    template <body_stream Body>
    friend auto operation_request(client& endpoint, http::request head, Body& body)
        -> task<http::received<http::response, body_reader<S>>> {
        co_return co_await endpoint.operation_request(std::move(head), body);
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
