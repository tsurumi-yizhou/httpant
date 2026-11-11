export module httpant:client.nghttp3;
import httpant.exception;

import httpant.dependencies.nghttp3;
import std;
import :trait;
import :message;
import :error;
import :session.nghttp3;
import :serialize.nghttp3;
import :parse.nghttp3;
import :endpoint.nghttp3;

export namespace http::v3 {

template <stream_factory S, template <class> class Queue = http::queues::local>
class client {
public:
    // RFC 7301 — the ALPN protocol identifier of HTTP/3 (RFC 9114 §3.1 — "h3").
    // The authority goes in :authority, not in a Host field.
    static constexpr std::string_view alpn = "h3";
    static constexpr bool uses_host_field = false;

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
public:
    template <body_stream Body>
    auto request(http::request req, Body& body)
        -> http::detail::operation<http::received<http::response, body_reader<S, Queue>>> {
        // RFC 9114 §5.2 — "Endpoints MUST NOT initiate new requests or promise new pushes on the connection after receipt of a GOAWAY frame from the peer."
        if (ctx_.core.goaway_received)
            throw detail::make_goaway_rejection(std::nullopt);
        if (ctx_.core.connection_error)
            std::rethrow_exception(ctx_.core.connection_error);

        // RFC 9114 §4.3.1 / §4.4 — HTTP/2 and HTTP/3 share the same
        // pseudo-field completeness, ordering, CONNECT, and Host rules.
        auto fields = http::detail::make_request_field_block(req, detail::make_nv);
        if (!fields)
            throw usage_error(
                std::string{"http/3: "} +
                std::string{http::detail::request_field_error_name(fields.error())});

        detail::check_outbound_field_section(ctx_, *fields);

        // RFC 9114 §4.1 — the request stream is opened through the factory with
        // an explicit direction; the identity is consumed by the H3 layer and
        // never delivered to the application.
        auto& stop = co_await current_stop_token();
        auto stream = co_await transport_.async_open_bidirectional(stop);
        auto stream_id = detail::to_stream_id(stream.identifier());
        auto shared_stream =
            std::make_shared<typename S::stream_type>(std::move(stream));
        open_streams_[stream_id] = shared_stream;
        detail::exchange_registration guard{
            ctx_, conn_.get(), stream_id, &open_streams_};

        auto sd = std::make_shared<detail::stream_data<Queue>>();
        sd->core.id = stream_id;
        ctx_.core.streams[stream_id] = sd;

        auto outbound_body = std::make_shared<detail::outbound_body_state<Queue>>();
        co_await detail::fill_outbound_body(body, *outbound_body);
        nghttp3_data_reader reader{.read_data = &detail::read_outbound_body<Queue>};
        if (!outbound_body->eof)
            ctx_.core.outbound_bodies[stream_id] = outbound_body;

        detail::check(nghttp3_conn_submit_request(conn_.get(), stream_id,
            fields->data(), fields->size(),
            outbound_body->eof ? nullptr : &reader,
            outbound_body->eof ? nullptr : outbound_body.get()), "submit_request");
        guard.submitted = true;

        co_await detail::pump_outbound_body(
            body, *outbound_body, stream_id, conn_.get(), runtime_);
        ctx_.core.outbound_bodies.erase(stream_id);
        guard.disarm();

        runtime_.read(shared_stream, false);
        // The header wait ends when the driver resumes it (end of headers,
        // stream close or abort, connection failure) or when the request's
        // own stop token is stopped.
        while (!sd->core.headers_done && !sd->core.aborted) {
            if (ctx_.core.goaway_received && ctx_.core.goaway_id &&
                static_cast<std::uint64_t>(stream_id) >=
                    static_cast<std::uint64_t>(*ctx_.core.goaway_id))
                throw detail::make_goaway_rejection(
                    static_cast<std::uint64_t>(stream_id));
            co_await detail::response_headers(sd);
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
                        .condition = error_condition::stream_reset,
                        .exchange_identity =
                            static_cast<std::uint64_t>(stream_id),
                        .library_code = std::nullopt,
                    },
                    reset_stream{sd->close_error_code},
                    std::format("http/3: request stream aborted (0x{:x})",
                                sd->close_error_code)};
            }
            throw detail::make_incomplete_close(stream_id, "http/3: stream closed before complete response");
        }

        auto head = http::response{
            .status = sd->core.status_code,
            .reason = {},
            .fields = std::move(sd->core.decoded.regular),
        };
        co_return http::received<http::response, body_reader<S, Queue>>{
            .head = std::move(head),
            .body = body_reader<S, Queue>{sd, shared_stream, ctx_},
        };
    }

    auto start() -> http::detail::operation<void> {
        return runtime_.start();
    }

    auto close() -> http::detail::operation<void> {
        return runtime_.close();
    }

public:
    auto shutdown() -> http::detail::operation<void> {
        return runtime_.shutdown();
    }

    [[nodiscard]] auto goaway_received() const -> bool { return ctx_.core.goaway_received; }

    [[nodiscard]] auto compression_state() const -> qpack_state {
        return detail::compression_state(ctx_);
    }

private:
    S& transport_;
    detail::conn_context<Queue> ctx_{};
    detail::connection_handle conn_{};
    typename detail::endpoint_runtime<S, Queue>::stream_map open_streams_{};
    detail::endpoint_runtime<S, Queue> runtime_;
};

} // namespace http::v3
