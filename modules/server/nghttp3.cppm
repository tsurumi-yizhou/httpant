export module httpant:server.nghttp3;

import httpant.dependencies.nghttp3;
import std;
import :trait;
import :message;
import :role;
import :error;
import :session.nghttp3;
import :serialize.nghttp3;
import :parse.nghttp3;
import :endpoint.nghttp3;

export namespace http::v3 {

template <stream_factory S, template <class> class Queue = http::queues::local>
class server {
public:
    // The prefix every local-misuse message of this engine starts with; the
    // exchange token reads it from the server type that minted it.
    static constexpr std::string_view message_prefix = error_prefix.view();

    explicit server(S& transport, configuration config = {})
        : transport_(transport),
          conn_(detail::create_connection(
              detail::endpoint_role::server, ctx_, config)),
          runtime_(transport_, conn_.get(), ctx_, open_streams_) {}

    server(const server&) = delete;
    server& operator=(const server&) = delete;

    // The token's engine payload: the request stream record. The shared core
    // has the owning-server pointer, so a token minted by one connection
    // cannot be used to respond on another (checked in respond).
    using exchange_token =
        http::detail::exchange_token<server, std::shared_ptr<detail::stream_data<Queue>>>;
    using incoming_request = http::detail::incoming_request<body_reader<S, Queue>, exchange_token>;

    // RFC 9114 §6.2.1 — "Each side MUST initiate a single control stream at
    // the beginning of the connection and send its SETTINGS frame as the first
    // frame on this stream." See client::start for the stream-factory
    // driven creation of the control/QPACK unidirectional streams.
public:
    // RFC 9114 §4.1 — "A server sends ... responses on the same stream as the
    // request"; the opaque move-only token holds that association atomically
    // with the completed request. Suspends until the endpoint driver has
    // completed the next request stream (headers + request body + FIN).
    auto receive() -> http::detail::operation<incoming_request> {
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
            co_await http::detail::park_until{ctx_.core.receive_waiter, [this] {
                return !ctx_.core.receive_queue_empty() ||
                       !ctx_.server_stream_failures.empty() ||
                       ctx_.core.connection_error != nullptr;
            }};
        }

        auto stream = std::move(ctx_.core.receive_queue_front());
        ctx_.core.receive_queue_pop();
        // A stream reset between header completion and delivery must not be
        // handed to the application as if it were live: fail it exactly like
        // the client-side aborted-stream path in request.
        if (stream->core.aborted) {
            if (stream->close_error_code != 0) {
                // RFC 9114 §8 — "QUIC allows the application to abruptly
                // terminate (reset) that stream and communicate a reason."
                throw protocol_error{
                    error_info{
                        .condition = error_condition::stream_reset,
                        .exchange_identity =
                            static_cast<std::uint64_t>(stream->core.id),
                        .library_code = std::nullopt,
                    },
                    reset_stream{stream->close_error_code},
                    std::format("http/3: request stream aborted (0x{:x})",
                                stream->close_error_code)};
            }
            throw detail::make_incomplete_close(stream->core.id, "http/3: stream closed before complete request");
        }
        // The transport handle of a stream the driver marked complete is an
        // internal invariant, so a missing entry is a library bug, not a
        // wire-level protocol error.
        auto transport = open_streams_.find(stream->core.id);
        if (transport == open_streams_.end())
            throw std::logic_error(
                "http/3: completed request stream has no transport handle");
        auto head = http::request{
            // The parse layer admits a request stream into the receive queue
            // only after it saw a representable :method (see decoded_fields),
            // so the delivered method is already validated.
            .method = *stream->core.decoded.method,
            .target = std::move(stream->core.decoded.path),
            .scheme = std::move(stream->core.decoded.scheme),
            .authority = std::move(stream->core.decoded.authority),
            .fields = std::move(stream->core.decoded.regular),
        };
        co_return incoming_request{
            .head = std::move(head),
            .body = body_reader<S, Queue>{
                stream, transport->second, ctx_},
            .token = exchange_token{*this, stream},
        };
    }

    template <body_stream Body>
    auto respond(
        exchange_token token,
        http::response res,
        Body& body) -> http::detail::operation<void> {
        if (!token.valid())
            throw usage_error("http/3: invalid exchange token");
        // A token minted by another server must not respond on this
        // connection; responding consumes the token (the stream handle moves
        // out), so a second respond with the same token fails the check above.
        token.check_owner(*this);
        auto stream = token.take_handle();
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
        auto request_method = *stream->core.decoded.method;
        auto allows_body = http::response_has_body(request_method, res.status);

        std::array<char, 3> status;
        auto* status_end = std::to_chars(status.data(), status.data() + status.size(), res.status.code()).ptr;
        std::vector<nghttp3_nv> nva;
        nva.reserve(res.fields.size() + 1);
        nva.push_back(detail::make_nv(":status", {status.data(), status_end}));
        for (const auto& field : res.fields) nva.push_back(detail::make_nv(field.name, field.value));
        detail::check_outbound_field_section(ctx_, nva);

        auto outbound_body = std::make_shared<detail::outbound_body_state<Queue>>();
        // Only the outbound-body registration is new here: the stream state
        // belongs to the received exchange, so the guard must not touch it.
        detail::exchange_registration<typename detail::endpoint_runtime<S, Queue>::stream_map, Queue>
            guard{ctx_, conn_.get(), stream_id};
        if (allows_body)
            co_await detail::fill_outbound_body(body, *outbound_body);
        else
            outbound_body->eof = true;
        nghttp3_data_reader reader{.read_data = &detail::read_outbound_body<Queue>};
        detail::check(nghttp3_conn_submit_response(conn_.get(), stream_id,
            nva.data(), nva.size(),
            outbound_body->eof ? nullptr : &reader), "submit_response");
        // Registered even without content: the FIN acknowledgement and the
        // stream's end reach the exchange through it.
        ctx_.core.outbound_bodies[stream_id] = outbound_body;
        if (!outbound_body->eof) {
            // RFC 9114 §4.1 — response content is sent as DATA frames on the
            // request stream; nghttp3's data callback therefore needs the body
            // state bound to that exact stream.
            detail::check(nghttp3_conn_set_stream_user_data(
                conn_.get(), stream_id, outbound_body.get()), "set_stream_user_data");
        }
        co_await detail::pump_outbound_body(
            body, *outbound_body, stream_id, conn_.get(), runtime_);
        // The response is out once the peer acknowledges its FIN: closing
        // the connection earlier would discard what the peer has not received.
        // A stream or connection that ends first ends the exchange too; the
        // peer may well have read the response before closing.
        co_await http::detail::park_until{outbound_body->ack_waiter, [this, &outbound_body] {
            return outbound_body->finished || ctx_.core.connection_error;
        }};
        ctx_.core.outbound_bodies.erase(stream_id);
        guard.disarm();
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
