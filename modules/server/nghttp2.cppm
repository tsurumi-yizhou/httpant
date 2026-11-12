export module httpant:server.nghttp2;
import httpant.exception;

import httpant.dependencies.nghttp2;
import std;
import :endpoint.nghttp2;
import :serialize.nghttp2;
import :session.nghttp2;
import :parse.nghttp2;
import :trait;
import :message;
import :role;

export namespace http::v2 {

    // ─── HTTP/2 server (RFC 9113) ─────────────────────────────────

    template <byte_stream S, template <class> class Queue = http::queues::local> class server {
    public:
        // The prefix every local-misuse message of this engine starts with; the
        // exchange token reads it from the server type that minted it.
        static constexpr std::string_view message_prefix = error_prefix.view();

        // The token's engine payload: the request stream record. The shared core
        // has the owning-server pointer, so a token minted by one connection
        // cannot be used to respond on another (checked in respond).
        using exchange_token = http::detail::exchange_token<server, std::shared_ptr<detail::stream_data<Queue>>>;
        using incoming_request = http::detail::incoming_request<body_reader<Queue>, exchange_token>;

        explicit server(S& transport, configuration configuration = {})
            : transport_(transport), configuration_(configuration), runtime_(transport_, session_, ctx_) {
            session_ = detail::create_session(detail::endpoint_role::server, ctx_, configuration_);
        }

        server(const server&) = delete;
        server& operator=(const server&) = delete;

    public:
        auto start() -> http::detail::operation<void> {
            co_await runtime_.start();
            co_await runtime_.handshake();
        }

        // Read the request head (waiting for the header section) and return it plus
        // a lazy body reader.
        auto receive() -> http::detail::operation<incoming_request> {
            // RFC 9113 §8.1 — "A client sends an HTTP request on a new stream, using a previously
            // unused stream identifier (Section 5.1.1). A server sends an HTTP response on the same
            // stream as the request." — a request is delivered once its header section is complete.
            for (;;) {
                if (ctx_.core.connection_error)
                    std::rethrow_exception(ctx_.core.connection_error);
                if (!ctx_.core.receive_queue_empty())
                    break;
                co_await detail::next_request(ctx_);
            }

            auto sd = ctx_.core.receive_queue_front();
            ctx_.core.receive_queue_pop();
            ctx_.last_processed_peer_stream_id = std::max(ctx_.last_processed_peer_stream_id, sd->core.id);

            auto head = http::request{
                // The parse layer admits a request stream into the receive queue
                // only after it saw a representable :method (see decoded_fields),
                // so the delivered method is already validated.
                .method = *sd->core.decoded.method,
                .target = std::move(sd->core.decoded.path),
                .scheme = std::move(sd->core.decoded.scheme),
                .authority = std::move(sd->core.decoded.authority),
                .fields = std::move(sd->core.decoded.regular),
            };

            co_return incoming_request{
                .head = std::move(head),
                .body = body_reader<Queue>{ctx_, sd, detail::credit_return{runtime_, sd->core.id}},
                .token = exchange_token{*this, sd},
            };
        }

        // RFC 9113 §8.1 — "A server sends an HTTP response on the same stream as the request."
        // The opaque move-only token holds that correlation atomically with the request.
        template <body_stream Body> auto respond(exchange_token token, http::response head, Body& body) -> http::detail::operation<void> {
            if (!token.valid())
                throw usage_error("http/2: invalid exchange token");
            // A token minted by another server must not respond on this
            // connection; responding consumes the token (the stream handle moves
            // out), so a second respond with the same token fails the check above.
            token.check_owner(*this);
            auto stream = token.take_handle();
            if (stream->core.closed || stream->core.aborted)
                co_return;
            if (ctx_.core.connection_error)
                std::rethrow_exception(ctx_.core.connection_error);
            // RFC 9110 §15.2 / §15.3.5 / §15.4.5 — "A 1xx response is terminated by
            // the end of the header section; it cannot contain content or trailers."
            // / "A 204 response is terminated by the end of the header section; it
            // cannot contain content or trailers." / "A 304 response is terminated
            // by the end of the header section; it cannot contain content or
            // trailers." RFC 9113 §8.1 — "HTTP/2 uses DATA frames to carry message
            // content." — such a response ends at the header section even for a GET
            // request, exactly as RFC 9110 §9.3.2 — "The HEAD method is identical
            // to GET except that the server MUST NOT send content in the response."
            // — does for HEAD. The shared predicate decides suppression.
            if (!http::response_has_body(*stream->core.decoded.method, head.status)) {
                http::buffer_body empty;
                co_await send_response(std::move(stream), std::move(head), empty);
                co_return;
            }
            co_await send_response(std::move(stream), std::move(head), body);
        }

        auto close() -> http::detail::operation<void> { return runtime_.close(); }

    public:
        // RFC 9113 §8.4 — a server push promises a safe, cacheable request and
        // streams its response on the promised stream. The response body is passed
        // separately (responses carry no embedded body).
        template <body_stream Body>
        auto push(const exchange_token& associated, http::request req, http::response res, Body& body) -> http::detail::operation<void> {
            if (!associated.valid())
                throw usage_error("http/2: invalid exchange token");
            associated.check_owner(*this);
            if (associated.handle()->core.closed || associated.handle()->core.aborted)
                co_return;
            auto associated_stream_id = associated.handle()->core.id;
            // RFC 9113 §6.8 — "Receivers of a GOAWAY frame MUST NOT open additional
            // streams on the connection" — a promised stream is a new stream, so a
            // push after GOAWAY is rejected loudly instead of being sent into a
            // closing connection.
            if (ctx_.core.goaway_received)
                throw detail::make_goaway_rejection(std::nullopt);
            // RFC 9113 §8.4 — "Promised requests MUST be safe (see Section 9.2.1 of [HTTP]) and
            // cacheable (see Section 9.2.3 of [HTTP]). Promised requests cannot include any content
            // or a trailer section."
            if (req.method != method::GET && req.method != method::HEAD)
                throw usage_error("http/2: pushed requests must be GET or HEAD");

            // RFC 9113 §8.4.1 — "The header fields in PUSH_PROMISE and any subsequent CONTINUATION
            // frames MUST be a valid and complete set of request header fields (Section 8.3.1)."
            auto fields = http::detail::make_request_field_block(req, detail::make_nv);
            if (!fields)
                throw usage_error(std::string{"http/2: pushed request "} + std::string{http::detail::request_field_error_name(fields.error())});

            // RFC 9113 §6.6 — "PUSH_PROMISE frames MUST only be sent on a peer-initiated stream that
            // is in either the 'open' or 'half-closed (remote)' state." — the associated request
            // stream; §8.4.1 — "The PUSH_PROMISE frames sent by the server are sent on that explicit
            // request's stream."
            auto promised_stream_id = detail::check_stream_id(
                nghttp2_submit_push_promise(session_.get(), NGHTTP2_FLAG_NONE, associated_stream_id, fields->data(), fields->size(), nullptr),
                "submit_push_promise");

            auto promised = std::make_shared<detail::stream_data<Queue>>();
            promised->core.id = promised_stream_id;
            ctx_.core.streams[promised_stream_id] = promised;

            // RFC 9113 §8.4.2 — "The client never sends a frame with the END_STREAM flag set for a
            // server push." — the stream is closed by the server's own END_STREAM. HEAD responses
            // must not carry a body (RFC 9110 §9.3.2), and RFC 9110 §15.2/§15.3.5/§15.4.5 — "A 1xx
            // response is terminated by the end of the header section" — likewise for 204/304.
            if (req.method == method::HEAD || !http::status_allows_body(res.status)) {
                http::buffer_body empty;
                co_await send_response(std::move(promised), std::move(res), empty);
            } else {
                co_await send_response(std::move(promised), std::move(res), body);
            }
            co_return;
        }

        // RFC 9113 §6.7 — see detail::endpoint_runtime::ping.
        auto ping() -> http::detail::operation<void> { return runtime_.ping(); }

        // RFC 9113 §6.8 — "An endpoint SHOULD always send a GOAWAY frame before
        // closing a connection so that the remote peer can know whether a stream
        // has been partially processed or not." The last-stream-id is the highest
        // request delivered to the application, clamped per §6.8 (see
        // detail::endpoint_runtime::shutdown).
        auto shutdown() -> http::detail::operation<void> { return runtime_.shutdown(); }

        auto update_settings(std::span<const setting> settings) -> http::detail::operation<settings_ticket> { return runtime_.update_settings(settings); }

        [[nodiscard]] auto acknowledged(settings_ticket ticket) const noexcept -> bool { return runtime_.acknowledged(ticket); }

        auto expire_settings(settings_ticket ticket) -> http::detail::operation<void> { return runtime_.expire_settings(ticket); }

        [[nodiscard]] auto compression_state() const -> hpack_state { return runtime_.compression_state(configuration_.compression); }

        [[nodiscard]] auto goaway_received() const -> bool { return ctx_.core.goaway_received; }
        // RFC 9113 §5.2 — see detail::endpoint_runtime.
        [[nodiscard]] auto remote_window_size() const -> std::int32_t { return runtime_.remote_window_size(); }
        [[nodiscard]] auto local_window_size() const -> std::int32_t { return runtime_.local_window_size(); }

    private:
        // Submit and stream a response head and body on the given stream.
        template <body_stream Body>
        auto send_response(std::shared_ptr<detail::stream_data<Queue>> sd, http::response head, Body& body) -> http::detail::operation<void> {
            auto stream_id = sd->core.id;
            // RFC 9113 §8.3.2 — ":status" holds an RFC 9110 §15 status code,
            // which http::status cannot leave the 100-599 range of.
            std::vector<nghttp2_nv> nva;
            auto status_str = std::format("{}", head.status.code());
            // RFC 9113 §8.3.2 — "For HTTP/2 responses, a single ':status' pseudo-header field is
            // defined that carries the HTTP status code field (see Section 15 of [HTTP]). This
            // pseudo-header field MUST be included in all responses, including interim responses;
            // otherwise, the response is malformed (Section 8.1.1)."
            nva.push_back(detail::make_nv(":status", status_str));
            for (auto& h : head.fields)
                nva.push_back(detail::make_nv(h.name, h.value));

            auto binding = detail::bind_outbound_body(body);

            detail::check(nghttp2_submit_response2(session_.get(), stream_id, nva.data(), nva.size(), &binding.provider), "submit_response");
            ctx_.core.outbound_bodies[stream_id] = binding.state;

            // Emit the response HEADERS and allow the empty provider to become
            // deferred before the first explicit resume.
            co_await runtime_.flush();

            co_await detail::stream_outbound_body(runtime_, session_.get(), ctx_, stream_id, std::move(sd), *binding.state, *binding.bridge, false);
        }

        S& transport_;
        detail::session_handle session_{};
        detail::session_context<Queue> ctx_{};
        configuration configuration_{};
        detail::endpoint_runtime<S, Queue> runtime_;
    };

} // namespace http::v2
