module;

#include <nghttp2/nghttp2.h>

#include <algorithm>
#include <coroutine>
#include <cstdint>
#include <exception>
#include <memory>
#include <optional>
#include <span>
#include <stdexcept>
#include <stop_token>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

export module httpant:client.nghttp2;

import :endpoint.nghttp2;
import :serialize.nghttp2;
import :session.nghttp2;
import :parse.nghttp2;
import :trait;
import :message;

export namespace http::v2 {

// ─── HTTP/2 client (RFC 9113) ─────────────────────────────────

template <byte_stream S>
class client {
public:
    explicit client(
        S& transport,
        configuration configuration = {})
        : transport_(transport),
          configuration_(configuration),
          runtime_(transport_, session_, ctx_) {
        session_ = detail::create_session(
            detail::endpoint_role::client, ctx_, configuration_);
    }

    ~client() { runtime_.stop(); }
    client(const client&) = delete;
    client& operator=(const client&) = delete;
    client(client&&) = delete;
    auto operator=(client&&) -> client& = delete;

private:
    auto operation_start() -> task<void> {
        co_await runtime_.start();
        co_await runtime_.handshake();
    }

    // Send the request head, stream the body, and return the response head plus
    // a lazy body reader once the response headers have arrived.
    template <body_stream Body>
    auto operation_request(http::request head, Body& body)
        -> task<http::received<http::response, body_reader>> {
        // RFC 9113 §6.8 — "Receivers of a GOAWAY frame MUST NOT open additional streams on the
        // connection, although a new connection can be established for new streams."
        if (ctx_.core.goaway_received)
            throw detail::make_goaway_rejection(std::nullopt);

        // RFC 9113 §8.3.1 / §8.5 — request pseudo-fields and CONNECT omission
        // rules are shared HTTP semantics with HTTP/3; the message partition
        // validates and orders one owned field block.
        auto fields = http::detail::make_request_field_block(head);
        if (!fields)
            throw std::runtime_error(
                std::string{"http/2: "} +
                std::string{http::detail::request_field_error_name(fields.error())});

        if (head.method != method::CONNECT) {
            auto scheme = request_scheme(head);
            auto authority = request_authority(head);
            // RFC 9110 §4.3 — a client sends requests for a single origin on one connection
            // (CONNECT tunneling aside). Record the origin of the first request so pushed
            // requests can be checked for authority (RFC 9113 §8.4). Once set, it is fixed;
            // a request for a different origin is the caller's responsibility to put on a new
            // connection.
            if (!ctx_.origin_scheme) {
                ctx_.origin_scheme = std::string(*scheme);
                ctx_.origin_authority = std::string(*authority);
            }
        }

        std::vector<nghttp2_nv> nva;
        nva.reserve(fields->size());
        for (auto& field : *fields)
            nva.push_back(detail::make_nv(field.name, field.value));

        auto sd = std::make_shared<detail::stream_data>();

        auto binding = detail::bind_outbound_body(body);

        auto stream_id = detail::check_stream_id(
            nghttp2_submit_request2(session_.get(), nullptr, nva.data(), nva.size(),
                &binding.provider, nullptr), "submit_request");
        sd->core.id = stream_id;
        ctx_.core.streams[stream_id] = sd;
        ctx_.core.outbound_bodies[stream_id] = binding.state;

        // Let nghttp2 emit the HEADERS and observe the initially empty provider.
        // Only a provider that returned NGHTTP2_ERR_DEFERRED can be resumed.
        co_await runtime_.flush();

        // Drive the request body through nghttp2's data provider: refill the
        // bridge, resume the stream, and flush until the body is exhausted.
        co_await detail::stream_outbound_body(
            runtime_, session_.get(), ctx_, stream_id, sd, *binding.state,
            *binding.bridge, true);

        // Wait for the response header section before returning. The connection
        // error is re-checked after each wake (v3-style delivery: the awaiter no
        // longer rethrows; the driver latched the failure and aborted the
        // streams, so the loop below surfaces it exactly once).
        while (!sd->core.headers_done) {
            // RFC 9113 §6.8 — "If the receiver of the GOAWAY has sent data on streams with a
            // higher stream identifier than what is indicated in the GOAWAY frame, those streams
            // are not or will not be processed." — a stream above the GOAWAY last-stream-id that
            // has not started its response is rejected; the typed rejection takes
            // precedence over the generic stream-abort the peer's GOAWAY also causes.
            if (ctx_.core.goaway_received &&
                stream_id > ctx_.goaway_last_stream_id)
                throw detail::make_goaway_rejection(
                    static_cast<std::uint64_t>(stream_id));
            if (ctx_.core.connection_error)
                std::rethrow_exception(ctx_.core.connection_error);
            if (sd->core.aborted)
                detail::throw_stream_abort(*sd);

            co_await detail::request_awaiter{ctx_, sd};
        }

        auto head_out = http::response{
            .status = sd->core.status_code,
            .reason = {},
            .fields = std::move(sd->core.decoded.regular),
        };

        co_return http::received<http::response, body_reader>{
            .head = std::move(head_out),
            .body = body_reader{ctx_, sd,
                [this, stream_id](std::size_t n) -> task<void> {
                    co_await runtime_.return_credit(stream_id, n);
                }},
        };
    }

    friend auto operation_start(client& endpoint) -> task<void> {
        co_await endpoint.operation_start();
    }

    template <body_stream Body>
    friend auto operation_request(client& endpoint, http::request head, Body& body)
        -> task<http::received<http::response, body_reader>> {
        co_return co_await endpoint.operation_request(std::move(head), body);
    }

public:

    // RFC 9113 §6.7 — see detail::endpoint_runtime::ping.
    auto ping() -> task<void> {
        co_await runtime_.ping();
    }

    // RFC 9113 §9.1 / §6.8 — send a GOAWAY carrying the clamped
    // last-stream-id before the connection closes (see
    // detail::endpoint_runtime::shutdown).
    auto shutdown() -> task<void> {
        co_await runtime_.shutdown();
    }

    auto update_settings(std::span<const setting> settings)
        -> task<settings_ticket>
    {
        co_return co_await runtime_.update_settings(settings);
    }

    [[nodiscard]] auto acknowledged(settings_ticket ticket) const noexcept -> bool {
        return runtime_.acknowledged(ticket);
    }

    auto expire_settings(settings_ticket ticket) -> task<void> {
        co_await runtime_.expire_settings(ticket);
    }

    [[nodiscard]] auto compression_state() const -> hpack_state {
        return runtime_.compression_state(configuration_.compression);
    }

    // A push whose promised stream the peer reset before its response completed
    // is never delivered: take_push surfaces the abort as a typed stream error
    // carrying the peer's RST_STREAM code (RFC 9113 §6.4), with RFC 9113 §8.7
    // retry semantics for REFUSED_STREAM. Aborts are reported before completed
    // pushes so an application that polls take_push learns of a vanished push
    // promptly rather than through a silent gap in the sequence.
    auto take_push() -> std::optional<pushed_exchange> {
        if (!ctx_.aborted_pushes.empty()) {
            auto push = ctx_.aborted_pushes.front();
            ctx_.aborted_pushes.pop_front();
            detail::throw_push_abort(push);
        }
        if (ctx_.completed_pushes.empty()) return std::nullopt;
        auto push = std::move(ctx_.completed_pushes.front());
        ctx_.completed_pushes.pop_front();
        ctx_.last_processed_peer_stream_id =
            std::max(ctx_.last_processed_peer_stream_id, push.stream_id);
        return std::move(push.exchange);
    }

    [[nodiscard]] auto goaway_received() const -> bool { return ctx_.core.goaway_received; }
    // RFC 9113 §5.2 — see detail::endpoint_runtime.
    [[nodiscard]] auto remote_window_size() const -> std::int32_t {
        return runtime_.remote_window_size();
    }
    [[nodiscard]] auto local_window_size() const -> std::int32_t {
        return runtime_.local_window_size();
    }

private:
    S& transport_;
    detail::session_handle session_{};
    detail::session_context ctx_{};
    configuration configuration_{};
    detail::endpoint_runtime<S> runtime_;
};

} // namespace http::v2
