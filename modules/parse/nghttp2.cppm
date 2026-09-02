module;

#include <nghttp2/nghttp2.h>

#include <array>
#include <coroutine>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <stdexcept>
#include <stop_token>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

export module httpant:parse.nghttp2;

import :session.nghttp2;
import :trait;
import :message;

export namespace http::v2 {

namespace detail {

inline auto create_callbacks() -> callbacks_handle {
    nghttp2_session_callbacks* raw_callbacks = nullptr;
    check(
        nghttp2_session_callbacks_new(&raw_callbacks),
        "session_callbacks_new");
    auto callbacks = callbacks_handle{raw_callbacks};
    auto* cbs = callbacks.get();

    nghttp2_session_callbacks_set_on_header_callback(cbs,
        [](nghttp2_session* session, const nghttp2_frame* frame,
           const uint8_t* name, std::size_t namelen,
           const uint8_t* value, std::size_t valuelen,
           uint8_t, void* ud) -> int {
            auto& ctx = *static_cast<session_context*>(ud);
            return http::detail::callback_boundary(ctx, NGHTTP2_ERR_CALLBACK_FAILURE, [&]() -> int {
                if (frame->hd.type == NGHTTP2_PUSH_PROMISE) {
                    // RFC 9113 §8.4.1 — "The PUSH_PROMISE frame includes a field block that contains
                    // control data and a complete set of request header fields that the server
                    // attributes to the request." — the promised request's pseudo-headers are
                    // captured here.
                    auto promised_stream_id = frame->push_promise.promised_stream_id;
                    // RFC 9113 §8.4 — a push the client already rejected (§8.4 validation in
                    // on_frame_recv_callback) must not be recorded or delivered.
                    if (ctx.rejected_pushes.contains(promised_stream_id))
                        return 0;
                    auto& push = ctx.pushed_streams[promised_stream_id];
                    if (!push) {
                        push = std::make_shared<push_data>();
                        push->promised_stream_id = promised_stream_id;
                        push->associated_stream_id = frame->hd.stream_id;
                    }

                    auto n = std::string(reinterpret_cast<const char*>(name), namelen);
                    auto v = std::string(reinterpret_cast<const char*>(value), valuelen);
                    static_cast<void>(push->request.append(std::move(n), std::move(v)));
                    return 0;
                }

                if (auto push_it = ctx.pushed_streams.find(frame->hd.stream_id);
                    push_it != ctx.pushed_streams.end()) {
                    auto n = std::string(reinterpret_cast<const char*>(name), namelen);
                    auto v = std::string(reinterpret_cast<const char*>(value), valuelen);
                    if (push_it->second->response.append(n, v) ==
                        http::detail::field_disposition::deferred_status) {
                        // RFC 9113 §8.1.1 — "Malformed requests or responses that
                        // are detected MUST be treated as a stream error (Section
                        // 5.4.2) of type PROTOCOL_ERROR." — a malformed :status
                        // makes the pushed response malformed. The reset is
                        // submitted directly: returning a callback failure code
                        // would make nghttp2 reset the stream with INTERNAL_ERROR
                        // instead. The stream is marked rejected so later frames
                        // of the promised stream are ignored, and locally aborted
                        // (with the submitted code) so the close event is recorded
                        // as this endpoint's own abort, never attributed to the
                        // peer — mirroring the request/response treatment in the
                        // streams branch.
                        auto status = parse_status(v);
                        if (!status) {
                            ctx.rejected_pushes.insert(frame->hd.stream_id);
                            push_it->second->locally_aborted = true;
                            push_it->second->local_reset_code = NGHTTP2_PROTOCOL_ERROR;
                            (void)nghttp2_submit_rst_stream(
                                session, NGHTTP2_FLAG_NONE, frame->hd.stream_id,
                                NGHTTP2_PROTOCOL_ERROR);
                            return 0;
                        }
                        push_it->second->status_code = static_cast<http::status>(*status);
                    }
                    return 0;
                }

                auto it = ctx.core.streams.find(frame->hd.stream_id);
                if (it == ctx.core.streams.end()) return 0;
                auto n = std::string(reinterpret_cast<const char*>(name), namelen);
                auto v = std::string(reinterpret_cast<const char*>(value), valuelen);
                if (it->second->core.decoded.append(n, v) ==
                    http::detail::field_disposition::deferred_status) {
                    // RFC 9113 §8.1.1 — a malformed :status makes the response
                    // malformed: "a stream error (Section 5.4.2) of type
                    // PROTOCOL_ERROR". As above, the reset is submitted directly
                    // because a callback failure code maps to INTERNAL_ERROR.
                    auto status = parse_status(v);
                    if (!status) {
                        it->second->core.aborted = true;
                        it->second->locally_aborted = true;
                        it->second->local_reset_code = NGHTTP2_PROTOCOL_ERROR;
                        (void)nghttp2_submit_rst_stream(
                            session, NGHTTP2_FLAG_NONE, frame->hd.stream_id,
                            NGHTTP2_PROTOCOL_ERROR);
                        return 0;
                    }
                    it->second->core.status_code = static_cast<http::status>(*status);
                }
                return 0;
            });
        });

    nghttp2_session_callbacks_set_on_frame_recv_callback(cbs,
        [](nghttp2_session* session, const nghttp2_frame* frame, void* ud) -> int {
            auto& ctx = *static_cast<session_context*>(ud);
            return http::detail::callback_boundary(ctx, NGHTTP2_ERR_CALLBACK_FAILURE, [&]() -> int {
                if (frame->hd.type == NGHTTP2_PUSH_PROMISE) {
                    // RFC 9113 §8.4 — "Promised requests MUST be safe ... and cacheable ... Clients
                    // that receive a promised request that is not cacheable, that is not known to be
                    // safe, or that indicates the presence of request content MUST reset the promised
                    // stream with a stream error (Section 5.4.2) of type PROTOCOL_ERROR." — once the
                    // PUSH_PROMISE field block is complete, the promised request's method is checked;
                    // only GET/HEAD are both safe and cacheable, and PUSH_PROMISE cannot carry
                    // content.
                    auto promised_stream_id = frame->push_promise.promised_stream_id;
                    auto it = ctx.pushed_streams.find(promised_stream_id);
                    if (it != ctx.pushed_streams.end()) {
                        const auto& push = it->second;
                        // RFC 9113 §8.3.1 — "All HTTP/2 requests MUST include exactly one valid value
                        // for the ":method", ":scheme", and ":path" pseudo-header fields, unless they
                        // are CONNECT requests." A pushed request is never CONNECT (§8.4 requires
                        // safety/cacheability), and §8.4 — "The server MUST include a value in the
                        // ":authority" pseudo-header field" — so all four are mandatory.
                        bool missing_pseudo = push->request.method_token.empty() ||
                                              push->request.path.empty() ||
                                              push->request.scheme.empty() ||
                                              push->request.authority.empty();
                        bool bad_method = push->request.method_token != "GET" &&
                                          push->request.method_token != "HEAD";
                        // RFC 9113 §8.4 — "A client MUST treat a PUSH_PROMISE for which the server is
                        // not authoritative as a stream error ... of type PROTOCOL_ERROR." (RFC 9113
                        // §10.1 — "HTTP/2 relies on the HTTP definition of authority"; RFC 9110 §4.2.2
                        // — scheme/host case-insensitive, default port omitted.)
                        bool not_authoritative = false;
                        if (!missing_pseudo && ctx.origin_scheme && ctx.origin_authority) {
                            not_authoritative = !http::detail::same_origin(
                                push->request.scheme,
                                push->request.authority,
                                *ctx.origin_scheme,
                                *ctx.origin_authority);
                        }
                        if (missing_pseudo || bad_method || not_authoritative) {
                            ctx.rejected_pushes.insert(promised_stream_id);
                            ctx.pushed_streams.erase(it);
                            (void)nghttp2_submit_rst_stream(
                                session, NGHTTP2_FLAG_NONE, promised_stream_id, NGHTTP2_PROTOCOL_ERROR);
                            return 0;
                        }
                    }
                    return 0;
                }
                if (frame->hd.type == NGHTTP2_HEADERS) {
                    auto it = ctx.core.streams.find(frame->hd.stream_id);
                    if (it != ctx.core.streams.end()) {
                        // A stream locally reset for a malformed :status
                        // (on_header_callback) keeps its record until the close
                        // event; nghttp2 currently skips on_frame_recv for such a
                        // CLOSING stream, but that is a library internal. Guard
                        // explicitly so headers_done can never be latched for an
                        // already-aborted stream, whatever nghttp2's routing does.
                        if (it->second->core.aborted) return 0;
                        // RFC 9113 §8.3.1 — "A server SHOULD treat a request as
                        // malformed if it contains a Host header field that
                        // identifies an entity that differs from the entity in the
                        // ":authority" pseudo-header field. The values of fields
                        // need to be normalized to compare them (see Section 6.2
                        // of [RFC3986]). An origin server can apply any
                        // normalization method, whereas other servers MUST perform
                        // scheme-based normalization (see Section 6.2.3 of
                        // [RFC3986]) of the two fields." — nghttp2 checks Host
                        // presence and uniqueness only, never value equality, so
                        // the agreement check is added here; the comparison
                        // normalizes scheme/host case and the default port, which
                        // covers both normalization choices for http/https.
                        bool host_disagrees = false;
                        if (!it->second->core.decoded.method_token.empty() &&
                            !it->second->core.decoded.authority.empty()) {
                            if (auto host = http::find_header(
                                    it->second->core.decoded.regular, "host")) {
                                host_disagrees = !http::detail::same_origin(
                                    it->second->core.decoded.scheme,
                                    it->second->core.decoded.authority,
                                    it->second->core.decoded.scheme,
                                    *host);
                            }
                        }
                        // Asterisk-form ':path: *' with a non-OPTIONS method needs
                        // no check here: nghttp2 rejects it when the header block
                        // completes (RFC 9113 §8.3.1 / §8.1.1, RST_STREAM
                        // PROTOCOL_ERROR) before this callback can see the frame.
                        if (host_disagrees) {
                            // RFC 9113 §8.1.1 — "Malformed requests or responses
                            // that are detected MUST be treated as a stream error
                            // (Section 5.4.2) of type PROTOCOL_ERROR."
                            it->second->core.aborted = true;
                            it->second->locally_aborted = true;
                            it->second->local_reset_code = NGHTTP2_PROTOCOL_ERROR;
                            it->second->core.headers_done = true;
                            (void)nghttp2_submit_rst_stream(
                                session, NGHTTP2_FLAG_NONE, frame->hd.stream_id,
                                NGHTTP2_PROTOCOL_ERROR);
                            return 0;
                        }
                        // RFC 9113 §8.1.1 — "An endpoint can send zero or more
                        // interim responses ... before a final response"; each
                        // interim (1xx) header block is complete in itself and
                        // carries no content. Only the final header section
                        // completes the response; interim fields are discarded so
                        // they cannot leak into the final response.
                        bool interim_response = it->second->core.decoded.method_token.empty() &&
                            is_informational(it->second->core.status_code);
                        if (interim_response) {
                            it->second->core.decoded = {};
                            it->second->core.status_code = 0;
                        } else {
                            it->second->core.headers_done = true;
                            // A request stream whose header section is complete becomes
                            // deliverable: the server surfaces it (with a lazy body
                            // reader) before the body arrives.
                            if (!it->second->core.decoded.method_token.empty() &&
                                !it->second->core.delivered) {
                                it->second->core.delivered = true;
                                ctx.core.receive_queue_push(it->second);
                            }
                        }
                    }
                }
                // RFC 9113 §6.5 — "ACK (0x01): When set, the ACK flag indicates that this frame
                // acknowledges receipt and application of the peer's SETTINGS frame." The connection
                // preface requires the peer's initial SETTINGS itself, not an ACK for our SETTINGS.
                if (frame->hd.type == NGHTTP2_SETTINGS && frame->hd.stream_id == 0) {
                    if ((frame->hd.flags & NGHTTP2_FLAG_ACK) != 0) {
                        if (!ctx.pending_settings.empty()) {
                            ctx.acknowledged_settings_sequence =
                                ctx.pending_settings.front().sequence;
                            ctx.pending_settings.pop_front();
                        }
                    } else {
                        ctx.peer_initial_settings_received = true;
                    }
                }
                if (frame->hd.type == NGHTTP2_GOAWAY) {
                    // RFC 9113 §6.8 — "The GOAWAY frame applies to the connection, not a specific
                    // stream." — record the advertised last stream id and error code so callers can
                    // stop new streams and detect rejected in-flight ones (§6.8, "Receivers of a
                    // GOAWAY frame MUST NOT open additional streams"). RFC 9113 §6.8 — "An endpoint
                    // MUST treat a GOAWAY frame with a stream identifier other than 0x00 as a
                    // connection error ... of type PROTOCOL_ERROR." — nghttp2 performs this check
                    // internally and reports it through on_invalid_frame_recv_callback below.
                    ctx.core.goaway_received = true;
                    ctx.goaway_last_stream_id = frame->goaway.last_stream_id;
                    ctx.goaway_error_code = frame->goaway.error_code;
                }
                if (frame->hd.flags & NGHTTP2_FLAG_END_STREAM) {
                    if (auto push_it = ctx.pushed_streams.find(frame->hd.stream_id);
                        push_it != ctx.pushed_streams.end()) {
                        // RFC 9113 §8.3.2 — "This pseudo-header field MUST be included in all
                        // responses, including interim responses; otherwise, the response is
                        // malformed (Section 8.1.1)." — a pushed response without a :status is
                        // rejected with RST_STREAM instead of being surfaced to take_push().
                        if (push_it->second->status_code == 0) {
                            auto stream_id = frame->hd.stream_id;
                            ctx.rejected_pushes.insert(stream_id);
                            // A bad :status value was already rejected in
                            // on_header_callback: the record is kept (locally
                            // aborted, RST_STREAM already submitted) so the stream
                            // close queues the typed abort instead of dropping the
                            // push silently. Only a response that ended without any
                            // :status is dropped outright here.
                            if (!push_it->second->locally_aborted) {
                                ctx.pushed_streams.erase(push_it);
                                (void)nghttp2_submit_rst_stream(
                                    session, NGHTTP2_FLAG_NONE, stream_id, NGHTTP2_PROTOCOL_ERROR);
                            }
                            return 0;
                        }
                        push_it->second->complete = true;
                        ctx.completed_pushes.push_back(completed_push{
                            .stream_id = frame->hd.stream_id,
                            .exchange = make_pushed_exchange(*push_it->second),
                        });
                        return 0;
                    }

                    auto it = ctx.core.streams.find(frame->hd.stream_id);
                    if (it != ctx.core.streams.end()) {
                        // RFC 9113 §8.1 — "An HTTP response is complete after the server sends -- or
                        // the client receives -- a frame with the END_STREAM flag set (including any
                        // CONTINUATION frames needed to complete a field block)."
                        it->second->core.complete = true;
                    }
                }
                return 0;
            });
        });

    // RFC 9113 §7 — "Error codes are 32-bit fields that are used in RST_STREAM and GOAWAY
    // frames to convey the reasons for the stream or connection error." nghttp2 supplies a
    // negative library error here, so it is mapped explicitly instead of being reinterpreted as
    // the unsigned HTTP/2 wire code.
    nghttp2_session_callbacks_set_on_invalid_frame_recv_callback(cbs,
        [](nghttp2_session*, const nghttp2_frame*, int library_code, void* ud) noexcept -> int {
            auto& ctx = *static_cast<session_context*>(ud);
            return http::detail::callback_boundary(ctx, NGHTTP2_ERR_CALLBACK_FAILURE, [&]() -> int {
                ctx.library_error_code = library_code;
                return 0;
            });
        });

    // RFC 9113 §8.2.1 — "A request or response containing uppercase header field names MUST be
    // treated as malformed (Section 8.1.1)." — nghttp2's HTTP messaging validation rejects
    // invalid field names/values; the invalid *regular* header fields it routes through this
    // callback (invalid pseudo-header fields and uppercase names are rejected by nghttp2
    // itself before this callback). Returning NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE keeps the
    // default stream-error treatment.
    nghttp2_session_callbacks_set_on_invalid_header_callback(cbs,
        [](nghttp2_session*, const nghttp2_frame*, const uint8_t*, std::size_t,
           const uint8_t*, std::size_t, uint8_t, void*) noexcept -> int {
            return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
        });

    // RFC 9113 §6.9 — "Flow control is directional with overall control
    // provided by the receiver." Automatic WINDOW_UPDATE is disabled
    // (create_session), so credit is returned only as the application consumes
    // the buffered body (body_reader); a peer cannot outrun the reader and
    // grow the staging buffer without bound. Push bodies are delivered
    // atomically by design, so their credit returns immediately.
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(cbs,
        [](nghttp2_session* session, uint8_t, std::int32_t stream_id,
           const uint8_t* data, std::size_t len, void* ud) -> int {
            auto& ctx = *static_cast<session_context*>(ud);
            return http::detail::callback_boundary(ctx, NGHTTP2_ERR_CALLBACK_FAILURE, [&]() -> int {
                if (auto push_it = ctx.pushed_streams.find(stream_id);
                    push_it != ctx.pushed_streams.end()) {
                    auto bytes = std::as_bytes(std::span{data, len});
                    push_it->second->body.insert(push_it->second->body.end(), bytes.begin(), bytes.end());
                    static_cast<void>(nghttp2_session_consume(session, stream_id, len));
                    return 0;
                }

                auto it = ctx.core.streams.find(stream_id);
                if (it != ctx.core.streams.end()) {
                    auto bytes = std::as_bytes(std::span{data, len});
                    it->second->body.append(bytes);
                }
                return 0;
            });
        });

    nghttp2_session_callbacks_set_on_begin_headers_callback(cbs,
        [](nghttp2_session*, const nghttp2_frame* frame, void* ud) -> int {
            auto& ctx = *static_cast<session_context*>(ud);
            return http::detail::callback_boundary(ctx, NGHTTP2_ERR_CALLBACK_FAILURE, [&]() -> int {
                if (frame->hd.type == NGHTTP2_PUSH_PROMISE) {
                    auto promised_stream_id = frame->push_promise.promised_stream_id;
                    if (ctx.rejected_pushes.contains(promised_stream_id))
                        return 0;
                    auto& push = ctx.pushed_streams[promised_stream_id];
                    if (!push) {
                        push = std::make_shared<push_data>();
                        push->promised_stream_id = promised_stream_id;
                        push->associated_stream_id = frame->hd.stream_id;
                    }
                    return 0;
                }

                if (frame->hd.type == NGHTTP2_HEADERS &&
                    frame->headers.cat == NGHTTP2_HCAT_PUSH_RESPONSE) {
                    // RFC 9113 §8.4.2 — "The response for a PUSH_PROMISE stream begins with a
                    // HEADERS frame" on "a server-initiated stream that uses the promised stream
                    // identifier."
                    if (ctx.rejected_pushes.contains(frame->hd.stream_id))
                        return 0;
                    auto& push = ctx.pushed_streams[frame->hd.stream_id];
                    if (!push) {
                        push = std::make_shared<push_data>();
                        push->promised_stream_id = frame->hd.stream_id;
                    }
                    // RFC 9113 §8.1.1 — interim (1xx) header blocks may precede the
                    // final pushed response; only the final block is delivered, so
                    // a new block after an interim one resets the accumulated
                    // fields.
                    if (is_informational(push->status_code)) {
                        push->response = {};
                        push->status_code = 0;
                    }
                    return 0;
                }

                if (frame->hd.type == NGHTTP2_HEADERS &&
                    frame->headers.cat == NGHTTP2_HCAT_REQUEST) {
                    auto sd = std::make_shared<stream_data>();
                    sd->core.id = frame->hd.stream_id;
                    ctx.core.streams[sd->core.id] = sd;
                }
                return 0;
            });
        });

    nghttp2_session_callbacks_set_on_stream_close_callback(cbs,
        [](nghttp2_session* session, std::int32_t stream_id,
           std::uint32_t error_code, void* ud) -> int {
            auto& ctx = *static_cast<session_context*>(ud);
            return http::detail::callback_boundary(ctx, NGHTTP2_ERR_CALLBACK_FAILURE, [&]() -> int {
                if (auto push_it = ctx.pushed_streams.find(stream_id);
                    push_it != ctx.pushed_streams.end()) {
                    push_it->second->closed = true;
                    // RFC 9113 §6.4 — "RST_STREAM (type=0x3) ... contains a single
                    // unsigned, 32-bit integer identifying the error code (Section
                    // 7)" — a promised stream that closed without END_STREAM was
                    // reset by the peer, and the peer's code is recorded so the
                    // abort surfaces with RFC 9113 §8.7 retry semantics. A nonzero
                    // code on a locally reset push (e.g. a malformed :status reset
                    // with RST_STREAM PROTOCOL_ERROR per RFC 9113 §8.1.1) is not
                    // attributed to the peer: locally_aborted stays authoritative,
                    // mirroring the request/response streams branch.
                    push_it->second->aborted = !push_it->second->complete;
                    bool reset_before_completion = push_it->second->aborted &&
                        !push_it->second->locally_aborted;
                    if (reset_before_completion)
                        push_it->second->peer_reset_code = error_code;
                    if (push_it->second->aborted)
                        ctx.aborted_pushes.push_back(aborted_push{
                            .stream_id = stream_id,
                            .peer_reset_code = push_it->second->peer_reset_code,
                            .local_reset_code = push_it->second->local_reset_code,
                        });
                    ctx.pushed_streams.erase(push_it);
                }
                if (auto it = ctx.core.streams.find(stream_id); it != ctx.core.streams.end()) {
                    it->second->core.closed = true;
                    // RFC 9113 §6.4 — "RST_STREAM (type=0x3) ... contains a single
                    // unsigned, 32-bit integer identifying the error code (Section 7)"
                    // — a stream that ended without END_STREAM was reset by the
                    // peer, and the peer's code is recorded so the abort surfaces
                    // with RFC 9113 §8.7 retry semantics. A nonzero code on a
                    // completed stream (e.g. nghttp2's implicit close of a locally
                    // reset malformed-response stream) is not attributed to the
                    // peer: locally_aborted stays authoritative for those.
                    bool reset_before_completion = !it->second->core.complete &&
                        !it->second->locally_aborted;
                    it->second->core.aborted = it->second->core.aborted ||
                        reset_before_completion;
                    if (reset_before_completion)
                        it->second->peer_reset_code = error_code;
                    // RFC 9113 §6.9 — connection-level credit for body bytes the
                    // application never consumed must return with the stream's
                    // death, or the connection window would shrink permanently.
                    auto leftover = it->second->body.remaining();
                    if (leftover > 0) {
                        static_cast<void>(nghttp2_session_consume_connection(session, leftover));
                        it->second->credit_settled = true;
                    }
                }
                ctx.core.outbound_bodies.erase(stream_id);
                return 0;
            });
        });

    nghttp2_session_callbacks_set_on_frame_send_callback(cbs,
        [](nghttp2_session*, const nghttp2_frame* frame, void* ud) -> int {
            auto& ctx = *static_cast<session_context*>(ud);
            return http::detail::callback_boundary(ctx, NGHTTP2_ERR_CALLBACK_FAILURE, [&]() -> int {
                if (frame->hd.type == NGHTTP2_SETTINGS &&
                    (frame->hd.flags & NGHTTP2_FLAG_ACK) == 0) {
                    if (ctx.unsent_settings.empty())
                        throw std::runtime_error(
                            "http/2: sent SETTINGS has no generation");
                    ctx.pending_settings.push_back(ctx.unsent_settings.front());
                    ctx.unsent_settings.pop_front();
                }
                // Capture the code of any GOAWAY we send — including one nghttp2
                // emits on its own when the peer commits a connection error —
                // so the termination can be surfaced with the wire's own code.
                if (frame->hd.type == NGHTTP2_GOAWAY)
                    ctx.sent_goaway_error_code = frame->goaway.error_code;
                return 0;
            });
        });

    return callbacks;
}

} // namespace detail

// A lazily-read HTTP/2 message body bound to a stream. The endpoint-owned
// connection driver is the sole transport reader and wakes this reader when
// DATA or a terminal stream event arrives. Automatic WINDOW_UPDATE is disabled
// (detail::create_session): flow-control credit returns through the credit
// hook only as the application consumes (RFC 9113 §6.9), which bounds the
// staging buffer by the advertised window.
class body_reader {
public:
    using credit_return = std::function<task<void>(std::size_t)>;

    body_reader(
        detail::session_context& context,
        std::shared_ptr<detail::stream_data> stream,
        credit_return credit)
        : context_(&context),
          stream_(std::move(stream)),
          credit_(std::move(credit)) {}

    body_reader(const body_reader&) = delete;
    auto operator=(const body_reader&) -> body_reader& = delete;
    body_reader(body_reader&&) = default;
    auto operator=(body_reader&&) -> body_reader& = default;

    auto async_read(
        std::span<std::byte> buf,
        std::stop_token stop) -> task<std::size_t> {
        for (;;) {
            if (!stream_->body.empty()) {
                auto n = stream_->body.read(buf);
                // RFC 9113 §6.9 — credit returns as the application consumes;
                // bytes whose credit was settled at stream close are not
                // counted twice.
                if (n > 0 && !stream_->credit_settled)
                    co_await credit_(n);
                co_return n;
            }
            if (stream_->core.complete) {
                co_return 0;
            }
            if (stream_->core.aborted) {
                detail::throw_stream_abort(*stream_);
            }
            // v3-style error delivery: the connection failure reaches this
            // reader through the abort flags the driver latched (notify_waiters
            // aborts every stream on connection failure), so a re-check of the
            // recorded connection error surfaces the typed failure.
            if (context_->core.connection_error)
                std::rethrow_exception(context_->core.connection_error);
            co_await detail::body_awaiter{*context_, stream_, stop};
        }
    }

private:
    detail::session_context* context_;
    std::shared_ptr<detail::stream_data> stream_;
    credit_return credit_;
};

} // namespace http::v2
