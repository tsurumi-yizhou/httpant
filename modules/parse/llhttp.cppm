module;

#include <llhttp.h>

#include <algorithm>
#include <array>
#include <climits>
#include <coroutine>
#include <cstddef>
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

export module httpant:parse.llhttp;

import :trait;
import :message;
import :error;
import :validate.llhttp;

export namespace http::v1 {

namespace detail {

constexpr auto from_llhttp_method(llhttp_method_t m) -> http::method {
    switch (m) {
        case HTTP_GET:     return method::GET;
        case HTTP_HEAD:    return method::HEAD;
        case HTTP_POST:    return method::POST;
        case HTTP_PUT:     return method::PUT;
        case HTTP_DELETE:  return method::DELETE_;
        case HTTP_CONNECT: return method::CONNECT;
        case HTTP_OPTIONS: return method::OPTIONS;
        case HTTP_TRACE:   return method::TRACE;
        case HTTP_PATCH:   return method::PATCH;
        default:           return method::UNKNOWN;
    }
}

template <llhttp_type_t Type>
inline auto make_settings() -> llhttp_settings_t {
    llhttp_settings_t s;
    llhttp_settings_init(&s);

    s.on_url = [](llhttp_t* p, const char* at, std::size_t len) -> int {
        static_cast<parser_state*>(p->data)->url.append(at, len);
        return 0;
    };
    s.on_status = [](llhttp_t* p, const char* at, std::size_t len) -> int {
        static_cast<parser_state*>(p->data)->status_text.append(at, len);
        return 0;
    };
    s.on_header_field = [](llhttp_t* p, const char* at, std::size_t len) -> int {
        auto* st = static_cast<parser_state*>(p->data);
        // RFC 9112 §7.1.2 — "A recipient MUST NOT merge a received trailer
        // field into the header section unless its corresponding header field
        // definition explicitly permits and instructs how the trailer field
        // value can be safely merged" (the message model has no trailer block,
        // so trailers must not land in fields at all). llhttp feeds trailer
        // lines through the header callbacks; the F_TRAILING flag is set for
        // the whole trailer section, so its snapshot is re-latched on every
        // callback (a trailer section split across two transport reads must
        // still be discarded) and the trailing field/value bytes never reach
        // the field section.
        st->trailing = (p->flags & F_TRAILING) != 0;
        if (st->trailing) return 0;
        // The previous field is complete once its value has been seen — the
        // value may be empty (RFC 9110 §5.2 "field-value = *field-content",
        // llhttp fires a zero-length on_header_value for it), so the gate is
        // value_seen, not an empty current_value. A field name split across
        // two transport reads fires on_header_field twice without a value and
        // must append to the same pending field.
        if (st->value_seen) {
            st->fields.push_back({std::move(st->current_field), std::move(st->current_value)});
            st->current_field.clear();
            st->current_value.clear();
            st->value_seen = false;
        }
        st->current_field.append(at, len);
        return 0;
    };
    s.on_header_value = [](llhttp_t* p, const char* at, std::size_t len) -> int {
        auto* st = static_cast<parser_state*>(p->data);
        st->trailing = (p->flags & F_TRAILING) != 0;
        if (st->trailing) return 0;
        st->value_seen = true;
        if constexpr (Type == HTTP_RESPONSE) {
            // RFC 9110 §5.5 — "a recipient of CR, LF, or NUL within a field
            // value MUST either reject the message or replace each of those
            // characters with SP before further processing" — the lenient
            // (obs-fold accepting) client parser admits NUL in field values
            // (probed: the NUL lands inside the value span), so it is
            // rejected here; CR/LF cannot appear inside a value (they delimit
            // field lines).
            if (std::find(at, at + len, '\0') != at + len)
                return HPE_INVALID_HEADER_TOKEN;
        }
        st->current_value.append(at, len);
        return 0;
    };
    s.on_headers_complete = [](llhttp_t* p) -> int {
        auto* st = static_cast<parser_state*>(p->data);
        if (!st->trailing && st->value_seen) {
            st->fields.push_back({std::move(st->current_field), std::move(st->current_value)});
            st->current_field.clear();
            st->current_value.clear();
            st->value_seen = false;
        }
        st->headers_done = true;
        st->status_code = static_cast<http::status>(p->status_code);
        st->req_method = from_llhttp_method(static_cast<llhttp_method_t>(p->method));
        st->keep_alive = llhttp_should_keep_alive(p) != 0;
        st->upgraded = llhttp_get_upgrade(p) != 0;
        st->content_length = (p->content_length == ULLONG_MAX) ? 0 : p->content_length;
        st->chunked = (p->flags & F_CHUNKED) != 0;
        if constexpr (Type == HTTP_REQUEST) {
            // RFC 9112 §3 — "HTTP-version = HTTP-name \"/\" DIGIT \".\" DIGIT";
            // only a syntactically valid start line reaches this callback with
            // a usable protocol version.
            st->protocol_version_valid =
                (p->http_major == 1 && (p->http_minor == 0 || p->http_minor == 1)) ||
                p->http_major > 1;
            st->http_major = p->http_major;
            st->http_minor = p->http_minor;
            // RFC 9110 §10.1.1 — a 100-continue expectation in an HTTP/1.0
            // request MUST be ignored.
            bool http_1_0 = st->http_major == 1 && st->http_minor == 0;
            bool content_follows = (p->flags & F_CHUNKED) != 0 ||
                (p->content_length != ULLONG_MAX && p->content_length > 0);
            if (!http_1_0 && content_follows && expects_continue(st->fields))
                st->expect_continue = true;
        }
        // Pause at the headers/body boundary: the caller surfaces the head,
        // then streams the body via read_body.
        return HPE_PAUSED;
    };
    s.on_body = [](llhttp_t* p, const char* at, std::size_t len) -> int {
        auto* st = static_cast<parser_state*>(p->data);
        auto bytes = std::as_bytes(std::span{at, len});
        st->body.append(bytes);
        return 0;
    };
    s.on_message_complete = [](llhttp_t* p) -> int {
        static_cast<parser_state*>(p->data)->complete = true;
        // Pause exactly at the message boundary so bytes of the next message
        // (or the upgraded tunnel) are recoverable for reuse on the persistent
        // connection (RFC 9112 §9.3).
        return HPE_PAUSED;
    };
    return s;
}

inline auto make_parse_error(const llhttp_t& parser, llhttp_errno_t err) -> protocol_error {
    auto message = std::string("http/1.1 parse error: ") + llhttp_errno_name(err);
    if (auto* reason = llhttp_get_error_reason(&parser); reason != nullptr && reason[0] != '\0') {
        message += " (";
        message += reason;
        message += ')';
    }
    return protocol_violation(std::move(message));
}

inline void consume(llhttp_t& parser, parser_state& state, std::vector<std::byte>& pending,
                    std::span<const std::byte> bytes) {
    if (bytes.empty()) return;
    auto err = llhttp_execute(
        &parser,
        reinterpret_cast<const char*>(bytes.data()),
        bytes.size());
    if (err != HPE_OK && err != HPE_PAUSED && err != HPE_PAUSED_UPGRADE)
        throw make_parse_error(parser, err);
    if (err == HPE_PAUSED || err == HPE_PAUSED_UPGRADE) {
        // Retain bytes that followed the pause position so a transport read
        // spanning the boundary is not lost.
        auto* pos = llhttp_get_error_pos(&parser);
        auto consumed = static_cast<std::size_t>(
            pos - reinterpret_cast<const char*>(bytes.data()));
        if (consumed < bytes.size())
            pending.append_range(bytes.subspan(consumed));

        if (err == HPE_PAUSED_UPGRADE) {
            state.pause = pause_kind::upgrade;
            state.keep_alive = llhttp_should_keep_alive(&parser) != 0;
            state.upgraded = true;
            return;
        }
        if (state.complete) {
            state.pause = pause_kind::message;
            // Refine persistence now that the message framing is known: a
            // close-delimited response is not persistent (RFC 9112 §6.3).
            state.keep_alive = llhttp_should_keep_alive(&parser) != 0;
            state.upgraded = state.upgraded || llhttp_get_upgrade(&parser) != 0;
            return;
        }
        state.pause = pause_kind::headers;
    } else {
        state.pause = pause_kind::none;
    }
}

// A reusable HTTP/1.1 message parser bound to one connection. llhttp lives for
// the whole connection (RFC 9112 §9.3 persistent connections); between messages
// llhttp_reset() preserves the parser type, callbacks, user data and lenient
// flags. Connection-scoped persistence facts outlive per-message state.
template <llhttp_type_t Type>
class message_parser {
public:
    message_parser() : settings_(make_settings<Type>()) {
        llhttp_init(&parser_, Type, &settings_);
        parser_.data = &state_;
        if constexpr (Type == HTTP_RESPONSE) {
            // RFC 9112 §5.2 — "A user agent that receives an obs-fold in a
            // response message that is not within a 'message/http' container
            // MUST replace each received obs-fold with one or more SP octets
            // prior to interpreting the field value." llhttp's strict header
            // parser rejects obs-fold outright (HPE_INVALID_HEADER_TOKEN);
            // lenient header parsing admits it and delivers the continuation
            // line as part of the value, the fold CRLF being replaced by the
            // continuation's leading whitespace — exactly the §5.2 SP
            // replacement. The server-side (request) parser stays strict so a
            // request with obs-fold is rejected with 400 (RFC 9112 §5.2), and
            // the assembled response values are still scanned for CR/LF/NUL
            // (RFC 9110 §5.5) before they are surfaced.
            // LENIENT_HEADERS is llhttp's per-parser switch: beyond obs-fold
            // it also admits other control characters in header values and a
            // space-prefixed first line ("Unexpected space after start line").
            // The post-checks compensate: values with NUL (and, by the value
            // grammar, CR/LF) are rejected by the on_header_value scan above,
            // and the space-prefixed start-line shape is not part of the
            // HTTP-version grammar (RFC 9112 §3), so the parser rejects it as
            // a malformed status line. Other admitted control characters pass
            // through only as field-value bytes (RFC 9110 §5.5 allows
            // recipients to replace them rather than reject), matching
            // llhttp's documented lenient behavior.
            llhttp_set_lenient_headers(&parser_, 1);
        }
    }

    message_parser(const message_parser&) = delete;
    auto operator=(const message_parser&) -> message_parser& = delete;

    // Reset per-message parsing state, keeping the parser for reuse and the
    // connection-scoped persistence flags and pending bytes.
    void begin_message() {
        state_ = {};
        llhttp_reset(&parser_);
    }

    // Read until the current message's header section has been parsed. The
    // parser pauses at the headers/body boundary, leaving the body (or the next
    // message) to be streamed by read_body. All bytes are fed to llhttp
    // verbatim; framing validation (including Content-Length comma-lists, RFC
    // 9112 §6.3 item 5) is llhttp's strict check, not a hand-rolled pre-pass.
    template <byte_stream S>
    auto read_headers(S& transport, std::stop_token stop = {}) -> task<void> {
        while (!state_.headers_done) {
            if (!pending_.empty()) {
                auto p = std::move(pending_);
                resume_paused();
                feed(p);
                continue;
            }
            resume_paused();
            auto n = co_await transport.async_read(std::span{buffer_}, stop);
            if (n == 0) {
                // RFC 9112 §6.3 — "If the sender closes the connection ... the
                // recipient MUST consider the message to be incomplete."
                throw protocol_error{
                    error_info{
                        .version = protocol_version::http1,
                        .scope = error_scope::connection,
                        .condition = error_condition::peer_closed,
                        .exchange_identity = std::nullopt,
                        .library_code = std::nullopt,
                        .retryable = false,
                    },
                    close_connection{std::nullopt},
                    "http/1.1: connection closed before headers"};
            }
            feed(std::span<const std::byte>{buffer_.data(), static_cast<std::size_t>(n)});
        }
        // Advance past the headers pause: for a message without a body (e.g. a
        // 204 response) llhttp fires message_complete immediately; otherwise
        // this is a no-op before the body is streamed.
        advance_after_headers();
        co_return;
    }

    // Stream the current message's body into buf. Drains bytes llhttp has
    // already accumulated, then pulls from the transport and feeds llhttp as
    // needed. Returns the number of bytes copied, or 0 once the message body is
    // complete (or the connection was upgraded, which has no framed body).
    template <byte_stream S>
    auto read_body(
        S& transport,
        std::span<std::byte> buf,
        std::stop_token stop) -> task<std::size_t> {
        for (;;) {
            if (state_.upgraded)
                co_return 0;

            if (!state_.body.empty())
                co_return state_.body.read(buf);
            if (state_.complete)
                co_return 0;

            if (!pending_.empty()) {
                auto p = std::move(pending_);
                resume_paused();
                try {
                    feed(p);
                } catch (const protocol_error& failure) {
                    rethrow_body_phase_failure(failure);
                }
                continue;
            }
            resume_paused();
            auto n = co_await transport.async_read(std::span{buffer_}, stop);
            if (n == 0) {
                finish_on_eof("http/1.1: connection closed before complete message");
                continue;
            }
            try {
                feed(std::span<const std::byte>{buffer_.data(), static_cast<std::size_t>(n)});
            } catch (const protocol_error& failure) {
                rethrow_body_phase_failure(failure);
            }
        }
    }

    // RFC 9112 §6.3 item 6 — "If the sender closes the connection or the
    // recipient times out before the indicated number of octets are received,
    // the recipient MUST consider the message to be incomplete and close the
    // connection." A body-phase framing error (e.g. an invalid chunk size)
    // leaves the message incomplete and the connection unusable, so the
    // message-scoped no_action failure is re-scoped to the connection with an
    // unconditional close, and the connection is latched closed so persistence
    // state stays honest.
    [[noreturn]] void rethrow_body_phase_failure(const protocol_error& failure) {
        if (failure.info().version == protocol_version::http1 &&
            failure.info().condition == error_condition::malformed_message) {
            auto info = failure.info();
            info.scope = error_scope::connection;
            connection_closed_ = true;
            throw protocol_error{
                info,
                close_connection{std::nullopt},
                failure.what()};
        }
        throw;
    }

    // RFC 9112 §9.3 — whether the connection persists after the current message.
    [[nodiscard]] auto should_keep_alive() const -> bool {
        return state_.keep_alive;
    }

    // RFC 9110 §15.2.2 — the current message switched (or requested switching)
    // to another application protocol.
    [[nodiscard]] auto upgraded() const -> bool {
        return state_.upgraded;
    }

    [[nodiscard]] auto complete() const -> bool {
        return state_.complete;
    }

    // RFC 9110 §15.2.1 — paused at the headers/content boundary of a request
    // carrying a 100-continue expectation, waiting for the interim response.
    [[nodiscard]] auto paused_for_continue() const -> bool {
        return state_.expect_continue && !state_.complete;
    }

    // Clear the one-shot 100-continue flag; read_body resumes the parser and
    // streams the request content.
    void resume_after_continue() {
        state_.expect_continue = false;
    }

    // RFC 9112 §6.3 item 2 — "Any 2xx (Successful) response to a CONNECT
    // request implies that the connection will become a tunnel immediately
    // after the empty line that concludes the header fields." llhttp only sets
    // its upgrade flag for Connection: Upgrade / 101 (never for a plain 2xx
    // CONNECT under a response parser, which does not know the request
    // method), so the client latches the upgrade itself: read_body stops, the
    // keep-alive state becomes irrelevant, and the bytes retained after the
    // header section are tunnel data, available through take_pending().
    void mark_connect_tunnel() {
        state_.upgraded = true;
        connection_upgraded_ = true;
    }

    [[nodiscard]] auto state() const -> const parser_state& {
        return state_;
    }

    // Bytes that followed a completed message within a single transport read.
    // For an upgraded connection (101 or a successful CONNECT tunnel) this is
    // the tunnel data; RFC 9112 §6.3 item 2 — "A client MUST ignore any
    // Content-Length or Transfer-Encoding header fields received in such a
    // message" — so bytes llhttp consumed as a (CL-framed or chunked) response
    // body of a 2xx CONNECT response are tunnel data too and are recovered
    // here.
    [[nodiscard]] auto take_pending() -> std::vector<std::byte> {
        std::vector<std::byte> out;
        while (!state_.body.empty()) {
            std::array<std::byte, io_buffer_size> chunk;
            auto n = state_.body.read(chunk);
            out.append_range(std::span<const std::byte>{chunk.data(), n});
        }
        out.append_range(std::move(pending_));
        return out;
    }

    // Connection-scoped persistence facts, updated as messages complete.
    [[nodiscard]] auto connection_closed() const -> bool { return connection_closed_; }
    [[nodiscard]] auto connection_upgraded() const -> bool { return connection_upgraded_; }

private:
    void feed(std::span<const std::byte> bytes) {
        consume(parser_, state_, pending_, bytes);
        if (state_.complete) {
            if (!state_.keep_alive) connection_closed_ = true;
            if (state_.upgraded) connection_upgraded_ = true;
        }
    }

    void resume_paused() {
        if (state_.pause == pause_kind::none || state_.pause == pause_kind::upgrade)
            return;
        llhttp_resume(&parser_);
        state_.pause = pause_kind::none;
    }

    // After the header section has been parsed, resume the headers pause and
    // advance llhttp with zero bytes. For a message llhttp knows has no body
    // (a 204/304 response or a Content-Length: 0 message) this fires
    // on_message_complete immediately; for a message with a body it is a no-op
    // and read_body pulls the body bytes. A response to HEAD also ends at the
    // header section (RFC 9110 §9.3.2), but llhttp cannot know the request
    // method — the client layer completes that exchange itself.
    void advance_after_headers() {
        if (state_.pause != pause_kind::headers) return;
        llhttp_resume(&parser_);
        state_.pause = pause_kind::none;
        auto err = llhttp_execute(&parser_, nullptr, 0);
        if (err == HPE_PAUSED || err == HPE_PAUSED_UPGRADE) {
            if (state_.complete) {
                state_.pause = pause_kind::message;
                state_.keep_alive = llhttp_should_keep_alive(&parser_) != 0;
                state_.upgraded = state_.upgraded || llhttp_get_upgrade(&parser_) != 0;
                if (!state_.keep_alive) connection_closed_ = true;
                if (state_.upgraded) connection_upgraded_ = true;
            }
            return;
        }
        if (err != HPE_OK)
            throw make_parse_error(parser_, err);
    }

    void finish_on_eof(std::string_view message) {
        auto err = llhttp_finish(&parser_);
        if (err != HPE_OK && err != HPE_PAUSED && err != HPE_PAUSED_UPGRADE)
            // llhttp_finish flags a message truncated mid-body (e.g. a chunked
            // body cut off by EOF) as HPE_INVALID_EOF_STATE; this is the
            // body-phase framing error of RFC 9112 §6.3 item 6 and must ride
            // the same connection-scoped re-scope (and closure latch) as any
            // other body-phase failure.
            rethrow_body_phase_failure(make_parse_error(parser_, err));
        if (!state_.complete)
            throw protocol_error{
                error_info{
                    .version = protocol_version::http1,
                    .scope = error_scope::connection,
                    .condition = error_condition::peer_closed,
                    .exchange_identity = std::nullopt,
                    .library_code = std::nullopt,
                    .retryable = false,
                },
                close_connection{std::nullopt},
                std::string(message)};
        // The message was completed by connection closure, so it is not
        // persistent (RFC 9112 §6.3).
        state_.keep_alive = llhttp_should_keep_alive(&parser_) != 0;
        state_.upgraded = state_.upgraded || llhttp_get_upgrade(&parser_) != 0;
        if (!state_.keep_alive) connection_closed_ = true;
        if (state_.upgraded) connection_upgraded_ = true;
    }

    llhttp_settings_t settings_{};
    llhttp_t parser_{};
    parser_state state_{};
    std::vector<std::byte> pending_{};
    std::array<std::byte, io_buffer_size> buffer_{};
    bool connection_closed_{false};
    bool connection_upgraded_{false};
};

} // namespace detail

// A lazily-read HTTP/1.1 message body bound to a connection parser. Reading it
// pulls from the transport and decodes framing incrementally; it must not be
// copied (two readers would race on the same parser).
template <llhttp_type_t Type, byte_stream S>
class body_reader {
public:
    struct lifecycle {
        bool consumed{false};
    };

    body_reader(
        S& transport,
        detail::message_parser<Type>& parser,
        std::shared_ptr<lifecycle> state)
        : transport_(transport), parser_(parser), state_(std::move(state)) {}

    body_reader(const body_reader&) = delete;
    auto operator=(const body_reader&) -> body_reader& = delete;
    body_reader(body_reader&&) = default;
    auto operator=(body_reader&&) -> body_reader& = default;

    auto async_read(
        std::span<std::byte> buf,
        std::stop_token stop) -> task<std::size_t> {
        // An exchange can be born consumed — a response to HEAD ends at the
        // header section (RFC 9110 §9.3.2) — in which case the parser must not
        // be touched: it still expects the Content-Length it saw on the wire.
        if (state_->consumed)
            co_return 0;
        auto size = co_await parser_.read_body(transport_, buf, stop);
        if (size == 0)
            state_->consumed = true;
        co_return size;
    }

private:
    S& transport_;
    detail::message_parser<Type>& parser_;
    std::shared_ptr<lifecycle> state_;
};

} // namespace http::v1
