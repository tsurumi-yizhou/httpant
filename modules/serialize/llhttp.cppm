module;

#include <array>
#include <charconv>
#include <coroutine>
#include <cstddef>
#include <cstdint>
#include <format>
#include <iterator>
#include <ranges>
#include <span>
#include <stdexcept>
#include <stop_token>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

export module httpant:serialize.llhttp;

import :trait;
import :message;
import :validate.llhttp;

export namespace http::v1 {

namespace detail {

// RFC 9110 §5.5 — "Field values containing CR, LF, or NUL characters are
// invalid and dangerous, due to the varying ways that implementations might
// parse and interpret those characters." On the send side there is no
// recipient to perform the SP replacement the RFC offers, so CR/LF/NUL in any
// outbound field name or value — the header-injection surface of RFC 9112
// §11.1 — is rejected before it reaches the wire. The request-target and
// reason-phrase are emitted verbatim on the start/status line and are checked
// the same way.
[[nodiscard]] inline auto has_crlf_nul(std::string_view s) -> bool {
    return s.find('\r') != std::string_view::npos ||
           s.find('\n') != std::string_view::npos ||
           s.find('\0') != std::string_view::npos;
}

inline void validate_outbound_fields(const headers& fields) {
    for (const auto& h : fields) {
        if (has_crlf_nul(h.name) || has_crlf_nul(h.value))
            throw std::runtime_error(
                "http/1.1: CR/LF/NUL in outbound field name or value");
    }
}

} // namespace detail

// ─── Head serialization (RFC 9112 §3, §4) ─────────────────────

inline auto serialize_head(const request& req) -> std::vector<std::byte> {
    // RFC 9110 §9.1 — "method = token" — the request-line is "method SP
    // request-target SP HTTP-version" (RFC 9112 §3), so the method must be a
    // non-empty token. method::UNKNOWN represents an unparseable inbound method
    // (RFC 9110 §9.1 — "Additional methods, outside the scope of this
    // specification, have been specified for use in HTTP") and has no token of
    // its own; emitting it would produce a malformed request-line (" / HTTP/1.1")
    // that the library's own server would answer with 400, so it is refused.
    if (req.method == method::UNKNOWN)
        throw std::runtime_error(
            "http/1.1: cannot serialize a request with an unknown method");
    // RFC 9112 §3.2 — "A client MUST send a Host header field in all HTTP/1.1
    // request messages." An outbound request without exactly one Host field
    // line is refused (the value may be empty when the target URI has no
    // authority component — RFC 9112 §3.2 — "If the authority component is
    // missing or undefined for the target URI, then a client MUST send a Host
    // header field with an empty field value").
    if (find_all_headers(req.fields, "host").size() != 1)
        throw std::runtime_error(
            "http/1.1: request must carry exactly one Host header field");
    // RFC 9112 §3.2 — "No whitespace is allowed in the request-target."
    // request-target = origin-form / absolute-form / authority-form /
    // asterisk-form (RFC 9110 §7.1); none of the forms admits SP/HTAB (uri-
    // host, IP-literal, absolute-path, "*" — RFC 3986 §3.2.2 / RFC 9110
    // §4.1), so SP/HTAB are rejected alongside the CR/LF/NUL that would
    // inject or split header lines.
    if (req.target.find(' ') != std::string_view::npos ||
        req.target.find('\t') != std::string_view::npos)
        throw std::runtime_error("http/1.1: whitespace in outbound request target");
    if (detail::has_crlf_nul(req.target))
        throw std::runtime_error("http/1.1: CR/LF/NUL in outbound request target");
    // RFC 9112 §3.2.4 — "asterisk-form = "*""; "The 'asterisk-form' of
    // request-target is only used for a server-wide OPTIONS request". RFC 9110
    // §7.1 — "These forms MUST NOT be used with other methods" — an outbound
    // asterisk-form target is only legal for OPTIONS.
    if (req.target == "*" && req.method != method::OPTIONS)
        throw std::runtime_error(
            "http/1.1: asterisk-form request-target requires OPTIONS");
    // RFC 7639 §2 — "Clients include the ALPN header field in an HTTP CONNECT
    // request to indicate the application-layer protocol that a client intends
    // to use within the tunnel." ALPN has no meaning on any other request;
    // emitting it would misdescribe the message, so it is refused — mirroring
    // the server-side rejection of the same condition (validate_request).
    if (req.method != method::CONNECT && find_header(req.fields, "alpn"))
        throw std::runtime_error("http/1.1: ALPN header in non-CONNECT request");
    detail::validate_outbound_fields(req.fields);

    std::string raw;
    // RFC 9112 §3 — request-line = method SP request-target SP HTTP-version.
    raw += std::string(to_string(req.method));
    raw += ' ';
    raw += req.target;
    raw += " HTTP/1.1\r\n";
    for (auto& h : req.fields) {
        raw += h.name;
        raw += ": ";
        raw += h.value;
        raw += "\r\n";
    }
    raw += "\r\n";
    return std::as_bytes(std::span{raw}) | std::ranges::to<std::vector<std::byte>>();
}

inline auto serialize_head(const response& res) -> std::vector<std::byte> {
    // RFC 9110 §15.1 — reason-phrase = 1*( HTAB / SP / VCHAR / obs-text ); a
    // CR/LF/NUL here would inject a new status line or header section.
    if (detail::has_crlf_nul(res.reason))
        throw std::runtime_error("http/1.1: CR/LF/NUL in outbound reason phrase");
    // RFC 9110 §15 — "All valid status codes are within the range of 100 to
    // 599, inclusive." An invalid code would produce an invalid status-line;
    // HTTP/2 and HTTP/3 enforce the same bound on their send paths.
    if (!http::detail::is_valid_status(res.status))
        throw std::runtime_error("http/1.1: response status outside 100-599");
    detail::validate_outbound_fields(res.fields);

    std::string raw;
    // RFC 9112 §4 — status-line = HTTP-version SP status-code SP reason-phrase.
    std::format_to(std::back_inserter(raw), "HTTP/1.1 {} ", res.status);
    raw += res.reason.empty() ? default_reason_phrase(res.status) : res.reason;
    raw += "\r\n";
    for (auto& h : res.fields) {
        raw += h.name;
        raw += ": ";
        raw += h.value;
        raw += "\r\n";
    }
    raw += "\r\n";
    return std::as_bytes(std::span{raw}) | std::ranges::to<std::vector<std::byte>>();
}

namespace detail {

// How a streaming body is framed on the wire.
enum class framing : std::uint8_t { none, content_length, chunked };

// Forward declaration: defined below with the other Content-Length helpers,
// but request_framing needs the numeric value to tell a zero-length
// declaration (no content) from one that declares content.
[[nodiscard]] inline auto content_length_of(const headers& fields) -> std::uint64_t;

// RFC 9112 §6.3 — the body length of a request is delimited by Content-Length
// or chunked; TRACE never carries a body (RFC 9110 §9.3.8).
[[nodiscard]] inline auto request_framing(const request& req) -> framing {
    validate_transfer_encoding(req.fields);
    if (req.method == method::TRACE) {
        // RFC 9110 §9.3.8 — "A client MUST NOT send content in a TRACE request."
        // A TRACE that *declares* content (a Transfer-Encoding or a
        // Content-Length greater than zero) is refused before the head goes out:
        // the framing would otherwise be none, the body would be dropped, and a
        // peer reading the declared Content-Length would wait for bytes that
        // never arrive — a framing mismatch on the connection (RFC 9112 §6.3).
        // A Content-Length of 0 declares no content and is acceptable.
        if (find_header(req.fields, "transfer-encoding"))
            throw std::runtime_error(
                "http/1.1: TRACE request must not declare Transfer-Encoding");
        if (find_header(req.fields, "content-length") && content_length_of(req.fields) > 0)
            throw std::runtime_error(
                "http/1.1: TRACE request must not declare content");
        return framing::none;
    }
    if (find_header(req.fields, "transfer-encoding")) return framing::chunked;
    if (find_header(req.fields, "content-length")) return framing::content_length;
    return framing::none;
}

// RFC 9112 §6.3 — a response body is delimited by Content-Length or chunked;
// a status that terminates at the header section has none.
[[nodiscard]] inline auto response_framing(const response& res) -> framing {
    validate_transfer_encoding(res.fields);
    if (!status_allows_body(res.status)) return framing::none;
    if (find_header(res.fields, "transfer-encoding")) return framing::chunked;
    if (find_header(res.fields, "content-length")) return framing::content_length;
    return framing::none;
}

// Append one body chunk to `out`, framed per `f`. For content_length framing
// the chunk must not exceed the declared remaining length; for chunked framing
// it is emitted as a single chunk (RFC 9112 §7.1).
inline void append_framed_chunk(std::vector<std::byte>& out, std::span<const std::byte> chunk,
                                framing f, std::uint64_t& remaining) {
    if (f == framing::none) return;
    if (f == framing::content_length) {
        // RFC 9112 §6.3 — a body longer than Content-Length is a framing error.
        if (chunk.size() > remaining)
            throw std::runtime_error("http/1.1: body exceeds content-length");
        out.insert(out.end(), chunk.begin(), chunk.end());
        remaining -= chunk.size();
        return;
    }
    // RFC 9112 §7.1 — "chunk = chunk-size [ chunk-ext ] CRLF chunk-data CRLF".
    auto hex = std::format("{:x}\r\n", chunk.size());
    out.reserve(out.size() + hex.size() + chunk.size() + 2);
    out.append_range(std::as_bytes(std::span{hex}));
    out.insert(out.end(), chunk.begin(), chunk.end());
    out.append_range(std::as_bytes(std::span{std::string_view{"\r\n"}}));
}

// Append the framing terminator. For chunked that is the last-chunk plus the
// empty trailer line (RFC 9112 §7.1); for content_length a short body is a
// framing error.
inline void finish_framing(std::vector<std::byte>& out, framing f, std::uint64_t remaining) {
    if (f == framing::content_length && remaining != 0)
        throw std::runtime_error("http/1.1: body shorter than content-length");
    if (f == framing::chunked) {
        // RFC 9112 §7.1 — "last-chunk = 1*("0") [ chunk-ext ] CRLF" then the
        // trailer section and the terminating empty line.
        constexpr std::string_view term = "0\r\n\r\n";
        out.append_range(std::as_bytes(std::span{term}));
    }
}

// Stream a body from `body` into `transport`, framing it per `f`. A framing of
// none either emits nothing (a message whose status terminates at the header
// section — RFC 9110 §15.2/§15.3.5/§15.3.6/§15.4.5 — or an empty body) or
// streams the raw bytes of a close-delimited response (RFC 9112 §6.3 item 8 —
// "Otherwise, this is a response message without a declared message body
// length, so the message body length is determined by the number of octets
// received prior to the server closing the connection"). The close-delimited
// shape is only reachable for responses whose status allows a body and that
// carry neither Content-Length nor Transfer-Encoding; write_request refuses
// the request-side equivalent before the head is emitted.
template <byte_stream S, body_stream Body>
inline auto stream_body(S& transport, Body& body, framing f, std::uint64_t content_length,
                        bool close_delimited, std::stop_token stop = {}) -> task<void> {
    if (f == framing::none && !close_delimited) {
        // Consume the body so the caller's body lifecycle completes; no bytes
        // are emitted (the status terminates the message at the header
        // section).
        std::array<std::byte, io_buffer_size> scratch;
        while (co_await body.async_read(scratch, stop) != 0) {}
        co_return;
    }
    std::array<std::byte, io_buffer_size> buf;
    std::uint64_t remaining = content_length;
    for (;;) {
        auto n = co_await body.async_read(buf, stop);
        if (n == 0) break;
        if (f == framing::none) {
            // RFC 9112 §6.3 item 8 — close-delimited response body: the raw
            // bytes follow the header section until the connection closes.
            co_await http::detail::write_all(
                transport, std::span<const std::byte>{buf.data(), n}, stop);
            continue;
        }
        std::vector<std::byte> framed;
        append_framed_chunk(framed, std::span<const std::byte>{buf.data(), n}, f, remaining);
        co_await http::detail::write_all(
            transport, std::span<const std::byte>{framed}, stop);
    }
    std::vector<std::byte> term;
    finish_framing(term, f, remaining);
    if (!term.empty())
        co_await http::detail::write_all(
            transport, std::span<const std::byte>{term}, stop);
}

// Drain a body_stream into an in-memory buffer (used by the buffered
// serialize() helpers; the streaming write path streams instead).
template <body_stream Body>
inline auto drain_body(Body& body, std::stop_token stop = {}) -> task<std::vector<std::byte>> {
    std::vector<std::byte> out;
    std::array<std::byte, io_buffer_size> buf;
    for (;;) {
        auto n = co_await body.async_read(buf, stop);
        if (n == 0) break;
        out.insert(out.end(), buf.data(), buf.data() + n);
    }
    co_return out;
}

// RFC 9112 §6.3 — parse the Content-Length header (already known present by the
// caller) as a decimal octet count: RFC 9110 §8.6 — "Content-Length = 1*DIGIT";
// trailing junk or an unrepresentable value is a framing error, not a prefix
// parse.
[[nodiscard]] inline auto content_length_of(const headers& fields) -> std::uint64_t {
    auto values = find_all_headers(fields, "content-length");
    if (values.empty())
        throw std::runtime_error("http/1.1: missing content-length");

    std::uint64_t parsed = 0;
    bool first = true;
    for (auto raw : values) {
        auto v = trim_ows(raw);
        std::uint64_t value = 0;
        auto [ptr, ec] = std::from_chars(v.data(), v.data() + v.size(), value);
        if (ec != std::errc{} || ptr != v.data() + v.size())
            throw std::runtime_error("http/1.1: invalid content-length");
        if (first) {
            parsed = value;
            first = false;
        } else if (value != parsed) {
            // RFC 9110 §8.6 — conflicting Content-Length field values make
            // the framing ambiguous; refuse instead of emitting a message
            // whose body length differs by field line.
            throw std::runtime_error(
                "http/1.1: conflicting content-length field values");
        }
    }
    return parsed;
}

// Assemble a fully buffered message: head bytes followed by the framed body.
template <byte_stream S, body_stream Body>
inline auto write_request(S& transport, const request& head, Body& body,
                          std::stop_token stop = {}) -> task<void> {
    auto f = request_framing(head);
    if (f == framing::none) {
        // RFC 9112 §6.3 item 7 — for a request without Content-Length or
        // Transfer-Encoding "the message body length is zero (no message body
        // is present)", and — RFC 9112 §6.3 — "A user agent that sends a
        // request that contains a message body MUST send either a valid
        // Content-Length header field or use the chunked transfer coding"
        // (RFC 9110 §9.3.8 — "A client MUST NOT send content in a TRACE
        // request"). Unlike the buffered serialize() path, which infers a
        // Content-Length for the drained body, the streaming path cannot
        // retroactively add the header after the head is written, so a
        // non-empty body is refused before anything goes out — it would
        // otherwise be silently dropped from the wire.
        std::array<std::byte, io_buffer_size> scratch;
        if (co_await body.async_read(scratch, stop) != 0)
            throw std::runtime_error(
                "http/1.1: request body present without Content-Length or Transfer-Encoding");
    }

    auto data = serialize_head(head);
    co_await http::detail::write_all(
        transport, std::span<const std::byte>{data.data(), data.size()}, stop);

    auto content_length = (f == framing::content_length) ? content_length_of(head.fields) : 0;
    co_await stream_body(transport, body, f, content_length, false, stop);
}

template <byte_stream S, body_stream Body>
inline auto write_response(S& transport, const response& head, Body& body,
                           std::stop_token stop = {}) -> task<void> {
    auto data = serialize_head(head);
    co_await http::detail::write_all(
        transport, std::span<const std::byte>{data.data(), data.size()}, stop);

    auto f = response_framing(head);
    auto content_length = (f == framing::content_length) ? content_length_of(head.fields) : 0;
    // RFC 9112 §6.3 item 8 — a response whose status allows a body but that
    // carries neither Content-Length nor Transfer-Encoding is close-delimited:
    // its body bytes follow the header section until the connection closes. A
    // status that terminates at the header section (1xx/204/205/304) has its
    // body suppressed instead.
    bool close_delimited = (f == framing::none) && status_allows_body(head.status);
    co_await stream_body(transport, body, f, content_length, close_delimited, stop);
}

// RFC 9110 §9.3.2 — a HEAD response "MUST NOT send content in such a response";
// a Content-Length field still describes the content a GET would have sent and
// is preserved verbatim. RFC 9110 §9.3.6 — a successful CONNECT response
// carries no content either. Only the head is written, so no body framing is
// applied or validated.
template <byte_stream S>
inline auto write_response_head(S& transport, const response& head,
                                std::stop_token stop = {}) -> task<void> {
    // RFC 9112 §6.1 — "A sender MUST NOT send a Content-Length header field
    // in any message that contains a Transfer-Encoding header field." The
    // bodyless response path bypasses write_response/response_framing, so the
    // invariant is re-asserted here for HEAD, CONNECT, 1xx, 204, and 304
    // responses as well.
    validate_transfer_encoding(head.fields);
    auto data = serialize_head(head);
    co_await http::detail::write_all(
        transport, std::span<const std::byte>{data.data(), data.size()}, stop);
}

// Append a fully drained body to the head, honoring the message framing. The
// body length is validated against Content-Length (RFC 9112 §6.3) or framed as
// chunks (RFC 9112 §7.1); a framing of none emits no body bytes.
[[nodiscard]] inline auto append_body(std::vector<std::byte> head, framing f,
                                      std::uint64_t content_length,
                                      const std::vector<std::byte>& body) -> std::vector<std::byte> {
    auto out = std::move(head);
    if (f == framing::content_length) {
        // RFC 9112 §6.3 — a body whose length differs from Content-Length is a
        // framing error on a persistent connection.
        if (body.size() != content_length)
            throw std::runtime_error("http/1.1: body length does not match content-length");
        out.insert(out.end(), body.begin(), body.end());
    } else if (f == framing::chunked) {
        std::uint64_t unused = 0;
        if (!body.empty())
            append_framed_chunk(out, std::span<const std::byte>{body.data(), body.size()}, f, unused);
        finish_framing(out, f, 0);
    }
    return out;
}

// Serialize a complete message into an in-memory buffer. Unlike the streaming
// write path, the buffered form can infer a Content-Length for a non-empty body
// (RFC 9110 §8.6) when the caller supplied neither Content-Length nor
// Transfer-Encoding.
template <body_stream Body>
inline auto serialize_request(const request& head, Body& body,
                              std::stop_token stop = {}) -> task<std::vector<std::byte>> {
    auto body_buf = co_await drain_body(body, stop);
    auto f = request_framing(head);
    http::request effective = head;
    // RFC 9110 §9.3.8 — TRACE never carries content, so no Content-Length is
    // inferred for it.
    if (f == framing::none && head.method != method::TRACE && !body_buf.empty()) {
        effective.fields.push_back({"content-length", std::to_string(body_buf.size())});
        f = framing::content_length;
    }
    auto content_length = (f == framing::content_length) ? content_length_of(effective.fields) : 0;
    co_return append_body(serialize_head(effective), f, content_length, body_buf);
}

template <body_stream Body>
inline auto serialize_response(const response& head, Body& body,
                               std::stop_token stop = {}) -> task<std::vector<std::byte>> {
    auto body_buf = co_await drain_body(body, stop);
    auto f = response_framing(head);
    http::response effective = head;
    // RFC 9110 §15 — a status that terminates at the header section (1xx, 204,
    // 205, 304) never carries content, so no Content-Length is inferred.
    if (f == framing::none && status_allows_body(head.status) && !body_buf.empty()) {
        effective.fields.push_back({"content-length", std::to_string(body_buf.size())});
        f = framing::content_length;
    }
    auto content_length = (f == framing::content_length) ? content_length_of(effective.fields) : 0;
    co_return append_body(serialize_head(effective), f, content_length, body_buf);
}

} // namespace detail

// Serialize a complete message: the head plus a streamed body framed per the
// message's Content-Length / Transfer-Encoding (RFC 9112 §6.3, §7.1). Returns a
// task producing the fully buffered wire bytes.
template <body_stream Body>
inline auto serialize(const request& req, Body& body,
                      std::stop_token stop = {}) -> task<std::vector<std::byte>> {
    co_return co_await detail::serialize_request(req, body, stop);
}

template <body_stream Body>
inline auto serialize(const response& res, Body& body,
                      std::stop_token stop = {}) -> task<std::vector<std::byte>> {
    co_return co_await detail::serialize_response(res, body, stop);
}

// Convenience overload for a message without a body.
inline auto serialize(const request& req, std::stop_token stop = {}) -> task<std::vector<std::byte>> {
    http::buffer_body empty;
    co_return co_await detail::serialize_request(req, empty, stop);
}

inline auto serialize(const response& res, std::stop_token stop = {}) -> task<std::vector<std::byte>> {
    http::buffer_body empty;
    co_return co_await detail::serialize_response(res, empty, stop);
}

} // namespace http::v1
