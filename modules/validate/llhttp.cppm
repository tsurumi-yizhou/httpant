module;

#include <cstddef>
#include <cstdint>
#include <optional>
#include <ranges>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

export module httpant:validate.llhttp;

import :trait;
import :message;
import :error;

export namespace http::v1 {

namespace detail {

// Transport reads and body staging use one fixed buffer size per parser /
// stream operation.
inline constexpr std::size_t io_buffer_size = 8 * 1024;

// Where llhttp paused inside a message. The parser stops at the headers/body
// boundary so the head can be surfaced before the body is streamed, and again
// at the message boundary so persistence facts can be captured.
enum class pause_kind : std::uint8_t { none, headers, message, upgrade };

struct parser_state {
    bool complete{false};
    bool headers_done{false};
    // RFC 9110 §10.1.1 — the request carries an "Expect: 100-continue"
    // expectation and content will follow; the parser pauses at the
    // headers/content boundary so the server can send an interim 100 before
    // the content is read.
    bool expect_continue{false};
    // RFC 9112 §9.3 — whether the connection persists after the current
    // message. Captured at headers (requests are always self-framed) and
    // refined at message completion (a close-delimited response is not
    // persistent).
    bool keep_alive{true};
    // RFC 9110 §15.2.2 / §9.3.6 — 101 or CONNECT switches the connection to a
    // different protocol; llhttp reports this at the headers boundary.
    bool upgraded{false};
    pause_kind pause{pause_kind::none};

    std::string current_field{};
    std::string current_value{};
    // RFC 9110 §5.2 — "field-value = *field-content": a field value may be
    // empty, and llhttp fires on_header_value with a zero-length span for one,
    // so current_value alone cannot tell whether the pending field already has
    // its value. This flag is set once a value has been seen for the pending
    // field; the next on_header_field invocation then pushes the completed
    // field. A field *name* split across two transport reads fires
    // on_header_field twice without an intervening value, so the push gate
    // must not be keyed on the field name being non-empty (that would emit a
    // bogus empty-valued field); the flag distinguishes the two cases.
    bool value_seen{false};
    std::string url{};
    std::string status_text{};
    // RFC 9112 §3.2 — the Host requirement is scoped to HTTP/1.1 (or later);
    // the wire protocol version is captured at the start line so validation
    // can apply version-scoped rules (RFC 9112 §9.3 HTTP/1.0 persistence).
    int http_major{1};
    int http_minor{1};
    // RFC 9112 §3 — "HTTP-version = HTTP-name \"/\" DIGIT \".\" DIGIT"; a
    // syntactically valid start line carries exactly HTTP/x.y, and only such a
    // line can reach headers_complete with a usable protocol version — llhttp
    // rejects a malformed version outright (e.g. "HTTP/1.1.1") — so this flag
    // distinguishes the valid versions (1.0, 1.1, later majors) from an
    // HTTP/0.9-style start line, whose version fields are not meaningful.
    bool protocol_version_valid{true};
    // RFC 9112 §7.1.2 — trailer fields must not be merged into the header
    // section; llhttp feeds trailer lines through the header callbacks, so the
    // F_TRAILING flag (set for the whole trailer section) is latched here to
    // discard them (see on_header_field/on_header_value).
    bool trailing{false};
    // RFC 9112 §6.3 — the framing llhttp derived from the header section: the
    // declared Content-Length (0 when absent) and whether the chunked transfer
    // coding is in effect. Used to detect a TRACE request that declares content
    // (RFC 9110 §9.3.8).
    std::uint64_t content_length{0};
    bool chunked{false};
    http::status status_code{0};
    http::method req_method{method::GET};
    headers fields{};
    http::detail::byte_cursor body{};
};

// RFC 9110 §5.5 — "A field value might be preceded and/or followed by
// optional whitespace (OWS)" (RFC 9110 §5.6.3 — "OWS = *( SP / HTAB )").
[[nodiscard]] inline auto trim_ows(std::string_view token) -> std::string_view {
    while (!token.empty() && (token.front() == ' ' || token.front() == '\t'))
        token.remove_prefix(1);
    while (!token.empty() && (token.back() == ' ' || token.back() == '\t'))
        token.remove_suffix(1);
    return token;
}

// The 100-599 status bound lives in :message (http::detail::is_valid_status),
// shared by all three protocol versions' send and receive paths.

// RFC 9110 §10.1.1 — "The only expectation defined by this specification is
// \"100-continue\" (with no defined parameters)." Returns whether an Expect
// header field carries exactly the 100-continue token.
[[nodiscard]] inline auto expects_continue(const headers& fields) -> bool {
    auto value = find_header(fields, "expect");
    return value.has_value() && iequal(trim_ows(*value), "100-continue");
}

// RFC 9110 §5.3 — "A recipient MAY combine multiple field lines within a
// field section that have the same field name into one field line, without
// changing the semantics of the message, by appending each subsequent field
// line value to the initial field line value in order, separated by a comma"
// — multiple Transfer-Encoding field lines therefore combine into one
// comma-separated list, and the codings must be read across every field line,
// not just the first.
[[nodiscard]] inline auto transfer_encoding_codings(const headers& fields)
    -> std::vector<std::string_view> {
    std::vector<std::string_view> codings;
    for (const auto& h : fields) {
        if (!iequal(h.name, "transfer-encoding")) continue;
        for (auto part : std::views::split(h.value, ',')) {
            auto coding = trim_ows(std::string_view{part.begin(), part.end()});
            if (coding.empty()) continue;
            codings.push_back(coding);
        }
    }
    return codings;
}

// Validate the Transfer-Encoding of a message about to be sent. RFC 9112 §6.3
// — "A sender MUST NOT send a Content-Length header field in any message that
// contains a Transfer-Encoding header field." RFC 9112 §6.1 — "If a
// Transfer-Encoding header field is present in a request and the chunked
// transfer coding is not the final encoding, the message body length cannot be
// determined reliably"; this library applies no transfer coding other than
// chunked, so any other coding would misdescribe the body on the wire and is
// rejected instead of being silently emitted.
inline void validate_transfer_encoding(const headers& fields) {
    if (!find_header(fields, "transfer-encoding")) return;
    if (find_header(fields, "content-length"))
        throw std::runtime_error(
            "http/1.1: Transfer-Encoding and Content-Length both present");
    // RFC 9112 §6.1 — "A sender MUST NOT apply the chunked transfer coding
    // more than once"; a single final chunked is the only valid shape here.
    auto codings = transfer_encoding_codings(fields);
    if (codings.size() != 1 || !iequal(codings.front(), "chunked"))
        throw std::runtime_error(
            "http/1.1: unsupported Transfer-Encoding (only chunked is sent)");
}

// RFC 9110 §7.6.1 — the "close" connection option requests connection closure
// after the current exchange. Connection options are case-insensitive tokens.
[[nodiscard]] inline auto has_close_option(const headers& fields) -> bool {
    for (const auto& h : fields) {
        if (!iequal(h.name, "connection")) continue;
        for (auto part : std::views::split(h.value, ',')) {
            auto token = trim_ows(std::string_view{part.begin(), part.end()});
            if (iequal(token, "close")) return true;
        }
    }
    return false;
}

// A protocol_error for a malformed HTTP/1.1 message. The message-layer error
// needs no wire action of its own: RFC 9112 §3.2 requires the server to answer
// with 400 (send_response) — expressed by server when it catches the error —
// while a client that received a malformed response simply closes the
// connection (close_connection, no code). Both actions live in the endpoint,
// so the error itself stays action-free.
inline auto protocol_violation(std::string message) -> protocol_error {
    return protocol_error{
        error_info{
            .version = protocol_version::http1,
            .scope = error_scope::message,
            .condition = error_condition::malformed_message,
            .exchange_identity = std::nullopt,
            .library_code = std::nullopt,
            .retryable = false,
        },
        no_action{},
        std::move(message)};
}

// Validate the Transfer-Encoding of a received response head. RFC 9112 §6.3
// item 4 — "If a Transfer-Encoding header field is present in a request and
// the chunked transfer coding is not the final encoding, the message body
// length cannot be determined reliably; the server MUST respond with the 400
// (Bad Request) status code and then close the connection." The library
// decodes no transfer coding other than chunked (the send-side guard refuses
// to emit any other), so the same boundary applies when receiving: a response
// whose combined Transfer-Encoding list is not exactly one "chunked" member
// cannot be decoded and is rejected instead of silently misdecoded. This
// guard is not redundant with llhttp's strictness: for a request llhttp
// rejects a multi-line Transfer-Encoding itself, but for a response it
// accepts any combination with only the last field line visible to its
// framing flags — e.g. "chunked" followed by "gzip" is parsed as if no
// chunked coding were present (RFC 9110 §5.3 combines the lines to
// "chunked, gzip", which llhttp never sees as a list).
inline void validate_response_transfer_encoding(const headers& fields) {
    if (!find_header(fields, "transfer-encoding")) return;
    auto codings = transfer_encoding_codings(fields);
    if (codings.size() != 1 || !iequal(codings.front(), "chunked"))
        throw protocol_violation(
            "http/1.1: Transfer-Encoding final coding is not chunked");
}

inline void validate_request(const parser_state& st) {
    // RFC 9112 §3.2 — "A server MUST respond with a 400 (Bad Request) status
    // code to any HTTP/1.1 request message that lacks a Host header field and
    // to any request message that contains more than one Host header field
    // line or a Host header field with an invalid field value." The Host
    // presence requirement is scoped to HTTP/1.1 (or later) — RFC 9112 §3.2 —
    // "A client MUST send a Host header field in all HTTP/1.1 request
    // messages" — and the server otherwise supports HTTP/1.0 persistence
    // (RFC 9112 §9.3), so an HTTP/1.0 request without Host is accepted. The
    // multiplicity rule is version-unscoped: the sentence above applies it to
    // "any request message", HTTP/1.0 included.
    auto hosts = find_all_headers(st.fields, "host");
    if (hosts.size() > 1)
        throw protocol_violation("http/1.1: multiple Host headers");
    bool http_1_1_or_later = st.protocol_version_valid &&
        (st.http_major > 1 || (st.http_major == 1 && st.http_minor >= 1));
    if (http_1_1_or_later) {
        if (hosts.empty())
            throw protocol_violation("http/1.1: missing Host header");
        if (hosts.size() == 1) {
            // RFC 9112 §3.2 — "a Host header field with an invalid field value"
            // must be answered with 400. Host is a singleton (RFC 9110 §7.2 —
            // "Host = uri-host [ \":\" port ]"). An EMPTY value is valid:
            // RFC 9112 §3.2 — "If the authority component is missing or
            // undefined for the target URI, then a client MUST send a Host
            // header field with an empty field value". All other values are
            // checked against the shared uri-host grammar; this rejects
            // "example.com/path", "example.com:bad", and "user@example.com",
            // not just the comma-list and embedded-whitespace shapes.
            auto value = trim_ows(hosts.front());
            if (!value.empty() && !http::detail::is_host_value(value))
                throw protocol_violation("http/1.1: invalid Host header value");
        }
    }

    // RFC 7639 §2 — ALPN is only valid in CONNECT requests.
    if (st.req_method != method::CONNECT && find_header(st.fields, "alpn"))
        throw protocol_violation("http/1.1: ALPN header in non-CONNECT request");

    // RFC 9112 §3.2.4 — "The 'asterisk-form' of request-target is only used
    // for a server-wide OPTIONS request"; RFC 9110 §7.1 — "These forms MUST
    // NOT be used with other methods." llhttp accepts the wire shape for any
    // method, so a non-OPTIONS request targeting "*" is a protocol violation
    // answered with 400 + close like the other malformed request heads.
    if (st.url == "*" && st.req_method != method::OPTIONS)
        throw protocol_violation("http/1.1: asterisk-form request-target requires OPTIONS");

    // RFC 9112 §6.3 item 4 — "If a Transfer-Encoding header field is present
    // in a request and the chunked transfer coding is not the final encoding,
    // the message body length cannot be determined reliably; the server MUST
    // respond with the 400 (Bad Request) status code and then close the
    // connection." The library decodes no transfer coding other than chunked
    // (the send-side guard above refuses to emit any other), so the receive
    // side mirrors that boundary: a request whose combined Transfer-Encoding
    // list (RFC 9110 §5.3 — multiple field lines combine into one list) is
    // not exactly one "chunked" member — including the smuggling shape
    // "gzip, chunked", which is legal per the RFC but would deliver
    // gzip-encoded bytes as the body — is rejected instead of being silently
    // misdecoded. (llhttp rejects multi-line Transfer-Encoding field sections
    // on requests itself, so this guard operates on the single line it admits;
    // the same check below guards the response path, where llhttp is lenient.)
    if (find_header(st.fields, "transfer-encoding")) {
        auto codings = transfer_encoding_codings(st.fields);
        if (codings.size() != 1 || !iequal(codings.front(), "chunked"))
            throw protocol_violation(
                "http/1.1: Transfer-Encoding final coding is not chunked");
    }

    // RFC 9110 §9.3.6 — "A server MUST reject a CONNECT request that targets
    // an empty or invalid port number, typically by responding with a 400
    // (Bad Request) status code." RFC 9112 §3.2.3 — "authority-form = uri-host
    // \":\" port" — the library's own grammar check rejects a missing port
    // ("example.com"), a non-numeric port, an empty port, and a port with a
    // path suffix ("example.com:80/foo").
    if (st.req_method == method::CONNECT) {
        if (!http::detail::is_authority_form(st.url))
            throw protocol_violation("http/1.1: CONNECT target must be authority-form");
    }

    // RFC 9110 §9.3.8 — "A client MUST NOT send content in a TRACE request."
    // A TRACE with a declared body (Content-Length > 0 or a transfer coding)
    // is rejected; a Content-Length of 0 carries no content.
    if (st.req_method == method::TRACE &&
        (st.chunked || st.content_length > 0))
        throw protocol_violation("http/1.1: TRACE request must not carry content");
}

} // namespace detail
} // namespace http::v1
