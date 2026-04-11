module;

#include <llhttp.h>

export module httpant:codec;

import std;
import :trait;
import :message;

export namespace http {

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

struct parser_state {
    bool complete{false};
    bool headers_done{false};
    std::string current_field{};
    std::string current_value{};
    std::string url{};
    std::string status_text{};
    http::status status_code{0};
    http::method req_method{method::GET};
    headers fields{};
    std::vector<std::byte> body{};
};

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
        if (!st->current_value.empty()) {
            st->fields.push_back({std::move(st->current_field), std::move(st->current_value)});
            st->current_field.clear();
            st->current_value.clear();
        }
        st->current_field.append(at, len);
        return 0;
    };
    s.on_header_value = [](llhttp_t* p, const char* at, std::size_t len) -> int {
        static_cast<parser_state*>(p->data)->current_value.append(at, len);
        return 0;
    };
    s.on_headers_complete = [](llhttp_t* p) -> int {
        auto* st = static_cast<parser_state*>(p->data);
        if (!st->current_field.empty()) {
            st->fields.push_back({std::move(st->current_field), std::move(st->current_value)});
            st->current_field.clear();
            st->current_value.clear();
        }
        st->headers_done = true;
        st->status_code = static_cast<http::status>(p->status_code);
        st->req_method = from_llhttp_method(static_cast<llhttp_method_t>(p->method));
        return 0;
    };
    s.on_body = [](llhttp_t* p, const char* at, std::size_t len) -> int {
        auto* st = static_cast<parser_state*>(p->data);
        auto bytes = std::as_bytes(std::span{at, len});
        st->body.insert(st->body.end(), bytes.begin(), bytes.end());
        return 0;
    };
    s.on_message_complete = [](llhttp_t* p) -> int {
        static_cast<parser_state*>(p->data)->complete = true;
        llhttp_pause(p);
        return 0;
    };
    return s;
}

inline void validate_request(const parser_state& st) {
    // RFC 9112 §3.2 — exactly one Host field required
    auto hosts = find_all_headers(st.fields, "host");
    if (hosts.empty())
        throw std::runtime_error("http/1.1: missing Host header");
    if (hosts.size() > 1)
        throw std::runtime_error("http/1.1: multiple Host headers");

    // RFC 7639 — ALPN field is only valid in CONNECT requests
    if (st.req_method != method::CONNECT && find_header(st.fields, "alpn"))
        throw std::runtime_error("http/1.1: ALPN header in non-CONNECT request");

    // RFC 9110 §9.3.6 — CONNECT target must be authority-form (host:port)
    if (st.req_method == method::CONNECT) {
        if (st.url.starts_with("/") || st.url.contains("://"))
            throw std::runtime_error("http/1.1: CONNECT target must be authority-form");
    }
}

inline auto make_parse_error(const llhttp_t& parser, llhttp_errno_t err) -> std::runtime_error {
    auto message = std::string("http/1.1 parse error: ") + llhttp_errno_name(err);
    if (auto* reason = llhttp_get_error_reason(&parser); reason != nullptr && reason[0] != '\0') {
        message += " (";
        message += reason;
        message += ')';
    }
    return std::runtime_error(std::move(message));
}

inline void consume(llhttp_t& parser, std::span<const std::byte> bytes) {
    auto err = llhttp_execute(
        &parser,
        reinterpret_cast<const char*>(bytes.data()),
        bytes.size());
    if (err != HPE_OK && err != HPE_PAUSED && err != HPE_PAUSED_UPGRADE)
        throw make_parse_error(parser, err);
    if (err == HPE_PAUSED) llhttp_resume(&parser);
}

inline void finish_on_eof(llhttp_t& parser, const parser_state& state, std::string_view message) {
    auto err = llhttp_finish(&parser);
    if (err != HPE_OK && err != HPE_PAUSED && err != HPE_PAUSED_UPGRADE)
        throw make_parse_error(parser, err);
    if (!state.complete)
        throw std::runtime_error(std::string(message));
    if (err == HPE_PAUSED) llhttp_resume(&parser);
}

} // namespace detail

// ─── Serialization (RFC 9112 §3, §6) ─────────────────────────

inline auto serialize(const request& req) -> std::vector<std::byte> {
    std::string raw;
    raw += std::string(to_string(req.method));
    raw += ' ';
    raw += req.target;
    raw += " HTTP/1.1\r\n";

    bool has_te = false;
    for (auto& h : req.fields) {
        // RFC 7639 — strip ALPN from non-CONNECT
        if (req.method != method::CONNECT && iequal(h.name, "alpn"))
            continue;
        raw += h.name;
        raw += ": ";
        raw += h.value;
        raw += "\r\n";
        if (iequal(h.name, "transfer-encoding")) has_te = true;
    }

    // Body: TRACE must not carry one (RFC 9110 §9.3.8)
    bool send_body = !req.body.empty() && req.method != method::TRACE;

    if (send_body && !has_te && !find_header(req.fields, "content-length")) {
        raw += "content-length: ";
        raw += std::to_string(req.body.size());
        raw += "\r\n";
    }
    raw += "\r\n";

    std::vector<std::byte> result;
    result.reserve(raw.size() + (send_body ? req.body.size() : 0));
    auto bytes = std::as_bytes(std::span{raw});
    result.insert(result.end(), bytes.begin(), bytes.end());
    if (send_body)
        result.insert(result.end(), req.body.begin(), req.body.end());
    return result;
}

inline auto serialize(const response& res) -> std::vector<std::byte> {
    bool body_ok = status_allows_body(res.status);
    bool has_te = !!find_header(res.fields, "transfer-encoding");

    std::string raw;
    raw += "HTTP/1.1 ";
    raw += std::to_string(res.status);
    raw += ' ';
    raw += res.reason.empty() ? default_reason_phrase(res.status) : res.reason;
    raw += "\r\n";
    for (auto& h : res.fields) {
        raw += h.name;
        raw += ": ";
        raw += h.value;
        raw += "\r\n";
    }
    if (body_ok && !res.body.empty() && !has_te && !find_header(res.fields, "content-length")) {
        raw += "content-length: ";
        raw += std::to_string(res.body.size());
        raw += "\r\n";
    }
    raw += "\r\n";

    std::vector<std::byte> result;
    result.reserve(raw.size() + (body_ok ? res.body.size() : 0));
    auto bytes = std::as_bytes(std::span{raw});
    result.insert(result.end(), bytes.begin(), bytes.end());
    if (body_ok)
        result.insert(result.end(), res.body.begin(), res.body.end());
    return result;
}

// Serialize a response for a HEAD request (omit body, keep headers)
inline auto serialize_head(const response& res) -> std::vector<std::byte> {
    std::string raw;
    raw += "HTTP/1.1 ";
    raw += std::to_string(res.status);
    raw += ' ';
    raw += res.reason.empty() ? default_reason_phrase(res.status) : res.reason;
    raw += "\r\n";
    for (auto& h : res.fields) {
        raw += h.name;
        raw += ": ";
        raw += h.value;
        raw += "\r\n";
    }
    raw += "\r\n";
    auto bytes = std::as_bytes(std::span{raw});
    return {bytes.begin(), bytes.end()};
}

// ─── HTTP/1.1 client (RFC 9112) ──────────────────────────────

template <duplex S>
class client_v1 {
public:
    explicit client_v1(S& transport) : transport_(transport) {}

    auto request(http::request req) -> task<http::response> {
        auto data = serialize(req);
        auto written = co_await async_write_to(
            transport_,
            std::span<const std::byte>{data.data(), data.size()});
        if (written == 0)
            throw std::runtime_error("http/1.1: write failed");

        auto settings = detail::make_settings();
        llhttp_t parser;
        llhttp_init(&parser, HTTP_RESPONSE, &settings);
        detail::parser_state state;
        parser.data = &state;

        std::array<std::byte, 8192> buf;

        // Skip 1xx informational responses (RFC 9110 §15.2)
        for (;;) {
            while (!state.complete) {
                auto n = co_await transport_.async_read(std::span{buf});
                if (n == 0) {
                    detail::finish_on_eof(
                        parser,
                        state,
                        state.headers_done
                            ? "http/1.1: connection closed before complete response"
                            : "http/1.1: connection closed before response");
                    break;
                }
                detail::consume(
                    parser,
                    std::span<const std::byte>{buf.data(), static_cast<std::size_t>(n)});
            }

            if (!is_informational(state.status_code)) break;

            // Reset for next message-head
            state = {};
            llhttp_init(&parser, HTTP_RESPONSE, &settings);
            parser.data = &state;
        }

        co_return http::response{
            .status = state.status_code,
            .reason = std::move(state.status_text),
            .fields = std::move(state.fields),
            .body   = std::move(state.body),
        };
    }

private:
    S& transport_;
};

// ─── HTTP/1.1 server (RFC 9112) ──────────────────────────────

template <duplex S>
class server_v1 {
public:
    explicit server_v1(S& transport) : transport_(transport) {}

    auto receive() -> task<http::request> {
        auto settings = detail::make_settings();
        llhttp_t parser;
        llhttp_init(&parser, HTTP_REQUEST, &settings);
        detail::parser_state state;
        parser.data = &state;

        std::array<std::byte, 8192> buf;
        while (!state.complete) {
            auto n = co_await transport_.async_read(std::span{buf});
            if (n == 0) {
                detail::finish_on_eof(parser, state, "http/1.1: connection closed before complete request");
                break;
            }
            detail::consume(
                parser,
                std::span<const std::byte>{buf.data(), static_cast<std::size_t>(n)});
        }

        if (state.headers_done)
            detail::validate_request(state);

        last_method_ = state.req_method;

        co_return http::request{
            .method = state.req_method,
            .target = std::move(state.url),
            .fields = std::move(state.fields),
            .body   = std::move(state.body),
        };
    }

    auto respond(http::response res) -> task<void> {
        // HEAD and successful CONNECT responses must not include content.
        auto data = (last_method_ == method::HEAD ||
                     (last_method_ == method::CONNECT && is_successful(res.status)))
            ? serialize_head(res) : serialize(res);
        co_await async_write_to(
            transport_,
            std::span<const std::byte>{data.data(), data.size()});
    }

private:
    S& transport_;
    method last_method_{method::GET};
};

} // namespace http
