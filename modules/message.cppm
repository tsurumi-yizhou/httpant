export module httpant:message;

import std;

export namespace http {

// ─── Method tokens (RFC 9110 §9) ─────────────────────────────

enum class method : std::uint8_t {
    UNKNOWN,
    GET, HEAD, POST, PUT, DELETE_, CONNECT, OPTIONS, TRACE, PATCH
};

constexpr auto to_string(method m) -> std::string_view {
    using enum method;
    switch (m) {
        case GET:     return "GET";
        case HEAD:    return "HEAD";
        case POST:    return "POST";
        case PUT:     return "PUT";
        case DELETE_: return "DELETE";
        case CONNECT: return "CONNECT";
        case OPTIONS: return "OPTIONS";
        case TRACE:   return "TRACE";
        case PATCH:   return "PATCH";
        case UNKNOWN: return "";
    }
    std::unreachable();
}

constexpr auto try_from_string(std::string_view s) -> std::optional<method> {
    using enum method;
    if (s == "GET")     return GET;
    if (s == "HEAD")    return HEAD;
    if (s == "POST")    return POST;
    if (s == "PUT")     return PUT;
    if (s == "DELETE")  return DELETE_;
    if (s == "CONNECT") return CONNECT;
    if (s == "OPTIONS") return OPTIONS;
    if (s == "TRACE")   return TRACE;
    if (s == "PATCH")   return PATCH;
    return std::nullopt;
}

constexpr auto from_string(std::string_view s) -> method {
    return try_from_string(s).value_or(method::UNKNOWN);
}

constexpr auto is_safe(method m) -> bool {
    return m == method::GET || m == method::HEAD ||
           m == method::OPTIONS || m == method::TRACE;
}

constexpr auto is_idempotent(method m) -> bool {
    return is_safe(m) || m == method::PUT || m == method::DELETE_;
}

// ─── Status codes (RFC 9110 §15) ─────────────────────────────

using status = std::uint16_t;

constexpr auto default_reason_phrase(status code) -> std::string_view {
    switch (code) {
        case 100: return "Continue";
        case 101: return "Switching Protocols";
        case 103: return "Early Hints";
        case 200: return "OK";
        case 201: return "Created";
        case 202: return "Accepted";
        case 203: return "Non-Authoritative Information";
        case 204: return "No Content";
        case 205: return "Reset Content";
        case 206: return "Partial Content";
        case 300: return "Multiple Choices";
        case 301: return "Moved Permanently";
        case 302: return "Found";
        case 303: return "See Other";
        case 304: return "Not Modified";
        case 307: return "Temporary Redirect";
        case 308: return "Permanent Redirect";
        case 400: return "Bad Request";
        case 401: return "Unauthorized";
        case 403: return "Forbidden";
        case 404: return "Not Found";
        case 405: return "Method Not Allowed";
        case 406: return "Not Acceptable";
        case 407: return "Proxy Authentication Required";
        case 408: return "Request Timeout";
        case 409: return "Conflict";
        case 410: return "Gone";
        case 411: return "Length Required";
        case 412: return "Precondition Failed";
        case 413: return "Content Too Large";
        case 414: return "URI Too Long";
        case 415: return "Unsupported Media Type";
        case 416: return "Range Not Satisfiable";
        case 417: return "Expectation Failed";
        case 418: return "I'm a Teapot";
        case 421: return "Misdirected Request";
        case 422: return "Unprocessable Content";
        case 425: return "Too Early";
        case 426: return "Upgrade Required";
        case 428: return "Precondition Required";
        case 429: return "Too Many Requests";
        case 431: return "Request Header Fields Too Large";
        case 451: return "Unavailable For Legal Reasons";
        case 500: return "Internal Server Error";
        case 501: return "Not Implemented";
        case 502: return "Bad Gateway";
        case 503: return "Service Unavailable";
        case 504: return "Gateway Timeout";
        case 505: return "HTTP Version Not Supported";
        default:  return "";
    }
}

constexpr auto is_informational(status s) -> bool { return s >= 100 && s < 200; }
constexpr auto is_successful(status s)    -> bool { return s >= 200 && s < 300; }
constexpr auto is_redirection(status s)   -> bool { return s >= 300 && s < 400; }
constexpr auto is_client_error(status s)  -> bool { return s >= 400 && s < 500; }
constexpr auto is_server_error(status s)  -> bool { return s >= 500 && s < 600; }

// Whether a response with this status may carry a body (RFC 9112 §6.3)
constexpr auto status_allows_body(status s) -> bool {
    return !is_informational(s) && s != 204 && s != 205 && s != 304;
}

// ─── Headers (RFC 9110 §5) ───────────────────────────────────

struct header {
    std::string name;
    std::string value;
};

using headers = std::vector<header>;

inline auto iequal(std::string_view a, std::string_view b) -> bool {
    return std::ranges::equal(a, b, [](char x, char y) {
        return std::tolower(static_cast<unsigned char>(x)) ==
               std::tolower(static_cast<unsigned char>(y));
    });
}

inline auto find_header(const headers& hdrs, std::string_view name)
    -> std::optional<std::string_view>
{
    for (auto& h : hdrs)
        if (iequal(h.name, name)) return h.value;
    return std::nullopt;
}

inline auto find_all_headers(const headers& hdrs, std::string_view name)
    -> std::vector<std::string_view>
{
    std::vector<std::string_view> result;
    for (auto& h : hdrs)
        if (iequal(h.name, name)) result.push_back(h.value);
    return result;
}

// ─── Messages (RFC 9110 §6) ─────────────────────────────────

struct request {
    http::method method{method::GET};
    std::string  target{"/"};
    std::string  scheme{};
    std::string  authority{};
    headers      fields{};
    std::vector<std::byte> body{};
};

struct response {
    http::status status{200};
    std::string  reason{};
    headers      fields{};
    std::vector<std::byte> body{};
};

struct pushed_exchange {
    std::uint64_t push_id{0};
    std::int64_t associated_stream_id{0};
    std::int64_t stream_id{0};
    request promised_request{};
    response pushed_response{};
};

inline auto request_scheme(const request& req) -> std::optional<std::string_view> {
    if (!req.scheme.empty()) return req.scheme;

    auto target = std::string_view{req.target};
    auto sep = target.find("://");
    if (sep == std::string_view::npos) return std::nullopt;
    return target.substr(0, sep);
}

inline auto request_authority(const request& req) -> std::optional<std::string_view> {
    if (!req.authority.empty()) return req.authority;
    if (auto host = find_header(req.fields, "host")) return *host;

    auto target = std::string_view{req.target};
    auto sep = target.find("://");
    if (sep != std::string_view::npos) {
        auto authority_start = sep + 3;
        auto path_start = target.find('/', authority_start);
        return target.substr(authority_start, path_start == std::string_view::npos
            ? std::string_view::npos
            : path_start - authority_start);
    }

    if (req.method == method::CONNECT) return target;
    return std::nullopt;
}

inline auto request_path(const request& req) -> std::optional<std::string_view> {
    if (req.method == method::CONNECT) return std::nullopt;

    auto target = std::string_view{req.target};
    auto sep = target.find("://");
    if (sep == std::string_view::npos) {
        if (target.empty()) return std::nullopt;
        return target;
    }

    auto authority_start = sep + 3;
    auto path_start = target.find('/', authority_start);
    if (path_start == std::string_view::npos) return std::string_view{"/"};
    return target.substr(path_start);
}

// ─── Entity tags (RFC 9110 §8.8.3) ──────────────────────────

struct etag {
    std::string value;
    bool weak{false};
};

inline auto parse_etag(std::string_view s) -> std::optional<etag> {
    if (s.starts_with("W/\"") && s.ends_with('"'))
        return etag{std::string(s.substr(3, s.size() - 4)), true};
    if (s.starts_with('"') && s.ends_with('"'))
        return etag{std::string(s.substr(1, s.size() - 2)), false};
    return std::nullopt;
}

inline auto strong_match(const etag& a, const etag& b) -> bool {
    return !a.weak && !b.weak && a.value == b.value;
}

inline auto weak_match(const etag& a, const etag& b) -> bool {
    return a.value == b.value;
}

// ─── Content type (RFC 9110 §8.3) ───────────────────────────

struct content_type {
    std::string type;
    std::string subtype;
    std::vector<std::pair<std::string, std::string>> parameters;
};

inline auto parse_content_type(std::string_view s) -> std::optional<content_type> {
    auto slash = s.find('/');
    if (slash == std::string_view::npos) return std::nullopt;
    auto semi = s.find(';');
    auto media = (semi != std::string_view::npos) ? s.substr(0, semi) : s;
    content_type ct;
    ct.type = std::string(media.substr(0, slash));
    ct.subtype = std::string(media.substr(slash + 1));
    while (!ct.subtype.empty() && ct.subtype.back() == ' ') ct.subtype.pop_back();
    if (semi != std::string_view::npos) {
        auto rest = s.substr(semi + 1);
        while (!rest.empty()) {
            while (!rest.empty() && rest.front() == ' ') rest.remove_prefix(1);
            auto eq = rest.find('=');
            if (eq == std::string_view::npos) break;
            auto next = rest.find(';');
            auto val = (next != std::string_view::npos)
                ? rest.substr(eq + 1, next - eq - 1) : rest.substr(eq + 1);
            ct.parameters.emplace_back(std::string(rest.substr(0, eq)), std::string(val));
            if (next == std::string_view::npos) break;
            rest = rest.substr(next + 1);
        }
    }
    return ct;
}

} // namespace http
