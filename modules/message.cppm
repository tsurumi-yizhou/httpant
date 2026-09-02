module;

#include <algorithm>
#include <cctype>
#include <charconv>
#include <cstdint>
#include <expected>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

export module httpant:message;

export namespace http {

// ─── Method tokens (RFC 9110 §9) ─────────────────────────────

// RFC 9110 §9.1 — "This specification defines a number of standardized methods that are commonly used in HTTP, as outlined by the following table."
enum class method : std::uint8_t {
    UNKNOWN,
    GET, HEAD, POST, PUT, DELETE_, CONNECT, OPTIONS, TRACE, PATCH
};

// RFC 9110 §9.1 — "By convention, standardized methods are defined in all-uppercase US-ASCII letters."
// method::UNKNOWN is the placeholder for an inbound method outside this set (RFC 9110 §9.1 —
// "Additional methods, outside the scope of this specification, have been specified for use in
// HTTP"); it carries no token of its own, so it maps to the empty string and must never be
// emitted on the wire — the send paths reject it (v1 serialize_head, make_request_field_block).
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

// RFC 9110 §9.1 — "The method token is case-sensitive because it might be used as a gateway to object-based systems with case-sensitive method names."
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

// RFC 9110 §9.1 — "Additional methods, outside the scope of this specification, have been specified for use in HTTP."
constexpr auto from_string(std::string_view s) -> method {
    return try_from_string(s).value_or(method::UNKNOWN);
}

// ─── Status codes (RFC 9110 §15) ─────────────────────────────

using status = std::uint16_t;

// RFC 9110 §15.1 — "The status codes listed below are defined in this specification.  The reason phrases listed here are only recommendations -- they can be replaced by local equivalents or left out altogether without affecting the protocol."
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

// RFC 9110 §15 — "The first digit of the status code defines the class of response."
// RFC 9110 §15 — "1xx (Informational): The request was received, continuing process"
// RFC 9110 §15 — "2xx (Successful): The request was successfully received, understood, and accepted"
// RFC 9110 §15 — "3xx (Redirection): Further action needs to be taken in order to complete the request"
// RFC 9110 §15 — "4xx (Client Error): The request contains bad syntax or cannot be fulfilled"
// RFC 9110 §15 — "5xx (Server Error): The server failed to fulfill an apparently valid request"
constexpr auto is_informational(status s) -> bool { return s >= 100 && s < 200; }
constexpr auto is_successful(status s)    -> bool { return s >= 200 && s < 300; }

// Whether a response with this status may carry a body: 1xx, 204, 205, and 304 all
// terminate at the end of the header section.
// RFC 9110 §15.2 — "A 1xx response is terminated by the end of the header section; it cannot contain content or trailers."
// RFC 9110 §15.3.5 — "A 204 response is terminated by the end of the header section; it cannot contain content or trailers."
// RFC 9110 §15.3.6 — "Since the 205 status code implies that no additional content will be provided, a server MUST NOT generate content in a 205 response."
// RFC 9110 §15.4.5 — "A 304 response is terminated by the end of the header section; it cannot contain content or trailers."
constexpr auto status_allows_body(status s) -> bool {
    return !is_informational(s) && s != 204 && s != 205 && s != 304;
}

namespace detail {

// RFC 9110 §15 — "status-code = 3DIGIT", i.e. 100-599. The range bound on an
// already-parsed status value; parse_status wraps it for wire tokens.
[[nodiscard]] constexpr auto is_valid_status(status s) -> bool {
    return s >= 100 && s <= 599;
}

// RFC 9110 §15 — "status-code = 3DIGIT", i.e. 100-599. Non-throwing so it
// can run at a C callback boundary; each protocol wraps the failure in its
// own error channel.
[[nodiscard]] inline auto parse_status(std::string_view token) -> std::optional<status> {
    status code = 0;
    auto [ptr, ec] = std::from_chars(token.data(), token.data() + token.size(), code);
    if (ec != std::errc{} || ptr != token.data() + token.size()) return std::nullopt;
    if (!is_valid_status(code)) return std::nullopt;
    return code;
}

} // namespace detail

// ─── Headers (RFC 9110 §5) ───────────────────────────────────

struct header {
    std::string name;
    std::string value;
};

using headers = std::vector<header>;

// RFC 9110 §5.1 — "Field names are case-insensitive and ought to be registered within the \"Hypertext Transfer Protocol (HTTP) Field Name Registry\"."
inline auto iequal(std::string_view a, std::string_view b) -> bool {
    return std::ranges::equal(a, b, [](char x, char y) {
        return std::tolower(static_cast<unsigned char>(x)) ==
               std::tolower(static_cast<unsigned char>(y));
    });
}

namespace detail {

// RFC 9110 §11.6.2 / §11.6.3 and RFC 6265 §4.2 — credentials and cookies
// carry per-user secrets. Compression backends map this shared classification
// to their protocol-specific never-index representation.
inline auto is_sensitive_field_name(std::string_view name) -> bool {
    return iequal(name, "authorization") || iequal(name, "cookie") ||
           iequal(name, "set-cookie");
}

// RFC 9110 §4.2.2 — "two URIs are considered to have the same origin when
// their scheme, host, and port match"; the RFC delegates DNS-resolution and
// service-identity comparison to the deployment. The library cannot perform
// either, so a same-origin check reduces to scheme (case-insensitive) plus
// authority (case-insensitive host, port normalized to the scheme default).
// Shared by the HTTP/2 push-authority check (RFC 9113 §8.4) and the
// Host↔:authority agreement check (RFC 9113 §8.3.1 / RFC 9114 §4.3.1).
[[nodiscard]] inline auto same_origin(
    std::string_view scheme_a,
    std::string_view authority_a,
    std::string_view scheme_b,
    std::string_view authority_b) -> bool {
    if (!iequal(scheme_a, scheme_b)) return false;
    // RFC 9110 §4.2.1 — "authority = <host, see [URI], Section 3.2.2>" — an
    // IPv6 host is bracketed ("[::1]:443"), so the port separator is found
    // after the closing bracket; otherwise the host and optional ":port"
    // split on the right-most colon.
    auto split = [](std::string_view authority)
        -> std::pair<std::string_view, std::string_view> {
        if (!authority.empty() && authority.front() == '[') {
            auto close = authority.find(']');
            if (close == std::string_view::npos) return {authority, {}};
            auto host = authority.substr(0, close + 1);
            auto port = (close + 1 < authority.size() && authority[close + 1] == ':')
                ? authority.substr(close + 2) : std::string_view{};
            return {host, port};
        }
        auto colon = authority.rfind(':');
        if (colon == std::string_view::npos) return {authority, {}};
        return {authority.substr(0, colon), authority.substr(colon + 1)};
    };
    auto [host_a, port_a] = split(authority_a);
    auto [host_b, port_b] = split(authority_b);
    if (!iequal(host_a, host_b)) return false;
    // RFC 9110 §4.2.2 — "If the port is equal to the default port for a
    // scheme, the normal form is to omit the port subcomponent."
    auto default_port = [](std::string_view scheme) -> std::string_view {
        if (iequal(scheme, "https")) return "443";
        if (iequal(scheme, "http")) return "80";
        return {};
    };
    auto normalize = [&](std::string_view port, std::string_view scheme) -> std::string_view {
        return port.empty() ? default_port(scheme) : port;
    };
    return normalize(port_a, scheme_a) == normalize(port_b, scheme_b);
}

} // namespace detail

inline auto find_header(const headers& hdrs, std::string_view name)
    -> std::optional<std::string_view>
{
    auto it = std::ranges::find_if(hdrs, [name](const header& h) {
        return iequal(h.name, name);
    });
    if (it == hdrs.end()) return std::nullopt;
    return it->value;
}

inline auto find_all_headers(const headers& hdrs, std::string_view name)
    -> std::vector<std::string_view>
{
    std::vector<std::string_view> result;
    for (auto& h : hdrs)
        if (iequal(h.name, name)) result.push_back(h.value);
    return result;
}

// RFC 9110 §5.3 — "A recipient MAY combine multiple field lines within a field section
// that have the same field name into one field line, without changing the semantics of the
// message, by appending each subsequent field line value to the initial field line value in
// order, separated by a comma (",") and optional whitespace (OWS, defined in Section 5.6.3).
// For consistency, use comma SP."
// RFC 9110 §5.3 — "In practice, the "Set-Cookie" header field ([COOKIE]) often appears in a
// response message across multiple field lines and does not use the list syntax" and "Since
// it cannot be combined into a single field value, recipients ought to handle "Set-Cookie"
// as a special case while processing fields." — do not use this for Set-Cookie; iterate
// find_all_headers instead.
[[nodiscard]] inline auto combined_header(const headers& fields, std::string_view name)
    -> std::optional<std::string>
{
    auto values = find_all_headers(fields, name);
    if (values.empty()) return std::nullopt;
    std::string combined;
    for (auto value : values) {
        if (!combined.empty()) combined += ", ";
        combined += value;
    }
    return combined;
}

// ─── Messages (RFC 9110 §6) ─────────────────────────────────

struct request {
    http::method method{method::GET};
    std::string  target{"/"};
    std::string  scheme{};
    std::string  authority{};
    headers      fields{};
};

struct response {
    http::status status{200};
    std::string  reason{};
    headers      fields{};
};

namespace detail {

// RFC 9112 §3.2 — "There are four distinct formats for the request-target, depending on
// both the method being requested and whether the request is to a proxy." and
// "request-target = origin-form / absolute-form / authority-form / asterisk-form".
// (The four forms are named in RFC 9110 §7.1; their ABNF lives in RFC 9112 §3.2.)
enum class target_form : std::uint8_t { origin, absolute, authority, asterisk, malformed };

struct parsed_target {
    target_form form{target_form::malformed};
    std::string_view scheme{};
    std::string_view authority{};
    std::string_view path{};
    std::string_view path_and_query{};
};

// RFC 9110 §7.1 — "The target URI excludes the reference's fragment component, if any,
// since fragment identifiers are reserved for client-side processing ([URI], Section 3.5)."
[[nodiscard]] inline auto strip_fragment(std::string_view target) -> std::string_view {
    auto hash = target.find('#');
    return hash == std::string_view::npos ? target : target.substr(0, hash);
}

// RFC 9112 §3.2 — "Host = uri-host [ ":" port ]" and RFC 3986 §3.2.2 —
// "uri-host = IP-literal / IPv4address / reg-name". This shared validator is
// used by the HTTP/1.1 request path, where a Host value outside this grammar
// must be answered with 400 (RFC 9112 §3.2). An empty host is valid at the
// field level (it means "no authority", RFC 9112 §3.2), so callers gate the
// empty case themselves.
[[nodiscard]] inline auto is_host_value(std::string_view value) -> bool {
    auto is_digit = [](char c) { return c >= '0' && c <= '9'; };
    auto is_hex = [](char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
               (c >= 'A' && c <= 'F');
    };
    auto is_unreserved = [](unsigned char c) {
        return std::isalnum(c) || c == '-' || c == '.' || c == '_' || c == '~';
    };
    auto is_sub_delim = [](unsigned char c) {
        switch (c) {
            case '!': case '$': case '&': case '\'': case '(': case ')':
            case '*': case '+': case ',': case ';': case '=':
                return true;
            default:
                return false;
        }
    };

    if (value.empty()) return true;

    // RFC 3986 §3.2.2 — IP-literal = "[" ( IPv6address / IPvFuture ) "]".
    if (value.front() == '[') {
        auto close = value.find(']');
        if (close == std::string_view::npos || close == 1)
            return false;
        auto rest = value.substr(close + 1);
        if (rest.empty()) return true;
        if (rest.front() != ':') return false;
        auto port = rest.substr(1);
        return !port.empty() && std::ranges::all_of(port, is_digit);
    }

    // Unbracketed IPv6 is not a valid uri-host; reject any bracket or
    // unbracketed colon that is not the single port separator.
    if (value.find('[') != std::string_view::npos ||
        value.find(']') != std::string_view::npos)
        return false;

    std::string_view host = value;
    std::string_view port{};
    if (auto colon = value.rfind(':'); colon != std::string_view::npos) {
        if (value.find(':') != colon)
            return false;
        host = value.substr(0, colon);
        port = value.substr(colon + 1);
        if (port.empty() || !std::ranges::all_of(port, is_digit))
            return false;
    }

    if (host.empty()) return false;

    // RFC 3986 §3.2.2 — reg-name = *( unreserved / pct-encoded / sub-delims ).
    // IPv4address is a subset of reg-name for this validation, so a separate
    // dotted-decimal parser is unnecessary for wire rejection.
    for (std::size_t i = 0; i < host.size(); ++i) {
        auto c = static_cast<unsigned char>(host[i]);
        if (c == '%') {
            if (i + 2 >= host.size() || !is_hex(host[i + 1]) ||
                !is_hex(host[i + 2]))
                return false;
            i += 2;
            continue;
        }
        if (!is_unreserved(c) && !is_sub_delim(c))
            return false;
    }
    return true;
}


// RFC 9112 §3.2.3 — "authority-form = uri-host ":" port"; "It consists of only the uri-host
// and port number of the tunnel destination, separated by a colon (":")." — the host must be
// non-empty and the port must be all digits; anything else is not authority-form.
[[nodiscard]] inline auto is_authority_form(std::string_view target) -> bool {
    // "only the uri-host and port number" — a deprecated userinfo component
    // ("user@host:port") is not part of authority-form, so '@' is rejected anywhere
    // in the target. RFC 9113 §8.3.1 — "':authority' MUST NOT include the deprecated
    // userinfo subcomponent" — the outbound H2/H3 CONNECT value has the same shape.
    if (target.find('@') != std::string_view::npos) return false;
    auto colon = target.rfind(':');
    if (colon == std::string_view::npos || colon == 0 || colon + 1 == target.size())
        return false;
    auto host = target.substr(0, colon);
    // A ':' inside the host portion is legal only within a bracketed IPv6 literal
    // ("[::1]:443"); an unbracketed colon ("a:b:443") is not uri-host. The rfind
    // port split already finds the separator after the closing bracket; a zone id
    // ("[fe80::1%25eth0]:443") is accepted as harmless laxness.
    if (host.find(':') != std::string_view::npos &&
        (host.size() < 2 || host.front() != '[' || host.back() != ']'))
        return false;
    // RFC 3986 §3.2.3 — "port = *DIGIT" — the port has no numeric bound; any digit
    // string is valid, however long.
    return std::ranges::all_of(target.substr(colon + 1),
        [](char c) { return std::isdigit(static_cast<unsigned char>(c)) != 0; });
}

[[nodiscard]] inline auto parse_target(std::string_view target, method m) -> parsed_target {
    target = strip_fragment(target);

    // RFC 9112 §3.2.4 — "asterisk-form = "*""; "The "asterisk-form" of request-target is
    // only used for a server-wide OPTIONS request (Section 9.3.7 of [HTTP])." and
    // RFC 9110 §7.1 — "These forms MUST NOT be used with other methods." — "*" carries
    // no scheme, authority, or path components, and is rejected for any method other
    // than OPTIONS.
    if (target == "*")
        return m == method::OPTIONS
            ? parsed_target{.form = target_form::asterisk}
            : parsed_target{};

    // RFC 9112 §3.2.2 — "absolute-form = absolute-URI".
    if (auto sep = target.find("://"); sep != std::string_view::npos) {
        auto authority_start = sep + 3;
        auto path_start = target.find('/', authority_start);
        parsed_target result{.form = target_form::absolute};
        result.scheme = target.substr(0, sep);
        result.authority = target.substr(authority_start,
            path_start == std::string_view::npos
                ? std::string_view::npos
                : path_start - authority_start);
        // RFC 9110 §4.2.1 — "http-URI = \"http\" \"//\" authority path-abempty
        // [ \"?\" query ]" and "The hierarchical path component and optional query
        // component identify the target resource within that origin server's namespace."
        if (path_start == std::string_view::npos) {
            // RFC 9110 §4.2.3 — "an empty path component is equivalent to an absolute
            // path of \"/\", so the normal form is to provide a path of \"/\" instead."
            result.path = "/";
            result.path_and_query = "/";
        } else {
            result.path_and_query = target.substr(path_start);
            auto query = result.path_and_query.find('?');
            result.path = query == std::string_view::npos
                ? result.path_and_query : result.path_and_query.substr(0, query);
        }
        return result;
    }

    // RFC 9112 §3.2.3 — "The "authority-form" of request-target is only used for CONNECT
    // requests (Section 9.3.6 of [HTTP])." and RFC 9110 §7.1 — "For CONNECT (Section 9.3.6),
    // the request target is the host name and port number of the tunnel destination,
    // separated by a colon."
    if (m == method::CONNECT) {
        if (!is_authority_form(target)) return {};
        return {.form = target_form::authority, .authority = target};
    }

    // RFC 9110 §4.1 — "partial-URI = relative-part [ \"?\" query ]" and an HTTP
    // protocol element can allow "only the path and optional query components".
    if (target.empty()) return {};
    auto query = target.find('?');
    auto path = query == std::string_view::npos ? target : target.substr(0, query);
    if (path.empty()) return {};
    return {.form = target_form::origin, .path = path, .path_and_query = target};
}

// RFC 9112 §3.2.4 — "asterisk-form = "*""; "The "asterisk-form" of request-target is
// only used for a server-wide OPTIONS request (Section 9.3.7 of [HTTP])." — the
// request-target is the literal single asterisk and the method is OPTIONS.
[[nodiscard]] inline auto is_asterisk_form(const request& req) -> bool {
    auto target = parse_target(req.target, req.method);
    return target.form == target_form::asterisk;
}

} // namespace detail

inline auto request_scheme(const request& req) -> std::optional<std::string_view> {
    if (!req.scheme.empty()) return req.scheme;

    // RFC 9112 §3.2.2 — "absolute-form = absolute-URI" — only absolute-form carries a
    // scheme; origin-form, authority-form, and asterisk-form have none.
    auto target = detail::parse_target(req.target, req.method);
    if (target.form != detail::target_form::absolute) return std::nullopt;
    return target.scheme;
}

inline auto request_authority(const request& req) -> std::optional<std::string_view> {
    if (!req.authority.empty()) return req.authority;

    auto target = detail::parse_target(req.target, req.method);
    switch (target.form) {
        // RFC 9112 §3.2.2 — "When an origin server receives a request with an
        // absolute-form of request-target, the origin server MUST ignore the
        // received Host header field (if any) and instead use the host
        // information of the request-target." — the URI authority outranks Host.
        case detail::target_form::absolute:
        // RFC 9112 §3.2.3 — "authority-form = uri-host ":" port" — the validated
        // CONNECT target is itself the authority.
        case detail::target_form::authority:
            return target.authority;
        default:
            break;
    }
    if (auto host = find_header(req.fields, "host")) return *host;
    return std::nullopt;
}

inline auto request_path(const request& req) -> std::optional<std::string_view> {
    auto target = detail::parse_target(req.target, req.method);
    switch (target.form) {
        // RFC 9110 §4.2.1 — "The hierarchical path component and optional query
        // component identify the target resource" — this path-only helper deliberately
        // excludes the optional query for Cookie path matching.
        case detail::target_form::origin:
        case detail::target_form::absolute:
            return target.path;
        // RFC 9110 §7.1 — CONNECT uses host and port, while OPTIONS can use "*";
        // neither method-specific form has a path component.
        default:
            return std::nullopt;
    }
}

[[nodiscard]] inline auto request_path_and_query(const request& req)
    -> std::optional<std::string_view>
{
    auto target = detail::parse_target(req.target, req.method);
    switch (target.form) {
        // RFC 9110 §4.1 — HTTP protocol elements can contain "only the path and
        // optional query components (partial-URI)"; preserve both components so
        // distinct target resources such as /x?a and /x?b remain distinct.
        case detail::target_form::origin:
        case detail::target_form::absolute:
            return target.path_and_query;
        // RFC 9110 §7.1 — CONNECT authority-form and OPTIONS asterisk-form are
        // method-specific request targets, not path-and-query values.
        default:
            return std::nullopt;
    }
}

[[nodiscard]] inline auto request_effective_uri(const request& req)
    -> std::optional<std::string>
{
    auto scheme = request_scheme(req);
    auto authority = request_authority(req);
    auto path_and_query = request_path_and_query(req);
    if (!scheme || !authority || !path_and_query) return std::nullopt;

    // RFC 9110 §7.3.1 — "The target URI is determined from the client request's
    // request-target and Host header field". Preserve path and query as part of the
    // effective URI so distinct target resources never share a cache key.
    std::string effective;
    effective.reserve(scheme->size() + authority->size() + path_and_query->size() + 3);
    effective.append(*scheme);
    effective.append("://");
    effective.append(*authority);
    effective.append(*path_and_query);
    return effective;
}

namespace detail {

enum class request_field_error : std::uint8_t {
    unknown_method,
    missing_authority,
    missing_path,
    missing_scheme,
    malformed_connect_authority,
};

// HTTP/2 and HTTP/3 use the same HTTP field model. Produce one owned,
// pseudo-first block here; each protocol adapter only maps these strings to
// its backend descriptor type.
[[nodiscard]] inline auto make_request_field_block(const request& req)
    -> std::expected<std::vector<header>, request_field_error>
{
    // RFC 9110 §9.1 — "method = token" — every wire method is a non-empty token.
    // method::UNKNOWN represents an unparseable inbound method (RFC 9110 §9.1 —
    // "Additional methods, outside the scope of this specification, have been
    // specified for use in HTTP") and has no token to send; an outbound request
    // carrying it is refused instead of emitting an empty ":method" pseudo-header
    // field that the peer could never interpret as a method.
    if (req.method == method::UNKNOWN)
        return std::unexpected{request_field_error::unknown_method};

    auto authority = request_authority(req);
    if (!authority)
        return std::unexpected{request_field_error::missing_authority};

    // RFC 9113 §8.5 — "The ':authority' pseudo-header field contains the host and
    // port to connect to (equivalent to the authority-form of the request-target of
    // CONNECT requests; see Section 3.2.3 of [HTTP/1.1])." and RFC 9114 §4.4 — the
    // same requirement. "A CONNECT request that does not conform to these
    // restrictions is malformed." The outbound value must therefore be valid
    // authority-form; is_authority_form rejects a missing or non-numeric port, a
    // path-like suffix, and a deprecated userinfo component ("user@host:port") —
    // RFC 9113 §8.3.1 — "':authority' MUST NOT include the deprecated userinfo
    // subcomponent for 'http' or 'https' schemed URIs."
    if (req.method == method::CONNECT) {
        if (!is_authority_form(*authority))
            return std::unexpected{request_field_error::malformed_connect_authority};
    }

    auto path = request_path(req);
    auto scheme = request_scheme(req);
    if (req.method != method::CONNECT) {
        // RFC 9113 §8.3.1 — "A request in asterisk form (for OPTIONS) includes the
        // value '*' for the ':path' pseudo-header field" (RFC 9114 §4.3.1 — "An
        // OPTIONS request that does not include a path component includes the value
        // * (ASCII 0x2a) for the :path pseudo-header field") — a server-wide
        // OPTIONS has no path component, but the wire value is still the literal "*".
        if (!path && !(req.method == method::OPTIONS && is_asterisk_form(req)))
            return std::unexpected{request_field_error::missing_path};
        if (!scheme) return std::unexpected{request_field_error::missing_scheme};
    }

    std::vector<header> block;
    block.reserve(req.fields.size() + (req.method == method::CONNECT ? 2 : 4));
    block.push_back({":method", std::string(to_string(req.method))});
    if (req.method != method::CONNECT) {
        block.push_back({":scheme", std::string(*scheme)});
        block.push_back({":authority", std::string(*authority)});
        block.push_back({":path", path ? std::string(*path) : "*"});
    } else {
        block.push_back({":authority", std::string(*authority)});
    }
    for (const auto& field : req.fields) {
        if (!iequal(field.name, "host")) block.push_back(field);
    }
    return block;
}

[[nodiscard]] inline auto request_field_error_name(request_field_error error)
    -> std::string_view
{
    switch (error) {
        case request_field_error::unknown_method: return "cannot send an unknown method";
        case request_field_error::missing_authority: return "missing authority pseudo-header";
        case request_field_error::missing_path: return "missing path pseudo-header";
        case request_field_error::missing_scheme: return "missing scheme pseudo-header";
        case request_field_error::malformed_connect_authority:
            return "malformed CONNECT :authority";
    }
    return "invalid request pseudo-header state";
}

// Result of decoded_fields::append. Pseudo-fields are split out of the
// regular header list; :status is deferred to the protocol callback, which
// applies its own non-throwing/typed status parser.
enum class field_disposition : std::uint8_t {
    stored,           // regular field, or a pseudo-field captured into its member
    deferred_status,  // :status — the caller applies its own status parser
};

struct decoded_fields {
    headers regular{};
    std::string method_token{};
    std::string path{};
    std::string scheme{};
    std::string authority{};

    // Returns field_disposition::deferred_status for :status so the protocol
    // callback can apply its own non-throwing/typed status parser. Unknown
    // pseudo-fields are ignored here; nghttp2/nghttp3 validate their placement
    // and legality.
    auto append(std::string name, std::string value) -> field_disposition {
        if (name == ":status") return field_disposition::deferred_status;
        if (name == ":method") method_token = std::move(value);
        else if (name == ":path") path = std::move(value);
        else if (name == ":scheme") scheme = std::move(value);
        else if (name == ":authority") authority = std::move(value);
        else if (!name.starts_with(':')) regular.push_back({std::move(name), std::move(value)});
        return field_disposition::stored;
    }
};

} // namespace detail

// ─── Entity tags (RFC 9110 §8.8.3) ──────────────────────────

struct etag {
    std::string value;
    bool weak{false};
};

// RFC 9110 §8.8.3 — "entity-tag = [ weak ] opaque-tag" / "weak = %s\"W/\"" and
// "opaque-tag = DQUOTE *etagc DQUOTE"; "etagc = %x21 / %x23-7E / obs-text";
// "An entity tag can be either a weak or strong validator, with strong being
// the default."
inline auto parse_etag(std::string_view s) -> std::optional<etag> {
    auto weak = false;
    if (s.starts_with("W/")) {
        weak = true;
        s.remove_prefix(2);
    }
    if (s.size() < 2 || s.front() != '"' || s.back() != '"') return std::nullopt;
    auto opaque = s.substr(1, s.size() - 2);
    // RFC 9110 §8.8.3 — "etagc = %x21 / %x23-7E / obs-text; VCHAR except double
    // quotes, plus obs-text" — an embedded DQUOTE or a control octet (including
    // DEL, %x7F) inside the opaque-tag is rejected rather than tolerated.
    for (auto c : opaque) {
        auto b = static_cast<unsigned char>(c);
        if (b == 0x22 || b < 0x21 || b == 0x7f) return std::nullopt;
    }
    return etag{std::string(opaque), weak};
}

// RFC 9110 §8.8.3.2 — "Strong comparison: two entity tags are equivalent if both
// are not weak and their opaque-tags match character-by-character." — a weak tag
// never strongly matches anything; the opaque-tags must be identical.
[[nodiscard]] inline auto etag_strong_compare(const etag& a, const etag& b) -> bool {
    return !a.weak && !b.weak && a.value == b.value;
}

// RFC 9110 §8.8.3.2 — "Weak comparison: two entity tags are equivalent if their
// opaque-tags match character-by-character, regardless of either or both being
// tagged as 'weak'." — the weak flag is ignored; only the opaque-tags matter.
[[nodiscard]] inline auto etag_weak_compare(const etag& a, const etag& b) -> bool {
    return a.value == b.value;
}

// ─── Content type (RFC 9110 §8.3) ───────────────────────────

namespace detail {

// RFC 9110 §5.6.2 — "token = 1*tchar"; "tchar = '!' / '#' / '$' / '%' / '&' / '\''
// / '*' / '+' / '-' / '.' / '^' / '_' / '`' / '|' / '~' / DIGIT / ALPHA; any
// VCHAR, except delimiters".
[[nodiscard]] inline auto is_tchar(unsigned char c) -> bool {
    switch (c) {
        case '!': case '#': case '$': case '%': case '&': case '\'': case '*':
        case '+': case '-': case '.': case '^': case '_': case '`': case '|': case '~':
            return true;
        default:
            return std::isalnum(c) != 0;
    }
}

} // namespace detail

struct content_type {
    std::string type;
    std::string subtype;
    std::vector<std::pair<std::string, std::string>> parameters;
};

// RFC 9110 §8.3.1 — "media-type = type \"/\" subtype parameters" / "type = token" /
// "subtype = token"; "The type/subtype MAY be followed by semicolon-delimited
// parameters (Section 5.6.6) in the form of name/value pairs."
inline auto parse_content_type(std::string_view s) -> std::optional<content_type> {
    auto slash = s.find('/');
    if (slash == std::string_view::npos) return std::nullopt;
    auto semi = s.find(';');
    auto media = (semi != std::string_view::npos) ? s.substr(0, semi) : s;
    auto type = media.substr(0, slash);
    auto subtype = media.substr(slash + 1);
    while (!subtype.empty() && subtype.back() == ' ') subtype.remove_suffix(1);
    // RFC 9110 §8.3.1 — "The type and subtype tokens are case-insensitive." and
    // RFC 9110 §5.6.2 — "token = 1*tchar" — an empty or non-token type/subtype
    // (e.g. embedded whitespace) is rejected instead of parsed loosely.
    if (type.empty() || subtype.empty()) return std::nullopt;
    if (!std::ranges::all_of(type, detail::is_tchar) ||
        !std::ranges::all_of(subtype, detail::is_tchar))
        return std::nullopt;
    content_type ct;
    ct.type = std::string(type);
    ct.subtype = std::string(subtype);
    if (semi != std::string_view::npos) {
        // RFC 9110 §5.6.6 — "parameter = parameter-name "=" parameter-value" /
        // "parameter-name = token" / "parameter-value = token / quoted-string" —
        // every segment must carry a name/value pair; a bare name, a non-token
        // name, or a non-token unquoted value is rejected instead of dropped.
        auto rest = s.substr(semi + 1);
        while (!rest.empty()) {
            while (!rest.empty() && rest.front() == ' ') rest.remove_prefix(1);
            if (rest.empty()) break;
            auto eq = rest.find('=');
            if (eq == std::string_view::npos) return std::nullopt;
            auto name = rest.substr(0, eq);
            if (name.empty() || !std::ranges::all_of(name, detail::is_tchar))
                return std::nullopt;
            rest.remove_prefix(eq + 1);
            std::string value;
            if (rest.starts_with('"')) {
                // RFC 9110 §5.6.4 — "quoted-string = DQUOTE *( qdtext /
                // quoted-pair ) DQUOTE" / "quoted-pair = "\" ( HTAB / SP /
                // VCHAR / obs-text )" — inside a quoted-string ';' does not
                // delimit the next parameter, and a quoted-pair contributes
                // its escaped octet to the value; an unterminated
                // quoted-string is malformed.
                rest.remove_prefix(1);
                auto closed = false;
                while (!rest.empty() && !closed) {
                    auto c = rest.front();
                    rest.remove_prefix(1);
                    if (c == '"') {
                        closed = true;
                    } else if (c == '\\') {
                        if (rest.empty()) return std::nullopt;
                        value.push_back(rest.front());
                        rest.remove_prefix(1);
                    } else {
                        value.push_back(c);
                    }
                }
                if (!closed) return std::nullopt;
                while (!rest.empty() && rest.front() == ' ') rest.remove_prefix(1);
                if (!rest.empty() && rest.front() != ';') return std::nullopt;
            } else {
                auto next = rest.find(';');
                auto val = next == std::string_view::npos ? rest : rest.substr(0, next);
                while (!val.empty() && val.back() == ' ') val.remove_suffix(1);
                if (val.empty() || !std::ranges::all_of(val, detail::is_tchar))
                    return std::nullopt;
                value = std::string(val);
                if (next == std::string_view::npos) rest = {};
                else rest.remove_prefix(next);
            }
            ct.parameters.emplace_back(std::string(name), std::move(value));
            if (!rest.empty()) rest.remove_prefix(1); // the ';' delimiter
        }
    }
    return ct;
}

} // namespace http
