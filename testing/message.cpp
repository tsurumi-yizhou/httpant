#include <boost/ut.hpp>

#include "test_support.hpp"

namespace httpant::testing {

using namespace boost::ut;
using namespace std::literals;

static suite<"message"> message_suite = [] {
    "http_message_types"_test = [] {
        // RFC 9110 §6.2 — "Request message control data includes a request
        // method (Section 9), request target (Section 7.1), and protocol
        // version"; RFC 9110 §5.1 — "Field names are case-insensitive".
        http::request req{
            .method = http::method::GET,
            .target = "/hello",
            .fields = {{"host", "example.com"}},
        };

        expect(http::to_string(req.method) == "GET"sv);
        expect(req.target == "/hello"sv);

        auto host = http::find_header(req.fields, "Host");
        expect(host.has_value());
        expect(*host == "example.com"sv);
    };

    "http_method_roundtrip"_test = [] {
        // RFC 9110 §9.1 — "method = token"; "By convention, standardized methods
        // are defined in all-uppercase US-ASCII letters." — each method token
        // round-trips through to_string / try_from_string.
        for (auto method : {http::method::GET, http::method::HEAD, http::method::POST,
                            http::method::PUT, http::method::DELETE_, http::method::CONNECT,
                            http::method::OPTIONS, http::method::TRACE, http::method::PATCH}) {
            auto token = http::to_string(method);
            auto parsed = http::try_from_string(token);
            expect(parsed.has_value());
            expect(*parsed == method);
        }
    };

    "header_lookup_is_case_insensitive"_test = [] {
        // RFC 9110 §5.1 — "Field names are case-insensitive and ought to be
        // registered within the "Hypertext Transfer Protocol (HTTP) Field Name
        // Registry"" — lookups match regardless of case.
        http::headers fields{{"Cache-Control", "max-age=60"}, {"Set-Cookie", "a=b"}};

        auto cache_control = http::find_header(fields, "cache-control");
        auto set_cookie = http::find_header(fields, "set-cookie");

        expect(cache_control.has_value());
        expect(*cache_control == "max-age=60"sv);
        expect(set_cookie.has_value());
        expect(*set_cookie == "a=b"sv);
    };

    "response_reason_phrase_defaults"_test = [] {
        // RFC 9110 §15.1 — "The reason phrases listed here are only
        // recommendations -- they can be replaced by local equivalents or left
        // out altogether without affecting the protocol." — an empty reason
        // phrase serializes with the recommended default ("Not Found" for 404).
        http::response response{
            .status = 404,
            .reason = {},
            .fields = {},
        };

        auto serialized = bytes_to_string(run_sync(http::v1::serialize(response)));
        expect(serialized.starts_with("HTTP/1.1 404 Not Found\r\n"sv));
    };

    "parse_etag_accepts_valid_tags"_test = [] {
        // RFC 9110 §8.8.3 — "entity-tag = [ weak ] opaque-tag" / "opaque-tag =
        // DQUOTE *etagc DQUOTE"; examples "ETag: \"xyzzy\"", "ETag: W/\"xyzzy\"",
        // "ETag: \"\"".
        auto strong = http::parse_etag(R"("xyzzy")");
        expect(strong.has_value());
        expect(strong->value == "xyzzy"sv);
        expect(!strong->weak);

        auto weak = http::parse_etag(R"(W/"xyzzy")");
        expect(weak.has_value());
        expect(weak->value == "xyzzy"sv);
        expect(weak->weak);

        auto empty = http::parse_etag(R"("")");
        expect(empty.has_value());
        expect(empty->value.empty());
    };

    "parse_etag_rejects_invalid_opaque_tag_chars"_test = [] {
        // RFC 9110 §8.8.3 — "etagc = %x21 / %x23-7E / obs-text; VCHAR except double
        // quotes, plus obs-text" — an embedded DQUOTE or a control octet inside the
        // opaque-tag is rejected.
        expect(!http::parse_etag(R"("a"b")").has_value());        // embedded DQUOTE
        expect(!http::parse_etag("W/\"a\x01b\"").has_value()); // control char
        expect(!http::parse_etag("\"a\x7f" "b\"").has_value()); // DEL
        expect(!http::parse_etag(R"(W/"a"b")").has_value());      // embedded DQUOTE, weak
        expect(!http::parse_etag("\"abc").has_value());           // missing closing quote
        expect(!http::parse_etag("abc\"").has_value());           // missing opening quote
        expect(!http::parse_etag("W/abc").has_value());           // no DQUOTE at all
    };

    "parse_etag_accepts_obs_text"_test = [] {
        // RFC 9110 §8.8.3 — "etagc = %x21 / %x23-7E / obs-text" — high octets are
        // allowed inside the opaque-tag.
        auto tag = http::parse_etag("\"a\xc3\xa9" "b\"");
        expect(tag.has_value());
        expect(tag->value == "a\xc3\xa9" "b"sv);
    };

    "parse_content_type_accepts_valid_media_types"_test = [] {
        auto ct = http::parse_content_type("text/html; charset=utf-8");
        expect(ct.has_value());
        expect(ct->type == "text"sv);
        expect(ct->subtype == "html"sv);
        expect(ct->parameters.size() == 1_u);
        expect(ct->parameters[0].first == "charset"sv);
        expect(ct->parameters[0].second == "utf-8"sv);

        // RFC 9110 §8.3.1 — "The type and subtype tokens are case-insensitive."
        auto upper = http::parse_content_type("Text/HTML");
        expect(upper.has_value());
        expect(upper->type == "Text"sv);
        expect(upper->subtype == "HTML"sv);

        auto no_params = http::parse_content_type("application/octet-stream");
        expect(no_params.has_value());
        expect(no_params->parameters.empty());
    };

    "parse_content_type_rejects_empty_or_non_token_type_subtype"_test = [] {
        // RFC 9110 §8.3.1 — "type = token" / "subtype = token" and RFC 9110 §5.6.2
        // — "token = 1*tchar" — empty or non-token components are rejected.
        expect(!http::parse_content_type("text/").has_value());       // empty subtype
        expect(!http::parse_content_type("/html").has_value());       // empty type
        expect(!http::parse_content_type("text /html").has_value());  // space in type
        expect(!http::parse_content_type("text/ht ml").has_value());  // space in subtype
        expect(!http::parse_content_type("").has_value());            // no slash
        expect(!http::parse_content_type("text").has_value());        // no slash
    };

    "parse_content_type_accepts_quoted_string_parameters"_test = [] {
        // RFC 9110 §5.6.6 — "parameter-value = token / quoted-string" — a
        // quoted-string value keeps its ';' (RFC 9110 §5.6.4 — "quoted-string
        // = DQUOTE *( qdtext / quoted-pair ) DQUOTE"), so it does not split
        // into a second parameter.
        auto ct = http::parse_content_type(R"(multipart/form-data; boundary="a;b")");
        expect(ct.has_value());
        expect(ct->type == "multipart"sv);
        expect(ct->subtype == "form-data"sv);
        expect(ct->parameters.size() == 1_u);
        expect(ct->parameters[0].first == "boundary"sv);
        expect(ct->parameters[0].second == "a;b"sv);

        // A quoted parameter may be followed by further parameters.
        auto multi = http::parse_content_type(R"(text/html; x="a;b"; charset=utf-8)");
        expect(multi.has_value());
        expect(multi->parameters.size() == 2_u);
        expect(multi->parameters[0].second == "a;b"sv);
        expect(multi->parameters[1].first == "charset"sv);
        expect(multi->parameters[1].second == "utf-8"sv);
    };

    "parse_content_type_unescapes_quoted_pairs"_test = [] {
        // RFC 9110 §5.6.4 — "quoted-pair = "\" ( HTAB / SP / VCHAR / obs-text )"
        // — "A sender that generates a quoted-pair ... MUST NOT generate a
        // quoted-pair ... unless ... necessary"; "Recipients that process
        // quoted-strings ... handle the quoted-pair ... as if it were replaced
        // by the octet following the backslash." — the backslash is consumed
        // and the escaped octet lands in the value.
        auto ct = http::parse_content_type(R"(text/plain; x="a\"b\\c")");
        expect(ct.has_value());
        expect(ct->parameters.size() == 1_u);
        expect(ct->parameters[0].first == "x"sv);
        expect(ct->parameters[0].second == "a\"b\\c"sv);
    };

    "parse_content_type_rejects_malformed_parameters"_test = [] {
        // RFC 9110 §5.6.6 — "parameter = parameter-name "=" parameter-value" —
        // a segment without "=" is not a parameter and is rejected rather than
        // silently dropped.
        expect(!http::parse_content_type("text/html; charset").has_value());
        // RFC 9110 §5.6.6 — "parameter-name = token" — a name containing a
        // non-tchar (here SP) is not a valid parameter name.
        expect(!http::parse_content_type("text/html; char set=utf-8").has_value());
        // RFC 9110 §5.6.4 — "quoted-string = DQUOTE *( qdtext / quoted-pair )
        // DQUOTE" — an unterminated quoted-string has no closing DQUOTE and is
        // rejected.
        expect(!http::parse_content_type(R"(text/html; x="abc)").has_value());
        expect(!http::parse_content_type(R"(text/html; x="abc\)").has_value());
    };

    "request_target_origin_form_strips_query_and_fragment"_test = [] {
        // RFC 9112 §3.2.1 — "origin-form = absolute-path [ "?" query ]" and
        // RFC 9110 §7.1 — "The target URI excludes the reference's fragment component"
        // — the path excludes both the query and the fragment.
        http::request req{.method = http::method::GET, .target = "/a/b?x=1#frag"};

        auto path = http::request_path(req);
        auto path_and_query = http::request_path_and_query(req);
        expect(path.has_value());
        expect(*path == "/a/b"sv);
        expect(path_and_query.has_value());
        // RFC 9110 §4.1 — a partial-URI contains "only the path and optional query
        // components"; RFC 9110 §7.1 — "The target URI excludes the reference's
        // fragment component" — preserve the query but exclude the fragment.
        expect(*path_and_query == "/a/b?x=1"sv);
        expect(!http::request_scheme(req).has_value());
    };

    "request_target_absolute_form_splits_components"_test = [] {
        // RFC 9112 §3.2.2 — "absolute-form = absolute-URI" — scheme and authority come
        // from the URI; the path excludes query and fragment (RFC 9110 §7.1).
        http::request req{.method = http::method::GET, .target = "http://example.com/p?q#f"};

        auto scheme = http::request_scheme(req);
        auto authority = http::request_authority(req);
        auto path = http::request_path(req);
        auto path_and_query = http::request_path_and_query(req);
        expect(scheme.has_value());
        expect(*scheme == "http"sv);
        expect(authority.has_value());
        expect(*authority == "example.com"sv);
        expect(path.has_value());
        expect(*path == "/p"sv);
        expect(path_and_query.has_value());
        // RFC 9110 §4.2.1 — "The hierarchical path component and optional query
        // component identify the target resource within that origin server's namespace."
        expect(*path_and_query == "/p?q"sv);
    };

    "request_target_absolute_form_ignores_host_header"_test = [] {
        // RFC 9112 §3.2.2 — "When an origin server receives a request with an
        // absolute-form of request-target, the origin server MUST ignore the
        // received Host header field (if any) and instead use the host
        // information of the request-target." — a conflicting Host header can
        // neither change the authority nor poison the effective URI.
        http::request req{
            .method = http::method::GET,
            .target = "http://target.example/p?q=1",
            .fields = {{"host", "poisoned.example"}},
        };

        auto authority = http::request_authority(req);
        expect(authority.has_value());
        expect(*authority == "target.example"sv);
        auto uri = http::request_effective_uri(req);
        expect(uri.has_value());
        expect(*uri == "http://target.example/p?q=1"sv);

        // RFC 9112 §3.2.3 — "authority-form = uri-host ":" port" — the CONNECT
        // target is itself the authority and likewise outranks the Host header.
        http::request connect{
            .method = http::method::CONNECT,
            .target = "tunnel.example:443",
            .fields = {{"host", "poisoned.example"}},
        };
        expect(http::request_authority(connect) == "tunnel.example:443"sv);

        // Origin-form still takes its authority from the Host header field.
        // RFC 9112 §3.2.1 — "origin-form = absolute-path [ "?" query ]".
        http::request origin{
            .method = http::method::GET,
            .target = "/p",
            .fields = {{"host", "host.example"}},
        };
        expect(http::request_authority(origin) == "host.example"sv);
    };

    "request_target_asterisk_form_has_no_components"_test = [] {
        // RFC 9112 §3.2.4 — "asterisk-form = "*"" and RFC 9110 §7.1 — "For OPTIONS
        // (Section 9.3.7), the request target can be a single asterisk ("*")." —
        // "*" is not a path and carries no scheme or authority.
        http::request req{.method = http::method::OPTIONS, .target = "*"};

        expect(!http::request_path(req).has_value());
        expect(!http::request_scheme(req).has_value());
        expect(!http::request_authority(req).has_value());
    };

    "request_target_authority_form_validates_host_port"_test = [] {
        // RFC 9112 §3.2.3 — "authority-form = uri-host ":" port"; RFC 9110 §7.1 —
        // "For CONNECT (Section 9.3.6), the request target is the host name and port
        // number of the tunnel destination, separated by a colon."
        http::request req{.method = http::method::CONNECT, .target = "example.com:443"};

        auto authority = http::request_authority(req);
        expect(authority.has_value());
        expect(*authority == "example.com:443"sv);
        expect(!http::request_path(req).has_value());

        // Missing port or a non-numeric port is not authority-form.
        http::request no_port{.method = http::method::CONNECT, .target = "example.com"};
        expect(!http::request_authority(no_port).has_value());
        http::request bad_port{.method = http::method::CONNECT, .target = "example.com:abc"};
        expect(!http::request_authority(bad_port).has_value());
    };

    "request_target_asterisk_form_rejected_for_non_options"_test = [] {
        // RFC 9110 §7.1 — "These forms MUST NOT be used with other methods."
        // (referring to the CONNECT authority-form and OPTIONS asterisk-form) and
        // RFC 9112 §3.2.4 — "The "asterisk-form" of request-target is only used
        // for a server-wide OPTIONS request" — "*" is not a valid request target
        // for any method other than OPTIONS: it must not yield a path, authority,
        // scheme, or effective URI.
        for (auto m : {http::method::GET, http::method::HEAD, http::method::POST,
                       http::method::PUT, http::method::DELETE_, http::method::CONNECT,
                       http::method::TRACE, http::method::PATCH}) {
            http::request req{.method = m, .target = "*"};
            expect(!http::request_path(req).has_value());
            expect(!http::request_path_and_query(req).has_value());
            expect(!http::request_scheme(req).has_value());
            expect(!http::request_authority(req).has_value());
            expect(!http::request_effective_uri(req).has_value());
        }
        // RFC 9112 §3.2.4 — asterisk-form remains legal for a server-wide OPTIONS.
        http::request options{.method = http::method::OPTIONS, .target = "*"};
        expect(!http::request_path(options).has_value());
        expect(!http::request_scheme(options).has_value());
    };

    "etag_comparison_functions"_test = [] {
        // RFC 9110 §8.8.3.2 — "Strong comparison: two entity tags are equivalent
        // if both are not weak and their opaque-tags match character-by-character."
        // and "Weak comparison: two entity tags are equivalent if their opaque-tags
        // match character-by-character, regardless of either or both being tagged
        // as 'weak'." — the table below reproduces the RFC's own Table 3 results.
        auto tag = [](std::string_view text) { return *http::parse_etag(text); };

        // ETag 1: W/"1" | ETag 2: W/"1" | strong: no | weak: yes
        auto w1 = tag(R"(W/"1")");
        expect(!http::etag_strong_compare(w1, tag(R"(W/"1")")));
        expect(http::etag_weak_compare(w1, tag(R"(W/"1")")));

        // ETag 1: W/"1" | ETag 2: W/"2" | strong: no | weak: no
        expect(!http::etag_strong_compare(w1, tag(R"(W/"2")")));
        expect(!http::etag_weak_compare(w1, tag(R"(W/"2")")));

        // ETag 1: W/"1" | ETag 2: "1" | strong: no | weak: yes
        auto s1 = tag(R"("1")");
        expect(!http::etag_strong_compare(w1, s1));
        expect(http::etag_weak_compare(w1, s1));

        // ETag 1: "1" | ETag 2: "1" | strong: yes | weak: yes
        expect(http::etag_strong_compare(s1, tag(R"("1")")));
        expect(http::etag_weak_compare(s1, tag(R"("1")")));

        // Identical opaque-tag, different weak markers, must differ strongly.
        expect(!http::etag_strong_compare(s1, w1));
        expect(http::etag_weak_compare(s1, w1));

        // Character-by-character: distinct opaque-tags never match either way.
        expect(!http::etag_weak_compare(tag(R"("abc")"), tag(R"("abd")")));
        // Same opaque-tag under a weak marker still matches weakly.
        expect(http::etag_weak_compare(tag(R"("abc")"), tag(R"(W/"abc")")));
    };

    "options_asterisk_form_maps_to_path_star"_test = [] {
        // RFC 9113 §8.3.1 — "A request in asterisk form (for OPTIONS) includes
        // the value '*' for the ':path' pseudo-header field" and RFC 9114 §4.3.1 —
        // "An OPTIONS request that does not include a path component includes the
        // value * (ASCII 0x2a) for the :path pseudo-header field; see Section 7.1
        // of [HTTP]" — a server-wide OPTIONS * must serialize to :path: * instead
        // of failing the shared HTTP/2 and HTTP/3 field block construction.
        http::request req{
            .method = http::method::OPTIONS,
            .target = "*",
            .scheme = "https",
            .authority = "example.com",
        };
        auto block = http::detail::make_request_field_block(req);
        expect(block.has_value());
        auto field = [&](std::string_view name) -> std::string {
            for (auto& h : *block)
                if (http::iequal(h.name, name)) return h.value;
            return {};
        };
        expect(field(":method") == "OPTIONS"sv);
        expect(field(":scheme") == "https"sv);
        expect(field(":authority") == "example.com"sv);
        expect(field(":path") == "*"sv);
        // RFC 9113 §8.3.1 — "All HTTP/2 requests MUST include exactly one valid
        // value for the ':method', ':scheme', and ':path' pseudo-header fields" —
        // an asterisk-form OPTIONS still requires an explicit scheme.
        http::request no_scheme{.method = http::method::OPTIONS, .target = "*"};
        expect(!http::detail::make_request_field_block(no_scheme).has_value());
    };

    "connect_authority_validated_as_authority_form"_test = [] {
        // RFC 9113 §8.5 — "The ':authority' pseudo-header field contains the host
        // and port to connect to (equivalent to the authority-form of the
        // request-target of CONNECT requests; see Section 3.2.3 of [HTTP/1.1])"
        // and "A CONNECT request that does not conform to these restrictions is
        // malformed (Section 8.1.1)" — the shared HTTP/2/3 field block rejects an
        // outbound CONNECT :authority that is not valid authority-form.
        http::request valid{
            .method = http::method::CONNECT,
            .target = "example.com:443",
        };
        auto block = http::detail::make_request_field_block(valid);
        expect(block.has_value());
        bool has_authority = false, has_path = false, has_scheme = false;
        for (auto& h : *block) {
            if (h.name == ":authority" && h.value == "example.com:443") has_authority = true;
            if (h.name == ":path") has_path = true;
            if (h.name == ":scheme") has_scheme = true;
        }
        expect(has_authority);
        // RFC 9113 §8.5 — "The ':scheme' and ':path' pseudo-header fields MUST be
        // omitted" for CONNECT.
        expect(!has_path);
        expect(!has_scheme);

        // RFC 9112 §3.2.3 — "authority-form = uri-host ":" port" — a missing port
        // or a non-numeric port is not authority-form.
        http::request no_port{
            .method = http::method::CONNECT,
            .authority = "example.com",
        };
        expect(http::detail::make_request_field_block(no_port).error() ==
               http::detail::request_field_error::malformed_connect_authority);
        http::request bad_port{
            .method = http::method::CONNECT,
            .authority = "example.com:abc",
        };
        expect(http::detail::make_request_field_block(bad_port).error() ==
               http::detail::request_field_error::malformed_connect_authority);

        // RFC 9113 §8.3.1 — "':authority' MUST NOT include the deprecated userinfo
        // subcomponent for 'http' or 'https' schemed URIs." — user@host:port is
        // rejected rather than emitted.
        http::request userinfo{
            .method = http::method::CONNECT,
            .authority = "user@example.com:443",
        };
        expect(http::detail::make_request_field_block(userinfo).error() ==
               http::detail::request_field_error::malformed_connect_authority);

        // RFC 9112 §3.2.3 — "authority-form = uri-host ":" port" — a colon inside
        // an unbracketed host ("a:b:443") is not uri-host, so the value is not
        // authority-form.
        http::request unbracketed_colon{
            .method = http::method::CONNECT,
            .authority = "a:b:443",
        };
        expect(http::detail::make_request_field_block(unbracketed_colon).error() ==
               http::detail::request_field_error::malformed_connect_authority);

        // RFC 9112 §3.2.3 — "authority-form = uri-host ":" port"; RFC 3986 §3.2.2 —
        // "IP-literal = "[" ( IPv6address / IPvFuture ) "]" — a bracketed IPv6
        // literal is valid uri-host; the port split happens after the closing
        // bracket.
        http::request ipv6{
            .method = http::method::CONNECT,
            .authority = "[::1]:443",
        };
        auto ipv6_block = http::detail::make_request_field_block(ipv6);
        expect(ipv6_block.has_value());
        bool ipv6_authority = false;
        for (auto& h : *ipv6_block)
            if (h.name == ":authority" && h.value == "[::1]:443") ipv6_authority = true;
        expect(ipv6_authority);
    };

    // RFC 9110 §9.1 — "method = token" — every wire method is a non-empty
    // token. method::UNKNOWN represents an unparseable inbound method (RFC 9110
    // §9.1 — "Additional methods, outside the scope of this specification, have
    // been specified for use in HTTP") and has no token of its own: the shared
    // HTTP/2/3 field block refuses to emit an empty ":method" pseudo-header
    // field for it instead of shipping a field the peer could never interpret.
    "unknown_method_rejected_by_request_field_block"_test = [] {
        http::request req{
            .method = http::method::UNKNOWN,
            .target = "/",
            .scheme = "https",
            .authority = "example.com",
            .fields = {{"host", "example.com"}},
        };
        auto block = http::detail::make_request_field_block(req);
        expect(!block.has_value());
        expect(block.error() == http::detail::request_field_error::unknown_method);
    };

    "combined_header_joins_field_lines_with_comma_sp"_test = [] {
        // RFC 9110 §5.3 — "A recipient MAY combine multiple field lines within a field
        // section that have the same field name into one field line ... separated by a
        // comma (",") and optional whitespace ... For consistency, use comma SP."
        http::headers fields{{"Via", "1.1 a"}, {"Host", "example.com"}, {"Via", "1.0 b"}};

        auto via = http::combined_header(fields, "via");
        expect(via.has_value());
        expect(*via == "1.1 a, 1.0 b"sv);

        auto host = http::combined_header(fields, "host");
        expect(host.has_value());
        expect(*host == "example.com"sv);

        expect(!http::combined_header(fields, "accept").has_value());
    };
};

} // namespace httpant::testing
