module;

#include <algorithm>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <expected>
#include <functional>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

export module httpant:caching;

import :message;

namespace http::detail {

[[nodiscard]] inline auto trim_cache_ows(std::string_view value) -> std::string_view {
    while (!value.empty() && (value.front() == ' ' || value.front() == '\t'))
        value.remove_prefix(1);
    while (!value.empty() && (value.back() == ' ' || value.back() == '\t'))
        value.remove_suffix(1);
    return value;
}

[[nodiscard]] inline auto normalize_field_value(std::string_view value) -> std::string {
    std::string out;
    bool first = true;
    while (!value.empty()) {
        while (!value.empty() && (value.front() == ' ' || value.front() == '\t'))
            value.remove_prefix(1);
        auto end = value.find(',');
        auto item = trim_cache_ows(
            end == std::string_view::npos ? value : value.substr(0, end));
        value = end == std::string_view::npos ? std::string_view{} : value.substr(end + 1);
        if (item.empty()) continue;
        if (!first) out += ", ";
        out.append(item);
        first = false;
    }
    return out;
}

// RFC 9111 §4.1 — "The header fields from two requests are defined to match if
// and only if those in the first request can be transformed to those in the
// second request by applying any of the following: ... combining multiple
// header field lines with the same field name (see Section 5.2 of [HTTP])" —
// returns nullopt when the field is absent entirely, so that absence can be
// told apart from a present-but-empty value.
[[nodiscard]] inline auto normalized_selecting_field(
    const headers& fields, std::string_view name) -> std::optional<std::string>
{
    auto lines = find_all_headers(fields, name);
    if (lines.empty()) return std::nullopt;
    std::string combined;
    for (auto line : lines) {
        auto normalized = normalize_field_value(line);
        if (normalized.empty()) continue;
        if (!combined.empty()) combined += ", ";
        combined += normalized;
    }
    return combined;
}

[[nodiscard]] inline auto parse_2digit(std::string_view value) -> std::optional<unsigned> {
    if (value.size() < 2 || value[0] < '0' || value[0] > '9' ||
        value[1] < '0' || value[1] > '9')
        return std::nullopt;
    return static_cast<unsigned>(value[0] - '0') * 10u +
           static_cast<unsigned>(value[1] - '0');
}

[[nodiscard]] inline auto parse_4digit(std::string_view value) -> std::optional<int> {
    if (value.size() < 4) return std::nullopt;
    int result = 0;
    for (char character : value.substr(0, 4)) {
        if (character < '0' || character > '9') return std::nullopt;
        result = result * 10 + (character - '0');
    }
    return result;
}

[[nodiscard]] inline auto parse_month_name(std::string_view value)
    -> std::optional<std::chrono::month>
{
    // RFC 9111 §4.2 — "Although all date formats are specified to be
    // case-sensitive, a cache recipient SHOULD match the field value
    // case-insensitively." — month names are matched without regard to case.
    static constexpr std::string_view names[]{
        "Jan", "Feb", "Mar", "Apr", "May", "Jun",
        "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
    for (std::size_t index = 0; index < std::size(names); ++index)
        if (iequal(value, names[index]))
            return std::chrono::month{static_cast<unsigned>(index + 1)};
    return std::nullopt;
}

[[nodiscard]] inline auto parse_time_of_day(std::string_view value)
    -> std::optional<std::chrono::seconds>
{
    using namespace std::chrono;
    if (value.size() < 8 || value[2] != ':' || value[5] != ':') return std::nullopt;
    auto hour = parse_2digit(value.substr(0, 2));
    auto minute = parse_2digit(value.substr(3, 2));
    auto second = parse_2digit(value.substr(6, 2));
    if (!hour || !minute || !second || *hour > 23 || *minute > 59 || *second > 60)
        return std::nullopt;
    // RFC 9110 §5.6.7 — "time-of-day = hour ":" minute ":" second
    // ; 00:00:00 - 23:59:60 (leap second)" — the grammar admits a leap-second
    // value of 60, which the civil-time model of std::chrono cannot
    // represent; it is clamped to the last representable second of the minute.
    return hours{*hour} + minutes{*minute} + seconds{std::min(*second, 59u)};
}

[[nodiscard]] inline auto make_time_point(
    int year,
    std::chrono::month month,
    unsigned day,
    std::chrono::seconds time_of_day)
    -> std::optional<std::chrono::system_clock::time_point>
{
    std::chrono::year_month_day date{
        std::chrono::year{year}, month, std::chrono::day{day}};
    if (!date.ok()) return std::nullopt;
    return std::chrono::sys_days{date} + time_of_day;
}

[[nodiscard]] inline auto parse_imf_fixdate(std::string_view value)
    -> std::optional<std::chrono::system_clock::time_point>
{
    if (value.size() != 29 || value[3] != ',' || value[4] != ' ' || value[7] != ' ' ||
        value[11] != ' ' || value[16] != ' ' || value[25] != ' ' ||
        !iequal(value.substr(26), "GMT"))
        return std::nullopt;
    auto day = parse_2digit(value.substr(5, 2));
    auto month = parse_month_name(value.substr(8, 3));
    auto year = parse_4digit(value.substr(12, 4));
    auto time = parse_time_of_day(value.substr(17, 8));
    if (!day || !month || !year || !time) return std::nullopt;
    return make_time_point(*year, *month, *day, *time);
}

[[nodiscard]] inline auto parse_rfc850_date(
    std::string_view value,
    std::chrono::system_clock::time_point reference_time)
    -> std::optional<std::chrono::system_clock::time_point>
{
    auto comma = value.find(',');
    if (comma == std::string_view::npos) return std::nullopt;
    auto rest = value.substr(comma + 1);
    if (rest.size() != 23 || rest[0] != ' ' || rest[3] != '-' || rest[7] != '-' ||
        rest[10] != ' ' || rest[19] != ' ' || !iequal(rest.substr(20), "GMT"))
        return std::nullopt;
    auto day = parse_2digit(rest.substr(1, 2));
    auto month = parse_month_name(rest.substr(4, 3));
    auto short_year = parse_2digit(rest.substr(8, 2));
    auto time = parse_time_of_day(rest.substr(11, 8));
    if (!day || !month || !short_year || !time) return std::nullopt;

    // RFC 9110 §5.6.7 — a year more than 50 years in the future denotes the
    // most recent past year with the same final two digits. The caller supplies
    // the reference instant so parsing is deterministic.
    auto reference_date = std::chrono::year_month_day{
        std::chrono::floor<std::chrono::days>(reference_time)};
    auto reference_year = static_cast<int>(reference_date.year());
    auto year = (reference_year / 100) * 100 + static_cast<int>(*short_year);
    if (year > reference_year + 50) year -= 100;
    return make_time_point(year, *month, *day, *time);
}

[[nodiscard]] inline auto parse_asctime_date(std::string_view value)
    -> std::optional<std::chrono::system_clock::time_point>
{
    if (value.size() != 24 || value[3] != ' ' || value[7] != ' ' ||
        value[10] != ' ' || value[19] != ' ')
        return std::nullopt;
    auto month = parse_month_name(value.substr(4, 3));
    std::optional<unsigned> day;
    if (value[8] == ' ') {
        if (value[9] < '0' || value[9] > '9') return std::nullopt;
        day = static_cast<unsigned>(value[9] - '0');
    } else {
        day = parse_2digit(value.substr(8, 2));
    }
    auto time = parse_time_of_day(value.substr(11, 8));
    auto year = parse_4digit(value.substr(20, 4));
    if (!month || !day || !time || !year) return std::nullopt;
    return make_time_point(*year, *month, *day, *time);
}

[[nodiscard]] inline auto parse_http_date(
    std::string_view value,
    std::chrono::system_clock::time_point reference_time)
    -> std::optional<std::chrono::system_clock::time_point>
{
    value = trim_cache_ows(value);
    if (auto parsed = parse_imf_fixdate(value)) return parsed;
    if (auto parsed = parse_rfc850_date(value, reference_time)) return parsed;
    return parse_asctime_date(value);
}

[[nodiscard]] inline auto date_value(
    const headers& fields,
    std::chrono::system_clock::time_point received)
    -> std::chrono::system_clock::time_point
{
    if (auto date = find_header(fields, "date"))
        if (auto parsed = parse_http_date(*date, received)) return *parsed;
    return received;
}

[[nodiscard]] inline auto parse_delta(std::string_view value)
    -> std::optional<std::chrono::seconds>
{
    value = trim_cache_ows(value);
    if (value.size() >= 2 && value.front() == '"' && value.back() == '"')
        value = value.substr(1, value.size() - 2);
    std::uint32_t delta = 0;
    auto [end, error] = std::from_chars(value.data(), value.data() + value.size(), delta);
    // RFC 9111 §1.2.2 — "delta-seconds = 1*DIGIT"; "If a cache receives a
    // delta-seconds value greater than the greatest integer it can represent,
    // or if any of its subsequent calculations overflows, the cache MUST
    // consider the value to be 2147483648 (2^31) or the greatest positive
    // integer it can conveniently represent." — a fully numeric value beyond
    // uint32_t clamps to its maximum instead of being dropped as malformed.
    if (error == std::errc::result_out_of_range &&
        end == value.data() + value.size())
        return std::chrono::seconds{std::numeric_limits<std::uint32_t>::max()};
    if (error != std::errc{} || end != value.data() + value.size()) return std::nullopt;
    return std::chrono::seconds{delta};
}

template <typename Function>
void for_each_cache_directive(const headers& fields, Function&& function) {
    for (auto line : find_all_headers(fields, "cache-control")) {
        while (!line.empty()) {
            // RFC 9111 §5.2 — "cache-directive = token [ "=" ( token /
            // quoted-string ) ]" — a directive argument may be a quoted
            // string, and RFC 9110 §5.6.4 — "quoted-string = DQUOTE *( qdtext
            // / quoted-pair ) DQUOTE" with "quoted-pair = "\" ( HTAB / SP /
            // VCHAR / obs-text )" — allows a comma inside it (e.g.
            // private="Set-Cookie, Authorization"), so the separator scan
            // skips DQUOTE-delimited regions and backslash escapes.
            std::size_t comma = std::string_view::npos;
            bool quoted = false;
            for (std::size_t index = 0; index < line.size(); ++index) {
                if (quoted && line[index] == '\\') {
                    ++index;  // quoted-pair: the escaped character is data
                    continue;
                }
                if (line[index] == '"') quoted = !quoted;
                else if (line[index] == ',' && !quoted) {
                    comma = index;
                    break;
                }
            }
            auto item = comma == std::string_view::npos ? line : line.substr(0, comma);
            line = comma == std::string_view::npos ? std::string_view{} : line.substr(comma + 1);
            item = trim_cache_ows(item);
            if (item.empty()) continue;
            auto equal = item.find('=');
            auto name = equal == std::string_view::npos ? item : item.substr(0, equal);
            name = trim_cache_ows(name);
            auto argument = equal == std::string_view::npos
                ? std::optional<std::string_view>{}
                : std::optional<std::string_view>{item.substr(equal + 1)};
            std::invoke(function, name, argument);
        }
    }
}

// RFC 9111 §4.3.4 — a 304 updates a stored response only when the
// validators of the two correspond under the first-match rule: strong
// validators in the 304 must be strongly equivalent to one on the stored
// response; weak validators may correspond under weak comparison; and a 304
// without any validator can only update a stored response that also lacks
// validators.
[[nodiscard]] inline auto not_modified_validators_match(
    const http::response& stored, const http::response& not_modified) -> bool
{
    auto new_tags = find_all_headers(not_modified.fields, "etag");
    // RFC 9111 §4.3.4 — "If the new response contains one or more 'strong
    // validators' ... then each of those strong validators identifies a
    // selected representation for update." — the presence of a strong
    // validator in the 304 makes the strong comparison the deciding rule;
    // weak validators in the same 304 are then irrelevant.
    auto new_has_strong = false;
    for (auto tag : new_tags)
        if (auto parsed = parse_etag(tag); parsed && !parsed->weak) new_has_strong = true;
    if (new_has_strong) {
        for (auto tag : new_tags) {
            // RFC 9110 §8.8.3 — "An entity tag can be either a weak or strong
            // validator, with strong being the default."
            auto parsed_new = parse_etag(tag);
            if (!parsed_new || parsed_new->weak) continue;
            for (auto stored_tag : find_all_headers(stored.fields, "etag")) {
                auto parsed_stored = parse_etag(stored_tag);
                // RFC 9110 §8.8.3.2 — "Strong comparison: two entity tags are
                // equivalent if both are not weak and their opaque-tags match
                // character-by-character."
                if (parsed_stored && http::etag_strong_compare(*parsed_new, *parsed_stored))
                    return true;
            }
        }
        // RFC 9111 §4.3.4 — "If none of the initial set contains at least one
        // of the same strong validators, then the cache MUST NOT use the new
        // response to update any stored responses."
        return false;
    }
    for (auto tag : new_tags) {
        auto parsed_new = parse_etag(tag);
        if (!parsed_new) continue;
        for (auto stored_tag : find_all_headers(stored.fields, "etag")) {
            auto parsed_stored = parse_etag(stored_tag);
            // RFC 9110 §8.8.3.2 — "Weak comparison: two entity tags are
            // equivalent if their opaque-tags match character-by-character,
            // regardless of either or both being tagged as 'weak'."
            if (parsed_stored && http::etag_weak_compare(*parsed_new, *parsed_stored))
                return true;
        }
    }
    if (!new_tags.empty()) return false;
    for (auto modified : find_all_headers(not_modified.fields, "last-modified")) {
        // RFC 9110 §8.8.2.2 — "A Last-Modified time, when used as a
        // validator in a request, is implicitly weak unless it is possible
        // to deduce that it is strong" — the cache uses it in
        // If-Modified-Since, which is weak comparison.
        auto parsed_new = parse_http_date(modified, std::chrono::system_clock::time_point{});
        if (!parsed_new) continue;
        for (auto stored_modified : find_all_headers(stored.fields, "last-modified")) {
            auto parsed_stored = parse_http_date(
                stored_modified, std::chrono::system_clock::time_point{});
            if (parsed_stored && *parsed_stored == *parsed_new) return true;
        }
    }
    if (find_header(not_modified.fields, "last-modified")) return false;
    // RFC 9111 §4.3.4 — "If the new response does not include any form of
    // validator ... and there is only one stored response in the initial
    // set, and that stored response also lacks a validator, then that stored
    // response is identified for update." — a validator-less 304 updates
    // only a validator-less stored response.
    return !find_header(stored.fields, "etag") && !find_header(stored.fields, "last-modified");
}

// RFC 9110 §12.5.5 — "Vary = [ ( "*" / field-name ) *( OWS "," [ OWS
// ( "*" / field-name ) ] ) ]" — list separators carry OWS (SP / HTAB). A
// member is a complete "*" or field-name and never spans a comma, so
// multiple Vary field lines, which combine into one comma-list under
// RFC 9110 §5.3, can be iterated line by line.
template <typename Function>
void for_each_vary_member(std::string_view value, Function&& function) {
    while (!value.empty()) {
        while (!value.empty() && (value.front() == ' ' || value.front() == '\t' ||
                                  value.front() == ','))
            value.remove_prefix(1);
        auto comma = value.find(',');
        auto member = comma == std::string_view::npos ? value : value.substr(0, comma);
        value = comma == std::string_view::npos
            ? std::string_view{} : value.substr(comma + 1);
        while (!member.empty() && (member.back() == ' ' || member.back() == '\t'))
            member.remove_suffix(1);
        if (member.empty()) continue;
        std::invoke(function, member);
    }
}

// RFC 9111 §4.1 — "A stored response with a Vary header field value
// containing a member '*' always fails to match." — the member test covers
// both the whole-value form and '*' appearing anywhere in a comma-list.
[[nodiscard]] inline auto vary_contains_star_member(std::string_view value) -> bool {
    auto contains_star = false;
    for_each_vary_member(value, [&](std::string_view member) {
        if (member == "*") contains_star = true;
    });
    return contains_star;
}

} // namespace http::detail

export namespace http {

enum class cache_kind : std::uint8_t { private_, shared };

// RFC 9111 §2 — 'The "cache key" is the information a cache uses to choose a
// response and is composed from, at a minimum, the request method and target
// URI used to retrieve the stored response' — the method is part of the key
// so that a stored POST response does not shadow a GET entry for the same
// effective URI (plan_storage admits POST; RFC 9110 §9.3.3).
struct cache_key {
    http::method method;
    std::string effective_uri;

    friend auto operator==(const cache_key&, const cache_key&) -> bool = default;
};

struct request_cache_control {
    bool no_cache{false};
    bool no_store{false};
    bool only_if_cached{false};
    std::optional<std::chrono::seconds> max_age;
    std::optional<std::chrono::seconds> min_fresh;
    bool any_max_stale{false};
    std::optional<std::chrono::seconds> max_stale;
};

struct response_cache_control {
    bool no_cache{false};
    bool no_store{false};
    bool must_revalidate{false};
    bool proxy_revalidate{false};
    bool public_{false};
    bool private_{false};
    bool no_transform{false};
    bool immutable{false};
    bool must_understand{false};
    bool invalid_freshness{false};
    std::optional<std::chrono::seconds> max_age;
    std::optional<std::chrono::seconds> shared_max_age;
};

[[nodiscard]] inline auto parse_request_cache_control(const headers& fields)
    -> request_cache_control
{
    request_cache_control result;
    detail::for_each_cache_directive(fields, [&](std::string_view name, auto argument) {
        if (iequal(name, "no-cache")) result.no_cache = true;
        else if (iequal(name, "no-store")) result.no_store = true;
        else if (iequal(name, "only-if-cached")) result.only_if_cached = true;
        else if (iequal(name, "max-age") && argument) {
            // RFC 9111 §4.2.1 — "When there is more than one value present
            // for a given directive (e.g., two Expires header field lines or
            // multiple Cache-Control: max-age directives), either the first
            // occurrence should be used or the response should be considered
            // stale." — the rule is stated for response freshness; the
            // request side applies the same first-occurrence choice, and an
            // unparseable occurrence leaves an earlier valid value intact
            // instead of erasing it (the client's stated bound stays
            // conservative rather than silently widening).
            if (!result.max_age)
                if (auto parsed = detail::parse_delta(*argument))
                    result.max_age = parsed;
        }
        else if (iequal(name, "min-fresh") && argument) {
            // RFC 9111 §4.2.1 first-occurrence rule applied as for max-age.
            if (!result.min_fresh)
                if (auto parsed = detail::parse_delta(*argument))
                    result.min_fresh = parsed;
        }
        else if (iequal(name, "max-stale")) {
            // RFC 9111 §4.2.1 first-occurrence rule applied as for max-age:
            // the first max-stale occurrence (valued or bare) wins, and an
            // unparseable value never erases an already-parsed one.
            if (!result.any_max_stale && !result.max_stale) {
                result.any_max_stale = !argument;
                if (argument)
                    if (auto parsed = detail::parse_delta(*argument))
                        result.max_stale = parsed;
            }
        }
    });
    return result;
}

[[nodiscard]] inline auto parse_response_cache_control(const headers& fields)
    -> response_cache_control
{
    response_cache_control result;
    detail::for_each_cache_directive(fields, [&](std::string_view name, auto argument) {
        if (iequal(name, "no-cache")) result.no_cache = true;
        else if (iequal(name, "no-store")) result.no_store = true;
        else if (iequal(name, "must-revalidate")) result.must_revalidate = true;
        else if (iequal(name, "proxy-revalidate")) result.proxy_revalidate = true;
        else if (iequal(name, "public")) result.public_ = true;
        else if (iequal(name, "private")) {
            // RFC 9111 §5.2.2.7 — the qualified form private="field-name"
            // permits a shared cache to store the response minus the listed
            // fields; here it is treated as unqualified (a shared cache
            // rejects the whole response), which the RFC notes is the common
            // handling for the qualified form.
            result.private_ = true;
        }
        else if (iequal(name, "no-transform")) result.no_transform = true;
        else if (iequal(name, "immutable")) result.immutable = true;
        else if (iequal(name, "must-understand")) result.must_understand = true;
        else if (iequal(name, "max-age") && argument) {
            // RFC 9111 §4.2.1 — "When there is more than one value present
            // for a given directive (e.g., two Expires header field lines or
            // multiple Cache-Control: max-age directives), either the first
            // occurrence should be used or the response should be considered
            // stale." — the first occurrence wins, so a later conflicting
            // value can never over-freshen the response.
            // RFC 9111 §4.2.1 — "Caches are encouraged to consider responses
            // that have invalid freshness information (e.g., a max-age
            // directive with non-integer content) to be stale." — a failed
            // parse marks the response stale instead of dropping the
            // directive as absent.
            if (!result.max_age && !result.invalid_freshness) {
                if (auto parsed = detail::parse_delta(*argument)) result.max_age = parsed;
                else result.invalid_freshness = true;
            }
        }
        else if (iequal(name, "s-maxage") && argument) {
            // RFC 9111 §5.2.2.10 — s-maxage governs shared caches only, yet
            // an invalid value marks invalid_freshness even for a private
            // cache, where the directive is inapplicable — safe-side, and
            // defensible under §4.2.1's 'encouraged' stale treatment.
            if (!result.shared_max_age && !result.invalid_freshness) {
                if (auto parsed = detail::parse_delta(*argument))
                    result.shared_max_age = parsed;
                else result.invalid_freshness = true;
            }
        }
    });
    return result;
}

struct cache_entry {
    cache_key key;
    http::request selecting_request;
    http::response stored;
    std::chrono::system_clock::time_point request_time;
    std::chrono::system_clock::time_point response_time;
};

enum class storage_rejection : std::uint8_t {
    invalid_effective_uri,
    request_no_store,
    response_no_store,
    private_response,
    unsupported_method,
    uncacheable_status,
    authorization,
    vary_all,
    post_without_explicit_freshness,
    post_content_location_mismatch,
};

enum class cache_action : std::uint8_t {
    use,
    revalidate,
    fetch,
    only_if_cached_miss,
};

[[nodiscard]] inline auto current_age(
    const cache_entry& entry,
    std::chrono::system_clock::time_point now) -> std::chrono::seconds
{
    using namespace std::chrono;
    auto age_value = seconds{0};
    // RFC 9111 §5.1 — "Age = delta-seconds" — the Age value gets the same
    // clamping delta-seconds parsing as the freshness directives (§1.2.2).
    if (auto age = find_header(entry.stored.fields, "age"))
        if (auto parsed = detail::parse_delta(*age)) age_value = *parsed;
    auto apparent_age = std::max(seconds{0}, duration_cast<seconds>(
        entry.response_time - detail::date_value(entry.stored.fields, entry.response_time)));
    auto response_delay = std::max(seconds{0}, duration_cast<seconds>(
        entry.response_time - entry.request_time));
    auto corrected_initial_age = std::max(apparent_age, age_value + response_delay);
    auto resident_time = std::max(seconds{0}, duration_cast<seconds>(
        now - entry.response_time));
    return corrected_initial_age + resident_time;
}

[[nodiscard]] inline auto freshness_lifetime(const cache_entry& entry, cache_kind kind)
    -> std::chrono::seconds
{
    using namespace std::chrono;
    auto control = parse_response_cache_control(entry.stored.fields);
    // RFC 9111 §4.2.1 — "Caches are encouraged to consider responses that
    // have invalid freshness information (e.g., a max-age directive with
    // non-integer content) to be stale." — an invalid freshness directive
    // yields a zero lifetime, so the response is treated as stale.
    if (control.invalid_freshness) return seconds{0};
    if (kind == cache_kind::shared && control.shared_max_age) return *control.shared_max_age;
    if (control.max_age) return *control.max_age;
    if (auto expires = find_header(entry.stored.fields, "expires")) {
        auto parsed = detail::parse_http_date(*expires, entry.response_time);
        if (!parsed) return seconds{0};
        return std::max(seconds{0}, duration_cast<seconds>(
            *parsed - detail::date_value(entry.stored.fields, entry.response_time)));
    }
    if (auto modified = find_header(entry.stored.fields, "last-modified")) {
        if (auto parsed = detail::parse_http_date(*modified, entry.response_time)) {
            // RFC 9111 §4.2.2 — "If the response has a Last-Modified header
            // field ... caches are encouraged to use a heuristic expiration
            // value that is no more than some fraction of the interval since
            // that time. A typical setting of this fraction might be 10%."
            auto interval = duration_cast<seconds>(
                detail::date_value(entry.stored.fields, entry.response_time) - *parsed);
            return std::max(seconds{0}, interval / 10);
        }
    }
    return seconds{0};
}

[[nodiscard]] inline auto is_fresh(
    const cache_entry& entry,
    cache_kind kind,
    std::chrono::system_clock::time_point now) -> bool
{
    return current_age(entry, now) < freshness_lifetime(entry, kind);
}

[[nodiscard]] inline auto is_default_cacheable_status(status value) -> bool {
    switch (value) {
        case 200:
        case 203:
        case 204:
        case 300:
        case 301:
        case 308:
        case 404:
        case 405:
        case 410:
        case 414:
        case 501:
            return true;
        default:
            return false;
    }
}

[[nodiscard]] inline auto plan_storage(
    cache_kind kind,
    const http::request& request,
    const http::response& response,
    std::chrono::system_clock::time_point request_time,
    std::chrono::system_clock::time_point response_time)
    -> std::expected<cache_entry, storage_rejection>
{
    auto effective_uri = request_effective_uri(request);
    if (!effective_uri)
        return std::unexpected{storage_rejection::invalid_effective_uri};
    auto request_control = parse_request_cache_control(request.fields);
    auto response_control = parse_response_cache_control(response.fields);
    if (request_control.no_store)
        return std::unexpected{storage_rejection::request_no_store};
    // RFC 9111 §5.2.2.3 — "When a cache that implements the must-understand
    // directive receives a response that includes it, the cache SHOULD
    // ignore the no-store directive if it understands and implements the
    // status code's caching requirements."
    if (response_control.no_store && !response_control.must_understand)
        return std::unexpected{storage_rejection::response_no_store};
    if (kind == cache_kind::shared && response_control.private_)
        return std::unexpected{storage_rejection::private_response};
    if (request.method != method::GET && request.method != method::HEAD &&
        request.method != method::POST)
        return std::unexpected{storage_rejection::unsupported_method};
    // RFC 9111 §3 — "A cache MUST NOT store a response to a request unless:
    // ... the response status code is final (see Section 15 of [HTTP])" — a
    // 1xx response is interim, not final, and RFC 9110 §15 — "All valid
    // status codes are within the range of 100 to 599, inclusive" — so a
    // code outside that range is invalid; neither is storable.
    if (response.status < 200 || response.status > 599)
        return std::unexpected{storage_rejection::uncacheable_status};
    // RFC 9111 §3 — "... if the response status code is 206 or 304, or the
    // must-understand cache directive ... is present: the cache understands
    // the response status code" — a 304 is never stored: RFC 9111 §4.3.4
    // freshens an existing entry through update_stored_entry instead.
    // RFC 9111 §3.4 — "A cache MAY combine these ranges into a single
    // stored response" — this cache does not combine partial content, a
    // deliberate simplification, so a 206 is not stored either.
    if (response.status == 206 || response.status == 304)
        return std::unexpected{storage_rejection::uncacheable_status};
    // RFC 9111 §5.2.2.3 — "The must-understand response directive limits
    // caching of the response to a cache that understands and conforms to
    // the requirements for that response's status code." — this cache's
    // status knowledge is the heuristic-cacheable set (RFC 9110 §15.1); a
    // must-understand response for any other status is not storable.
    if (response_control.must_understand && !is_default_cacheable_status(response.status))
        return std::unexpected{storage_rejection::uncacheable_status};

    // RFC 9111 §3 — the response must be heuristically cacheable or carry
    // explicit freshness; §5.2.2.7 — "it also indicates that a private cache
    // MAY store the response ... even if the response would not otherwise be
    // heuristically cacheable by a private cache."
    auto explicitly_cacheable = response_control.public_ ||
        response_control.max_age ||
        (kind == cache_kind::private_ && response_control.private_) ||
        (kind == cache_kind::shared && response_control.shared_max_age) ||
        find_header(response.fields, "expires").has_value();
    if (!is_default_cacheable_status(response.status) && !explicitly_cacheable)
        return std::unexpected{storage_rejection::uncacheable_status};

    if (kind == cache_kind::shared && find_header(request.fields, "authorization") &&
        !(response_control.public_ || response_control.must_revalidate ||
          response_control.shared_max_age))
        return std::unexpected{storage_rejection::authorization};
    // RFC 9111 §4.1 — "A stored response with a Vary header field value
    // containing a member '*' always fails to match." — multiple Vary field
    // lines combine into one comma-list under RFC 9110 §5.3, so every field
    // line is scanned for a '*' member.
    for (auto vary : find_all_headers(response.fields, "vary")) {
        if (detail::vary_contains_star_member(vary))
            return std::unexpected{storage_rejection::vary_all};
    }

    if (request.method == method::POST) {
        // RFC 9110 §9.3.3 — "Responses to POST requests are only cacheable
        // when they include explicit freshness information ... and a
        // Content-Location header field that has the same value as the
        // POST's target URI" — the conditions do not restrict the status:
        // non-final, 206, and 304 responses are rejected above, and any
        // other status with explicit freshness and a matching
        // Content-Location is storable.
        if (!(response_control.max_age || response_control.shared_max_age ||
              find_header(response.fields, "expires")))
            return std::unexpected{storage_rejection::post_without_explicit_freshness};
        auto location = find_header(response.fields, "content-location");
        auto path_and_query = request_path_and_query(request);
        if (!location || (*location != *effective_uri &&
                          (!path_and_query || *location != *path_and_query)))
            return std::unexpected{storage_rejection::post_content_location_mismatch};
    }

    return cache_entry{
        .key = cache_key{.method = request.method,
                         .effective_uri = std::move(*effective_uri)},
        .selecting_request = request,
        .stored = response,
        .request_time = request_time,
        .response_time = response_time,
    };
}

[[nodiscard]] inline auto matches_vary(const cache_entry& entry, const http::request& request)
    -> bool
{
    auto vary_lines = find_all_headers(entry.stored.fields, "vary");
    if (vary_lines.empty()) return true;
    // RFC 9111 §4.1 — "A stored response with a Vary header field value
    // containing a member '*' always fails to match." — multiple Vary field
    // lines combine into one comma-list under RFC 9110 §5.3, so the member
    // test covers every field line.
    for (auto line : vary_lines)
        if (detail::vary_contains_star_member(line)) return false;
    for (auto line : vary_lines) {
        auto mismatch = false;
        detail::for_each_vary_member(line, [&](std::string_view field) {
            if (mismatch) return;
            auto stored_value = detail::normalized_selecting_field(
                entry.selecting_request.fields, field);
            auto request_value = detail::normalized_selecting_field(request.fields, field);
            // RFC 9111 §4.1 — "If (after any normalization that might take place) a
            // header field is absent from a request, it can only match another
            // request if it is also absent there."
            if (stored_value.has_value() != request_value.has_value() ||
                (stored_value && *stored_value != *request_value))
                mismatch = true;
        });
        if (mismatch) return false;
    }
    return true;
}

[[nodiscard]] inline auto can_satisfy_method(method stored, method requested) -> bool {
    if (stored == method::GET) return requested == method::GET || requested == method::HEAD;
    if (stored == method::HEAD) return requested == method::HEAD;
    if (stored == method::POST) return requested == method::GET || requested == method::HEAD;
    return false;
}

[[nodiscard]] inline auto evaluate_cache_use(
    cache_kind kind,
    const http::request& request,
    const cache_entry* candidate,
    std::chrono::system_clock::time_point now) -> cache_action
{
    auto request_control = parse_request_cache_control(request.fields);
    auto miss = [&] {
        return request_control.only_if_cached
            ? cache_action::only_if_cached_miss : cache_action::fetch;
    };
    auto forward = [&] {
        return request_control.only_if_cached
            ? cache_action::only_if_cached_miss : cache_action::revalidate;
    };
    // RFC 9111 §5.2.1.5 — "The no-store request directive indicates that a
    // cache MUST NOT store any part of either this request or any response
    // to it." — the directive forbids storage, not reuse; forcing a full
    // fetch here is a deliberate stricter-than-RFC choice: a no-store
    // request bypasses the cache entirely rather than risking reuse of an
    // entry the client explicitly declined to keep.
    if (request_control.no_store || !candidate) return miss();

    const auto& entry = *candidate;
    auto effective_uri = request_effective_uri(request);
    if (!effective_uri || entry.key.effective_uri != *effective_uri ||
        !can_satisfy_method(entry.selecting_request.method, request.method) ||
        !matches_vary(entry, request))
        return miss();

    if (request_control.no_cache) return forward();
    auto response_control = parse_response_cache_control(entry.stored.fields);
    if (response_control.no_cache) return forward();

    auto age = current_age(entry, now);
    auto lifetime = freshness_lifetime(entry, kind);
    auto fresh = age < lifetime;
    if (request_control.max_age) fresh = fresh && age <= *request_control.max_age;
    // RFC 9111 §5.2.1.3 — "The min-fresh request directive indicates that
    // the client prefers a response whose freshness lifetime is no less
    // than its current age plus the specified time in seconds." — the
    // boundary is inclusive.
    if (request_control.min_fresh) fresh = fresh &&
        age + *request_control.min_fresh <= lifetime;
    if (fresh) return cache_action::use;

    auto forbids_stale = response_control.must_revalidate ||
        (kind == cache_kind::shared &&
         (response_control.proxy_revalidate || response_control.shared_max_age));
    if (!forbids_stale) {
        auto staleness = age > lifetime ? age - lifetime : std::chrono::seconds{0};
        if (request_control.any_max_stale ||
            (request_control.max_stale && staleness <= *request_control.max_stale))
            return cache_action::use;
    }
    return forward();
}

[[nodiscard]] inline auto make_conditional(
    const http::request& request,
    const cache_entry& entry) -> http::request
{
    auto conditional = request;
    if (auto tag = find_header(entry.stored.fields, "etag"))
        conditional.fields.push_back({"if-none-match", std::string(*tag)});
    if (auto modified = find_header(entry.stored.fields, "last-modified"))
        conditional.fields.push_back({"if-modified-since", std::string(*modified)});
    return conditional;
}

[[nodiscard]] inline auto update_stored_entry(
    cache_entry entry,
    const http::response& not_modified,
    std::chrono::system_clock::time_point validation_request_time,
    std::chrono::system_clock::time_point validation_response_time)
    -> std::optional<cache_entry>
{
    // RFC 9111 §4.3.4 — "If the new response contains one or more 'strong
    // validators' ... then each of those strong validators identifies a
    // selected representation for update. ... If none of the initial set
    // contains at least one of the same strong validators, then the cache
    // MUST NOT use the new response to update any stored responses." — a
    // 304 whose validators do not correspond is a MUST-NOT-update event, so
    // the function returns nullopt to let the caller distinguish a rejected
    // freshening from an applied one instead of silently handing back the
    // unchanged entry.
    if (!detail::not_modified_validators_match(entry.stored, not_modified))
        return std::nullopt;
    for (const auto& field : not_modified.fields) {
        // RFC 9111 §3.2 — fields excluded from a 304 metadata update do not
        // replace representation framing or range metadata of the stored response.
        if (iequal(field.name, "content-length") || iequal(field.name, "content-range") ||
            iequal(field.name, "transfer-encoding") || iequal(field.name, "trailer"))
            continue;
        std::erase_if(entry.stored.fields, [&](const header& stored) {
            return iequal(stored.name, field.name);
        });
        entry.stored.fields.push_back(field);
    }
    entry.request_time = validation_request_time;
    entry.response_time = validation_response_time;
    return entry;
}

} // namespace http
