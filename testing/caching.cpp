#include <boost/ut.hpp>

#include "test_support.hpp"

namespace httpant::testing {

using namespace boost::ut;
using namespace std::literals;

namespace {

constexpr auto instant(std::int64_t seconds) -> std::chrono::system_clock::time_point {
    return std::chrono::system_clock::time_point{std::chrono::seconds{seconds}};
}

auto response_with(std::string value, http::status status = 200) -> http::response {
    return http::response{
        .status = status,
        .reason = {},
        .fields = {{"cache-control", std::move(value)}},
    };
}

auto stored(http::request request, http::response response,
            std::chrono::system_clock::time_point request_time = instant(1'000),
            std::chrono::system_clock::time_point response_time = instant(1'004))
    -> http::cache_entry
{
    auto uri = http::request_effective_uri(request);
    return http::cache_entry{
        .key = http::cache_key{.method = request.method,
                               .effective_uri = std::move(*uri)},
        .selecting_request = std::move(request),
        .stored = std::move(response),
        .request_time = request_time,
        .response_time = response_time,
    };
}

} // namespace

static suite<"caching"> caching_suite = [] {
    "request_and_response_directives_are_typed_and_merge_field_lines"_test = [] {
        // RFC 9110 §5.3 — "A recipient MAY combine multiple field lines within a
        // field section that have the same field name into one field line, without
        // changing the semantics of the message, by appending each subsequent field
        // line value to the initial field line value in order, separated by a comma
        // (',') and optional whitespace (OWS, defined in Section 5.6.3)". Distinct
        // directives spread across field lines therefore still form one Cache-Control value.
        http::headers request_fields{{"cache-control", "max-age=60, min-fresh=5"},
                                     {"cache-control", "max-stale=9, only-if-cached"}};
        auto request = http::parse_request_cache_control(request_fields);
        expect(request.max_age == std::chrono::seconds{60});
        expect(request.min_fresh == std::chrono::seconds{5});
        expect(request.max_stale == std::chrono::seconds{9});
        expect(request.only_if_cached);

        http::headers response_fields{{"cache-control", "private, max-age=30"},
                                      {"cache-control", "s-maxage=10, must-revalidate"}};
        auto response = http::parse_response_cache_control(response_fields);
        expect(response.private_);
        expect(response.max_age == std::chrono::seconds{30});
        expect(response.shared_max_age == std::chrono::seconds{10});
        expect(response.must_revalidate);
    };

    "current_age_includes_response_delay"_test = [] {
        // RFC 9111 §4.2.3 — "response_delay = response_time - request_time" and
        // "corrected_age_value = age_value + response_delay".
        auto entry = stored(basic_get("/age"), http::response{
            .status = 200, .reason = {}, .fields = {{"age", "10"}}});
        expect(http::current_age(entry, instant(1'010)) == std::chrono::seconds{20});
    };

    "shared_and_private_freshness_use_different_directives"_test = [] {
        // RFC 9111 §5.2.2.10 — "For a shared cache, the s-maxage value takes
        // precedence over the max-age directive or the Expires header field."
        auto entry = stored(basic_get("/kind"), response_with("max-age=60, s-maxage=10"),
                            instant(1'000), instant(1'000));
        expect(http::freshness_lifetime(entry, http::cache_kind::private_) == 60s);
        expect(http::freshness_lifetime(entry, http::cache_kind::shared) == 10s);
        expect(http::is_fresh(entry, http::cache_kind::private_, instant(1'020)));
        expect(!http::is_fresh(entry, http::cache_kind::shared, instant(1'020)));
    };

    "private_response_is_only_rejected_by_shared_cache"_test = [] {
        // RFC 9111 §5.2.2.7 — "The private response directive indicates that the
        // response can be stored only in a private cache."
        auto request = basic_get("/private");
        auto response = response_with("private, max-age=60");
        expect(http::plan_storage(http::cache_kind::private_, request, response,
                                  instant(1), instant(2)).has_value());
        auto shared = http::plan_storage(http::cache_kind::shared, request, response,
                                         instant(1), instant(2));
        expect(!shared.has_value());
        expect(shared.error() == http::storage_rejection::private_response);
    };

    "request_no_store_rejects_storage"_test = [] {
        // RFC 9111 §5.2.1.5 — "The no-store request directive indicates that a
        // cache MUST NOT store any part of either this request or any response to it."
        auto request = basic_get("/no-store");
        request.fields.push_back({"cache-control", "no-store"});
        auto plan = http::plan_storage(http::cache_kind::private_, request,
                                       response_with("max-age=60"), instant(1), instant(2));
        expect(!plan.has_value());
        expect(plan.error() == http::storage_rejection::request_no_store);
    };

    "default_and_explicit_status_cacheability"_test = [] {
        // RFC 9111 §3 — the response is storable if "a status code that is
        // defined as heuristically cacheable" or one of the explicit
        // freshness signals is present, including "a private response
        // directive, if the cache is not shared (see Section 5.2.2.7)".
        // RFC 9111 §5.2.2.7 — "it also indicates that a private cache MAY
        // store the response, subject to the constraints defined in
        // Section 3, even if the response would not otherwise be
        // heuristically cacheable by a private cache."
        auto request = basic_get("/status");
        expect(http::plan_storage(http::cache_kind::private_, request,
                                  response_with("", 404), instant(1), instant(2)).has_value());
        expect(http::plan_storage(http::cache_kind::private_, request,
                                  response_with("public, max-age=60", 302),
                                  instant(1), instant(2)).has_value());
        // RFC 9111 §5.2.2.7 — "The unqualified private response directive
        // indicates that a shared cache MUST NOT store the response (i.e.,
        // the response is intended for a single user)." — for a private
        // cache the directive is an explicit cacheability signal.
        expect(http::plan_storage(http::cache_kind::private_, request,
                                  response_with("private", 302),
                                  instant(1), instant(2)).has_value());
        auto shared = http::plan_storage(http::cache_kind::shared, request,
                                         response_with("private", 302),
                                         instant(1), instant(2));
        expect(!shared.has_value());
        expect(shared.error() == http::storage_rejection::private_response);
        auto rejected = http::plan_storage(http::cache_kind::private_, request,
                                           response_with("", 302), instant(1), instant(2));
        expect(!rejected.has_value());
        expect(rejected.error() == http::storage_rejection::uncacheable_status);
    };

    "storage_requires_a_final_understood_status"_test = [] {
        // RFC 9111 §3 — "A cache MUST NOT store a response to a request
        // unless: ... the response status code is final (see Section 15 of
        // [HTTP])" — an interim 1xx response is not final even with explicit
        // freshness, so it must not be stored.
        auto request = basic_get("/interim");
        auto interim = http::plan_storage(http::cache_kind::private_, request,
                                          response_with("max-age=60", 100),
                                          instant(1), instant(2));
        expect(!interim.has_value());
        expect(interim.error() == http::storage_rejection::uncacheable_status);
        // RFC 9111 §3 — "... if the response status code is 206 or 304 ...:
        // the cache understands the response status code" — a 304 is not a
        // storable representation: RFC 9111 §4.3.4 freshens an existing
        // stored entry via update_stored_entry instead, so a 304 carrying
        // explicit freshness must still be rejected.
        auto not_modified = http::plan_storage(http::cache_kind::private_, request,
                                               response_with("max-age=60", 304),
                                               instant(1), instant(2));
        expect(!not_modified.has_value());
        expect(not_modified.error() == http::storage_rejection::uncacheable_status);
        // RFC 9110 §15 — "All valid status codes are within the range of 100
        // to 599, inclusive." — a code outside that range is invalid and
        // cannot be final either.
        auto invalid = http::plan_storage(http::cache_kind::private_, request,
                                          response_with("max-age=60", 600),
                                          instant(1), instant(2));
        expect(!invalid.has_value());
        expect(invalid.error() == http::storage_rejection::uncacheable_status);
    };

    "response_no_store_and_vary_all_reject_storage"_test = [] {
        // RFC 9111 §5.2.2.5 — "The no-store response directive indicates that a
        // cache MUST NOT store any part of either the immediate request or the
        // response." RFC 9111 §4.1 — "A stored response with a Vary header field
        // value containing a member '*' always fails to match."
        auto request = basic_get("/reject");
        auto no_store = http::plan_storage(
            http::cache_kind::private_, request, response_with("no-store"),
            instant(1), instant(2));
        expect(!no_store.has_value());
        expect(no_store.error() == http::storage_rejection::response_no_store);
        auto vary = response_with("max-age=60");
        vary.fields.push_back({"vary", "*"});
        auto vary_all = http::plan_storage(
            http::cache_kind::private_, request, vary, instant(1), instant(2));
        expect(!vary_all.has_value());
        expect(vary_all.error() == http::storage_rejection::vary_all);
        // RFC 9111 §4.1 — "A stored response with a Vary header field value
        // containing a member '*' always fails to match." — a '*' member
        // anywhere in the comma-list rejects storage, not only the whole
        // value "*".
        auto listed = response_with("max-age=60");
        listed.fields.push_back({"vary", "accept-encoding, *"});
        auto listed_all = http::plan_storage(
            http::cache_kind::private_, request, listed, instant(1), instant(2));
        expect(!listed_all.has_value());
        expect(listed_all.error() == http::storage_rejection::vary_all);
        auto entry = stored(request, http::response{
            .status = 200, .reason = {}, .fields = {{"vary", "accept-encoding, *"}}});
        expect(!http::matches_vary(entry, request));
    };

    "vary_star_detection_combines_multiple_field_lines"_test = [] {
        // RFC 9110 §5.3 — "A recipient MAY combine multiple field lines within a
        // field section that have the same field name into one field line,
        // without changing the semantics of the message, by appending each
        // subsequent field line value to the initial field line value in order,
        // separated by a comma (',') and optional whitespace" — a '*' member on
        // a second 'Vary:' field line therefore combines into
        // 'Vary: accept-encoding, *'.
        // RFC 9111 §4.1 — "A stored response with a Vary header field value
        // containing a member '*' always fails to match."
        auto request = basic_get("/vary-multi-star");
        auto response = response_with("max-age=60");
        response.fields.push_back({"vary", "accept-encoding"});
        response.fields.push_back({"vary", "*"});
        auto plan = http::plan_storage(http::cache_kind::private_, request, response,
                                       instant(1), instant(2));
        expect(!plan.has_value());
        expect(plan.error() == http::storage_rejection::vary_all);
        // The field line order must not matter: 'Vary: *' followed by
        // 'Vary: accept-encoding' combines into the same list.
        auto reversed = response_with("max-age=60");
        reversed.fields.push_back({"vary", "*"});
        reversed.fields.push_back({"vary", "accept-encoding"});
        auto reversed_plan = http::plan_storage(
            http::cache_kind::private_, request, reversed, instant(1), instant(2));
        expect(!reversed_plan.has_value());
        expect(reversed_plan.error() == http::storage_rejection::vary_all);
        // matches_vary applies the same combined-member rule to stored entries.
        auto entry = stored(request, http::response{
            .status = 200, .reason = {},
            .fields = {{"vary", "accept-encoding"}, {"vary", "*"}}});
        expect(!http::matches_vary(entry, request));
    };

    "authorization_rule_applies_only_to_shared_cache"_test = [] {
        // RFC 9111 §3.5 — "A shared cache MUST NOT use a cached response to a
        // request with an Authorization header field" unless an enabling response
        // directive is present.
        auto request = basic_get("/authorized");
        request.fields.push_back({"authorization", "Bearer secret"});
        auto response = response_with("max-age=60");
        expect(http::plan_storage(http::cache_kind::private_, request, response,
                                  instant(1), instant(2)).has_value());
        auto shared = http::plan_storage(http::cache_kind::shared, request, response,
                                         instant(1), instant(2));
        expect(shared.error() == http::storage_rejection::authorization);
        expect(http::plan_storage(http::cache_kind::shared, request,
                                  response_with("public, max-age=60"),
                                  instant(1), instant(2)).has_value());
    };

    "request_freshness_directives_control_use"_test = [] {
        // RFC 9111 §5.2.1.1/§5.2.1.2 — max-age limits acceptable age and
        // max-stale permits a response that has exceeded its freshness lifetime.
        auto request = basic_get("/use");
        auto entry = stored(request, response_with("max-age=20"), instant(1'000), instant(1'000));
        auto max_age = request;
        max_age.fields.push_back({"cache-control", "max-age=5"});
        expect(http::evaluate_cache_use(http::cache_kind::private_, max_age, &entry,
                                        instant(1'010)) == http::cache_action::revalidate);
        auto max_stale = request;
        max_stale.fields.push_back({"cache-control", "max-stale=15"});
        expect(http::evaluate_cache_use(http::cache_kind::private_, max_stale, &entry,
                                        instant(1'030)) == http::cache_action::use);
    };

    "min_fresh_no_cache_and_must_revalidate_are_enforced"_test = [] {
        // RFC 9111 §5.2.1.3 — "The min-fresh request directive indicates that the
        // client prefers a response whose freshness lifetime is no less than its current
        // age plus the specified number of seconds." no-cache and must-revalidate require
        // validation before reuse.
        auto request = basic_get("/validate");
        auto entry = stored(request, response_with("max-age=20, must-revalidate"),
                            instant(1'000), instant(1'000));
        auto min_fresh = request;
        min_fresh.fields.push_back({"cache-control", "min-fresh=15"});
        expect(http::evaluate_cache_use(http::cache_kind::private_, min_fresh, &entry,
                                        instant(1'010)) == http::cache_action::revalidate);
        auto no_cache = request;
        no_cache.fields.push_back({"cache-control", "no-cache, max-stale"});
        expect(http::evaluate_cache_use(http::cache_kind::private_, no_cache, &entry,
                                        instant(1'030)) == http::cache_action::revalidate);
    };

    "only_if_cached_has_typed_miss"_test = [] {
        // RFC 9111 §5.2.1.7 — "The only-if-cached request directive indicates
        // that the client only wishes to obtain a stored response."
        auto request = basic_get("/missing");
        request.fields.push_back({"cache-control", "only-if-cached"});
        expect(http::evaluate_cache_use(http::cache_kind::private_, request, nullptr,
                                        instant(1)) == http::cache_action::only_if_cached_miss);
    };

    "only_if_cached_never_requests_network_revalidation"_test = [] {
        // RFC 9111 §5.2.1.7 — "The cache SHOULD either respond using a stored
        // response that is consistent with the other constraints of the request or
        // respond with a 504 (Gateway Timeout) status code."
        auto request = basic_get("/stale-only");
        auto entry = stored(request, response_with("max-age=1"), instant(1'000), instant(1'000));
        request.fields.push_back({"cache-control", "only-if-cached"});
        expect(http::evaluate_cache_use(http::cache_kind::private_, request, &entry,
                                        instant(1'010)) ==
               http::cache_action::only_if_cached_miss);
    };

    "unqualified_max_stale_allows_stale_response"_test = [] {
        // RFC 9111 §5.2.1.2 — "If no value is assigned to the directive, then the
        // client will accept a stale response of any age."
        auto request = basic_get("/any-stale");
        auto entry = stored(request, response_with("max-age=1"), instant(1'000), instant(1'000));
        request.fields.push_back({"cache-control", "max-stale"});
        expect(http::evaluate_cache_use(http::cache_kind::private_, request, &entry,
                                        instant(9'000)) == http::cache_action::use);
    };

    "post_storage_can_satisfy_get_and_head_but_not_post"_test = [] {
        // RFC 9110 §9.3.3 — "A cached POST response can be reused to satisfy a later
        // GET or HEAD request" when explicit freshness and matching Content-Location exist.
        auto post = basic_get("/result?view=full");
        post.method = http::method::POST;
        auto response = response_with("max-age=60");
        response.fields.push_back({"content-location", "/result?view=full"});
        auto plan = http::plan_storage(http::cache_kind::private_, post, response,
                                       instant(1'000), instant(1'000));
        expect(plan.has_value());
        auto get = basic_get("/result?view=full");
        expect(http::evaluate_cache_use(http::cache_kind::private_, get, &*plan,
                                        instant(1'010)) == http::cache_action::use);
        expect(http::evaluate_cache_use(http::cache_kind::private_, post, &*plan,
                                        instant(1'010)) == http::cache_action::fetch);
    };

    "effective_uri_preserves_query"_test = [] {
        // RFC 9110 §4.2.1 — "The path component contains data ... along with the
        // optional query component, serves to identify a resource."
        auto first = http::request_effective_uri(basic_get("/x?a"));
        auto second = http::request_effective_uri(basic_get("/x?b"));
        expect(first.has_value() && second.has_value());
        expect(*first != *second);
    };

    "vary_and_304_update_preserve_forbidden_fields"_test = [] {
        // RFC 9111 §4.1 — a stored response selected by Vary requires matching
        // nominated request fields. RFC 9111 §3.2 excludes Content-Length from 304
        // updates. RFC 9111 §4.3.4 — a 304 updates a stored response only when it
        // "contains one or more strong validators" and the stored response has "one
        // of those same strong validators".
        auto request = basic_get("/vary");
        request.fields.push_back({"accept", "text/plain"});
        auto entry = stored(request, http::response{
            .status = 200, .reason = {},
            .fields = {{"vary", "accept"}, {"etag", "\"old\""},
                       {"content-length", "4"}}});
        auto different = request;
        different.fields.back().value = "text/html";
        expect(!http::matches_vary(entry, different));

        auto updated = http::update_stored_entry(
            entry,
            http::response{.status = 304, .reason = {},
                           .fields = {{"etag", "\"old\""},
                                      {"cache-control", "max-age=60"},
                                      {"content-length", "999"}}},
            instant(2'000), instant(2'003));
        expect(updated.has_value());
        expect(http::find_header(updated->stored.fields, "etag") == "\"old\""sv);
        expect(http::find_header(updated->stored.fields, "cache-control") == "max-age=60"sv);
        expect(http::find_header(updated->stored.fields, "content-length") == "4"sv);
        expect(updated->request_time == instant(2'000));
        expect(updated->response_time == instant(2'003));
    };

    "304_update_requires_a_matching_strong_validator"_test = [] {
        // RFC 9111 §4.3.4 — "If none of the initial set contains at least one
        // of the same strong validators, then the cache MUST NOT use the new
        // response to update any stored responses." — a 304 carrying a
        // different strong ETag is a MUST-NOT-update event, surfaced as
        // nullopt so the caller can distinguish rejected from freshened.
        auto request = basic_get("/fresh-304");
        auto entry = stored(request, http::response{
            .status = 200, .reason = {},
            .fields = {{"etag", "\"old\""}, {"cache-control", "max-age=60"}}});
        auto rejected = http::update_stored_entry(
            entry,
            http::response{.status = 304, .reason = {},
                           .fields = {{"etag", "\"new\""}}},
            instant(2'000), instant(2'003));
        expect(!rejected.has_value());
    };

    "304_weak_validator_correspondence_updates"_test = [] {
        // RFC 9111 §4.3.4 — "If the new response contains no strong
        // validators but does contain one or more 'weak validators', and
        // those validators correspond to one of the initial set's stored
        // responses, then the most recent of those matching stored responses
        // is identified for update."
        // RFC 9110 §8.8.3.2 — "Weak comparison: two entity tags are
        // equivalent if their opaque-tags match character-by-character,
        // regardless of either or both being tagged as 'weak'."
        auto request = basic_get("/weak-304");
        auto entry = stored(request, http::response{
            .status = 200, .reason = {},
            .fields = {{"etag", "W/\"tag\""}, {"cache-control", "max-age=60"}}});
        auto updated = http::update_stored_entry(
            entry,
            http::response{.status = 304, .reason = {},
                           .fields = {{"etag", "W/\"tag\""},
                                      {"cache-control", "max-age=30"}}},
            instant(2'000), instant(2'003));
        expect(updated.has_value());
        expect(http::find_header(updated->stored.fields, "cache-control") == "max-age=30"sv);
        expect(updated->response_time == instant(2'003));
    };

    "304_last_modified_only_correspondence_updates"_test = [] {
        // RFC 9111 §4.3.4 — "If the new response contains no strong validators
        // but does contain one or more 'weak validators', and those validators
        // correspond to one of the initial set's stored responses, then the
        // most recent of those matching stored responses is identified for
        // update." — a 304 carrying only a Last-Modified date, which is
        // implicitly weak, matches a stored response with the same date.
        // RFC 9110 §8.8.2.2 — "A Last-Modified time, when used as a validator
        // in a request, is implicitly weak unless it is possible to deduce
        // that it is strong."
        auto request = basic_get("/last-modified-304");
        auto entry = stored(request, http::response{
            .status = 200, .reason = {},
            .fields = {{"last-modified", "Sun, 06 Nov 1994 08:49:37 GMT"},
                       {"cache-control", "max-age=60"}}});
        auto updated = http::update_stored_entry(
            entry,
            http::response{.status = 304, .reason = {},
                           .fields = {{"last-modified", "Sun, 06 Nov 1994 08:49:37 GMT"},
                                      {"cache-control", "max-age=30"}}},
            instant(2'000), instant(2'003));
        expect(updated.has_value());
        expect(http::find_header(updated->stored.fields, "cache-control") == "max-age=30"sv);
        expect(updated->response_time == instant(2'003));
        // A different Last-Modified date does not correspond and must not update.
        auto rejected = http::update_stored_entry(
            entry,
            http::response{.status = 304, .reason = {},
                           .fields = {{"last-modified", "Mon, 07 Nov 1994 08:49:37 GMT"}}},
            instant(2'000), instant(2'003));
        expect(!rejected.has_value());
    };

    "304_strong_validator_does_not_update_weak_stored_tag"_test = [] {
        // RFC 9111 §4.3.4 — "If the new response contains one or more 'strong
        // validators', then each of those strong validators identifies a
        // selected representation for update. ... If none of the initial set
        // contains at least one of the same strong validators, then the cache
        // MUST NOT use the new response to update any stored responses."
        // RFC 9110 §8.8.3.2 — "Strong comparison: two entity tags are
        // equivalent if both are not weak and their opaque-tags match
        // character-by-character." — a strong 304 ETag cannot be matched by a
        // stored response carrying only the weak form of the same opaque-tag.
        auto request = basic_get("/strong-over-weak");
        auto entry = stored(request, http::response{
            .status = 200, .reason = {},
            .fields = {{"etag", "W/\"tag\""}, {"cache-control", "max-age=60"}}});
        auto unchanged = http::update_stored_entry(
            entry,
            http::response{.status = 304, .reason = {},
                           .fields = {{"etag", "\"tag\""},
                                      {"cache-control", "max-age=30"}}},
            instant(2'000), instant(2'003));
        expect(!unchanged.has_value());
    };

    "304_without_validator_updates_only_a_validatorless_entry"_test = [] {
        // RFC 9111 §4.3.4 — "If the new response does not include any form of
        // validator ... and there is only one stored response in the initial set,
        // and that stored response also lacks a validator, then that stored
        // response is identified for update."
        auto request = basic_get("/no-validator");
        auto entry = stored(request, http::response{
            .status = 200, .reason = {}, .fields = {{"cache-control", "max-age=60"}}});
        auto updated = http::update_stored_entry(
            entry,
            http::response{.status = 304, .reason = {},
                           .fields = {{"cache-control", "max-age=30"}}},
            instant(2'000), instant(2'003));
        expect(updated.has_value());
        expect(http::find_header(updated->stored.fields, "cache-control") == "max-age=30"sv);
        // A validator-less 304 must not update an entry that does carry a validator.
        auto stored_with_validator = stored(request, http::response{
            .status = 200, .reason = {},
            .fields = {{"etag", "\"tag\""}, {"cache-control", "max-age=60"}}});
        auto untouched = http::update_stored_entry(
            stored_with_validator,
            http::response{.status = 304, .reason = {},
                           .fields = {{"cache-control", "max-age=30"}}},
            instant(2'000), instant(2'003));
        expect(!untouched.has_value());
    };

    "conditional_request_uses_both_available_validators"_test = [] {
        // RFC 9111 §4.3.1 — a cache "MUST send the relevant entity tags" and
        // "SHOULD send the Last-Modified value" when validating one stored response.
        auto request = basic_get("/conditional");
        auto entry = stored(request, http::response{
            .status = 200, .reason = {},
            .fields = {{"etag", "\"tag\""},
                       {"last-modified", "Sun, 06 Nov 1994 08:49:37 GMT"}}});
        auto conditional = http::make_conditional(request, entry);
        expect(http::find_header(conditional.fields, "if-none-match") == "\"tag\""sv);
        expect(http::find_header(conditional.fields, "if-modified-since") ==
               "Sun, 06 Nov 1994 08:49:37 GMT"sv);
    };

    "obsolete_http_date_year_uses_entry_reference_time"_test = [] {
        // RFC 9110 §5.6.7 — an rfc850 year more than 50 years in the future is
        // interpreted as the most recent past year with the same final two digits.
        auto entry = stored(
            basic_get("/date"),
            http::response{.status = 200, .reason = {},
                           .fields = {{"date", "Sun, 06 Nov 2050 08:49:37 GMT"},
                                      {"expires", "Sunday, 06-Nov-94 08:49:37 GMT"}}},
            instant(2'551'744'577), instant(2'551'744'577));
        expect(http::freshness_lifetime(entry, http::cache_kind::private_) >
               std::chrono::hours{24 * 365 * 40});
    };

    "absolute_form_target_defines_cache_key_authority"_test = [] {
        // RFC 9112 §3.2.2 — "When an origin server receives a request with an
        // absolute-form of request-target, the origin server MUST ignore the
        // received Host header field (if any) and instead use the host
        // information of the request-target." — the cache key derives from the
        // effective URI, so a Host header cannot poison an absolute-form key.
        http::request proxied{
            .method = http::method::GET,
            .target = "http://origin.example/x",
            .scheme = {},
            .authority = {},
            .fields = {{"host", "poisoned.example"}},
        };
        auto plan = http::plan_storage(http::cache_kind::private_, proxied,
                                       response_with("max-age=60"), instant(1), instant(2));
        expect(plan.has_value());
        expect(plan->key.method == http::method::GET);
        expect(plan->key.effective_uri == "http://origin.example/x"sv);
    };

    "vary_matching_combines_field_lines"_test = [] {
        // RFC 9111 §4.1 — "The header fields from two requests are defined to
        // match if and only if those in the first request can be transformed to
        // those in the second request by applying any of the following: ...
        // combining multiple header field lines with the same field name".
        auto selected = basic_get("/vary-multi");
        selected.fields.push_back({"accept", "text/plain"});
        selected.fields.push_back({"accept", "text/html"});
        auto entry = stored(selected, http::response{
            .status = 200, .reason = {}, .fields = {{"vary", "accept"}}});

        auto combined = basic_get("/vary-multi");
        combined.fields.push_back({"accept", "text/plain, text/html"});
        expect(http::matches_vary(entry, combined));
        auto partial = basic_get("/vary-multi");
        partial.fields.push_back({"accept", "text/plain"});
        expect(!http::matches_vary(entry, partial));
    };

    "vary_absent_field_matches_only_absence"_test = [] {
        // RFC 9111 §4.1 — "If (after any normalization that might take place) a
        // header field is absent from a request, it can only match another
        // request if it is also absent there."
        auto selected = basic_get("/vary-absent");
        selected.fields.push_back({"accept-language", ""});
        auto entry = stored(selected, http::response{
            .status = 200, .reason = {}, .fields = {{"vary", "accept-language"}}});

        auto absent = basic_get("/vary-absent");
        expect(!http::matches_vary(entry, absent));
        auto also_empty = basic_get("/vary-absent");
        also_empty.fields.push_back({"accept-language", ""});
        expect(http::matches_vary(entry, also_empty));
        auto valued = basic_get("/vary-absent");
        valued.fields.push_back({"accept-language", "en"});
        expect(!http::matches_vary(entry, valued));
    };

    "delta_seconds_overflow_clamps_instead_of_being_ignored"_test = [] {
        // RFC 9111 §1.2.2 — "delta-seconds = 1*DIGIT"; "If a cache receives a
        // delta-seconds value greater than the greatest integer it can
        // represent, or if any of its subsequent calculations overflows, the
        // cache MUST consider the value to be 2147483648 (2^31) or the greatest
        // positive integer it can conveniently represent." — the parser's
        // conveniently representable maximum is uint32_t; an all-digit value
        // beyond it clamps instead of dropping the directive.
        http::headers overflow{{"cache-control", "max-age=99999999999"}};
        expect(http::parse_request_cache_control(overflow).max_age ==
               std::chrono::seconds{4'294'967'295});
        http::headers exact{{"cache-control", "max-age=4294967295"}};
        expect(http::parse_request_cache_control(exact).max_age ==
               std::chrono::seconds{4'294'967'295});
        // A malformed (non-numeric) value is still ignored entirely.
        http::headers malformed{{"cache-control", "max-age=12x"}};
        expect(!http::parse_request_cache_control(malformed).max_age.has_value());

        // RFC 9111 §5.1 — "Age = delta-seconds" — the Age header field value
        // clamps the same way when calculating the current age.
        auto entry = stored(basic_get("/overflow-age"), http::response{
            .status = 200, .reason = {}, .fields = {{"age", "99999999999"}}},
            instant(1'000), instant(1'000));
        expect(http::current_age(entry, instant(1'000)) ==
               std::chrono::seconds{4'294'967'295});
    };

    "min_fresh_boundary_is_inclusive"_test = [] {
        // RFC 9111 §5.2.1.3 — "The min-fresh request directive indicates
        // that the client prefers a response whose freshness lifetime is no
        // less than its current age plus the specified time in seconds." —
        // at the exact boundary (age + min-fresh == lifetime) the response
        // still satisfies the directive.
        auto request = basic_get("/min-fresh-edge");
        auto entry = stored(request, response_with("max-age=20"),
                            instant(1'000), instant(1'000));
        auto boundary = request;
        boundary.fields.push_back({"cache-control", "min-fresh=10"});
        expect(http::evaluate_cache_use(http::cache_kind::private_, boundary, &entry,
                                        instant(1'010)) == http::cache_action::use);
        auto beyond = request;
        beyond.fields.push_back({"cache-control", "min-fresh=11"});
        expect(http::evaluate_cache_use(http::cache_kind::private_, beyond, &entry,
                                        instant(1'010)) == http::cache_action::revalidate);
    };

    "duplicate_and_invalid_freshness_directives_use_first_occurrence_or_stale"_test = [] {
        // RFC 9111 §4.2.1 — "When there is more than one value present for a
        // given directive (e.g., two Expires header field lines or multiple
        // Cache-Control: max-age directives), either the first occurrence
        // should be used or the response should be considered stale." — the
        // first occurrence is used, so a conflicting later value cannot
        // over-freshen the response.
        http::headers duplicate{{"cache-control", "max-age=60, max-age=5"}};
        expect(http::parse_response_cache_control(duplicate).max_age ==
               std::chrono::seconds{60});
        http::headers across_lines{{"cache-control", "max-age=60"},
                                   {"cache-control", "max-age=5"}};
        expect(http::parse_response_cache_control(across_lines).max_age ==
               std::chrono::seconds{60});
        // RFC 9111 §4.2.1 — "Caches are encouraged to consider responses
        // that have invalid freshness information (e.g., a max-age directive
        // with non-integer content) to be stale." — an invalid first
        // occurrence marks the response stale rather than letting a later
        // occurrence establish freshness.
        http::headers invalid{{"cache-control", "max-age=12x, max-age=60"}};
        auto control = http::parse_response_cache_control(invalid);
        expect(!control.max_age.has_value());
        expect(control.invalid_freshness);
        auto entry = stored(basic_get("/invalid-freshness"), response_with("max-age=12x"));
        expect(http::freshness_lifetime(entry, http::cache_kind::private_) == 0s);
        expect(!http::is_fresh(entry, http::cache_kind::private_, instant(1'000)));
    };

    "http_date_parsing_is_case_insensitive"_test = [] {
        // RFC 9111 §4.2 — "Although all date formats are specified to be
        // case-sensitive, a cache recipient SHOULD match the field value
        // case-insensitively." — lowercase month names and zone abbreviations
        // are accepted.
        auto entry = stored(basic_get("/lowercase-date"), http::response{
            .status = 200, .reason = {},
            .fields = {{"date", "Sun, 06 Nov 2022 08:49:37 GMT"},
                       {"expires", "sun, 06 nov 2022 09:49:37 gmt"}}});
        expect(http::freshness_lifetime(entry, http::cache_kind::private_) == 3600s);
        // RFC 9111 §4.2 — "A cache recipient SHOULD consider a date with a
        // zone abbreviation other than 'GMT' to be invalid for calculating
        // expiration."
        auto other_zone = stored(basic_get("/non-gmt"), http::response{
            .status = 200, .reason = {},
            .fields = {{"date", "Sun, 06 Nov 2022 08:49:37 GMT"},
                       {"expires", "Sun, 06 Nov 2022 09:49:37 UTC"}}});
        expect(http::freshness_lifetime(other_zone, http::cache_kind::private_) == 0s);
    };

    "must_understand_gates_storage_and_overrides_no_store"_test = [] {
        // RFC 9111 §5.2.2.3 — "The must-understand response directive limits
        // caching of the response to a cache that understands and conforms
        // to the requirements for that response's status code."
        // RFC 9111 §5.2.2.3 — "When a cache that implements the
        // must-understand directive receives a response that includes it,
        // the cache SHOULD ignore the no-store directive if it understands
        // and implements the status code's caching requirements."
        http::headers directives{{"cache-control", "must-understand, no-store"}};
        auto control = http::parse_response_cache_control(directives);
        expect(control.must_understand);
        expect(control.no_store);

        auto request = basic_get("/must-understand");
        expect(http::plan_storage(http::cache_kind::private_, request,
                                  response_with("no-store", 200),
                                  instant(1), instant(2)).error() ==
               http::storage_rejection::response_no_store);
        // must-understand with a status the cache understands overrides no-store.
        expect(http::plan_storage(http::cache_kind::private_, request,
                                  response_with("must-understand, no-store", 200),
                                  instant(1), instant(2)).has_value());
        // must-understand with a status the cache does not understand is
        // not storable even when explicit freshness is present.
        auto unknown = http::plan_storage(http::cache_kind::private_, request,
                                          response_with("must-understand, max-age=60", 302),
                                          instant(1), instant(2));
        expect(!unknown.has_value());
        expect(unknown.error() == http::storage_rejection::uncacheable_status);
    };

    "post_storage_is_not_restricted_to_200"_test = [] {
        // RFC 9110 §9.3.3 — "Responses to POST requests are only cacheable
        // when they include explicit freshness information ... and a
        // Content-Location header field that has the same value as the
        // POST's target URI" — the conditions do not restrict the status
        // code, so a 201 with explicit freshness and a matching
        // Content-Location is storable.
        auto post = basic_get("/created?view=full");
        post.method = http::method::POST;
        auto response = response_with("max-age=60", 201);
        response.fields.push_back({"content-location", "/created?view=full"});
        auto plan = http::plan_storage(http::cache_kind::private_, post, response,
                                       instant(1'000), instant(1'000));
        expect(plan.has_value());
        expect(plan->stored.status == 201);
        expect(plan->key.method == http::method::POST);
    };

    "cache_key_distinguishes_methods_for_the_same_uri"_test = [] {
        // RFC 9111 §2 — 'The "cache key" is the information a cache uses to
        // choose a response and is composed from, at a minimum, the request
        // method and target URI used to retrieve the stored response' — a
        // stored POST entry and a GET entry for the same effective URI are
        // distinct keys and must not shadow each other.
        auto get_plan = http::plan_storage(http::cache_kind::private_, basic_get("/keyed"),
                                           response_with("max-age=60"), instant(1), instant(2));
        expect(get_plan.has_value());
        auto post = basic_get("/keyed");
        post.method = http::method::POST;
        auto post_response = response_with("max-age=60");
        post_response.fields.push_back({"content-location", "/keyed"});
        auto post_plan = http::plan_storage(http::cache_kind::private_, post, post_response,
                                            instant(1), instant(2));
        expect(post_plan.has_value());
        expect(get_plan->key != post_plan->key);
        expect(get_plan->key.effective_uri == post_plan->key.effective_uri);
    };

    "quoted_string_directive_arguments_keep_inner_commas"_test = [] {
        // RFC 9111 §5.2.2 — "cache-directive = token [ "=" ( token /
        // quoted-string ) ]" and RFC 9110 §5.6.4 — "quoted-string = DQUOTE
        // *( qdtext / quoted-pair ) DQUOTE" — a comma inside a quoted-string
        // argument (e.g. the qualified form private="Set-Cookie,
        // Authorization") is data, not a directive separator, so the
        // directive after the closing DQUOTE must still be parsed, and a
        // token inside the quotes must not become a directive.
        http::headers qualified{{"cache-control",
                                 "private=\"Set-Cookie, Authorization\", max-age=60"}};
        auto control = http::parse_response_cache_control(qualified);
        expect(control.private_);
        expect(control.max_age == std::chrono::seconds{60});
        // RFC 9110 §5.6.4 — "quoted-pair = "\" ( HTAB / SP / VCHAR /
        // obs-text )" — a backslash-escaped DQUOTE does not close the quoted
        // string, so the comma after it is still inside the argument.
        http::headers escaped{{"cache-control",
                               "private=\"Set-Cookie, \\\"Authorization\\\", X\", max-age=30"}};
        auto escaped_control = http::parse_response_cache_control(escaped);
        expect(escaped_control.private_);
        expect(escaped_control.max_age == std::chrono::seconds{30});
    };

    "request_directives_use_first_occurrence_and_keep_earlier_valid_value"_test = [] {
        // RFC 9111 §4.2.1 — "When there is more than one value present for a
        // given directive (e.g., two Expires header field lines or multiple
        // Cache-Control: max-age directives), either the first occurrence
        // should be used or the response should be considered stale." — the
        // request directives apply the same first-occurrence choice.
        http::headers duplicate{{"cache-control", "max-age=60, max-age=5"}};
        expect(http::parse_request_cache_control(duplicate).max_age ==
               std::chrono::seconds{60});
        http::headers min_fresh{{"cache-control", "min-fresh=10, min-fresh=1"}};
        expect(http::parse_request_cache_control(min_fresh).min_fresh ==
               std::chrono::seconds{10});
        http::headers max_stale{{"cache-control", "max-stale=9, max-stale=1"}};
        expect(http::parse_request_cache_control(max_stale).max_stale ==
               std::chrono::seconds{9});
        // An unparseable duplicate must not erase an already-parsed value:
        // the earlier valid bound survives (conservative, per the same
        // §4.2.1 first-occurrence choice).
        http::headers invalid_second{{"cache-control", "max-age=60, max-age=12x"}};
        expect(http::parse_request_cache_control(invalid_second).max_age ==
               std::chrono::seconds{60});
        // An unparseable first occurrence is skipped, letting the first
        // parseable occurrence win.
        http::headers invalid_first{{"cache-control", "max-age=12x, max-age=60"}};
        expect(http::parse_request_cache_control(invalid_first).max_age ==
               std::chrono::seconds{60});
    };
};

} // namespace httpant::testing
