module;

#include <nghttp2/nghttp2.h>

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <stdexcept>
#include <string_view>
#include <utility>
#include <vector>

export module httpant:serialize.nghttp2;

import :session.nghttp2;
import :trait;
import :message;

export namespace http::v2 {

namespace detail {

inline auto setting_identifier(setting_name name) -> std::int32_t {
    return static_cast<std::int32_t>(std::to_underlying(name));
}

inline auto make_settings(std::span<const setting> settings)
    -> std::vector<nghttp2_settings_entry>
{
    std::vector<nghttp2_settings_entry> entries;
    entries.reserve(settings.size());
    for (const auto& setting : settings)
        entries.push_back({setting_identifier(setting.name), setting.value});
    return entries;
}

inline auto read_outbound_body(
    nghttp2_session*,
    std::int32_t,
    uint8_t* buf,
    std::size_t length,
    uint32_t* flags,
    nghttp2_data_source* src,
    void*) -> nghttp2_ssize
{
    auto* state = static_cast<outbound_body_state*>(src->ptr);
    if (state == nullptr) return NGHTTP2_ERR_CALLBACK_FAILURE;
    bool eof = false;
    auto n = state->read(buf, length, eof);
    if (eof) {
        state->deferred = false;
        *flags |= NGHTTP2_DATA_FLAG_EOF;
        return static_cast<nghttp2_ssize>(n.value_or(0));
    }
    if (!n) {
        state->deferred = true;
        return NGHTTP2_ERR_DEFERRED;
    }
    state->deferred = false;
    return static_cast<nghttp2_ssize>(*n);
}

// The outbound body plumbing shared by client requests and server (including
// pushed) responses: a body_bridge the exchange coroutine refills, an
// outbound_body_state nghttp2's data provider drains, and the provider binding
// the two. The provider's source points at the shared state, so the binding
// must be moved as a whole (the provider never outlives the binding).
template <body_stream Body>
struct outbound_body_binding {
    std::shared_ptr<body_bridge<Body>> bridge;
    std::shared_ptr<outbound_body_state> state;
    nghttp2_data_provider2 provider;
};

template <body_stream Body>
inline auto bind_outbound_body(Body& body) -> outbound_body_binding<Body> {
    auto bridge = std::make_shared<body_bridge<Body>>(body);
    auto state = std::make_shared<outbound_body_state>();
    state->read = [bridge](std::uint8_t* destination, std::size_t size, bool& eof) {
        return bridge->read(destination, size, eof);
    };
    auto* raw_state = state.get();
    return {
        .bridge = std::move(bridge),
        .state = std::move(state),
        .provider = nghttp2_data_provider2{
            .source = nghttp2_data_source{.ptr = raw_state},
            .read_callback = &read_outbound_body,
        },
    };
}

inline auto make_nv(std::string_view name, std::string_view value) -> nghttp2_nv {
    auto sensitive = http::detail::is_sensitive_field_name(name);
    // The const_cast is safe: nghttp2 never mutates the name/value bytes — it
    // copies them into its own buffers at submit time (nghttp2_submit_request2
    // / nghttp2_submit_response2 document that the nv arrays may be freed once
    // the call returns); the non-const pointer is a C API artifact.
    return {
        .name = reinterpret_cast<uint8_t*>(const_cast<char*>(name.data())),
        .value = reinterpret_cast<uint8_t*>(const_cast<char*>(value.data())),
        .namelen = name.size(),
        .valuelen = value.size(),
        // RFC 7541 §7.1.3 — sensitive fields can use the literal never-indexed
        // representation so intermediaries do not add them to a dynamic table.
        .flags = static_cast<std::uint8_t>(
            sensitive ? NGHTTP2_NV_FLAG_NO_INDEX : NGHTTP2_NV_FLAG_NONE),
    };
}

} // namespace detail
} // namespace http::v2
