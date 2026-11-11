export module httpant:serialize.nghttp3;
import httpant.exception;

import httpant.dependencies.nghttp3;
import std;
import :trait;
import :message;
import :session.nghttp3;

export namespace http::v3 {

namespace detail {

// Request/response objects own these strings through submit; the library
// copies names and values because neither NO_COPY flag is set.
inline auto make_nv(std::string_view name, std::string_view value) -> nghttp3_nv {
    return {
        .name = reinterpret_cast<const std::uint8_t*>(name.data()),
        .value = reinterpret_cast<const std::uint8_t*>(value.data()),
        .namelen = name.size(),
        .valuelen = value.size(),
        .flags = static_cast<std::uint8_t>(http::detail::is_sensitive_field_name(name)
            ? NGHTTP3_NV_FLAG_NEVER_INDEX : NGHTTP3_NV_FLAG_NONE),
    };
}

// RFC 9114 §4.2.2 — "The size of a field list is calculated based on the
// uncompressed size of fields, including the length of the name and value in
// bytes plus an overhead of 32 bytes for each field."
inline auto field_section_size(std::span<const nghttp3_nv> fields) -> std::uint64_t {
    std::uint64_t size = 0;
    for (const auto& field : fields)
        size += static_cast<std::uint64_t>(field.namelen) + field.valuelen +
            field_entry_overhead;
    return size;
}

// RFC 9114 §4.2.2 — "An implementation that has received this parameter
// SHOULD NOT send an HTTP message header that exceeds the indicated size, as
// the peer will likely refuse to process it." (RFC 9114 §7.2.4.2 — "An HTTP
// implementation MUST NOT send frames or requests that would be invalid based
// on its current understanding of the peer's settings.") The peer's
// SETTINGS_MAX_FIELD_SECTION_SIZE defaults to unlimited until a SETTINGS
// frame arrives, so before that point every outbound field section passes.
template <template <class> class Queue>
inline void check_outbound_field_section(const conn_context<Queue>& ctx, std::span<const nghttp3_nv> fields) {
    if (field_section_size(fields) > ctx.peer_max_field_section_size)
        throw usage_error(
            "http/3: field section exceeds peer SETTINGS_MAX_FIELD_SECTION_SIZE");
}

template <body_stream Body, template <class> class Queue>
inline auto fill_outbound_body(Body& body, outbound_body_state<Queue>& state) -> http::detail::operation<void> {
    state.data.resize(body_buffer_limit);
    auto size = co_await body.async_read(std::span{state.data}, co_await current_stop_token());
    if (size > state.data.size())
        throw usage_error("http/3: body source returned an invalid byte count");
    state.data.resize(size);
    state.acknowledged = 0;
    state.offered = false;
    state.eof = size == 0;
}
// Parks pump_outbound_body while a body chunk has been offered to nghttp3 but
// not yet released. flush() releases a chunk once the transport accepts its
// copy; a flush already running for another stream may still hold the gate.
template <template <class> class Queue>
inline auto outbound_ack(outbound_body_state<Queue>& state) {
    return http::detail::park_until{state.ack_waiter, [&state] {
        return state.data.empty() || !state.offered;
    }};
}

template <body_stream Body, stream_factory S, template <class> class Queue>
inline auto pump_outbound_body(
    Body& body,
    outbound_body_state<Queue>& state,
    std::int64_t stream_id,
    nghttp3_conn* connection,
    endpoint_runtime<S, Queue>& runtime) -> http::detail::operation<void>
{
    for (;;) {
        co_await runtime.flush();
        if (!state.eof && state.data.empty()) {
            co_await fill_outbound_body(body, state);
            check(nghttp3_conn_resume_stream(connection, stream_id), "resume_stream");
            continue;
        }
        if (state.eof && state.data.empty())
            co_return;
        // The current chunk has been offered to nghttp3 and is waiting for
        // the transport. Wait for acked_stream_data to clear it instead of
        // re-entering flush() and busy-polling.
        co_await outbound_ack(state);
    }
}

template <template <class> class Queue>
inline auto read_outbound_body(
    nghttp3_conn*,
    std::int64_t,
    nghttp3_vec* vec,
    std::size_t veccnt,
    std::uint32_t* flags,
    void* user_data,
    void* stream_user_data) noexcept -> nghttp3_ssize
{
    auto& ctx = *static_cast<conn_context<Queue>*>(user_data);
    try {
        auto* state = static_cast<outbound_body_state<Queue>*>(stream_user_data);
        if (state == nullptr)
            throw std::logic_error("http/3: missing outbound body stream state");
        if (veccnt == 0)
            throw std::logic_error("http/3: outbound body read called with no vector capacity");
        // RFC 9114 §4.1 — "After sending a request, a client MUST close the stream for sending. After sending a final response, the server MUST close the stream for sending."
        if (state->eof && state->data.empty()) {
            *flags |= NGHTTP3_DATA_FLAG_EOF;
            return 0;
        }
        if (state->data.empty())
            return NGHTTP3_ERR_WOULDBLOCK;
        if (state->offered)
            return NGHTTP3_ERR_WOULDBLOCK;

        vec[0].base = reinterpret_cast<std::uint8_t*>(state->data.data());
        vec[0].len = state->data.size();
        state->offered = true;
        if (state->eof)
            *flags |= NGHTTP3_DATA_FLAG_EOF;
        return 1;
    } catch (...) {
        ctx.core.pending_callback_failure = http::exceptions::current_exception();
        return NGHTTP3_ERR_CALLBACK_FAILURE;
    }
}

} // namespace detail

} // namespace http::v3
