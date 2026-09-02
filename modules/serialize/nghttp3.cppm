module;

#include <nghttp3/nghttp3.h>

#include <cassert>
#include <coroutine>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <span>
#include <stdexcept>
#include <stop_token>
#include <string>
#include <string_view>
#include <vector>

export module httpant:serialize.nghttp3;

import :trait;
import :message;
import :session.nghttp3;

export namespace http::v3 {

namespace detail {

struct nv_block {
    std::vector<std::string> storage{};
    std::vector<nghttp3_nv> fields{};

    explicit nv_block(std::size_t count = 0) {
        storage.reserve(count * 2);
        fields.reserve(count);
    }

    void push(std::string_view name, std::string_view value) {
        // Pointer stability is load-bearing: every stored nghttp3_nv borrows
        // .data() from the two strings emplaced below, so a reallocation here
        // would dangle each previously stored pointer. The reserve(count*2) /
        // reserve(count) at construction is therefore a hard bound, not a
        // hint; one push beyond it is a caller bug.
        assert(storage.size() + 2 <= storage.capacity() &&
               "http/3: nv_block storage grew past its reservation");
        assert(fields.size() + 1 <= fields.capacity() &&
               "http/3: nv_block fields grew past their reservation");
        storage.emplace_back(name);
        storage.emplace_back(value);
        auto& sn = storage[storage.size() - 2];
        auto& sv = storage[storage.size() - 1];
        fields.push_back({
            .name = reinterpret_cast<const uint8_t*>(sn.data()),
            .value = reinterpret_cast<const uint8_t*>(sv.data()),
            .namelen = sn.size(),
            .valuelen = sv.size(),
            // RFC 9204 §4.5.4/§4.5.6 — the 'N' bit of a literal field line
            // marks the field as never-indexed; RFC 9204 §7.1.3 — "The
            // never-indexed literal bit ... can be used to signal to
            // intermediaries that a particular value was intentionally sent
            // as a literal." Sensitive fields therefore use the literal
            // representation with the N bit set and are never inserted into
            // the dynamic table.
            .flags = static_cast<std::uint8_t>(
                http::detail::is_sensitive_field_name(name)
                    ? NGHTTP3_NV_FLAG_NEVER_INDEX
                    : NGHTTP3_NV_FLAG_NONE),
        });
    }
};

// RFC 9114 §4.2.2 — "The size of a field list is calculated based on the
// uncompressed size of fields, including the length of the name and value in
// bytes plus an overhead of 32 bytes for each field."
inline auto field_section_size(const nv_block& block) -> std::uint64_t {
    std::uint64_t size = 0;
    for (const auto& field : block.fields)
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
inline void check_outbound_field_section(const conn_context& ctx, const nv_block& block) {
    if (field_section_size(block) > ctx.peer_max_field_section_size)
        throw std::runtime_error(
            "http/3: field section exceeds peer SETTINGS_MAX_FIELD_SECTION_SIZE");
}

template <body_stream Body>
inline auto fill_outbound_body(
    Body& body,
    outbound_body_state& state,
    std::stop_token stop) -> task<void>
{
    state.data.resize(body_buffer_limit);
    auto size = co_await body.async_read(std::span{state.data}, stop);
    if (size > state.data.size())
        throw std::runtime_error("http/3: body source returned an invalid byte count");
    state.data.resize(size);
    state.acknowledged = 0;
    state.offered = false;
    state.eof = size == 0;
}
// Parks pump_outbound_body while a body chunk has been offered to nghttp3 but
// not yet fully acknowledged. Without this wait, a transport whose
// acknowledgement completes before nghttp3's acked_stream_data callback would
// spin in flush() until the peer ACK clears the retained chunk.
struct outbound_ack_awaiter {
    outbound_body_state& state;

    [[nodiscard]] bool await_ready() const noexcept {
        return state.data.empty() || !state.offered;
    }
    void await_suspend(std::coroutine_handle<> handle) {
        if (state.ack_waiter)
            throw std::logic_error("http/3: second outbound ack wait parked on the same body");
        state.ack_waiter = handle;
    }
    void await_resume() const noexcept {}
};

template <body_stream Body, stream_factory S>
inline auto pump_outbound_body(
    Body& body,
    outbound_body_state& state,
    std::int64_t stream_id,
    nghttp3_conn* connection,
    endpoint_runtime<S>& runtime) -> task<void>
{
    for (;;) {
        co_await runtime.flush();
        if (!state.eof && state.data.empty()) {
            co_await fill_outbound_body(body, state, runtime.stop_token());
            check(nghttp3_conn_resume_stream(connection, stream_id), "resume_stream");
            continue;
        }
        if (state.eof && state.data.empty())
            co_return;
        // The current chunk has been offered to nghttp3 and is waiting for
        // the peer ACK. Wait for acked_stream_data to clear it instead of
        // re-entering flush() and busy-polling.
        co_await outbound_ack_awaiter{state};
    }
}

inline auto read_outbound_body(
    nghttp3_conn*,
    std::int64_t,
    nghttp3_vec* vec,
    std::size_t veccnt,
    std::uint32_t* flags,
    void* user_data,
    void* stream_user_data) noexcept -> nghttp3_ssize
{
    auto& ctx = *static_cast<conn_context*>(user_data);
    try {
        auto* state = static_cast<outbound_body_state*>(stream_user_data);
        if (state == nullptr)
            throw std::runtime_error("http/3: missing outbound body stream state");
        if (veccnt == 0)
            throw std::runtime_error("http/3: outbound body read called with no vector capacity");
        // RFC 9114 §4.1 — "After sending a request, a client MUST close the stream for sending. After sending a final response, the server MUST close the stream for sending."
        if (state->eof && state->data.empty()) {
            *flags |= NGHTTP3_DATA_FLAG_EOF;
            return 0;
        }
        if (state->data.empty())
            return NGHTTP3_ERR_WOULDBLOCK;
        if (state->offered)
            return NGHTTP3_ERR_WOULDBLOCK;

        vec[0].base = reinterpret_cast<uint8_t*>(state->data.data());
        vec[0].len = state->data.size();
        state->offered = true;
        if (state->eof)
            *flags |= NGHTTP3_DATA_FLAG_EOF;
        return 1;
    } catch (...) {
        ctx.core.pending_callback_failure = std::current_exception();
        return NGHTTP3_ERR_CALLBACK_FAILURE;
    }
}

} // namespace detail

} // namespace http::v3
