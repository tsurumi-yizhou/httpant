export module httpant:session.core;

import std;
import :trait;
import :message;
import :error;

// Version-free machinery shared by the HTTP/2 (nghttp2) and HTTP/3 (nghttp3)
// session layers. The per-engine session files keep their public configuration
// types, engine-owned handles/deleters, callback glue, and engine-specific
// state; this partition holds the parts that are textually identical or
// engine-agnostic so the protocol semantics live in exactly one place.
export namespace http {

namespace detail {

// ─── Engine object handles ──────────────────────────────────

// An owned engine object: a unique_ptr bound to the engine's destructor. The
// deleter is engine-provided (it calls the engine's own teardown API, e.g.
// nghttp2_session_del / nghttp3_conn_del), so the handle itself is
// version-free and both session files alias their handles through it.
template <typename T, typename Deleter>
using engine_handle = std::unique_ptr<T, Deleter>;

// ─── Protocol-error construction ─────────────────────────────

// RFC 9113 §6.8 / RFC 9114 §5.2 — streams above the peer's GOAWAY boundary
// were not processed and can be retried on a different connection. GOAWAY
// itself is already the wire signal, so rejecting the local operation needs no
// action. The engine's message prefix is a template argument, so the constant
// is part of the call, not a runtime string that can be the wrong one.
template <literal Prefix>
[[nodiscard]] inline auto make_goaway_rejection(
    std::optional<std::uint64_t> exchange) -> protocol_error
{
    return protocol_error{
        error_info{
            .scope = exchange ? error_scope::stream : error_scope::message,
            .condition = error_condition::goaway_rejected,
            .exchange_identity = exchange,
            .library_code = std::nullopt,
        },
        no_action{},
        std::string(Prefix.view()) + "request rejected by GOAWAY"};
}

// Shared protocol_error construction core: the engine builders fill the typed
// error_info (message structs use designated initializers), pair it with the
// RFC-required protocol action, and prefix the detail message with the engine's own
// constant — the pattern v2's reset-failure builder and v3's frame /
// stream-message builders all repeat. Engine-side wrappers (v2's code-pair
// selection, v3's record_* glue and fused builders) stay in the engine files.
template <literal Prefix, typename Action>
[[nodiscard]] inline auto make_protocol_error(
    error_info info,
    Action action,
    std::string_view detail) -> protocol_error
{
    return protocol_error{
        std::move(info),
        std::move(action),
        std::string(Prefix.view()) + std::string(detail)};
}

// ─── C callback exception boundary ───────────────────────────

// Exceptions cannot propagate through the engines' C callback ABI, so every
// engine callback body runs behind this boundary: a thrown exception is
// latched into the connection context (pending_callback_failure, rethrown by
// the endpoint driver after the engine call returns) and the engine receives
// its own callback-failure code instead. The callback may return void
// (success maps to 0) or an int engine result code (forwarded). Both nghttp2
// and nghttp3 share this exact semantics; only the failure code differs.
template <typename Ctx, typename Callback>
inline auto callback_boundary(Ctx& ctx, int engine_failure_code, Callback&& callback) noexcept
    -> int {
    try {
        if constexpr (std::is_void_v<std::invoke_result_t<Callback>>) {
            callback();
            return 0;
        } else {
            return std::forward<Callback>(callback)();
        }
    } catch (...) {
        ctx.core.pending_callback_failure = std::current_exception();
        return engine_failure_code;
    }
}

// ─── Per-stream waiter state ─────────────────────────────────

// The shared core of the two engine stream_data structs: the flags a request /
// response stream's lifecycle latches, the decoded field section, the three
// single-waiter slots (headers / body data / send capacity), and the wake
// helpers. The engines embed it and keep their body-storage and error-code
// members around it (v2: byte_cursor body, credit_settled, peer/local reset
// pair; v3: deque body, close_error_code, field_section_size).
template <typename Id, template <class> class Queue = http::queues::local>
struct stream_state_core {
    Id id{0};
    bool headers_done{false};
    bool complete{false};
    bool closed{false};
    bool aborted{false};
    http::detail::decoded_fields decoded{};
    http::status status_code{};
    // Whether the exchange has crossed the public delivery boundary (a server
    // request delivered to receive() / a client response delivered to the
    // application); the driver uses it to queue each exchange exactly once.
    bool delivered{false};
    // Single-waiter slots (waiter_slot): at most one coroutine may park on
    // each; parking a second throws std::logic_error (asserted at the
    // awaiters). Resumptions are claimed with std::exchange so a normal wakeup
    // and a stop callback can never both resume the same coroutine.
    waiter_slot<Queue> headers_waiter{};
    waiter_slot<Queue> body_waiter{};
    waiter_slot<Queue> capacity_waiter{};

    // The headers slot is resumed by resume_waiter, matching the v3 engine's
    // established names.
    void resume_waiter() noexcept { headers_waiter.resume(); }
    void resume_body_waiter() noexcept { body_waiter.resume(); }
    void resume_capacity_waiter() noexcept { capacity_waiter.resume(); }
};

// Resume only conditions made ready by data, capacity, or terminal events.
template <typename Id, template <class> class Queue>
void wake_stream_conditions(
    stream_state_core<Id, Queue>& stream,
    bool has_body,
    bool goaway_rejected,
    bool connection_failed,
    bool capacity_ready) noexcept
{
    // RFC 9113 §6.8 / RFC 9114 §5.2 — a stream covered by GOAWAY, or any
    // stream after a connection failure, must wake its header waiter so a
    // suspended exchange fails fast instead of hanging; a complete or aborted
    // stream delivers EOF / the typed abort to its body reader.
    if (stream.headers_done || stream.aborted || goaway_rejected ||
        connection_failed)
        stream.resume_waiter();
    if (has_body || stream.complete || stream.aborted || connection_failed)
        stream.resume_body_waiter();
    if (capacity_ready || stream.closed || stream.aborted || goaway_rejected || connection_failed)
        stream.resume_capacity_waiter();
}

// ─── Connection-level waiter state ───────────────────────────

// The common core of the two engine connection contexts (v2's session_context
// / v3's conn_context): the per-stream and per-outbound-body registries, the
// queue of completed server request streams awaiting receive(), the GOAWAY
// flag and boundary, the first-wins connection-error latch, the
// callback-failure slot, and the single receive() waiter. The engines embed
// it and keep their protocol-specific state around it (v2: push machinery,
// origin, settings generations, GOAWAY richness, output buffer; v3: control /
// QPACK stream ids, peer settings snapshot, connection error code). Stream
// must embed stream_state_core<Id> as `core`.
template <typename Id, typename Stream, typename OutboundBody, template <class> class Queue = http::queues::local>
struct connection_core {
    std::unordered_map<Id, std::shared_ptr<Stream>> streams{};
    std::unordered_map<Id, std::shared_ptr<OutboundBody>> outbound_bodies{};
    http::queues::buffer<std::shared_ptr<Stream>, Queue> receive_queue{};
    [[nodiscard]] auto receive_queue_empty() const noexcept -> bool { return receive_queue.empty(); }
    void receive_queue_push(std::shared_ptr<Stream> stream) { receive_queue.push_back(std::move(stream)); }
    [[nodiscard]] auto receive_queue_front() noexcept -> const std::shared_ptr<Stream>& { return receive_queue.front(); }
    void receive_queue_pop() { receive_queue.pop_front(); }

    bool goaway_received{false};
    // RFC 9113 §6.8 / RFC 9114 §5.2 — the last stream id the peer's GOAWAY
    // declared; streams above it were not processed and must fail fast.
    std::optional<Id> goaway_id{};
    // A connection-level failure recorded by the endpoint-owned driver (a
    // protocol violation on any stream, or a transport failure). Once set,
    // every subsequent operation fails fast instead of hanging on a stream
    // whose reader already stopped.
    std::exception_ptr connection_error{};
    // An exception a C callback boundary caught; the driver rethrows it after
    // the engine call returns, because it cannot propagate through the C API.
    std::exception_ptr pending_callback_failure{};
    // The endpoint-owned driver resumes this waiter once a server stream
    // completes (or the connection fails), so receive() can suspend until the
    // next request arrives. Single-waiter slot (waiter_slot).
    waiter_slot<Queue> receive_waiter{};
};

// Connection failure router: first-wins latch of the typed failure, then every
// stream wakes through the condition table with the connection-failure signal
// and the receive waiter is resumed, so no operation hangs once the driver has
// stopped. The stream_factory's serialized completion contract and v2's
// sole-reader driver both require the wake to happen exactly once per failure.
// Engine drivers keep their own failure cleanup around this core (v3 marks
// streams aborted and terminates outbound bodies; v2 additionally wakes its
// handshake waiter).
template <typename Id, typename Stream, typename OutboundBody, template <class> class Queue>
void fail_connection(
    connection_core<Id, Stream, OutboundBody, Queue>& ctx,
    std::exception_ptr failure) noexcept
{
    if (ctx.connection_error)
        return;
    ctx.connection_error = std::move(failure);
    // A woken exchange can erase its own entry, so wake from a snapshot.
    std::vector<std::shared_ptr<Stream>> streams;
    streams.reserve(ctx.streams.size());
    for (auto& [_, stream] : ctx.streams)
        streams.push_back(stream);
    for (auto& stream : streams)
        wake_stream_conditions(stream->core, false, false, true, false);
    ctx.receive_waiter.resume();
}

} // namespace detail

} // namespace http
