module;

#include <algorithm>
#include <concepts>
#include <coroutine>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <optional>
#include <span>
#include <stdexcept>
#include <stop_token>
#include <type_traits>
#include <utility>
#include <vector>

#include <stdexec/execution.hpp>

export module httpant:trait;

export namespace http {

namespace detail {

struct task_promise_base;

struct task_final_awaiter {
    bool await_ready() const noexcept { return false; }

    template <typename Promise>
    auto await_suspend(std::coroutine_handle<Promise> handle) const noexcept
        -> std::coroutine_handle<>;

    void await_resume() const noexcept {}
};

struct task_promise_base {
    std::exception_ptr exception_;
    std::coroutine_handle<> continuation_;
    void* operation_{};
    void (*complete_)(void*) noexcept{};
    const void* stop_token_{};
    bool (*stop_requested_)(const void*) noexcept{};

    auto initial_suspend() noexcept -> std::suspend_always { return {}; }
    auto final_suspend() noexcept -> task_final_awaiter { return {}; }
    void unhandled_exception() noexcept { exception_ = std::current_exception(); }

    [[nodiscard]] auto stop_requested() const noexcept -> bool {
        return stop_requested_ != nullptr && stop_requested_(stop_token_);
    }
};

template <typename Promise>
auto task_final_awaiter::await_suspend(std::coroutine_handle<Promise> handle) const noexcept
    -> std::coroutine_handle<> {
    auto& promise = handle.promise();
    if (promise.complete_ != nullptr) {
        promise.complete_(promise.operation_);
        return std::noop_coroutine();
    }
    if (promise.continuation_)
        return promise.continuation_;
    return std::noop_coroutine();
}

// The only difference between task<T> and task<void> is the result channel
// (return_value vs return_void), so the storage lives here and a single task
// implementation serves both.
template <typename T>
struct task_result {
    std::optional<T> result_;

    void return_value(T value) { result_.emplace(std::move(value)); }
};

template <>
struct task_result<void> {
    void return_void() noexcept {}
};

// set_value_t(T) would be ill-formed for T = void (a substituted void
// parameter is not the (void) special case), so the signatures are selected
// here alongside the result storage.
template <typename T>
struct task_completion {
    using signatures = stdexec::completion_signatures<
        stdexec::set_value_t(T),
        stdexec::set_error_t(std::exception_ptr),
        stdexec::set_stopped_t()>;
};

template <>
struct task_completion<void> {
    using signatures = stdexec::completion_signatures<
        stdexec::set_value_t(),
        stdexec::set_error_t(std::exception_ptr),
        stdexec::set_stopped_t()>;
};

} // namespace detail

// A lazy, single-consumer, move-only coroutine with no executor: drive it
// with .start() or co_await, or connect() it as a P2300 sender. T = void
// shares this exact implementation through detail::task_result.
template <typename T = void>
class task {
public:
    struct promise_type : detail::task_promise_base, detail::task_result<T> {
        auto get_return_object() -> task {
            return task{std::coroutine_handle<promise_type>::from_promise(*this)};
        }
    };

    using handle_type = std::coroutine_handle<promise_type>;
    using sender_concept = stdexec::sender_tag;
    using completion_signatures = typename detail::task_completion<T>::signatures;

    task() = default;
    explicit task(handle_type handle) : handle_(handle) {}
    task(const task&) = delete;
    auto operator=(const task&) -> task& = delete;
    task(task&& other) noexcept
        : handle_(std::exchange(other.handle_, {})),
          started_(std::exchange(other.started_, false)) {}
    auto operator=(task&& other) noexcept -> task& {
        if (this != &other) {
            if (handle_)
                handle_.destroy();
            handle_ = std::exchange(other.handle_, {});
            started_ = std::exchange(other.started_, false);
        }
        return *this;
    }
    ~task() {
        if (handle_)
            handle_.destroy();
    }

    struct awaiter {
        handle_type handle_;

        explicit awaiter(handle_type handle) noexcept : handle_(handle) {}
        awaiter(const awaiter&) = delete;
        auto operator=(const awaiter&) -> awaiter& = delete;
        awaiter(awaiter&& other) noexcept : handle_(std::exchange(other.handle_, {})) {}
        ~awaiter() {
            if (handle_)
                handle_.destroy();
        }

        bool await_ready() const noexcept { return !handle_ || handle_.done(); }
        auto await_suspend(std::coroutine_handle<> continuation) noexcept -> handle_type {
            handle_.promise().continuation_ = continuation;
            return handle_;
        }
        auto await_resume() -> T {
            if (!handle_)
                throw std::runtime_error("task: no coroutine");
            if (handle_.promise().exception_)
                std::rethrow_exception(handle_.promise().exception_);
            if constexpr (!std::is_void_v<T>)
                return std::move(*handle_.promise().result_);
        }
    };

    [[nodiscard]] auto operator co_await() && -> awaiter {
        return awaiter{std::exchange(handle_, {})};
    }

    // Starts the coroutine without a receiver. Starting is explicit one-shot
    // state: repeated calls are no-ops, so a live coroutine can never be
    // resumed twice from here.
    void start() {
        if (!handle_ || started_)
            return;
        started_ = true;
        if (!handle_.done())
            handle_.resume();
    }

    [[nodiscard]] auto done() const noexcept -> bool {
        return !handle_ || handle_.done();
    }

    template <typename Receiver>
    class operation {
    public:
        using operation_state_concept = stdexec::operation_state_tag;

        operation(handle_type handle, Receiver receiver)
            : handle_(handle), receiver_(std::move(receiver)) {}
        operation(const operation&) = delete;
        auto operator=(const operation&) -> operation& = delete;
        operation(operation&&) = delete;
        auto operator=(operation&&) -> operation& = delete;
        ~operation() {
            if (handle_)
                handle_.destroy();
        }

        void start() noexcept {
            if (!handle_) {
                stdexec::set_error(std::move(receiver_), std::make_exception_ptr(
                    std::runtime_error("task: no coroutine")));
                return;
            }

            auto token = stdexec::get_stop_token(stdexec::get_env(receiver_));
            stop_token_.emplace(std::move(token));
            auto& promise = handle_.promise();
            promise.operation_ = this;
            promise.complete_ = &operation::complete;
            promise.stop_token_ = &*stop_token_;
            promise.stop_requested_ = [](const void* value) noexcept {
                return static_cast<const stop_token_type*>(value)->stop_requested();
            };
            if (handle_.done()) {
                // The coroutine already ran to completion through
                // task::start(); deliver the stored result instead of
                // resuming a finished coroutine (which is UB).
                complete(this);
                return;
            }
            if (promise.stop_requested()) {
                stdexec::set_stopped(std::move(receiver_));
                return;
            }
            handle_.resume();
        }

    private:
        using stop_token_type = decltype(stdexec::get_stop_token(
            stdexec::get_env(std::declval<const Receiver&>())));

        static void complete(void* value) noexcept {
            auto& self = *static_cast<operation*>(value);
            auto& promise = self.handle_.promise();
            // A coroutine that reached its final suspend produced a result;
            // deliver it even when cancellation raced with completion.
            // Stopped is reserved for work that never ran (the short-circuit
            // in start()).
            if (promise.exception_) {
                stdexec::set_error(std::move(self.receiver_), promise.exception_);
            } else if constexpr (std::is_void_v<T>) {
                stdexec::set_value(std::move(self.receiver_));
            } else {
                stdexec::set_value(std::move(self.receiver_), std::move(*promise.result_));
            }
        }

        handle_type handle_;
        Receiver receiver_;
        std::optional<stop_token_type> stop_token_;
    };

    template <typename Receiver>
    [[nodiscard]] auto connect(Receiver receiver) && -> operation<Receiver> {
        return operation<Receiver>{std::exchange(handle_, {}), std::move(receiver)};
    }

private:
    handle_type handle_{};
    bool started_{false};
};

// ─── Transport concepts ──────────────────────────────────────

namespace detail {

template <typename A>
concept has_await_members = requires(A a) {
    { a.await_ready() } -> std::convertible_to<bool>;
    a.await_suspend(std::coroutine_handle<>{});
    a.await_resume();
};

template <typename A>
concept has_member_co_await = requires(A a) {
    std::move(a).operator co_await();
};

template <typename A>
concept has_free_co_await = requires(A a) {
    operator co_await(std::move(a));
};

template <typename A>
concept awaitable = has_await_members<A> || has_member_co_await<A> || has_free_co_await<A>;

template <typename A>
decltype(auto) get_awaiter(A&& awaitable_value) {
    if constexpr (requires { std::forward<A>(awaitable_value).operator co_await(); }) {
        return std::forward<A>(awaitable_value).operator co_await();
    } else if constexpr (requires { operator co_await(std::forward<A>(awaitable_value)); }) {
        return operator co_await(std::forward<A>(awaitable_value));
    } else {
        return std::forward<A>(awaitable_value);
    }
}

// Internal: an awaitable whose await_resume() yields exactly T. Unlike
// `awaitable`, which only checks the awaiter shape, this verifies the value
// channel so a transport that returns the wrong byte count (or a stream-shaped
// object where a byte count belongs) fails at compile time.
template <typename A, typename T>
concept awaitable_result = requires(A awaitable_value) {
    { get_awaiter(std::move(awaitable_value)).await_resume() } -> std::same_as<T>;
};

} // namespace detail

// A readable asynchronous body source. Message bodies are expressed as this:
// the producer (protocol layer on the read path, caller on the write path)
// exposes async_read, and the consumer reads until it returns 0 (EOF). The
// operation accepts a std::stop_token so a suspended read can be cancelled.
template <typename S>
concept body_stream = requires(S& s, std::span<std::byte> buf, std::stop_token stop) {
    { s.async_read(buf, stop) } -> detail::awaitable_result<std::size_t>;
};

// A protocol head together with a lazily-read body stream (Body must satisfy
// body_stream). Protocol read operations return this so the caller can consume
// the body incrementally instead of the library buffering it.
template <typename Head, typename Body>
struct received {
    Head head;
    Body body;
};

namespace detail {

// A single-slot coroutine waiter: at most one coroutine may park on a slot at
// a time (a second park throws std::logic_error, since it would silently
// overwrite the first handle and hang it), and a wakeup is claimed with
// std::exchange so a normal resume and a stop cancellation can never both
// resume the same coroutine. The stop-claim ordering is park first, then
// re-check the stop token, un-parking (take) on cancel — registering a
// std::stop_callback only after the slot is claimed means the callback never
// fires reentrantly inside its own construction for an already-stopped token.
// The engine awaiters keep their own await_ready predicates; this slot is only
// the park/resume mechanism every stream and connection waiter shares.
class waiter_slot {
public:
    // Park: records the suspended coroutine. Throws std::logic_error when the
    // slot is already claimed (asserted at the awaiters).
    void park(std::coroutine_handle<> handle) {
        if (handle_)
            throw std::logic_error("httpant: second waiter parked on a single-slot waiter");
        handle_ = handle;
    }

    // Wake the parked coroutine exactly once, if any. The exchange-claim means
    // the slot is empty for whichever side loses a racing wake. The return
    // value (whether a coroutine was resumed) is informational.
    auto resume() noexcept -> bool {
        if (!handle_) return false;
        std::exchange(handle_, {}).resume();
        return true;
    }

    // Claim the parked coroutine without resuming it — the stop-cancellation
    // path that completes the wait inline instead of parking.
    [[nodiscard]] auto take() noexcept -> std::coroutine_handle<> {
        return std::exchange(handle_, {});
    }

private:
    std::coroutine_handle<> handle_{};
};

// A compact FIFO cursor shared by buffered protocol readers. Consumed storage
// is released at the exact empty transition, so callers cannot retain stale
// offsets or duplicate the reset invariant.
class byte_cursor {
public:
    byte_cursor() = default;
    explicit byte_cursor(std::vector<std::byte> data)
        : data_(std::move(data)) {}

    [[nodiscard]] auto empty() const noexcept -> bool {
        return offset_ == data_.size();
    }

    [[nodiscard]] auto remaining() const noexcept -> std::size_t {
        return data_.size() - offset_;
    }

    void append(std::span<const std::byte> bytes) {
        if (empty()) {
            data_.clear();
            offset_ = 0;
        }
        data_.insert(data_.end(), bytes.begin(), bytes.end());
    }

    auto read(std::span<std::byte> output) -> std::size_t {
        auto size = std::min(output.size(), data_.size() - offset_);
        if (size != 0) {
            std::ranges::copy(
                std::span{data_}.subspan(offset_, size), output.begin());
            offset_ += size;
        }
        if (empty()) {
            data_.clear();
            offset_ = 0;
        }
        return size;
    }

private:
    std::vector<std::byte> data_{};
    std::size_t offset_{0};
};

} // namespace detail

// An in-memory body_stream used to supply a request/response body on the write
// path. Move-only; async_read yields the buffered bytes, then 0 at EOF.
class buffer_body {
public:
    buffer_body() = default;
    explicit buffer_body(std::vector<std::byte> data) : data_(std::move(data)) {}

    struct read_awaiter {
        buffer_body& self;
        std::span<std::byte> buf;

        bool await_ready() noexcept { return true; }
        void await_suspend(std::coroutine_handle<>) noexcept {}
        auto await_resume() noexcept -> std::size_t {
            return self.data_.read(buf);
        }
    };

    auto async_read(std::span<std::byte> buf) -> read_awaiter {
        return {*this, buf};
    }

    // Stop-aware overload required by body_stream: an in-memory body always
    // completes synchronously, so the stop token is accepted and ignored.
    auto async_read(std::span<std::byte> buf, std::stop_token) -> read_awaiter {
        return {*this, buf};
    }

private:
    detail::byte_cursor data_{};
};

// Bridges an async body_stream to a synchronous data-provider callback used by
// nghttp2/nghttp3 (whose read callbacks cannot co_await). The exchange
// coroutine calls refill() to pull the next chunk from the body; the C callback
// drains the staging buffer via read() and reports "needs refill" as
// std::nullopt (the caller maps it to its DEFERRED/WOULDBLOCK code).
template <body_stream Body>
class body_bridge {
public:
    explicit body_bridge(Body& body) : body_(body) {}

    body_bridge(const body_bridge&) = delete;
    auto operator=(const body_bridge&) -> body_bridge& = delete;

    // Pull the next chunk when the staging buffer has been drained. Returns
    // true once the body reached EOF (and the buffer is empty). The stop token
    // is propagated to the underlying body operation so a refill in flight can
    // be cancelled.
    auto refill(std::stop_token stop = {}) -> task<bool> {
        if (eof_) co_return true;
        if (offset_ < buffer_.size()) co_return false;
        buffer_.assign(io_buffer_size, std::byte{});
        auto n = co_await body_.async_read(buffer_, stop);
        if (n == 0) {
            eof_ = true;
            buffer_.clear();
            offset_ = 0;
            co_return true;
        }
        buffer_.resize(n);
        offset_ = 0;
        co_return false;
    }

    // Synchronously drain buffered bytes into dst. Sets eof when the body is
    // fully consumed; returns std::nullopt when the buffer is empty and more
    // refill() calls are required (not EOF yet).
    auto read(std::uint8_t* dst, std::size_t length, bool& eof)
        -> std::optional<std::size_t> {
        if (offset_ < buffer_.size()) {
            auto n = std::min(length, buffer_.size() - offset_);
            std::copy_n(buffer_.data() + offset_, n, reinterpret_cast<std::byte*>(dst));
            offset_ += n;
            if (offset_ == buffer_.size()) {
                buffer_.clear();
                offset_ = 0;
            }
            return n;
        }
        if (eof_) {
            eof = true;
            return 0;
        }
        return std::nullopt;
    }

    [[nodiscard]] auto eof() const -> bool { return eof_; }
    [[nodiscard]] auto drained() const -> bool { return offset_ >= buffer_.size(); }

private:
    static constexpr std::size_t io_buffer_size = 16 * 1024;
    Body& body_;
    std::vector<std::byte> buffer_{};
    std::size_t offset_{0};
    bool eof_{false};
};

// The single transport abstraction: an asynchronous byte stream. No copy
// semantics are attached to it — copying a handle is an implementation detail
// of the transport (TCP/TLS copies share the connection; a QUIC stream copy
// references the same logical stream). New streams are only created through a
// stream_factory. The contract requires a stop token so every operation has
// an explicit cancellation path; the await_resume value channel is verified
// (size_t), not just the awaiter shape.
template <typename S>
concept byte_stream = requires(
    S& s, std::span<std::byte> rb, std::span<const std::byte> wb, std::stop_token stop) {
    { s.async_read(rb, stop) } -> detail::awaitable_result<std::size_t>;
    { s.async_write(wb, stop) } -> detail::awaitable_result<std::size_t>;
};

namespace detail {

// Optional FIN-aware write overload, used by HTTP/3 to close the send side of
// a stream. Not required of every byte_stream (HTTP/1.1 and HTTP/2 never need
// it); async_write_to dispatches to it only when available. Like byte_stream,
// the size_t value channel is verified, not just the awaiter shape.
template <typename S>
concept fin_writable = requires(S& s, std::span<const std::byte> buf, bool fin, std::stop_token stop) {
    { s.async_write(buf, fin, stop) } -> awaitable_result<std::size_t>;
};

template <typename S>
auto async_write_to(S& stream, std::span<const std::byte> buf, bool fin = false, std::stop_token stop = {}) -> decltype(auto) {
    if constexpr (fin_writable<S>) {
        return stream.async_write(buf, fin, stop);
    } else {
        if (fin)
            throw std::runtime_error("transport does not support FIN-aware writes");
        return stream.async_write(buf, stop);
    }
}

template <byte_stream S>
auto write_all(
    S& stream,
    std::span<const std::byte> buffer,
    std::stop_token stop = {}) -> task<void> {
    while (!buffer.empty()) {
        auto written = co_await async_write_to(stream, buffer, false, stop);
        if (written == 0)
            throw std::runtime_error("transport write made no progress");
        if (written > buffer.size())
            throw std::runtime_error("transport write exceeded input size");
        buffer = buffer.subspan(written);
    }
}

} // namespace detail

// ─── Stream-factory transport (QUIC-style, RFC 9114) ────────

// A stream handle's identity, direction, and transport error space. Identity is
// opaque to the application; it is only compared/assigned by the factory and
// consumed by the protocol layer (nghttp3 stream IDs are derived from it).
struct stream_identifier {
    std::uint64_t value;

    auto operator==(const stream_identifier&) const -> bool = default;
};

enum class stream_access : std::uint8_t {
    send_only,
    receive_only,
    bidirectional,
};

enum class stream_side : std::uint8_t {
    sending,
    receiving,
    both,
};

struct application_error {
    std::uint64_t value;

    auto operator==(const application_error&) const -> bool = default;
};

// Thrown by a stream transport's async_read / async_write when the peer resets
// or abandons this one stream (QUIC RESET_STREAM / STOP_SENDING). RFC 9114
// §4.1.1 — stream errors are stream-level events, so the protocol layer treats
// this as terminal for that stream only, never as a connection failure.
struct stream_reset : std::runtime_error {
    explicit stream_reset(application_error error_code)
        : std::runtime_error{"stream reset by peer"}, error_code{error_code} {}
    application_error error_code;
};

// HTTP/3 owns one nghttp3/QPACK state machine. Every factory completion that
// resumes protocol code must therefore be serialized with every other
// completion for that connection. A transport may use any executor internally,
// but it must marshal resumptions onto one serialized execution context.
// Additionally, once async_close has begun the factory must not resume any
// outstanding operation: the protocol layer destroys its per-connection state
// as close proceeds, and a late resumption would touch freed state.
enum class stream_completion_order : std::uint8_t {
    serialized,
    unconstrained,
};

// A factory that can construct local streams. Two explicit operations encode
// the direction at the call site, so a factory never has to reject a
// receive-only open request at runtime.
template <typename F>
concept stream_constructible = requires(F& factory, std::stop_token stop) {
    typename F::stream_type;
    { factory.async_open_bidirectional(stop) }
        -> detail::awaitable_result<typename F::stream_type>;
    { factory.async_open_unidirectional(stop) }
        -> detail::awaitable_result<typename F::stream_type>;
};

// A factory that can accept peer-initiated streams. The returned handle's
// access() reports the direction; the application never guesses it from an id.
template <typename F>
concept stream_accepting = requires(F& factory, std::stop_token stop) {
    typename F::stream_type;
    { factory.async_accept(stop) }
        -> detail::awaitable_result<typename F::stream_type>;
};

// The write-acknowledgement contract for HTTP/3. `accepted` is the number of
// bytes the transport accepted for nghttp3_conn_add_write_offset; `buffer_release`
// completes when the adapter no longer references the caller's span; and
// `acknowledgement` completes with the number of peer-acknowledged bytes for
// nghttp3_conn_add_ack_offset.
template <typename BufferRelease, typename Acknowledgement>
struct stream_write_result {
    std::size_t accepted;
    BufferRelease buffer_release;
    Acknowledgement acknowledgement;
};

namespace detail {
template <typename R>
concept stream_write_result_like = requires(R result) {
    { result.accepted } -> std::convertible_to<std::size_t>;
    requires awaitable<decltype(result.buffer_release)>;
    requires awaitable<decltype(result.acknowledgement)>;
};

// Internal: an awaitable whose await_resume() yields the three-part write
// result (accepted / buffer_release / acknowledgement).
template <typename A>
concept stream_write_awaitable = requires(A awaitable_value) {
    { get_awaiter(std::move(awaitable_value)).await_resume() }
        -> stream_write_result_like;
};
} // namespace detail

// A multi-stream, QUIC-style connection factory. The connection itself is not a
// byte_stream (it has no connection-level read/write); it constructs and
// accepts per-stream handles that each carry their own identity, direction,
// byte I/O, receive-credit, and shutdown.
template <typename F>
concept stream_factory =
    stream_constructible<F> &&
    stream_accepting<F> &&
    requires {
        requires F::completion_order == stream_completion_order::serialized;
    } &&
    requires(
        F& factory,
        typename F::stream_type& stream,
        const typename F::stream_type& const_stream,
        std::span<std::byte> input,
        std::span<const std::byte> output,
        std::size_t consumed,
        application_error error,
        std::stop_token stop)
    {
        { const_stream.identifier() } -> std::same_as<stream_identifier>;
        { const_stream.access() } -> std::same_as<stream_access>;

        { stream.async_read(input, stop) }
            -> detail::awaitable_result<std::size_t>;

        { stream.async_write(output, false, stop) }
            -> detail::stream_write_awaitable;

        stream.consume(consumed);
        stream.shutdown(stream_side::sending, error);
        stream.shutdown(stream_side::receiving, error);

        { factory.async_close(error) } -> detail::awaitable_result<void>;
    };

} // namespace http
