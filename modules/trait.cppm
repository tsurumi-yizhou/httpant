export module httpant:trait;

import std;

export namespace http {

// ─── Lazy coroutine task (single-consumer, move-only) ────────

template <typename T = void>
class task {
public:
    struct promise_type;
    using handle_type = std::coroutine_handle<promise_type>;

    struct promise_type {
        std::optional<T> result_;
        std::exception_ptr exception_;
        std::coroutine_handle<> continuation_;

        auto get_return_object() -> task { return task{handle_type::from_promise(*this)}; }
        auto initial_suspend() noexcept -> std::suspend_always { return {}; }
        auto final_suspend() noexcept {
            struct awaiter {
                bool await_ready() noexcept { return false; }
                auto await_suspend(handle_type h) noexcept -> std::coroutine_handle<> {
                    if (h.promise().continuation_) return h.promise().continuation_;
                    return std::noop_coroutine();
                }
                void await_resume() noexcept {}
            };
            return awaiter{};
        }
        void return_value(T value) { result_ = std::move(value); }
        void unhandled_exception() { exception_ = std::current_exception(); }
    };

    task() = default;
    explicit task(handle_type h) : handle_(h) {}
    task(task&& o) noexcept : handle_(std::exchange(o.handle_, {})) {}
    task& operator=(task&& o) noexcept {
        if (this != &o) {
            if (handle_) handle_.destroy();
            handle_ = std::exchange(o.handle_, {});
        }
        return *this;
    }
    ~task() { if (handle_) handle_.destroy(); }

    auto operator co_await() {
        struct awaiter {
            handle_type handle_;
            bool await_ready() noexcept { return !handle_ || handle_.done(); }
            auto await_suspend(std::coroutine_handle<> c) noexcept {
                handle_.promise().continuation_ = c;
                return handle_;
            }
            auto await_resume() -> T {
                if (handle_.promise().exception_)
                    std::rethrow_exception(handle_.promise().exception_);
                return std::move(*handle_.promise().result_);
            }
        };
        return awaiter{handle_};
    }

    void start() {
        if (handle_ && !handle_.done())
            handle_.resume();
    }

private:
    handle_type handle_{};
};

template <>
class task<void> {
public:
    struct promise_type;
    using handle_type = std::coroutine_handle<promise_type>;

    struct promise_type {
        std::exception_ptr exception_;
        std::coroutine_handle<> continuation_;

        auto get_return_object() -> task { return task{handle_type::from_promise(*this)}; }
        auto initial_suspend() noexcept -> std::suspend_always { return {}; }
        auto final_suspend() noexcept {
            struct awaiter {
                bool await_ready() noexcept { return false; }
                auto await_suspend(handle_type h) noexcept -> std::coroutine_handle<> {
                    if (h.promise().continuation_) return h.promise().continuation_;
                    return std::noop_coroutine();
                }
                void await_resume() noexcept {}
            };
            return awaiter{};
        }
        void return_void() {}
        void unhandled_exception() { exception_ = std::current_exception(); }
    };

    task() = default;
    explicit task(handle_type h) : handle_(h) {}
    task(task&& o) noexcept : handle_(std::exchange(o.handle_, {})) {}
    task& operator=(task&& o) noexcept {
        if (this != &o) {
            if (handle_) handle_.destroy();
            handle_ = std::exchange(o.handle_, {});
        }
        return *this;
    }
    ~task() { if (handle_) handle_.destroy(); }

    auto operator co_await() {
        struct awaiter {
            handle_type handle_;
            bool await_ready() noexcept { return !handle_ || handle_.done(); }
            auto await_suspend(std::coroutine_handle<> c) noexcept {
                handle_.promise().continuation_ = c;
                return handle_;
            }
            void await_resume() {
                if (handle_.promise().exception_)
                    std::rethrow_exception(handle_.promise().exception_);
            }
        };
        return awaiter{handle_};
    }

    void start() {
        if (handle_ && !handle_.done())
            handle_.resume();
    }

private:
    handle_type handle_{};
};

// ─── Transport concepts ──────────────────────────────────────

template <typename A>
concept has_await_members = requires(A a) {
    { a.await_ready() } -> std::convertible_to<bool>;
    a.await_suspend(std::coroutine_handle<>{});
    a.await_resume();
};

template <typename A>
concept has_member_co_await = requires(A a) {
    a.operator co_await();
};

template <typename A>
concept has_free_co_await = requires(A a) {
    operator co_await(a);
};

template <typename A>
concept awaitable = has_await_members<A> || has_member_co_await<A> || has_free_co_await<A>;

template <typename S>
concept readable = requires(S& s, std::span<std::byte> buf) {
    { s.async_read(buf) } -> awaitable;
};

template <typename S>
concept basic_writable = requires(S& s, std::span<const std::byte> buf) {
    { s.async_write(buf) } -> awaitable;
};

template <typename S>
concept fin_writable = requires(S& s, std::span<const std::byte> buf, bool fin) {
    { s.async_write(buf, fin) } -> awaitable;
};

template <typename S>
concept writable = basic_writable<S> || fin_writable<S>;

template <typename S>
concept derivable = requires(S& s, std::int64_t id) {
    { s.async_accept() } -> awaitable;
    { s.async_open(id) } -> awaitable;
};

template <typename S>
concept duplex = readable<S> && writable<S>;

template <typename S>
concept multiplexed = duplex<S> && derivable<S>;

template <typename S>
auto async_write_to(S& stream, std::span<const std::byte> buf, bool fin = false) -> decltype(auto) {
    if constexpr (fin_writable<S>) {
        return stream.async_write(buf, fin);
    } else {
        if (fin)
            throw std::runtime_error("transport does not support FIN-aware writes");
        return stream.async_write(buf);
    }
}

} // namespace http
