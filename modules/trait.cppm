export module httpant:trait;

import httpant.dependencies.stdexec;
import std;

export namespace http {

// The cancellation signal of a coroutine chain. A stop request completes the
// pending operation by throwing it, so the unwinding runs every catch latch
// and destructor on the way up; the execution stack turns it back into
// set_stopped. It is not a std::exception: `catch (const std::exception&)`
// handles failures, not cancellation.
struct stopped {};

// A call outside the library's contract: a request on a closed connection, an
// exchange token from another server, an outbound message that cannot be
// framed, a transport that breaks the byte_stream contract. Only the caller
// can fix it, so it is a std::logic_error.
class usage_error : public std::logic_error {
public:
    using std::logic_error::logic_error;
};

template <typename T>
class task;

class task_scope;

namespace detail {

template <typename T>
class with_stop_awaiter;

// A promise that exposes its chain's stop token takes part in stop
// propagation: whatever it awaits receives that token.
template <typename Promise>
concept stop_aware_promise = requires(const Promise& promise) {
    { promise.stop_token() } -> std::same_as<const std::stop_token&>;
};

inline const std::stop_token unstoppable{};

template <typename Promise>
[[nodiscard]] auto stop_token_of(const Promise& promise) noexcept -> const std::stop_token& {
    if constexpr (stop_aware_promise<Promise>)
        return promise.stop_token();
    else
        return unstoppable;
}

[[nodiscard]] inline auto is_stopped(const std::exception_ptr& failure) noexcept -> bool {
    try {
        std::rethrow_exception(failure);
    } catch (const stopped&) {
        return true;
    } catch (...) {
        return false;
    }
}

// Coroutine frames come from a per-thread pool of size classes, so a protocol
// operation that builds a chain of tasks allocates from the heap only until
// the pool has warmed up. A frame freed on another thread joins that thread's
// pool; each class keeps a bounded number of blocks and returns the rest.
class frame_pool {
public:
    static auto allocate(std::size_t size) -> void* {
        auto index = class_of(size);
        if (index == classes) return ::operator new(size);
        // Blocks are always a whole size class, so any pool can reuse them.
        if (auto* pool = local()) {
            auto& list = pool->free_[index];
            if (list.count != 0) {
                auto* block = list.head;
                list.head = block->next;
                --list.count;
                return block;
            }
        }
        return ::operator new(class_size(index));
    }

    static void deallocate(void* frame, std::size_t size) noexcept {
        auto index = class_of(size);
        auto* pool = index == classes ? nullptr : local();
        if (pool == nullptr || pool->free_[index].count >= max_cached)
            return ::operator delete(frame);
        auto& list = pool->free_[index];
        auto* block = static_cast<block_node*>(frame);
        block->next = list.head;
        list.head = block;
        ++list.count;
    }

private:
    struct block_node {
        block_node* next;
    };
    struct free_list {
        block_node* head{nullptr};
        std::size_t count{0};
    };

    // 64 B, 128 B, ... 32 KiB; larger frames use the heap directly.
    static constexpr std::size_t first_class = 64;
    static constexpr std::size_t classes = 10;
    static constexpr std::size_t max_cached = 32;

    static constexpr auto class_size(std::size_t index) -> std::size_t { return first_class << index; }
    static constexpr auto class_of(std::size_t size) -> std::size_t {
        std::size_t index = 0;
        while (index < classes && class_size(index) < size) ++index;
        return index;
    }

    explicit frame_pool(bool* destroyed) noexcept : destroyed_(destroyed) {}
    ~frame_pool() {
        *destroyed_ = true;
        for (auto& list : free_)
            for (auto* block = list.head; block != nullptr;) {
                auto* next = block->next;
                ::operator delete(block);
                block = next;
            }
    }
    frame_pool(const frame_pool&) = delete;
    auto operator=(const frame_pool&) -> frame_pool& = delete;

    // The calling thread's pool, or null once thread teardown has destroyed
    // it: a frame freed that late goes straight back to the heap. The flag is
    // trivially destructible, so it stays readable after the pool is gone.
    static auto local() -> frame_pool* {
        static thread_local bool destroyed = false;
        static thread_local frame_pool pool{&destroyed};
        return destroyed ? nullptr : &pool;
    }

    bool* destroyed_;
    free_list free_[classes]{};
};

struct task_promise_base;

// The final suspend point transfers to whoever waits: a root's owner (an
// execution operation or a scope) through its completion hook, otherwise the
// awaiting coroutine.
struct task_final_awaiter {
    bool await_ready() const noexcept { return false; }

    template <typename Promise>
    auto await_suspend(std::coroutine_handle<Promise> handle) const noexcept
        -> std::coroutine_handle<>;

    void await_resume() const noexcept {}
};

struct task_promise_base {
    static auto operator new(std::size_t size) -> void* { return frame_pool::allocate(size); }
    static void operator delete(void* frame, std::size_t size) noexcept {
        frame_pool::deallocate(frame, size);
    }

    std::exception_ptr exception_;
    std::coroutine_handle<> continuation_;
    void* owner_{};
    std::coroutine_handle<> (*complete_)(void*, task_promise_base&) noexcept {};
    // A child borrows its parent's token, since the parent outlives every
    // child it awaits; a root points at a token its owner keeps alive.
    const std::stop_token* stop_{&unstoppable};
    std::stop_token root_stop_{};

    auto initial_suspend() noexcept -> std::suspend_always { return {}; }
    auto final_suspend() noexcept -> task_final_awaiter { return {}; }
    void unhandled_exception() noexcept { exception_ = std::current_exception(); }

    [[nodiscard]] auto stop_token() const noexcept -> const std::stop_token& { return *stop_; }
};

template <typename Promise>
auto task_final_awaiter::await_suspend(std::coroutine_handle<Promise> handle) const noexcept
    -> std::coroutine_handle<> {
    auto& promise = handle.promise();
    if (promise.complete_ != nullptr)
        return promise.complete_(promise.owner_, promise);
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

} // namespace detail

// ─── The coroutine stack ─────────────────────────────────────
//
// A lazy, single-consumer, move-only coroutine with no executor. It runs by
// resumption: co_await it from another task, which hands down its stop token,
// or start() it as a root with a token of its own. The execution stack does
// not see tasks; it runs them behind its own senders (http::execution).
template <typename T = void>
class [[clang::coro_await_elidable]] task {
public:
    struct promise_type : detail::task_promise_base, detail::task_result<T> {
        auto get_return_object() -> task {
            return task{std::coroutine_handle<promise_type>::from_promise(*this)};
        }
    };

    using handle_type = std::coroutine_handle<promise_type>;
    using value_type = T;

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

        template <typename Promise>
        auto await_suspend(std::coroutine_handle<Promise> parent) noexcept -> handle_type {
            auto& promise = handle_.promise();
            promise.continuation_ = parent;
            promise.stop_ = &detail::stop_token_of(parent.promise());
            return handle_;
        }

        auto await_resume() -> T {
            if (!handle_)
                throw usage_error("task: no coroutine");
            if (handle_.promise().exception_)
                std::rethrow_exception(handle_.promise().exception_);
            if constexpr (!std::is_void_v<T>)
                return std::move(*handle_.promise().result_);
        }
    };

    [[nodiscard]] auto operator co_await() && -> awaiter {
        return awaiter{std::exchange(handle_, {})};
    }

    // Starts a root coroutine. The token cancels the chain; it is kept in the
    // frame, so it lives as long as the coroutine. Starting is one-shot:
    // repeated calls are no-ops, so a live coroutine is never resumed twice.
    void start(std::stop_token stop = {}) {
        if (!handle_ || started_)
            return;
        started_ = true;
        auto& promise = handle_.promise();
        promise.root_stop_ = std::move(stop);
        promise.stop_ = &promise.root_stop_;
        if (!handle_.done())
            handle_.resume();
    }

    [[nodiscard]] auto done() const noexcept -> bool {
        return !handle_ || handle_.done();
    }

    // The outcome of a finished root: its value, or its exception rethrown.
    auto result() -> T {
        if (!handle_ || !handle_.done())
            throw usage_error("task: result of a coroutine that has not finished");
        if (handle_.promise().exception_)
            std::rethrow_exception(handle_.promise().exception_);
        if constexpr (!std::is_void_v<T>)
            return std::move(*handle_.promise().result_);
    }

private:
    friend class task_scope;
    template <typename>
    friend class detail::with_stop_awaiter;
    template <typename, typename>
    friend class execution_sender;

    handle_type handle_{};
    bool started_{false};
};

namespace detail {

// The calling chain's stop token, for an operation at a boundary that takes
// one as an argument (a transport read, a body read). It never suspends.
class stop_token_reader {
public:
    [[nodiscard]] auto await_ready() const noexcept -> bool { return false; }
    template <typename Promise>
    auto await_suspend(std::coroutine_handle<Promise> handle) noexcept -> bool {
        token_ = &stop_token_of(handle.promise());
        return false;
    }
    [[nodiscard]] auto await_resume() const noexcept -> const std::stop_token& { return *token_; }

private:
    const std::stop_token* token_{&unstoppable};
};

} // namespace detail

[[nodiscard]] inline auto current_stop_token() noexcept -> detail::stop_token_reader {
    return {};
}

// ─── Awaitables ──────────────────────────────────────────────

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

// ─── Awaiting a sender ───────────────────────────────────────
//
// The execution stack meets the coroutine stack here: the operation state
// lives in the awaiting frame, its receiver points back at the awaiter, and
// the receiver's environment has the awaiting chain's stop token. A
// stopped sender resumes the coroutine with http::stopped.

template <typename S>
concept tagged_sender = requires { typename std::remove_cvref_t<S>::sender_concept; };

struct sender_env {
    const std::stop_token* stop;

    [[nodiscard]] auto query(std::remove_cvref_t<decltype(stdexec::get_stop_token)>) const noexcept
        -> std::stop_token {
        return *stop;
    }
};

template <typename... Ts>
using decayed_tuple = std::tuple<std::decay_t<Ts>...>;

template <typename S>
class sender_awaiter {
    struct receiver {
        using receiver_concept = stdexec::receiver_t;
        sender_awaiter* self_;

        [[nodiscard]] auto get_env() const noexcept -> sender_env { return {self_->stop_}; }

        template <typename... Values>
        void set_value(Values&&... values) noexcept {
            try {
                self_->result_.template emplace<1>(
                    std::in_place_type<decayed_tuple<Values...>>, std::forward<Values>(values)...);
            } catch (...) {
                self_->result_.template emplace<2>(std::current_exception());
            }
            self_->complete();
        }
        template <typename Error>
        void set_error(Error&& error) noexcept {
            self_->result_.template emplace<2>(as_exception(std::forward<Error>(error)));
            self_->complete();
        }
        void set_stopped() noexcept {
            self_->result_.template emplace<3>();
            self_->complete();
        }
    };

    using operation_type = stdexec::connect_result_t<S, receiver>;
    using values_type = stdexec::value_types_of_t<S, sender_env, decayed_tuple, std::variant>;
    static_assert(std::variant_size_v<values_type> == 1,
                  "http::task awaits one distinct set_value signature (including set_value()); "
                  "normalize alternatives with a sender adaptor before awaiting");
    using single_values = std::variant_alternative_t<0, values_type>;

    template <typename Tuple>
    struct value_of {
        using type = Tuple;
    };
    template <typename Value>
    struct value_of<std::tuple<Value>> {
        using type = Value;
    };
    template <typename Empty>
        requires(std::tuple_size_v<Empty> == 0)
    struct value_of<Empty> {
        using type = void;
    };
    using value_type = typename value_of<single_values>::type;

    template <typename Error>
    static auto as_exception(Error&& error) noexcept -> std::exception_ptr {
        try {
            using decayed = std::decay_t<Error>;
            if constexpr (std::same_as<decayed, std::exception_ptr>)
                return error;
            else if constexpr (std::same_as<decayed, std::error_code>)
                return std::make_exception_ptr(std::system_error(error));
            else
                return std::make_exception_ptr(std::forward<Error>(error));
        } catch (...) {
            return std::current_exception();
        }
    }

public:
    template <typename Sender>
    explicit sender_awaiter(Sender&& sender) : sender_(std::forward<Sender>(sender)) {}
    // At a boundary that takes its stop token as an argument, that token goes in
    // the receiver's environment instead of the awaiting chain's.
    template <typename Sender>
    sender_awaiter(Sender&& sender, const std::stop_token& stop)
        : sender_(std::forward<Sender>(sender)), stop_(&stop), explicit_stop_(true) {}
    sender_awaiter(const sender_awaiter&) = delete;
    auto operator=(const sender_awaiter&) -> sender_awaiter& = delete;
    ~sender_awaiter() {
        if (live_)
            operation().~operation_type();
    }

    [[nodiscard]] auto await_ready() const noexcept -> bool { return false; }

    template <typename Promise>
    auto await_suspend(std::coroutine_handle<Promise> handle) noexcept -> bool {
        continuation_ = handle;
        if (!explicit_stop_)
            stop_ = &stop_token_of(handle.promise());
        // A stop already requested ends the await before the operation
        // starts, whether or not the sender itself watches its token.
        if (stop_->stop_requested()) {
            result_.template emplace<3>();
            return false;
        }
        try {
            ::new (static_cast<void*>(storage_)) operation_type(
                stdexec::connect(std::move(sender_), receiver{this}));
        } catch (...) {
            result_.template emplace<2>(std::current_exception());
            return false;
        }
        live_ = true;
        stdexec::start(operation());
        // Publish suspension only after start has returned. Completion either
        // publishes its result to this exchange, or observes suspended and
        // resumes us. This is the last access to the frame: another thread
        // can resume and destroy it as soon as the exchange succeeds.
        return phase_.exchange(phase::suspended, std::memory_order_acq_rel)
            != phase::completed;
    }

    auto await_resume() -> value_type {
        if (auto* failure = std::get_if<2>(&result_))
            std::rethrow_exception(*failure);
        if (result_.index() == 3)
            throw stopped{};
        auto& values = std::get<0>(std::get<1>(result_));
        if constexpr (std::tuple_size_v<single_values> == 1)
            return std::move(std::get<0>(values));
        else if constexpr (std::tuple_size_v<single_values> > 1)
            return std::move(values);
    }

private:
    auto operation() noexcept -> operation_type& {
        return *std::launder(reinterpret_cast<operation_type*>(storage_));
    }

    void complete() noexcept {
        auto continuation = continuation_;
        if (phase_.exchange(phase::completed, std::memory_order_acq_rel)
            == phase::suspended)
            continuation.resume();
        // Resumption may have destroyed this awaiter and its operation.
    }

    S sender_;
    const std::stop_token* stop_{&unstoppable};
    bool explicit_stop_{false};
    std::coroutine_handle<> continuation_{};
    std::variant<std::monostate, values_type, std::exception_ptr, std::monostate> result_{};
    enum class phase { starting, suspended, completed };
    std::atomic<phase> phase_{phase::starting};
    bool live_{false};
    alignas(operation_type) unsigned char storage_[sizeof(operation_type)];
};

} // namespace detail

// co_await a P2300 sender from a task. Found by plain lookup inside
// namespace http and by a using-declaration elsewhere. A task is excluded: it
// is awaited natively.
template <detail::tagged_sender S>
    requires(!detail::has_member_co_await<S>)
[[nodiscard]] auto operator co_await(S&& sender)
    -> detail::sender_awaiter<std::remove_cvref_t<S>> {
    return detail::sender_awaiter<std::remove_cvref_t<S>>{std::forward<S>(sender)};
}

namespace detail {

template <typename T>
class with_stop_awaiter {
public:
    with_stop_awaiter(const std::stop_token& stop, task<T> child)
        : stop_(stop), child_(std::move(child)) {}

    [[nodiscard]] auto await_ready() const noexcept -> bool { return child_.done(); }
    auto await_suspend(std::coroutine_handle<> parent) noexcept -> std::coroutine_handle<> {
        auto& promise = child_.handle_.promise();
        promise.continuation_ = parent;
        promise.stop_ = &stop_;
        return child_.handle_;
    }
    auto await_resume() -> T { return child_.result(); }

private:
    const std::stop_token& stop_;
    task<T> child_;
};

} // namespace detail

// Awaits a task under an explicit stop token instead of the awaiting chain's,
// for a boundary that receives its token as an argument. The token must
// outlive the await.
template <typename T>
[[nodiscard]] auto with_stop(const std::stop_token& stop, task<T> child)
    -> detail::with_stop_awaiter<T> {
    return {stop, std::move(child)};
}

// Awaits a sender with an explicit stop token in its receiver's environment.
template <detail::tagged_sender S>
    requires(!detail::has_member_co_await<S>)
[[nodiscard]] auto with_stop(const std::stop_token& stop, S&& sender)
    -> detail::sender_awaiter<std::remove_cvref_t<S>> {
    return detail::sender_awaiter<std::remove_cvref_t<S>>{std::forward<S>(sender), stop};
}

// ─── Structured children ─────────────────────────────────────

// A counting scope (inspired by P3149): the children an endpoint runs beside the
// application, such as the HTTP/2 reader or the HTTP/3 accept loop and stream
// readers. A child starts when spawned, with the scope's stop token. join()
// completes once every child has finished, rethrowing the first child failure;
// it ignores the joiner's own stop token, so a closing endpoint always waits
// for its I/O to settle. Destroying a scope with a running child would free a
// frame whose I/O is still in flight, so the destructor requests stop and
// terminates if a child is still running.
class task_scope {
public:
    task_scope() = default;
    task_scope(const task_scope&) = delete;
    auto operator=(const task_scope&) -> task_scope& = delete;
    ~task_scope() {
        source_.request_stop();
        if (running_ != 0) {
            std::println(std::cerr,
                "httpant: an endpoint was destroyed while its driver was running; "
                "co_await close(endpoint) first");
            std::terminate();
        }
    }

    void spawn(task<void> child) {
        std::erase_if(children_, [](const task<void>& finished) { return finished.done(); });
        auto handle = child.handle_;
        if (!handle)
            throw usage_error("httpant: cannot spawn an empty task");
        // A started task is already running (or finished) under another
        // owner; resuming it here would resume it twice.
        if (child.started_)
            throw usage_error("httpant: cannot spawn a task that was already started");
        auto& promise = handle.promise();
        promise.owner_ = this;
        promise.complete_ = &task_scope::finished;
        promise.stop_ = &token_;
        child.started_ = true;
        children_.push_back(std::move(child));
        ++running_;
        handle.resume();
    }

    void request_stop() noexcept { source_.request_stop(); }
    [[nodiscard]] auto stop_requested() const noexcept -> bool { return source_.stop_requested(); }
    [[nodiscard]] auto stop_token() const noexcept -> const std::stop_token& { return token_; }
    [[nodiscard]] auto running() const noexcept -> bool { return running_ != 0; }

    class join_awaiter {
    public:
        explicit join_awaiter(task_scope& scope) noexcept : scope_(scope) {}
        [[nodiscard]] auto await_ready() const noexcept -> bool { return scope_.running_ == 0; }
        void await_suspend(std::coroutine_handle<> handle) {
            if (scope_.joiner_)
                throw usage_error("httpant: a scope is already being joined");
            scope_.joiner_ = handle;
        }
        void await_resume() {
            scope_.children_.clear();
            if (auto failure = std::exchange(scope_.failure_, {}))
                std::rethrow_exception(failure);
        }

    private:
        task_scope& scope_;
    };

    [[nodiscard]] auto join() noexcept -> join_awaiter { return join_awaiter{*this}; }

private:
    static auto finished(void* owner, detail::task_promise_base& promise) noexcept
        -> std::coroutine_handle<> {
        auto& self = *static_cast<task_scope*>(owner);
        if (promise.exception_ && !self.failure_ && !detail::is_stopped(promise.exception_))
            self.failure_ = promise.exception_;
        if (--self.running_ == 0 && self.joiner_)
            return std::exchange(self.joiner_, {});
        return std::noop_coroutine();
    }

    std::stop_source source_{};
    std::stop_token token_{source_.get_token()};
    std::vector<task<void>> children_{};
    std::size_t running_{0};
    std::coroutine_handle<> joiner_{};
    std::exception_ptr failure_{};
};

namespace detail {

// ─── Deferred wake-ups ───────────────────────────────────────
//
// A connection driver (the HTTP/2 reader, an HTTP/3 stream reader) wakes the
// coroutines parked on its streams while it processes input. Resuming them
// inline would run application code on the driver's own stack, in the middle
// of an engine callback.
//
// While a wake_scope is active on a thread, wake() therefore queues the
// handle instead of resuming it. The driver leaves the scope, then awaits
// dispatch_wakeups, which resumes the queued coroutines once the driver has
// itself suspended. The driver is a child of the endpoint's task_scope, so a
// woken coroutine cannot free it: closing joins the driver first.
using wake_queue = std::vector<std::coroutine_handle<>>;

inline thread_local wake_queue* active_wake_queue = nullptr;

class wake_scope {
public:
    explicit wake_scope(wake_queue& queue) noexcept
        : previous_(std::exchange(active_wake_queue, &queue)) {}
    wake_scope(const wake_scope&) = delete;
    auto operator=(const wake_scope&) -> wake_scope& = delete;
    ~wake_scope() { active_wake_queue = previous_; }

private:
    wake_queue* previous_;
};

// Resume a parked coroutine now, or queue it when a wake_scope is active.
inline void wake(std::coroutine_handle<> handle) noexcept {
    if (active_wake_queue != nullptr)
        active_wake_queue->push_back(handle);
    else
        handle.resume();
}

struct dispatch_wakeups {
    wake_queue& queue;

    [[nodiscard]] auto await_ready() const noexcept -> bool { return queue.empty(); }

    auto await_suspend(std::coroutine_handle<> driver) noexcept -> std::coroutine_handle<> {
        wake_queue batch;
        batch.swap(queue);
        for (auto handle : batch)
            handle.resume();
        return driver;
    }

    void await_resume() const noexcept {}
};

// Connection-local machinery below (scope, wake queues, waiters and engine
// state) has one serialized mutator. Start, completion, close and stop requests
// that can reach these waiters must run in that context. The generic sender
// awaiter above supports cross-thread completion; it does not marshal engine
// state or external request_stop calls onto a connection's context.
//
// A single-slot coroutine waiter: at most one coroutine may park on a slot at
// a time (a second park would overwrite and hang the first), and a wakeup is
// claimed with std::exchange so a normal resume and a stop request can never
// both resume the same coroutine.
class waiter_slot {
public:
    void park(std::coroutine_handle<> handle) {
        if (handle_)
            throw usage_error("httpant: a second coroutine waits on the same stream");
        handle_ = handle;
    }

    // Wake the parked coroutine exactly once, if any.
    void resume() noexcept {
        if (handle_)
            wake(std::exchange(handle_, {}));
    }

    [[nodiscard]] auto take() noexcept -> std::coroutine_handle<> {
        return std::exchange(handle_, {});
    }

private:
    std::coroutine_handle<> handle_{};
};

// The one way an engine coroutine waits for its connection driver: it parks
// on a waiter_slot until Ready holds. A stop request on the waiting chain
// claims the slot and resumes the coroutine with http::stopped; whichever of
// the wake and the stop claims the slot first is the only one that resumes.
template <typename Ready>
class park_until {
public:
    park_until(waiter_slot& slot, Ready ready) : slot_(slot), ready_(std::move(ready)) {}
    // At a boundary that takes its stop token as an argument (a body read), that
    // token governs the wait instead of the chain's.
    park_until(waiter_slot& slot, Ready ready, const std::stop_token& stop)
        : slot_(slot), ready_(std::move(ready)), stop_(&stop) {}
    park_until(const park_until&) = delete;
    auto operator=(const park_until&) -> park_until& = delete;

    [[nodiscard]] auto await_ready() -> bool { return ready_(); }

    template <typename Promise>
    auto await_suspend(std::coroutine_handle<Promise> handle) -> bool {
        auto& stop = stop_ != nullptr ? *stop_ : stop_token_of(handle.promise());
        if (stop.stop_requested()) {
            cancelled_ = true;
            return false;
        }
        slot_.park(handle);
        if (stop.stop_possible()) {
            // A stop racing this registration runs the claim inside the
            // constructor; it only records the cancellation, and the
            // suspension is undone here instead of resuming reentrantly.
            registering_ = true;
            callback_.emplace(stop, claim{this});
            registering_ = false;
            if (cancelled_) {
                static_cast<void>(slot_.take());
                return false;
            }
        }
        return true;
    }

    void await_resume() {
        callback_.reset();
        if (cancelled_)
            throw stopped{};
    }

private:
    struct claim {
        park_until* self;
        void operator()() const noexcept {
            self->cancelled_ = true;
            if (self->registering_)
                return;
            if (auto handle = self->slot_.take())
                handle.resume();
        }
    };

    waiter_slot& slot_;
    Ready ready_;
    const std::stop_token* stop_{nullptr};
    bool cancelled_{false};
    bool registering_{false};
    std::optional<std::stop_callback<claim>> callback_{};
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

// ─── The execution stack ─────────────────────────────────────
//
// A lazy P2300 sender over a protocol operation. Nothing happens at the call
// that makes it: connect stores the receiver and start creates the coroutine
// that implements the operation, with the receiver's stop token as the
// chain's root token. std::stop_token passes through, an unstoppable token
// costs nothing, and any other stoppable token (inplace_stop_token) is
// forwarded into a source the operation owns; the forwarding callback is
// removed before the receiver completes.
namespace detail {

template <typename Token>
struct stop_bridge {
    struct forward {
        std::stop_source* source;
        void operator()() const noexcept {
            // A synchronous stop completion can destroy the operation and
            // this callback. Keep the stop state alive until request_stop
            // returns, without accessing the callback again.
            auto keep_alive = *source;
            keep_alive.request_stop();
        }
    };

    std::stop_source source{};
    std::stop_token token{source.get_token()};
    std::optional<stdexec::stop_callback_for_t<Token, forward>> callback{};

    void attach(Token outer) { callback.emplace(std::move(outer), forward{&source}); }
    void detach() noexcept { callback.reset(); }
};

template <>
struct stop_bridge<std::stop_token> {
    std::stop_token token{};

    void attach(std::stop_token outer) noexcept { token = std::move(outer); }
    void detach() noexcept {}
};

template <stdexec::unstoppable_token Token>
struct stop_bridge<Token> {
    std::stop_token token{};

    void attach(Token) noexcept {}
    void detach() noexcept {}
};

template <typename T>
struct completion_of {
    using type = stdexec::completion_signatures<
        stdexec::set_value_t(T),
        stdexec::set_error_t(std::exception_ptr),
        stdexec::set_stopped_t()>;
};

template <>
struct completion_of<void> {
    using type = stdexec::completion_signatures<
        stdexec::set_value_t(),
        stdexec::set_error_t(std::exception_ptr),
        stdexec::set_stopped_t()>;
};

} // namespace detail

// Operation is a callable that makes the task<T> implementing the operation;
// it runs at start, so its captured arguments are what the sender owns.
template <typename T, typename Operation>
class execution_sender {
public:
    using sender_concept = stdexec::sender_tag;
    using completion_signatures = typename detail::completion_of<T>::type;

    explicit execution_sender(Operation operation) : operation_(std::move(operation)) {}
    // Single consumer: an operation runs once.
    execution_sender(execution_sender&&) noexcept = default;
    auto operator=(execution_sender&&) noexcept -> execution_sender& = default;
    execution_sender(const execution_sender&) = delete;
    auto operator=(const execution_sender&) -> execution_sender& = delete;

    template <typename Receiver>
    class state {
    public:
        using operation_state_concept = stdexec::operation_state_tag;

        state(Operation operation, Receiver receiver)
            : operation_(std::move(operation)), receiver_(std::move(receiver)) {}
        state(const state&) = delete;
        auto operator=(const state&) -> state& = delete;

        void start() noexcept {
            try {
                stop_.attach(stdexec::get_stop_token(stdexec::get_env(receiver_)));
                if (stop_.token.stop_requested()) {
                    stop_.detach();
                    auto receiver = std::move(receiver_);
                    stdexec::set_stopped(std::move(receiver));
                    return;
                }
                task_ = std::invoke(std::move(operation_));
                if (!task_.handle_)
                    throw usage_error("httpant: operation returned an empty task");
            } catch (...) {
                auto failure = std::current_exception();
                stop_.detach();
                auto receiver = std::move(receiver_);
                stdexec::set_error(std::move(receiver), std::move(failure));
                return;
            }
            auto& promise = task_.handle_.promise();
            promise.owner_ = this;
            promise.complete_ = &state::complete;
            promise.stop_ = &stop_.token;
            task_.started_ = true;
            task_.handle_.resume();
        }

    private:
        using token_type = stdexec::stop_token_of_t<stdexec::env_of_t<Receiver>>;

        static auto complete(void* owner, detail::task_promise_base&) noexcept
            -> std::coroutine_handle<> {
            auto& self = *static_cast<state*>(owner);
            auto& promise = self.task_.handle_.promise();
            self.stop_.detach();
            // Receiver completion is allowed to destroy the operation (and
            // the suspended root frame). Deliver from independent storage;
            // neither receiver nor result may borrow that frame afterward.
            auto receiver = std::move(self.receiver_);
            if (promise.exception_) {
                auto failure = promise.exception_;
                if (detail::is_stopped(failure))
                    stdexec::set_stopped(std::move(receiver));
                else
                    stdexec::set_error(std::move(receiver), std::move(failure));
            } else if constexpr (std::is_void_v<T>) {
                stdexec::set_value(std::move(receiver));
            } else {
                try {
                    auto value = std::move(*promise.result_);
                    stdexec::set_value(std::move(receiver), std::move(value));
                } catch (...) {
                    stdexec::set_error(std::move(receiver), std::current_exception());
                }
            }
            return std::noop_coroutine();
        }

        Operation operation_;
        Receiver receiver_;
        detail::stop_bridge<token_type> stop_{};
        task<T> task_{};
    };

    template <typename Receiver>
    [[nodiscard]] auto connect(Receiver receiver) && -> state<Receiver> {
        return state<Receiver>{std::move(operation_), std::move(receiver)};
    }

private:
    Operation operation_;
};

// Wraps an operation that makes a task<T> into the lazy sender above; T is
// deduced from what the operation returns.
template <typename Operation>
[[nodiscard]] auto defer(Operation operation) {
    using result = std::invoke_result_t<Operation&&>;
    return execution_sender<typename result::value_type, Operation>{std::move(operation)};
}

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
template <typename Head, body_stream Body>
struct received {
    Head head;
    Body body;
};

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

    // An in-memory body completes synchronously, so the stop token is
    // accepted and ignored.
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
    // true once the body reached EOF (and the buffer is empty). The read takes
    // the calling chain's stop token. The staging buffer is allocated once and
    // never zero-filled.
    auto refill() -> task<bool> {
        if (eof_) co_return true;
        if (offset_ < size_) co_return false;
        if (!buffer_)
            buffer_ = std::make_unique_for_overwrite<std::byte[]>(io_buffer_size);
        auto n = co_await body_.async_read(
            std::span{buffer_.get(), io_buffer_size}, co_await current_stop_token());
        offset_ = 0;
        size_ = n;
        if (n == 0) {
            eof_ = true;
            co_return true;
        }
        co_return false;
    }

    // Synchronously drain buffered bytes into dst. Sets eof when the body is
    // fully consumed; returns std::nullopt when the buffer is empty and more
    // refill() calls are required (not EOF yet).
    auto read(std::uint8_t* dst, std::size_t length, bool& eof)
        -> std::optional<std::size_t> {
        if (offset_ < size_) {
            auto n = std::min(length, size_ - offset_);
            std::copy_n(buffer_.get() + offset_, n, reinterpret_cast<std::byte*>(dst));
            offset_ += n;
            return n;
        }
        if (eof_) {
            eof = true;
            return 0;
        }
        return std::nullopt;
    }

    [[nodiscard]] auto eof() const -> bool { return eof_; }
    [[nodiscard]] auto drained() const -> bool { return offset_ >= size_; }

private:
    static constexpr std::size_t io_buffer_size = 16 * 1024;
    Body& body_;
    std::unique_ptr<std::byte[]> buffer_{};
    std::size_t offset_{0};
    std::size_t size_{0};
    bool eof_{false};
};

// The single transport abstraction: an asynchronous byte stream. No copy
// semantics are attached to it — copying a handle is an implementation detail
// of the transport (TCP/TLS copies share the connection; a QUIC stream copy
// references the same logical stream). New streams are only created through a
// stream_factory. The contract requires a stop token so every operation has
// an explicit cancellation path: once the token is stopped, a pending
// operation completes, by throwing http::stopped unless it already finished.
// The await_resume value channel is verified (size_t), not just the awaiter
// shape.
template <typename S>
concept byte_stream = requires(
    S& s, std::span<std::byte> rb, std::span<const std::byte> wb, std::stop_token stop) {
    { s.async_read(rb, stop) } -> detail::awaitable_result<std::size_t>;
    { s.async_write(wb, stop) } -> detail::awaitable_result<std::size_t>;
};

namespace detail {

// Writes the whole buffer with the calling chain's stop token. A transport
// that reports no progress, or more bytes than it was given, breaks the
// byte_stream contract.
template <byte_stream S>
auto write_all(S& stream, std::span<const std::byte> buffer) -> task<void> {
    auto& stop = co_await current_stop_token();
    while (!buffer.empty()) {
        auto written = co_await stream.async_write(buffer, stop);
        if (written == 0)
            throw usage_error("transport: write made no progress");
        if (written > buffer.size())
            throw usage_error("transport: write reported more bytes than it was given");
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
// A factory states this by declaring
// `static constexpr auto completion_order = stream_completion_order::serialized`.
// Every operation completes, normally or with an error, once its stop token is
// stopped or the factory is closed: closing an endpoint joins its readers.
enum class stream_completion_order : std::uint8_t {
    serialized,
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
