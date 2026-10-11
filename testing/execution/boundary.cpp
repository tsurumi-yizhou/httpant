import httpant.dependencies.boost.ut;
import httpant.dependencies.stdexec;
import std;
import httpant;

namespace httpant::testing::execution {
using namespace boost::ut;
using http::operator co_await;
namespace {

enum class channel { value, error, stopped };

struct immediate_sender {
    using sender_concept = stdexec::sender_tag;
    using completion_signatures = stdexec::completion_signatures<
        stdexec::set_value_t(int), stdexec::set_error_t(std::exception_ptr),
        stdexec::set_stopped_t()>;
    channel result{channel::value};
    bool throw_connect{false};

    template <typename R>
    struct operation {
        using operation_state_concept = stdexec::operation_state_tag;
        R receiver;
        channel result;
        void start() noexcept {
            switch (result) {
            case channel::value: stdexec::set_value(std::move(receiver), 42); break;
            case channel::error:
                stdexec::set_error(std::move(receiver),
                    std::make_exception_ptr(std::runtime_error("sender error")));
                break;
            case channel::stopped: stdexec::set_stopped(std::move(receiver)); break;
            }
        }
    };
    template <typename R>
    auto connect(R receiver) && -> operation<R> {
        if (throw_connect) throw std::runtime_error("connect error");
        return {std::move(receiver), result};
    }
};

struct throwing_value {
    throwing_value() = default;
    throwing_value(throwing_value&&) { throw std::runtime_error("value move"); }
};

struct throwing_value_sender {
    using sender_concept = stdexec::sender_tag;
    using completion_signatures = stdexec::completion_signatures<stdexec::set_value_t(throwing_value)>;
    template <typename R>
    struct operation {
        using operation_state_concept = stdexec::operation_state_tag;
        R receiver;
        void start() noexcept { stdexec::set_value(std::move(receiver), throwing_value{}); }
    };
    template <typename R>
    auto connect(R receiver) && -> operation<R> { return {std::move(receiver)}; }
};

// The worker belongs to the test, not to the operation that completion may
// destroy. In the early case start joins the worker, forcing completion before
// start returns. The late case is released by the test.
struct thread_control {
    std::thread worker;
    std::atomic<bool> release{false};
    std::atomic<int> operation_destructions{0};
    std::thread::id completing_thread;
    ~thread_control() { if (worker.joinable()) worker.join(); }
};

struct threaded_sender {
    using sender_concept = stdexec::sender_tag;
    using completion_signatures = immediate_sender::completion_signatures;
    thread_control* control;
    bool early;
    channel result{channel::value};
    template <typename R>
    struct operation {
        using operation_state_concept = stdexec::operation_state_tag;
        R receiver;
        thread_control* control;
        bool early;
        channel result;
        ~operation() { ++control->operation_destructions; }
        void start() noexcept {
            auto* owner = control;
            auto inline_completion = early;
            owner->worker = std::thread([r = std::move(receiver), owner,
                                        early = inline_completion, result = result]() mutable {
                while (!early && !owner->release.load(std::memory_order_acquire))
                    std::this_thread::yield();
                owner->completing_thread = std::this_thread::get_id();
                switch (result) {
                case channel::value: stdexec::set_value(std::move(r), 42); break;
                case channel::error:
                    stdexec::set_error(std::move(r),
                        std::make_exception_ptr(std::runtime_error("thread error")));
                    break;
                case channel::stopped: stdexec::set_stopped(std::move(r)); break;
                }
            });
            if (inline_completion) owner->worker.join();
        }
    };
    template <typename R>
    auto connect(R receiver) && -> operation<R> {
        return {std::move(receiver), control, early, result};
    }
};

struct observation {
    int completions{0};
    channel result{channel::value};
    std::string text;
};

// Destroy the operation first, then consume the receiver members
// and the result reference. They must both survive destruction of the frame.
struct destroying_receiver {
    using receiver_concept = stdexec::receiver_t;
    std::function<void()> destroy;
    observation* observed;
    void set_value(const std::string& value) noexcept {
        destroy();
        ++observed->completions;
        observed->text = value;
        observed->result = channel::value;
    }
    void set_error(const std::exception_ptr& failure) noexcept {
        destroy();
        ++observed->completions;
        observed->result = channel::error;
        try { std::rethrow_exception(failure); }
        catch (const std::exception& e) { observed->text = e.what(); }
    }
    void set_stopped() noexcept {
        destroy();
        ++observed->completions;
        observed->result = channel::stopped;
    }
};

// A legal user token that can fail registration or request cancellation from
// inside its callback constructor, in addition to plain std::stop_token
// behavior. It exercises the generic bridge instead of a token special case.
struct custom_token;
template <typename F>
struct custom_callback;
struct custom_token {
    std::stop_token token;
    std::stop_source* request_on_attach{};
    bool fail_attach{false};
    template <typename F> using callback_type = custom_callback<F>;
    bool stop_possible() const noexcept { return token.stop_possible(); }
    bool stop_requested() const noexcept { return token.stop_requested(); }
    bool operator==(const custom_token&) const noexcept = default;
};
template <typename F>
struct custom_callback {
    std::optional<std::stop_callback<F>> callback;
    custom_callback(custom_token token, F fn) {
        if (token.fail_attach) throw std::runtime_error("attach error");
        if (token.request_on_attach) token.request_on_attach->request_stop();
        callback.emplace(token.token, std::move(fn));
    }
};

template <typename Token>
struct token_receiver {
    using receiver_concept = stdexec::receiver_t;
    Token token;
    observation* observed;
    std::function<void()> destroy{};
    auto get_env() const noexcept { return stdexec::prop{stdexec::get_stop_token, token}; }
    void set_value(int value) noexcept {
        if (destroy) destroy();
        ++observed->completions;
        observed->result = channel::value;
        observed->text = std::to_string(value);
    }
    void set_error(std::exception_ptr failure) noexcept {
        if (destroy) destroy();
        ++observed->completions;
        observed->result = channel::error;
        try { std::rethrow_exception(failure); }
        catch (const std::exception& e) { observed->text = e.what(); }
    }
    void set_stopped() noexcept {
        if (destroy) destroy();
        ++observed->completions;
        observed->result = channel::stopped;
    }
};

struct cleanup {
    int* count;
    ~cleanup() { ++*count; }
};

// Stop may complete this standalone sender on the requesting thread. No
// connection or protocol state is shared here. Registration itself cannot
// resume the coroutine before the generic sender awaiter's handshake.
struct cancel_sender {
    using sender_concept = stdexec::sender_tag;
    using completion_signatures = stdexec::completion_signatures<
        stdexec::set_value_t(int), stdexec::set_stopped_t()>;
    template <typename R>
    struct operation {
        using operation_state_concept = stdexec::operation_state_tag;
        struct cancel {
            operation* self;
            void operator()() const noexcept { stdexec::set_stopped(std::move(self->receiver)); }
        };
        R receiver;
        std::optional<std::stop_callback<cancel>> callback;
        void start() noexcept {
            callback.emplace(stdexec::get_stop_token(stdexec::get_env(receiver)), cancel{this});
        }
    };
    template <typename R>
    auto connect(R receiver) && -> operation<R> { return {std::move(receiver), {}}; }
};

struct delivery_value {
    bool* armed;
    delivery_value(bool* flag) : armed(flag) {}
    delivery_value(delivery_value&& other) : armed(other.armed) {
        if (*armed) throw std::runtime_error("delivery move");
    }
};
struct arm_delivery {
    bool* armed;
    ~arm_delivery() { *armed = true; }
};
struct delivery_receiver {
    using receiver_concept = stdexec::receiver_t;
    observation* observed;
    void set_value(delivery_value&&) noexcept { ++observed->completions; }
    void set_stopped() noexcept { ++observed->completions; }
    void set_error(std::exception_ptr e) noexcept {
        ++observed->completions;
        observed->result = channel::error;
        try { std::rethrow_exception(e); }
        catch (const std::exception& e) { observed->text = e.what(); }
    }
};

} // namespace

static suite<"execution boundary"> boundary_tests = [] {
    "sender_await_connect_and_result_failures_unwind"_test = [] {
        for (int scenario = 0; scenario < 4; ++scenario) {
            int destructors = 0;
            bool caught = false;
            auto run = [&]() -> http::task<void> {
                cleanup guard{&destructors};
                try {
                    if (scenario == 3) static_cast<void>(co_await throwing_value_sender{});
                    else static_cast<void>(co_await immediate_sender{
                        scenario == 2 ? channel::stopped : channel::error, scenario == 0});
                } catch (const http::stopped&) { caught = scenario == 2; }
                catch (const std::runtime_error& error) {
                    caught = std::string_view{error.what()} ==
                        (scenario == 0 ? "connect error" : scenario == 3 ? "value move" : "sender error");
                }
            };
            auto root = run();
            root.start();
            expect(root.done());
            root.result();
            expect(caught);
            expect(destructors == 1_i);
        }
    };

    "cross_thread_completion_before_and_after_start_returns"_test = [] {
        for (bool early : {true, false}) {
            for (auto result : {channel::value, channel::error, channel::stopped}) {
                for (int iteration = 0; iteration < 128; ++iteration) {
                    thread_control control;
                    int resumptions = 0;
                    std::thread::id resuming_thread;
                    auto run = [&]() -> http::task<void> {
                        try {
                            expect((co_await threaded_sender{&control, early, result}) == 42_i);
                            expect(result == channel::value);
                        } catch (const http::stopped&) { expect(result == channel::stopped); }
                        catch (const std::runtime_error&) { expect(result == channel::error); }
                        ++resumptions;
                        resuming_thread = std::this_thread::get_id();
                    };
                    auto root = run();
                    root.start();
                    control.release.store(true, std::memory_order_release);
                    if (control.worker.joinable()) control.worker.join();
                    expect(root.done());
                    root.result();
                    expect(resumptions == 1_i);
                    expect(resuming_thread == (early ? std::this_thread::get_id() : control.completing_thread));
                    expect(control.operation_destructions.load() == 1_i);
                }
            }
        }
    };

    "receiver_can_destroy_operation_before_reading_value_error_or_stopped"_test = [] {
        for (auto result : {channel::value, channel::error, channel::stopped}) {
            observation observed;
            int destructors = 0;
            auto factory = [&]() -> http::task<std::string> {
                cleanup guard{&destructors};
                if (result == channel::error) throw std::runtime_error("root error");
                if (result == channel::stopped) throw http::stopped{};
                co_return std::string(4096, 'x');
            };
            using sender = decltype(http::defer(factory));
            using operation = stdexec::connect_result_t<sender, destroying_receiver>;
            std::unique_ptr<operation> state;
            state.reset(new operation(stdexec::connect(http::defer(factory),
                destroying_receiver{[&] { state.reset(); }, &observed})));
            stdexec::start(*state);
            expect(!state);
            expect(observed.completions == 1_i);
            expect(observed.result == result);
            expect(observed.text == (result == channel::value ? std::string(4096, 'x') :
                                     result == channel::error ? "root error" : ""));
            expect(destructors == 1_i);
        }
    };

    "asynchronous_completion_can_destroy_root_and_awaited_operation"_test = [] {
        thread_control control;
        observation observed;
        auto factory = [&]() -> http::task<std::string> {
            auto value = co_await threaded_sender{&control, false};
            co_return std::to_string(value);
        };
        using operation = stdexec::connect_result_t<decltype(http::defer(factory)), destroying_receiver>;
        std::unique_ptr<operation> state;
        state.reset(new operation(stdexec::connect(http::defer(factory),
            destroying_receiver{[&] { state.reset(); }, &observed})));
        stdexec::start(*state);
        control.release.store(true, std::memory_order_release);
        control.worker.join();
        expect(!state);
        expect(observed.completions == 1_i);
        expect(observed.text == "42");
        expect(control.operation_destructions.load() == 1_i);
    };

    "bridge_attach_failure_and_registration_stop_complete_once"_test = [] {
        for (bool fail_attach : {true, false}) {
            std::stop_source source;
            observation observed;
            int calls = 0;
            auto factory = [&]() -> http::task<int> { ++calls; co_return 42; };
            auto state = stdexec::connect(http::defer(factory), token_receiver<custom_token>{
                custom_token{source.get_token(), &source, fail_attach}, &observed});
            stdexec::start(state);
            expect(calls == 0_i);
            expect(observed.completions == 1_i);
            expect(observed.result == (fail_attach ? channel::error : channel::stopped));
            if (fail_attach) expect(observed.text == "attach error");
        }
    };

    "inplace_and_custom_tokens_forward_external_stop_and_allow_reentrant_destruction"_test = [] {
        auto exercise = []<typename Source, typename Token>(Source& source, Token token) {
            observation observed;
            int destructors = 0;
            auto factory = [&]() -> http::task<int> {
                cleanup guard{&destructors};
                co_return co_await cancel_sender{};
            };
            using receiver = token_receiver<Token>;
            using operation = stdexec::connect_result_t<decltype(http::defer(factory)), receiver>;
            std::unique_ptr<operation> state;
            state.reset(new operation(stdexec::connect(http::defer(factory),
                receiver{token, &observed, [&] { state.reset(); }})));
            stdexec::start(*state);
            std::thread([&] { source.request_stop(); }).join();
            expect(!state);
            expect(observed.completions == 1_i);
            expect(observed.result == channel::stopped);
            expect(destructors == 1_i);
        };
        stdexec::inplace_stop_source inplace;
        exercise(inplace, inplace.get_token());
        std::stop_source standard;
        exercise(standard, standard.get_token());
        std::stop_source custom;
        exercise(custom, custom_token{custom.get_token()});
    };

    "empty_task_factory_and_delivery_move_are_sender_errors"_test = [] {
        observation empty_observed;
        auto empty = stdexec::connect(http::defer([] { return http::task<int>{}; }),
            token_receiver<std::stop_token>{{}, &empty_observed});
        stdexec::start(empty);
        expect(empty_observed.result == channel::error);
        expect(empty_observed.completions == 1_i);
        bool armed = false;
        auto factory = [&]() -> http::task<delivery_value> {
            arm_delivery on_exit{&armed};
            co_return delivery_value{&armed};
        };
        observation delivered;
        auto state = stdexec::connect(http::defer(factory), delivery_receiver{&delivered});
        stdexec::start(state);
        expect(delivered.completions == 1_i);
        expect(delivered.result == channel::error);
        expect(delivered.text == "delivery move");
    };

    "bridge_detach_races_external_stop_and_success_or_error"_test = [] {
        for (auto result : {channel::value, channel::error}) {
            for (int iteration = 0; iteration < 128; ++iteration) {
                thread_control control;
                stdexec::inplace_stop_source source;
                observation observed;
                auto factory = [&]() -> http::task<int> {
                    co_return co_await threaded_sender{&control, false, result};
                };
                auto state = stdexec::connect(http::defer(factory),
                    token_receiver<stdexec::inplace_stop_token>{source.get_token(), &observed});
                stdexec::start(state);
                std::thread requester([&] {
                    while (!control.release.load(std::memory_order_acquire)) std::this_thread::yield();
                    source.request_stop();
                });
                control.release.store(true, std::memory_order_release);
                control.worker.join();
                requester.join();
                expect(observed.completions == 1_i);
                expect(observed.result == result);
            }
        }
    };

    "scope_rejects_empty_child_without_poisoning_join"_test = [] {
        http::task_scope scope;
        bool caught = false;
        try { scope.spawn({}); } catch (const http::usage_error&) { caught = true; }
        expect(caught);
        expect(!scope.running());
        auto join = [&]() -> http::task<void> { co_await scope.join(); };
        auto root = join();
        root.start();
        expect(root.done());
        root.result();
    };

    "serialized_waiter_stop_and_deferred_wake_claim_once"_test = [] {
        http::detail::waiter_slot slot;
        http::detail::wake_queue queue;
        std::stop_source source;
        int resumptions = 0;
        bool cancelled = false;
        auto wait = [&]() -> http::task<void> {
            try { co_await http::detail::park_until{slot, [] { return false; }}; }
            catch (const http::stopped&) { cancelled = true; }
            ++resumptions;
        };
        auto root = wait();
        root.start(source.get_token());
        {
            http::detail::wake_scope defer{queue};
            slot.resume();
        }
        source.request_stop();
        expect(resumptions == 0_i);
        auto dispatch = [&]() -> http::task<void> { co_await http::detail::dispatch_wakeups{queue}; };
        auto driver = dispatch();
        driver.start();
        driver.result();
        root.result();
        expect(cancelled);
        expect(resumptions == 1_i);
        slot.resume();
        expect(resumptions == 1_i);
    };
};
} // namespace httpant::testing::execution
