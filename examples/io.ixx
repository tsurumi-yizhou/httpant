export module httpant.examples.io;

import std;
import httpant;
import httpant.io;

// Application-side helpers shared by the native example and benchmark.
// All protocol mutation and stop delivery happen on the context's run thread.
export namespace httpant::example {
namespace io = http::io::net;
using clock = std::chrono::steady_clock;
#ifdef __linux__
inline const io::ip::tcp::endpoint loopback{io::ip::address_v4{{127, 0, 0, 2}}, 0};
#else
inline const io::ip::tcp::endpoint loopback{io::ip::address_v4{{127, 0, 0, 1}}, 0};
#endif

inline auto parse_endpoint(std::string_view text, std::optional<std::uint16_t> port = {}) -> io::ip::tcp::endpoint {
    auto host = text;
    if (!port) {
        auto colon = text.rfind(':');
        if (colon == text.npos) throw std::invalid_argument("endpoint requires port");
        auto part = text.substr(colon + 1); unsigned value = 0;
        auto [end, error] = std::from_chars(part.data(), part.data() + part.size(), value);
        if (error != std::errc{} || end != part.data() + part.size() || value > 65535) throw std::invalid_argument("endpoint port");
        port = static_cast<std::uint16_t>(value); host = text.substr(0, colon);
    }
    if (host.starts_with('[') && host.ends_with(']')) host = host.substr(1, host.size() - 2);
    return {io::ip::make_address(host), *port};
}

inline auto host(io::ip::tcp::endpoint address) -> std::string {
    return address.address().to_string();
}

inline void require(bool condition, std::string_view message) {
    if (!condition)
        throw std::runtime_error(std::string{message});
}

inline auto number(std::string_view text, bool zero = false) -> std::size_t {
    std::size_t value = 0;
    auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), value);
    if (error != std::errc{} || end != text.data() + text.size() || (!zero && !value))
        throw std::invalid_argument(std::format("invalid numeric argument: {}", text));
    return value;
}

inline auto guarded(http::task_scope& scope, http::task<void> child) -> http::task<void> {
    try {
        co_await std::move(child);
    } catch (...) {
        scope.request_stop();
        throw;
    }
}

inline auto parallel(std::vector<http::task<void>> children) -> http::task<void> {
    co_await http::coroutine::with_scope(
        [&children](http::task_scope& scope) -> http::task<void> {
            const auto& token = co_await http::current_stop_token();
            std::stop_callback forward{token, [&scope] { scope.request_stop(); }};
            for (auto& child : children)
                scope.spawn(guarded(scope, std::move(child)));
            co_await scope.join();
        });
}

namespace detail {
struct run_result {
    io::io_context* context;
    std::stop_source stop;
    std::exception_ptr failure;
    bool done = false;
    bool stopped = false;
    bool timed_out = false;
};

struct receiver {
    using receiver_concept = stdexec::receiver_t;
    run_result* target;
    auto get_env() const noexcept {
        return stdexec::prop{stdexec::get_stop_token, target->stop.get_token()};
    }
    void set_value() noexcept {
        target->done = true;
        target->context->stop();
    }
    void set_error(std::exception_ptr error) noexcept {
        target->failure = std::move(error);
        set_value();
    }
    void set_error(std::error_code error) noexcept {
        try {
            throw std::system_error(error);
        } catch (...) {
            set_error(std::current_exception());
        }
    }
    void set_stopped() noexcept {
        target->stopped = true;
        set_value();
    }
};

struct alarm : native_io::request {
    run_result* target;
    bool queued = false;
    bool delivered = false;
    explicit alarm(run_result& result) : target(&result) {
        complete = [](native_io::request& request, std::int64_t, std::error_code) noexcept {
            auto& self = static_cast<alarm&>(request);
            self.delivered = true;
            if (!self.target->done) {
                self.target->timed_out = true;
                self.target->stop.request_stop();
            } else
                self.target->context->stop();
        };
    }
};
} // namespace detail

inline void run(io::io_context& context, http::task<void> task,
                std::chrono::seconds timeout = std::chrono::seconds{30}) {
    detail::run_result result{&context};
    detail::alarm alarm{result};
    auto operation = stdexec::connect(
        http::defer([&task]() mutable { return std::move(task); }), detail::receiver{&result});
    std::condition_variable_any wake;
    std::jthread watchdog{[&](std::stop_token stop) {
        std::mutex mutex;
        std::unique_lock lock{mutex};
        wake.wait_for(lock, stop, timeout, [] { return false; });
        if (!stop.stop_requested()) {
            alarm.queued = true;
            context.get_scheduler().engine()->start(alarm);
        }
    }};
    stdexec::start(operation);
    context.run();
    watchdog.request_stop();
    watchdog.join();
    // A deadline can race successful completion. Drain its queued post before
    // this stack frame disappears or this context is used for another sample.
    if (alarm.queued && !alarm.delivered)
        context.run();
    require(result.done, "context stopped before application completion");
    require(!result.timed_out, "native application timed out");
    if (result.failure)
        std::rethrow_exception(result.failure);
    require(!result.stopped, "native application stopped");
}
} // namespace httpant::example
