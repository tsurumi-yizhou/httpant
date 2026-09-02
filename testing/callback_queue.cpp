#include <boost/ut.hpp>

#include <asio.hpp>

#include <coroutine>
#include <exception>
#include <stop_token>
#include <string>
#include <system_error>
#include <utility>

import httpant;

#include "../examples/quic_support.hpp"

namespace httpant::testing {

using namespace boost::ut;
using httpant::examples::callback_queue;

template <typename T>
class queue_task {
public:
    struct promise_type {
        std::exception_ptr error{};
        T result{};

        auto get_return_object() -> queue_task {
            return queue_task{std::coroutine_handle<promise_type>::from_promise(*this)};
        }
        auto initial_suspend() const noexcept -> std::suspend_never { return {}; }
        auto final_suspend() const noexcept -> std::suspend_always { return {}; }
        void unhandled_exception() noexcept { error = std::current_exception(); }
        void return_value(T value) { result = std::move(value); }
    };

    explicit queue_task(std::coroutine_handle<promise_type> coroutine) : coroutine_(coroutine) {}
    queue_task(queue_task&& other) noexcept : coroutine_(std::exchange(other.coroutine_, {})) {}
    ~queue_task() {
        if (coroutine_)
            coroutine_.destroy();
    }

    [[nodiscard]] auto done() const -> bool { return coroutine_.done(); }
    auto take() -> T {
        if (coroutine_.promise().error)
            std::rethrow_exception(coroutine_.promise().error);
        return std::move(coroutine_.promise().result);
    }

private:
    std::coroutine_handle<promise_type> coroutine_{};
};

auto pop(callback_queue<int>& queue, std::stop_token stop = {}) -> queue_task<int> {
    co_return co_await queue.async_pop(stop);
}

static suite<"callback_queue"> callback_queue_suite = [] {
    // Internal machinery test: callback delivery resumes a suspended waiter exactly once.
    "push_completes_waiter"_test = [] {
        asio::io_context context;
        callback_queue<int> queue{context.get_executor(), "test queue"};
        auto operation = pop(queue);

        queue.push(42);
        context.run();

        expect(operation.done());
        expect(operation.take() == 42_i);
    };

    // Internal machinery test: stop disarms the queue waiter and a later push cannot resume it again.
    "stop_wins_once_and_disarms_waiter"_test = [] {
        asio::io_context context;
        callback_queue<int> queue{context.get_executor(), "test queue"};
        std::stop_source source;
        auto operation = pop(queue, source.get_token());

        expect(source.request_stop());
        queue.push(42);
        context.run();

        expect(operation.done());
        auto canceled = false;
        try {
            static_cast<void>(operation.take());
        } catch (const std::system_error& error) {
            canceled = error.code() == std::errc::operation_canceled;
        }
        expect(canceled);

        context.restart();
        auto next = pop(queue);
        context.run();
        expect(next.done());
        expect(next.take() == 42_i);
    };

    // Internal machinery test: destroying a suspended operation removes its continuation.
    "operation_destruction_disarms_waiter"_test = [] {
        asio::io_context context;
        callback_queue<int> queue{context.get_executor(), "test queue"};
        {
            auto operation = pop(queue);
            expect(!operation.done());
        }

        queue.push(7);
        context.run();
        context.restart();
        auto next = pop(queue);
        context.run();
        expect(next.done());
        expect(next.take() == 7_i);
    };

    // Internal machinery test: closing the queue completes its active waiter with the close error.
    "close_completes_waiter"_test = [] {
        asio::io_context context;
        callback_queue<int> queue{context.get_executor(), "test queue"};
        auto operation = pop(queue);

        queue.close(std::make_exception_ptr(std::runtime_error("closed by test")));
        context.run();

        expect(operation.done());
        auto message = std::string{};
        try {
            static_cast<void>(operation.take());
        } catch (const std::runtime_error& error) {
            message = error.what();
        }
        expect(message == "closed by test");
    };
};

} // namespace httpant::testing
