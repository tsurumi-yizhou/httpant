#include <boost/ut.hpp>

#include "test_support.hpp"

namespace httpant::testing {

using namespace boost::ut;

static suite<"task"> task_suite = [] {
    "task_value"_test = [] {
        auto make_value = []() -> http::task<int> {
            co_return 42;
        };

        expect(run_sync(make_value()) == 42_i);
    };

    "task_void"_test = [] {
        auto executed = false;
        auto do_work = [&]() -> http::task<void> {
            executed = true;
            co_return;
        };

        run_sync(do_work());
        expect(executed);
    };

    "task_exception_propagates"_test = [] {
        auto fail = []() -> http::task<int> {
            throw std::runtime_error("boom");
            co_return 0;
        };

        auto threw = false;
        try {
            static_cast<void>(run_sync(fail()));
        } catch (const std::runtime_error&) {
            threw = true;
        }

        expect(threw);
    };
};

} // namespace httpant::testing
