import httpant.dependencies.boost.ut;
import std;
import httpant;
import httpant.testing;

namespace httpant::testing {

using namespace boost::ut;

static suite<"task"> task_suite = [] {
    // Coroutine frames come from a per-thread pool of size classes: a freed
    // frame is the next one handed out for its class, frames of one class are
    // interchangeable, and sizes beyond the largest class go to the heap.
    "task_frames_are_pooled_by_size_class"_test = [] {
        using pool = http::detail::frame_pool;
        void* first = pool::allocate(100);
        pool::deallocate(first, 100);
        void* reused = pool::allocate(100);
        expect(reused == first);
        pool::deallocate(reused, 100);

        // 100 and 128 bytes are the same 128-byte class
        void* same_class = pool::allocate(128);
        expect(same_class == first);
        pool::deallocate(same_class, 128);

        // a different class is a different block
        void* other = pool::allocate(1000);
        expect(other != first);
        pool::deallocate(other, 1000);

        void* huge = pool::allocate(1u << 20);
        expect(huge != nullptr);
        pool::deallocate(huge, 1u << 20);
    };

    // The pool never grows without bound: more frames than a class caches are
    // returned to the heap, and all of them can be freed in any order.
    "task_pool_caches_a_bounded_number_of_frames"_test = [] {
        using pool = http::detail::frame_pool;
        std::vector<void*> frames;
        for (int i = 0; i < 200; ++i)
            frames.push_back(pool::allocate(64));
        for (auto it = frames.rbegin(); it != frames.rend(); ++it)
            pool::deallocate(*it, 64);
        expect(frames.size() == 200_u);
    };

    // A frame allocated on one thread and destroyed on another is returned to
    // the pool of the thread that frees it.
    "task_frame_freed_on_another_thread"_test = [] {
        using pool = http::detail::frame_pool;
        void* frame = pool::allocate(256);
        std::thread([&] { pool::deallocate(frame, 256); }).join();
        void* other = pool::allocate(256);
        pool::deallocate(other, 256);
        expect(other != nullptr);
    };

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
