export module httpant.io:mechanism;
import std;
import :windows;

namespace native_io {
    template <template <class> class Queue> struct engine<Queue>::impl : detail::windows<Queue> {};
    template <template <class> class Queue> engine<Queue>::engine() : impl_(std::make_unique<impl>()) {}
    template <template <class> class Queue> engine<Queue>::~engine() = default;
    template <template <class> class Queue> auto engine<Queue>::name() noexcept -> const char* { return "iocp"; }
    template <template <class> class Queue> void engine<Queue>::start(request& r) noexcept {
        r.rejected = false;
        if (auto error = impl_->push(r)) {
            r.rejected = true;
            r.complete(r, -1, error);
            return;
        }
        impl_->signal();
    }
    template <template <class> class Queue> void engine<Queue>::cancel(request& r) noexcept {
        r.cancelled.store(true, std::memory_order_release);
        impl_->signal();
    }
    template <template <class> class Queue> void engine<Queue>::cancel_file(handle file) noexcept {
        impl_->mark_closed(file);
        impl_->signal();
    }
    template <template <class> class Queue> void engine<Queue>::stop() noexcept {
        impl_->stopped.store(true, std::memory_order_release);
        impl_->signal();
    }
    template <template <class> class Queue> void engine<Queue>::run() { impl_->run(); }
} // namespace native_io
