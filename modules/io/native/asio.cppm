module;
#include <asio/detail/config.hpp>
#ifndef ASIO_HAS_FILE
#include <errno.h>
#include <sys/uio.h>
#include <unistd.h>
#endif

export module httpant.io:mechanism;
import std;
import :queue;
#ifdef _WIN32
import :windows;
#endif

namespace native_io {
    namespace detail {
        auto asio_running() noexcept -> const void*&;
        struct asio_operation;
        struct asio_state {
            asio_operation* pending = nullptr;
            bool worker = false;
            std::atomic<bool> done{false};
        };
        static_assert(sizeof(asio_state) <= sizeof(request::native));
        auto asio_data(request& r) noexcept -> asio_state& { return *std::launder(reinterpret_cast<asio_state*>(r.native.data())); }
        class asio_loop {
        public:
            asio_loop();
            ~asio_loop();
            asio_loop(const asio_loop&) = delete;
            auto operator=(const asio_loop&) -> asio_loop& = delete;
            void signal() noexcept;
            void restart();
            void run_one(bool pending);
            void start(request&);
            void cancel(request&) noexcept;
            void close(handle) noexcept;

        private:
            struct impl;
            impl* impl_;
        };
    } // namespace detail

    template <template <class> class Queue> struct engine<Queue>::impl : detail::queue<Queue> {
        using detail::queue<Queue>::active;
        using detail::queue<Queue>::take;
        using detail::queue<Queue>::track;
        using detail::queue<Queue>::finish;
        detail::asio_loop loop;
        std::mutex runtime;
        // Closes from other threads, guarded by the queue's mutex.
        std::vector<handle> closed;
        bool rescan = false;
#ifndef ASIO_HAS_FILE
        std::counting_semaphore<> work_ready{0};
        Queue<request*> work;
        std::atomic<bool> closing{false};
        std::vector<std::jthread> workers;
        ~impl() {
            closing.store(true, std::memory_order_release);
            work_ready.release(static_cast<std::ptrdiff_t>(workers.size()));
            workers.clear();
        }
        void run_worker() {
            for (;;) {
                work_ready.acquire();
                request* r;
                while (!work.try_pop(r)) {
                    if (closing.load(std::memory_order_acquire))
                        return;
                    std::this_thread::yield();
                }
                if (!r->cancelled.load(std::memory_order_acquire) && !r->is_closed()) {
                    iovec buffer{r->buffer, std::min<std::size_t>(r->size, std::numeric_limits<int>::max())};
                    ssize_t result;
                    do {
                        result = r->kind == operation::read_at ? ::preadv(static_cast<int>(r->file), &buffer, 1, static_cast<off_t>(r->offset))
                                                               : ::pwritev(static_cast<int>(r->file), &buffer, 1, static_cast<off_t>(r->offset));
                    } while (result < 0 && errno == EINTR);
                    r->result = result;
                    if (result < 0)
                        r->error = {errno, std::generic_category()};
                } else
                    r->result = -1;
                detail::asio_data(*r).done.store(true, std::memory_order_release);
                signal();
            }
        }
#endif
        void signal() noexcept {
            if (detail::asio_running() == this)
                rescan = true;
            else
                loop.signal();
        }
        void complete(request& r) noexcept {
            std::destroy_at(&detail::asio_data(r));
            finish(r, r.result, r.error);
        }
        void close_pending() {
            std::vector<handle> files;
            {
                std::lock_guard lock{this->mutex};
                files.swap(closed);
            }
            for (auto file : files)
                loop.close(file);
        }
        void submit_pending() {
            auto* list = take();
            close_pending();
            while (list) {
                auto* r = list;
                list = list->next;
                if (r->cancelled.load(std::memory_order_acquire) || r->is_closed()) {
                    finish(*r, -1);
                    continue;
                }
                if (r->kind == operation::post) {
                    finish(*r, 0);
                    continue;
                }
                ::new (r->native.data()) detail::asio_state{};
                try {
#ifndef ASIO_HAS_FILE
                    if (r->kind == operation::read_at || r->kind == operation::write_at) {
                        detail::asio_data(*r).worker = true;
                        if (workers.empty()) {
                            workers.reserve(2);
                            for (int i = 0; i < 2; ++i)
                                workers.emplace_back([this] { run_worker(); });
                        }
                        if (!work.push(r)) {
                            r->error = std::make_error_code(std::errc::no_buffer_space);
                            r->result = -1;
                            complete(*r);
                            continue;
                        }
                        track(*r);
                        work_ready.release();
                        continue;
                    }
#endif
                    track(*r);
                    loop.start(*r);
                } catch (const std::system_error& error) {
                    r->error = error.code();
                    r->result = -1;
                    complete(*r);
                } catch (...) {
                    r->error = std::make_error_code(std::errc::not_enough_memory);
                    r->result = -1;
                    complete(*r);
                }
            }
        }
        void progress() {
            for (auto* r = active; r;) {
                auto* next = r->active_next;
                auto& state = detail::asio_data(*r);
                if (state.worker) {
                    if (state.done.load(std::memory_order_acquire))
                        complete(*r);
                } else if (r->result_ready)
                    complete(*r);
                else if (r->cancelled.load(std::memory_order_acquire) || r->is_closed())
                    loop.cancel(*r);
                r = next;
            }
        }
    };
    template <template <class> class Queue> engine<Queue>::engine() : impl_(std::make_unique<impl>()) {}
    template <template <class> class Queue> engine<Queue>::~engine() = default;
    template <template <class> class Queue> auto engine<Queue>::name() noexcept -> const char* { return "asio"; }
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
        if (detail::asio_running() == impl_.get())
            impl_->loop.close(file);
        else {
            std::unique_lock runtime{impl_->runtime, std::try_to_lock};
            if (runtime.owns_lock())
                impl_->loop.close(file);
            else {
                std::lock_guard lock{impl_->mutex};
                impl_->closed.push_back(file);
            }
        }
        impl_->signal();
    }
    template <template <class> class Queue> void engine<Queue>::stop() noexcept {
        impl_->stopped.store(true, std::memory_order_release);
        impl_->signal();
    }
    template <template <class> class Queue> void engine<Queue>::run() {
        std::lock_guard runtime{impl_->runtime};
        if (impl_->stopped.exchange(false, std::memory_order_acquire))
            return;
        struct guard {
            impl* self;
            const void* previous;
            ~guard() {
                self->close_pending();
                detail::asio_running() = previous;
            }
        } scope{impl_.get(), std::exchange(detail::asio_running(), impl_.get())};
        for (;;) {
            impl_->loop.restart();
            impl_->submit_pending();
            impl_->progress();
            if (impl_->stopped.exchange(false, std::memory_order_acquire))
                break;
            auto rescan = std::exchange(impl_->rescan, false);
            impl_->loop.run_one(impl_->has_pending() || rescan);
        }
    }
} // namespace native_io
