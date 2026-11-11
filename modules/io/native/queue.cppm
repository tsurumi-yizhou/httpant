export module httpant.io:queue;
import std;
import :native;

export namespace native_io::detail {
    template <template <class> class Queue>
        requires http::queues::queue<Queue<request*>, request*>
    struct queue {
        std::mutex mutex;
        Queue<request*> pending;
        std::atomic<std::size_t> pending_count{0};
        request* active = nullptr;
        request* registered = nullptr;
        std::atomic<bool> stopped{false};

        auto push(request& r) noexcept -> std::error_code {
            {
                std::lock_guard lock{mutex};
                r.registered_next = registered;
                r.registered_previous = &registered;
                if (registered) registered->registered_previous = &r.registered_next;
                registered = &r;
            }
            pending_count.fetch_add(1, std::memory_order_release);
            std::error_code error;
            try {
                if (pending.push(&r)) return {};
                error = std::make_error_code(std::errc::no_buffer_space);
            } catch (const std::bad_alloc&) {
                error = std::make_error_code(std::errc::not_enough_memory);
            }
            pending_count.fetch_sub(1, std::memory_order_release);
            unregister(r);
            return error;
        }
        void unregister(request& r) noexcept {
            std::lock_guard lock{mutex};
            if (auto** previous = std::exchange(r.registered_previous, nullptr)) {
                *previous = r.registered_next;
                if (r.registered_next) r.registered_next->registered_previous = previous;
            }
        }
        auto take(std::size_t limit = 64) noexcept -> request* {
            request* result = nullptr;
            auto** end = &result;
            request* item;
            while (limit-- && pending.try_pop(item)) {
                pending_count.fetch_sub(1, std::memory_order_acquire);
                *end = item;
                end = &item->next;
            }
            *end = nullptr;
            return result;
        }
        void track(request& r) noexcept {
            std::lock_guard lock{mutex};
            r.active_next = active;
            r.active_previous = &active;
            if (active)
                active->active_previous = &r.active_next;
            active = &r;
        }
        auto has_pending() noexcept -> bool { return pending_count.load(std::memory_order_acquire) != 0; }
        void untrack(request& r) noexcept {
            std::lock_guard lock{mutex};
            if (auto** previous = std::exchange(r.active_previous, nullptr)) {
                *previous = r.active_next;
                if (r.active_next)
                    r.active_next->active_previous = previous;
                r.active_next = nullptr;
            }
        }
        void mark_closed(handle file) noexcept {
            std::lock_guard lock{mutex};
            for (auto* r = registered; r; r = r->registered_next)
                if (r->file == file)
                    r->closed.store(true, std::memory_order_release);
        }
        void finish(request& r, std::int64_t value, std::error_code error = {}) noexcept {
            untrack(r);
            unregister(r);
            if (r.is_closed()) {
                if (!error && r.kind == operation::accept && value >= 0)
                    close_socket(value);
                error = std::make_error_code(std::errc::operation_canceled);
            }
            r.complete(r, value, error);
        }
        auto deadline() const noexcept -> std::chrono::steady_clock::time_point {
            auto next = std::chrono::steady_clock::time_point::max();
            for (auto* r = active; r; r = r->active_next)
                if (r->kind == operation::timer)
                    next = std::min(next, r->deadline);
            return next;
        }
        auto wait_ms(int ceiling) const noexcept -> int {
            auto now = std::chrono::steady_clock::now();
            for (auto* r = active; r; r = r->active_next)
                if (r->kind == operation::timer) {
                    auto left = std::chrono::ceil<std::chrono::milliseconds>(r->deadline - now).count();
                    ceiling = static_cast<int>(std::min<std::int64_t>(ceiling, std::max<std::int64_t>(0, left)));
                }
            return ceiling;
        }
    };
} // namespace native_io::detail
