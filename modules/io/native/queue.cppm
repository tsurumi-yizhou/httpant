module httpant.io:queue;
import std;
import httpant.io;

namespace native_io::detail {
    struct queue {
        std::mutex mutex;
        request* pending = nullptr;
        request* tail = nullptr;
        request* active = nullptr;
        std::atomic<bool> stopped{false};

        void push(request& r) noexcept {
            std::lock_guard lock{mutex};
            r.next = nullptr;
            if (tail)
                tail->next = &r;
            else
                pending = &r;
            tail = &r;
        }
        auto take(std::size_t limit = std::numeric_limits<std::size_t>::max()) noexcept -> request* {
            if (!limit)
                return nullptr;
            std::lock_guard lock{mutex};
            auto* result = pending;
            auto** end = &pending;
            while (*end && limit--)
                end = &(*end)->next;
            pending = std::exchange(*end, nullptr);
            if (!pending)
                tail = nullptr;
            return result;
        }
        void track(request& r) noexcept {
            std::lock_guard lock{mutex};
            r.active_next = active;
            active = &r;
        }
        auto has_pending() noexcept -> bool {
            std::lock_guard lock{mutex};
            return pending != nullptr;
        }
        void untrack(request& r) noexcept {
            std::lock_guard lock{mutex};
            for (auto** p = &active; *p; p = &(*p)->active_next)
                if (*p == &r) {
                    *p = r.active_next;
                    break;
                }
        }
        void mark_closed(handle file) noexcept {
            std::lock_guard lock{mutex};
            for (auto* r = pending; r; r = r->next)
                if (r->file == file)
                    r->closed.store(true, std::memory_order_release);
            for (auto* r = active; r; r = r->active_next)
                if (r->file == file)
                    r->closed.store(true, std::memory_order_release);
        }
        void finish(request& r, std::int64_t value, std::error_code error = {}) noexcept {
            untrack(r);
            if (r.is_closed()) {
                if (!error && r.kind == operation::accept && value >= 0)
                    close_socket(value);
                error = std::make_error_code(std::errc::operation_canceled);
            }
            r.complete(r, value, error);
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
