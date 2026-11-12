module;
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <ioringapi.h>

export module httpant.io:mechanism;
import std;
import :windows;

namespace native_io {
    using namespace detail;
    namespace detail {
        auto ring_error(HRESULT result) noexcept -> std::error_code {
            auto code = HRESULT_FACILITY(result) == FACILITY_WIN32 ? HRESULT_CODE(result) : static_cast<int>(result);
            return {code, std::system_category()};
        }
        void check(HRESULT result, const char* what) {
            if (FAILED(result))
                throw std::system_error(ring_error(result), what);
        }
    } // namespace detail
    template <template <class> class Queue> struct engine<Queue>::impl : detail::windows<Queue> {
        using detail::windows<Queue>::port;
        using detail::windows<Queue>::complete;
        HIORING ring = nullptr;
        HANDLE event = nullptr;
        std::optional<detail::waiter> wait;
        bool dirty = false;
        impl() {
            check(::CreateIoRing(IORING_VERSION_3, IORING_CREATE_FLAGS{}, 256, 512, &ring), "CreateIoRing");
            try {
                event = ::CreateEventW(nullptr, FALSE, FALSE, nullptr);
                if (!event)
                    fail_win("CreateEvent ring");
                check(::SetIoRingCompletionEvent(ring, event), "SetIoRingCompletionEvent");
                wait.emplace(event, 2);
                wait->watch(port);
            } catch (...) {
                if (event)
                    ::CloseHandle(event);
                ::CloseIoRing(ring);
                throw;
            }
        }
        ~impl() override {
            wait.reset();
            ::CloseIoRing(ring);
            ::CloseHandle(event);
        }
        void signaled() override {
            wait->waiting = false;
            wait->watch(port);
        }
        void flush() override {
            if (!std::exchange(dirty, false))
                return;
            UINT32 submitted = 0;
            check(::SubmitIoRing(ring, 0, 0, &submitted), "SubmitIoRing");
        }
        template <class Build> void build(Build fn) {
            auto result = fn();
            if (result == IORING_E_SUBMISSION_QUEUE_FULL) {
                flush();
                result = fn();
            }
            check(result, "BuildIoRing operation");
            dirty = true;
        }
        void submit(request& r) override {
            if (r.kind != operation::read_at && r.kind != operation::write_at) {
                detail::windows<Queue>::submit(r);
                return;
            }
            auto file = IoRingHandleRefFromHandle(reinterpret_cast<HANDLE>(r.file));
            auto buffer = IoRingBufferRefFromPointer(r.buffer);
            auto size = static_cast<UINT32>(std::min<std::size_t>(r.size, std::numeric_limits<UINT32>::max()));
            auto id = reinterpret_cast<UINT_PTR>(&r);
            build([&] {
                if (r.kind == operation::read_at)
                    return ::BuildIoRingReadFile(ring, file, buffer, size, r.offset, id, IOSQE_FLAGS_NONE);
                return ::BuildIoRingWriteFile(ring, file, buffer, size, r.offset, FILE_WRITE_FLAGS_NONE, id, IOSQE_FLAGS_NONE);
            });
            state(r).ring = state(r).pending = true;
        }
        void cancel(request& r) override {
            if (!state(r).ring) {
                detail::windows<Queue>::cancel(r);
                return;
            }
            auto id = reinterpret_cast<UINT_PTR>(&r);
            build([&] { return ::BuildIoRingCancelRequest(ring, IoRingHandleRefFromHandle(reinterpret_cast<HANDLE>(r.file)), id, id | 1); });
        }
        void drain() override {
            IORING_CQE entry{};
            for (;;) {
                auto result = ::PopIoRingCompletion(ring, &entry);
                if (result == S_FALSE)
                    break;
                check(result, "PopIoRingCompletion");
                auto id = entry.UserData;
                auto& r = *reinterpret_cast<request*>(id & ~UINT_PTR{1});
                if (id & 1)
                    r.cancel_acknowledged = true;
                else {
                    r.result_ready = true;
                    r.result = static_cast<std::int64_t>(entry.Information);
                    if (entry.ResultCode == HRESULT_FROM_WIN32(ERROR_HANDLE_EOF) && r.kind == operation::read_at)
                        r.result = 0;
                    else if (FAILED(entry.ResultCode))
                        r.error = ring_error(entry.ResultCode);
                }
                if (r.result_ready && (!r.cancel_sent || r.cancel_acknowledged)) {
                    state(r).pending = false;
                    complete(r);
                }
            }
        }
    };
    template <template <class> class Queue> engine<Queue>::engine() : impl_(std::make_unique<impl>()) {}
    template <template <class> class Queue> engine<Queue>::~engine() = default;
    template <template <class> class Queue> auto engine<Queue>::name() noexcept -> const char* { return "windows-io-ring"; }
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
