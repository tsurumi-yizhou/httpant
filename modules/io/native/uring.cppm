module;
#include <errno.h>
#include <liburing.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <unistd.h>

export module httpant.io:mechanism;
import std;
import :queue;

namespace native_io {
    namespace detail {
        thread_local const void* running_engine = nullptr;

        struct datagram_state {
            msghdr message{};
            std::array<iovec, max_buffers> buffers{};
        };
        static_assert(sizeof(datagram_state) <= sizeof(request::native));
        auto datagram(request& r) noexcept -> datagram_state& {
            return *std::launder(reinterpret_cast<datagram_state*>(r.native.data()));
        }

    }
    using namespace detail;

    template <template <class> class Queue>
    struct engine<Queue>::impl : detail::queue<Queue> {
        using detail::queue<Queue>::active;
        using detail::queue<Queue>::take;
        using detail::queue<Queue>::track;
        using detail::queue<Queue>::finish;
        using detail::queue<Queue>::deadline;
        using detail::queue<Queue>::wait_ms;
        io_uring ring{};
        int wake = -1;
        std::uint64_t wake_value = 0;
        std::atomic<bool> wake_pending{false};
        std::atomic<bool> cancellation_pending{false};
        bool enabled = false;
        static constexpr std::uint64_t wake_id = 2;

        // The ring stays disabled until run(): its first caller becomes the only issuer.
        impl() {
            io_uring_params params{};
            params.flags = IORING_SETUP_SINGLE_ISSUER | IORING_SETUP_DEFER_TASKRUN | IORING_SETUP_TASKRUN_FLAG | IORING_SETUP_R_DISABLED;
            auto result = ::io_uring_queue_init_params(256, &ring, &params);
            if (result < 0)
                throw std::system_error(-result, std::generic_category(), "io_uring_queue_init");
            wake = ::eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
            if (wake < 0) {
                auto error = errno;
                ::io_uring_queue_exit(&ring);
                throw std::system_error(error, std::generic_category(), "eventfd");
            }
            try {
                arm_wake();
            } catch (...) {
                ::io_uring_queue_exit(&ring);
                ::close(wake);
                throw;
            }
        }
        ~impl() {
            ::io_uring_queue_exit(&ring);
            ::close(wake);
        }
        void signal() noexcept {
            if (running_engine == this || wake_pending.exchange(true, std::memory_order_acq_rel))
                return;
            std::uint64_t one = 1;
            ssize_t n;
            do {
                n = ::write(wake, &one, sizeof one);
            } while (n < 0 && errno == EINTR);
        }
        void enable() {
            if (enabled)
                return;
            if (auto result = ::io_uring_enable_rings(&ring); result < 0)
                throw std::system_error(-result, std::generic_category(), "io_uring_enable_rings");
            if (auto result = ::io_uring_register_ring_fd(&ring); result < 0)
                throw std::system_error(-result, std::generic_category(), "io_uring_register_ring_fd");
            enabled = true;
        }
        // Deferred task work posts completions only when the issuer enters the kernel;
        // the task-run flag makes liburing enter only while such work is pending.
        void flush() {
            int result;
            do {
                result = ::io_uring_submit(&ring);
            } while (result == -EINTR);
            if (result < 0)
                throw std::system_error(-result, std::generic_category(), "io_uring_submit");
        }
        auto sqe() -> io_uring_sqe* {
            if (auto* entry = ::io_uring_get_sqe(&ring))
                return entry;
            flush();
            auto* entry = ::io_uring_get_sqe(&ring);
            if (!entry)
                throw std::system_error(std::make_error_code(std::errc::no_buffer_space), "io_uring submission queue");
            return entry;
        }
        void arm_wake() {
            auto* entry = sqe();
            ::io_uring_prep_poll_add(entry, wake, POLLIN);
            ::io_uring_sqe_set_data64(entry, wake_id);
        }
        void submit(request& r) {
            auto* entry = sqe();
            auto fd = static_cast<int>(r.file);
            auto size = static_cast<unsigned>(std::min<std::size_t>(r.size, std::numeric_limits<int>::max()));
            switch (r.kind) {
            case operation::read:
            case operation::write:
            case operation::receive:
            case operation::send:
            case operation::receive_from:
            case operation::send_to: {
                auto* state = ::new (r.native.data()) datagram_state{};
                auto count = r.buffer_count;
                for (unsigned i = 0; i < count; ++i) state->buffers[i] = {r.buffers[i].data, r.buffers[i].size};
                if (!count) { state->buffers[0] = {r.buffer, size}; count = 1; }
                if (r.kind == operation::receive_from || r.kind == operation::send_to) {
                    state->message.msg_name = r.address.data();
                    state->message.msg_namelen = r.kind == operation::send_to ? r.address.size() : r.address.bytes.size();
                }
                state->message.msg_iov = state->buffers.data();
                state->message.msg_iovlen = count;
                if (r.kind == operation::read)
                    ::io_uring_prep_readv(entry, fd, state->buffers.data(), count, -1);
                else if (r.kind == operation::receive || r.kind == operation::receive_from)
                    ::io_uring_prep_recvmsg(entry, fd, &state->message, r.flags);
                else
                    ::io_uring_prep_sendmsg(entry, fd, &state->message, r.flags | MSG_NOSIGNAL);
                break;
            }
            case operation::read_at:
                ::io_uring_prep_read(entry, fd, r.buffer, size, r.offset);
                break;
            case operation::write_at:
                ::io_uring_prep_write(entry, fd, r.buffer, size, r.offset);
                break;
            case operation::accept:
                ::io_uring_prep_accept(entry, fd, nullptr, nullptr, SOCK_CLOEXEC);
                break;
            case operation::readable:
                ::io_uring_prep_poll_add(entry, fd, (r.events & 1 ? POLLIN : 0) | (r.events & 2 ? POLLOUT : 0));
                break;
            case operation::connect: {
                ::io_uring_prep_connect(entry, fd, static_cast<const sockaddr*>(r.address.data()), r.address.size());
                break;
            }
            case operation::timer: {
                auto left = std::max(r.deadline - std::chrono::steady_clock::now(), std::chrono::steady_clock::duration::zero());
                auto ns = std::chrono::duration_cast<std::chrono::nanoseconds>(left).count();
                auto* ts = ::new (r.native.data()) __kernel_timespec{ns / 1000000000, ns % 1000000000};
                ::io_uring_prep_timeout(entry, ts, 0, 0);
                break;
            }
            case operation::post:
                ::io_uring_prep_nop(entry);
                break;
            }
            ::io_uring_sqe_set_data(entry, &r);
            track(r);
        }
        void submit_pending() {
            auto* list = take();
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
                try {
                    submit(*r);
                } catch (const std::system_error& error) {
                    finish(*r, 0, error.code());
                }
            }
            if (cancellation_pending.exchange(false, std::memory_order_acq_rel)) {
                for (auto* r = active; r; r = r->active_next) {
                    if (!(r->cancelled.load(std::memory_order_acquire) || r->is_closed()) || r->cancel_sent || r->result_ready)
                        continue;
                    auto* entry = sqe();
                    ::io_uring_prep_cancel(entry, r, 0);
                    ::io_uring_sqe_set_data64(entry, reinterpret_cast<std::uintptr_t>(r) | 1);
                    r->cancel_sent = true;
                }
            }
        }
        void dispatch(io_uring_cqe& entry) {
            auto id = entry.user_data;
            auto result = entry.res;
            ::io_uring_cqe_seen(&ring, &entry);
            if (id == wake_id) {
                while (::read(wake, &wake_value, sizeof wake_value) < 0 && errno == EINTR) {
                }
                wake_pending.store(false, std::memory_order_release);
                arm_wake();
                return;
            }
            auto* r = reinterpret_cast<request*>(static_cast<std::uintptr_t>(id & ~std::uint64_t{1}));
            if (id & 1)
                r->cancel_acknowledged = true;
            else {
                r->result_ready = true;
                r->result = result;
                if (r->kind == operation::timer && result == -ETIME)
                    r->result = 0;
                else if (result < 0)
                    r->error = std::error_code{-result, std::generic_category()};
                else if (r->kind == operation::readable)
                    r->result = (result & POLLIN && r->events & 1 ? 1 : 0) | (result & POLLOUT && r->events & 2 ? 2 : 0) | (result & POLLERR ? 4 : 0);
                else if (r->kind == operation::receive || r->kind == operation::receive_from) {
                    if (r->kind == operation::receive_from)
                        r->address.length = datagram(*r).message.msg_namelen;
                }
            }
            if (r->result_ready && (!r->cancel_sent || r->cancel_acknowledged))
                finish(*r, r->result, r->error);
        }
    };
    template <template <class> class Queue>
    engine<Queue>::engine() : impl_(std::make_unique<impl>()) {}
    template <template <class> class Queue>
    engine<Queue>::~engine() = default;
    template <template <class> class Queue>
    auto engine<Queue>::name() noexcept -> const char* { return "liburing"; }
    template <template <class> class Queue>
    void engine<Queue>::start(request& r) noexcept {
        r.rejected = false;
        if (auto error = impl_->push(r)) {
            r.rejected = true;
            r.complete(r, -1, error);
            return;
        }
        impl_->signal();
    }
    template <template <class> class Queue>
    void engine<Queue>::cancel(request& r) noexcept {
        r.cancelled.store(true, std::memory_order_release);
        impl_->cancellation_pending.store(true, std::memory_order_release);
        impl_->signal();
    }
    template <template <class> class Queue>
    void engine<Queue>::cancel_file(handle file) noexcept {
        impl_->mark_closed(file);
        impl_->cancellation_pending.store(true, std::memory_order_release);
        impl_->signal();
    }
    template <template <class> class Queue>
    void engine<Queue>::stop() noexcept {
        impl_->stopped.store(true, std::memory_order_release);
        impl_->signal();
    }
    template <template <class> class Queue>
    void engine<Queue>::run() {
        if (impl_->stopped.exchange(false, std::memory_order_acquire))
            return;
        struct running_guard {
            const void* previous;
            ~running_guard() { running_engine = previous; }
        } guard{std::exchange(running_engine, impl_.get())};
        impl_->enable();
        for (;;) {
            impl_->submit_pending();
            if (impl_->stopped.exchange(false, std::memory_order_acquire))
                break;
            // Local posts must not starve ready I/O, timers, or cancel acks.
            if (impl_->has_pending()) {
                impl_->flush();
                io_uring_cqe* ready = nullptr;
                for (int count = 0; count < 256 && ::io_uring_peek_cqe(&impl_->ring, &ready) == 0; ++count)
                    impl_->dispatch(*ready);
                continue;
            }
            auto result = ::io_uring_submit_and_wait(&impl_->ring, 1);
            if (result == -EINTR)
                continue;
            if (result < 0)
                throw std::system_error(-result, std::generic_category(), "io_uring_submit_and_wait");
            io_uring_cqe* entry = nullptr;
            result = ::io_uring_wait_cqe(&impl_->ring, &entry);
            if (result == -EINTR)
                continue;
            if (result < 0)
                throw std::system_error(-result, std::generic_category(), "io_uring_wait_cqe");
            impl_->dispatch(*entry);
            for (int count = 0; count < 256 && ::io_uring_peek_cqe(&impl_->ring, &entry) == 0; ++count)
                impl_->dispatch(*entry);
        }
    }
} // namespace native_io
