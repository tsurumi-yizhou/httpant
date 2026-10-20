module;
#include <errno.h>
#include <liburing.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <unistd.h>

module httpant.io;
import std;
import :queue;

namespace native_io {
    struct engine::impl : detail::queue {
        io_uring ring{};
        int wake = -1;
        std::uint64_t wake_value = 0;
        static constexpr std::uint64_t wake_id = 2;

        impl() {
            auto result = ::io_uring_queue_init(256, &ring, 0);
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
                flush();
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
            std::uint64_t one = 1;
            ssize_t n;
            do {
                n = ::write(wake, &one, sizeof one);
            } while (n < 0 && errno == EINTR);
        }
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
                ::io_uring_prep_read(entry, fd, r.buffer, size, -1);
                break;
            case operation::write:
                ::io_uring_prep_send(entry, fd, r.buffer, size, MSG_NOSIGNAL);
                break;
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
                ::io_uring_prep_poll_add(entry, fd, POLLIN);
                break;
            case operation::connect: {
                auto* a = ::new (r.native.data()) sockaddr_in{};
                a->sin_family = AF_INET;
                a->sin_port = htons(r.address.port);
                auto ip =
                    (std::uint32_t{r.address.ip[0]} << 24) | (std::uint32_t{r.address.ip[1]} << 16) | (std::uint32_t{r.address.ip[2]} << 8) | r.address.ip[3];
                a->sin_addr.s_addr = htonl(ip);
                ::io_uring_prep_connect(entry, fd, reinterpret_cast<sockaddr*>(a), sizeof *a);
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
                    r->complete(*r, 0, {});
                    continue;
                }
                try {
                    submit(*r);
                } catch (const std::system_error& error) {
                    r->complete(*r, 0, error.code());
                }
            }
            for (auto* r = active; r; r = r->active_next) {
                if (!(r->cancelled.load(std::memory_order_acquire) || r->is_closed()) || r->cancel_sent || r->result_ready)
                    continue;
                auto* entry = sqe();
                ::io_uring_prep_cancel(entry, r, 0);
                ::io_uring_sqe_set_data64(entry, reinterpret_cast<std::uintptr_t>(r) | 1);
                r->cancel_sent = true;
            }
            flush();
        }
        void dispatch(io_uring_cqe& entry) {
            auto id = entry.user_data;
            auto result = entry.res;
            ::io_uring_cqe_seen(&ring, &entry);
            if (id == wake_id) {
                while (::read(wake, &wake_value, sizeof wake_value) < 0 && errno == EINTR) {
                }
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
            }
            if (r->result_ready && (!r->cancel_sent || r->cancel_acknowledged))
                finish(*r, r->result, r->error);
        }
    };
    engine::engine() : impl_(std::make_unique<impl>()) {}
    engine::~engine() = default;
    auto engine::name() noexcept -> const char* { return "liburing"; }
    void engine::start(request& r) noexcept {
        impl_->push(r);
        impl_->signal();
    }
    void engine::cancel(request& r) noexcept {
        r.cancelled.store(true, std::memory_order_release);
        impl_->signal();
    }
    void engine::cancel_file(handle file) noexcept {
        impl_->mark_closed(file);
        impl_->signal();
    }
    void engine::stop() noexcept {
        impl_->stopped.store(true, std::memory_order_release);
        impl_->signal();
    }
    void engine::run() {
        if (impl_->stopped.exchange(false, std::memory_order_acquire))
            return;
        for (;;) {
            impl_->submit_pending();
            if (impl_->stopped.exchange(false, std::memory_order_acquire))
                break;
            io_uring_cqe* entry = nullptr;
            auto result = ::io_uring_wait_cqe(&impl_->ring, &entry);
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
