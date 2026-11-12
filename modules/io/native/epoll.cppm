module;
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/timerfd.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

export module httpant.io:mechanism;
import std;
import :queue;

namespace native_io {
    namespace detail {
        thread_local const void* running = nullptr;
        struct request_state {
            std::uint32_t filter = 0;
            bool armed = false;
            bool ready = true;
            bool connecting = false;
            bool worker = false;
            std::atomic<bool> worker_done{false};
        };
        static_assert(sizeof(request_state) <= sizeof(request::native));
        auto state(request& r) noexcept -> request_state& { return *std::launder(reinterpret_cast<request_state*>(r.native.data())); }
    } // namespace detail
    using namespace detail;

    template <template <class> class Queue> struct engine<Queue>::impl : detail::queue<Queue> {
        using detail::queue<Queue>::active;
        using detail::queue<Queue>::take;
        using detail::queue<Queue>::track;
        using detail::queue<Queue>::finish;
        using detail::queue<Queue>::deadline;
        using detail::queue<Queue>::wait_ms;
        int descriptor = -1;
        int wake = -1;
        int timer = -1;
        std::chrono::steady_clock::time_point armed = std::chrono::steady_clock::time_point::max();
        std::atomic<bool> wake_pending{false};
        bool rescan = false;
        std::map<int, std::uint32_t> registrations;
        std::counting_semaphore<> work_ready{0};
        Queue<request*> work;
        std::atomic<bool> closing{false};
        std::vector<std::jthread> workers;
        impl() {
            descriptor = ::epoll_create1(EPOLL_CLOEXEC);
            if (descriptor < 0)
                throw std::system_error(errno, std::generic_category(), "epoll_create1");
            try {
                wake = ::eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
                if (wake < 0)
                    throw std::system_error(errno, std::generic_category(), "eventfd");
                epoll_event event{};
                event.events = EPOLLIN;
                event.data.fd = wake;
                if (::epoll_ctl(descriptor, EPOLL_CTL_ADD, wake, &event) < 0)
                    throw std::system_error(errno, std::generic_category(), "epoll wake registration");
                timer = ::timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
                if (timer < 0)
                    throw std::system_error(errno, std::generic_category(), "timerfd_create");
                event.data.fd = timer;
                if (::epoll_ctl(descriptor, EPOLL_CTL_ADD, timer, &event) < 0)
                    throw std::system_error(errno, std::generic_category(), "epoll timer registration");

            } catch (...) {
                {
                    closing = true;
                }
                work_ready.release(static_cast<std::ptrdiff_t>(workers.size()));
                workers.clear();
                if (timer >= 0)
                    ::close(timer);
                if (wake >= 0)
                    ::close(wake);
                ::close(descriptor);
                throw;
            }
        }
        ~impl() {
            {
                closing = true;
            }
            work_ready.release(static_cast<std::ptrdiff_t>(workers.size()));
            workers.clear();
            ::close(timer);
            ::close(wake);
            ::close(descriptor);
        }
        void arm_timer() {
            auto next = deadline();
            if (next == armed)
                return;
            itimerspec value{};
            if (next != std::chrono::steady_clock::time_point::max()) {
                auto ns = std::max<long long>(1, std::chrono::duration_cast<std::chrono::nanoseconds>(next - std::chrono::steady_clock::now()).count());
                value.it_value = {ns / 1000000000, ns % 1000000000};
            }
            if (::timerfd_settime(timer, 0, &value, nullptr) < 0)
                throw std::system_error(errno, std::generic_category(), "timerfd_settime");
            armed = next;
        }
        void signal() noexcept {
            if (running == this) {
                rescan = true;
                return;
            }
            if (wake_pending.exchange(true, std::memory_order_acq_rel))
                return;
            std::uint64_t one = 1;
            while (::write(wake, &one, sizeof one) < 0 && errno == EINTR) {
            }
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
                        if (r->kind == operation::read_at)
                            result = ::preadv(static_cast<int>(r->file), &buffer, 1, static_cast<off_t>(r->offset));
                        else
                            result = ::pwritev(static_cast<int>(r->file), &buffer, 1, static_cast<off_t>(r->offset));
                    } while (result < 0 && errno == EINTR);
                    r->result = result;
                    if (result < 0)
                        r->error = {errno, std::generic_category()};
                } else
                    r->result = -1;
                state(*r).worker_done.store(true, std::memory_order_release);
                signal();
            }
        }
        void update(handle file) {
            std::uint32_t filters = 0;
            bool needed = false;
            for (auto* r = active; r; r = r->active_next)
                if (r->file == file && state(*r).armed) {
                    filters |= state(*r).filter;
                    needed = true;
                }
            auto fd = static_cast<int>(file);
            auto it = registrations.find(fd);
            if (!needed) {
                if (it != registrations.end()) {
                    ::epoll_ctl(descriptor, EPOLL_CTL_DEL, fd, nullptr);
                    registrations.erase(it);
                }
                return;
            }
            epoll_event event{};
            event.events = filters;
            event.data.fd = fd;
            bool inserted = false;
            if (it == registrations.end()) {
                it = registrations.emplace(fd, filters).first;
                inserted = true;
            }
            if (::epoll_ctl(descriptor, inserted ? EPOLL_CTL_ADD : EPOLL_CTL_MOD, fd, &event) < 0) {
                auto error = errno;
                if (inserted)
                    registrations.erase(it);
                throw std::system_error(error, std::generic_category(), "epoll_ctl");
            }
            it->second = filters;
        }
        void disarm(request& r) {
            if (!state(r).armed)
                return;
            state(r).armed = false;
            state(r).filter = 0;
            update(r.file);
        }
        void arm(request& r, std::uint32_t filter) {
            for (auto* other = active; other; other = other->active_next)
                if (other != &r && other->file == r.file && state(*other).armed && state(*other).filter == filter)
                    throw std::system_error(std::make_error_code(std::errc::operation_in_progress));
            state(r).armed = true;
            state(r).filter = filter;
            state(r).ready = false;
            update(r.file);
        }
        void attempt(request& r) {
            if (r.result_ready)
                return;
            auto& s = state(r);
            if (s.worker) {
                r.result_ready = s.worker_done.load(std::memory_order_acquire);
                return;
            }
            if (r.cancelled.load(std::memory_order_acquire) || r.is_closed()) {
                disarm(r);
                r.result = -1;
                r.result_ready = true;
                return;
            }
            if (r.kind == operation::timer) {
                r.result_ready = r.deadline <= std::chrono::steady_clock::now();
                return;
            }
            if (!s.ready)
                return;
            disarm(r);
            s.ready = false;
            auto fd = static_cast<int>(r.file);
            std::array<iovec, max_buffers> buffers{};
            auto count = r.buffer_count;
            for (unsigned i = 0; i < count; ++i)
                buffers[i] = {r.buffers[i].data, r.buffers[i].size};
            if (!count) {
                buffers[0] = {r.buffer, r.size};
                count = 1;
            }
            ssize_t result = 0;
            std::uint32_t filter = EPOLLIN;
            switch (r.kind) {
            case operation::read:
                do {
                    result = ::readv(fd, buffers.data(), count);
                } while (result < 0 && errno == EINTR);
                break;
            case operation::write: {
                filter = EPOLLOUT;
                msghdr message{};
                message.msg_iov = buffers.data();
                message.msg_iovlen = count;
                do {
                    result = ::sendmsg(fd, &message, MSG_NOSIGNAL);
                } while (result < 0 && errno == EINTR);
                break;
            }
            case operation::receive:
            case operation::receive_from: {
                socket_address from;
                msghdr message{};
                message.msg_iov = buffers.data();
                message.msg_iovlen = count;
                if (r.kind == operation::receive_from) {
                    message.msg_name = from.data();
                    message.msg_namelen = from.bytes.size();
                }
                do {
                    result = ::recvmsg(fd, &message, r.flags);
                } while (result < 0 && errno == EINTR);
                if (result >= 0 && r.kind == operation::receive_from) {
                    from.length = message.msg_namelen;
                    r.address = from;
                }
                break;
            }
            case operation::send:
            case operation::send_to: {
                filter = EPOLLOUT;
                msghdr message{};
                message.msg_iov = buffers.data();
                message.msg_iovlen = count;
                if (r.kind == operation::send_to) {
                    message.msg_name = r.address.data();
                    message.msg_namelen = r.address.size();
                }
                do {
                    result = ::sendmsg(fd, &message, r.flags | MSG_NOSIGNAL);
                } while (result < 0 && errno == EINTR);
                break;
            }
            case operation::accept: {
                int peer;
                do {
                    peer = ::accept4(fd, nullptr, nullptr, SOCK_NONBLOCK | SOCK_CLOEXEC);
                } while (peer < 0 && errno == EINTR);
                result = peer;
                if (peer >= 0)
                    configure_stream(peer);
                break;
            }
            case operation::connect: {
                filter = EPOLLOUT;
                if (!s.connecting) {
                    auto& a = r.address;
                    result = ::connect(fd, static_cast<const sockaddr*>(a.data()), a.size());
                    if (result < 0 && errno == EINPROGRESS) {
                        s.connecting = true;
                        arm(r, filter);
                        return;
                    }
                } else {
                    int error = 0;
                    socklen_t size = sizeof error;
                    result = ::getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &size);
                    if (result == 0 && error) {
                        errno = error;
                        result = -1;
                    }
                }
                break;
            }
            case operation::readable:
                if (!s.connecting) {
                    s.connecting = true;
                    arm(r, (r.events & 1 ? EPOLLIN : 0) | (r.events & 2 ? EPOLLOUT : 0));
                    return;
                }
                result = r.offset;
                break;
            case operation::post:
                break;
            case operation::timer:
            case operation::read_at:
            case operation::write_at:
                return;
            }
            if (result < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                arm(r, filter);
                return;
            }
            r.result = result;
            if (result < 0)
                r.error = {errno, std::generic_category()};
            r.result_ready = true;
        }
        void submit_pending() {
            auto* list = take(64);
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
                ::new (r->native.data()) request_state{};
                try {
                    if (r->kind == operation::read_at || r->kind == operation::write_at) {
                        state(*r).worker = true;
                        if (workers.empty()) {
                            workers.reserve(2);
                            for (int i = 0; i < 2; ++i)
                                workers.emplace_back([this] { run_worker(); });
                        }
                        if (!work.push(r)) {
                            finish(*r, -1, std::make_error_code(std::errc::no_buffer_space));
                            continue;
                        }
                        track(*r);
                        work_ready.release();
                    } else {
                        track(*r);
                    }
                } catch (const std::system_error& error) {
                    finish(*r, 0, error.code());
                } catch (...) {
                    finish(*r, 0, std::make_error_code(std::errc::not_enough_memory));
                }
            }
        }
        void progress() {
            for (auto* r = active; r;) {
                auto* next = r->active_next;
                try {
                    attempt(*r);
                } catch (const std::system_error& error) {
                    disarm(*r);
                    r->error = error.code();
                    r->result_ready = true;
                } catch (const std::bad_alloc&) {
                    disarm(*r);
                    r->error = std::make_error_code(std::errc::not_enough_memory);
                    r->result_ready = true;
                }
                if (r->result_ready)
                    finish(*r, r->result, r->error);
                r = next;
            }
        }
    };
    template <template <class> class Queue> engine<Queue>::engine() : impl_(std::make_unique<impl>()) {}
    template <template <class> class Queue> engine<Queue>::~engine() = default;
    template <template <class> class Queue> auto engine<Queue>::name() noexcept -> const char* { return "epoll"; }
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
    template <template <class> class Queue> void engine<Queue>::run() {
        if (impl_->stopped.exchange(false, std::memory_order_acquire))
            return;
        struct guard {
            const void* previous;
            ~guard() { running = previous; }
        } scope{std::exchange(running, impl_.get())};
        for (;;) {
            impl_->submit_pending();
            impl_->progress();
            if (impl_->stopped.exchange(false, std::memory_order_acquire))
                break;
            epoll_event events[64];
            impl_->arm_timer();
            // A completion can cancel a request already visited by progress().
            // Poll readiness once, then revisit it before blocking again.
            auto rescan = std::exchange(impl_->rescan, false);
            auto count = ::epoll_wait(impl_->descriptor, events, 64, impl_->has_pending() || rescan ? 0 : -1);
            if (count < 0) {
                if (errno == EINTR)
                    continue;
                throw std::system_error(errno, std::generic_category(), "epoll_wait");
            }
            for (int i = 0; i < count; ++i) {
                auto fd = events[i].data.fd;
                if (fd == impl_->timer) {
                    std::uint64_t expirations;
                    while (::read(fd, &expirations, sizeof expirations) < 0 && errno == EINTR) {
                    }
                    impl_->armed = std::chrono::steady_clock::time_point::max();
                    continue;
                }
                if (fd == impl_->wake) {
                    std::uint64_t value;
                    while (::read(fd, &value, sizeof value) < 0 && errno == EINTR) {
                    }
                    impl_->wake_pending.store(false, std::memory_order_release);
                    continue;
                }
                for (auto* r = impl_->active; r; r = r->active_next)
                    if (r->file == fd && state(*r).armed && (events[i].events & (state(*r).filter | EPOLLERR | EPOLLHUP))) {
                        state(*r).ready = true;
                        r->offset = (events[i].events & EPOLLIN && r->events & 1 ? 1 : 0) | (events[i].events & EPOLLOUT && r->events & 2 ? 2 : 0) |
                                    (events[i].events & EPOLLERR ? 4 : 0);
                    }
            }
        }
    }
} // namespace native_io
