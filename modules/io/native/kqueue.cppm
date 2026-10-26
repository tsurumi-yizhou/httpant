module;
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/event.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

export module httpant.io:mechanism;
import std;
import :queue;

namespace native_io {
    namespace detail {
        struct request_state {
            short filter = 0;
            bool secondary = false;
            bool ready = true;
            bool connecting = false;
            bool worker = false;
            std::atomic<bool> worker_done{false};
        };
        static_assert(sizeof(request_state) <= sizeof(request::native));
        auto state(request& r) noexcept -> request_state& { return *std::launder(reinterpret_cast<request_state*>(r.native.data())); }
    } // namespace
    using namespace detail;

    template <template <class> class Queue>
    struct engine<Queue>::impl : detail::queue<Queue> {
        using detail::queue<Queue>::active;
        using detail::queue<Queue>::take;
        using detail::queue<Queue>::track;
        using detail::queue<Queue>::finish;
        using detail::queue<Queue>::deadline;
        using detail::queue<Queue>::wait_ms;
        int descriptor = -1;
        std::counting_semaphore<> work_ready{0};
        Queue<request*> work;
        std::atomic<bool> closing{false};
        std::vector<std::jthread> workers;
        impl() {
            descriptor = ::kqueue();
            if (descriptor < 0)
                throw std::system_error(errno, std::generic_category(), "kqueue");
            try {
                if (::fcntl(descriptor, F_SETFD, FD_CLOEXEC) < 0)
                    throw std::system_error(errno, std::generic_category(), "kqueue cloexec");
                struct kevent event;
                EV_SET(&event, 1, EVFILT_USER, EV_ADD | EV_CLEAR, 0, 0, nullptr);
                if (::kevent(descriptor, &event, 1, nullptr, 0, nullptr) < 0)
                    throw std::system_error(errno, std::generic_category(), "kqueue wake registration");

            } catch (...) {
                {
                    closing = true;
                }
                work_ready.release(static_cast<std::ptrdiff_t>(workers.size()));
                workers.clear();
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
            ::close(descriptor);
        }
        void signal() noexcept {
            struct kevent event;
            EV_SET(&event, 1, EVFILT_USER, 0, NOTE_TRIGGER, 0, nullptr);
            while (::kevent(descriptor, &event, 1, nullptr, 0, nullptr) < 0 && errno == EINTR) {
            }
        }
        void run_worker() {
            for (;;) {
                work_ready.acquire();
                request* r;
                while (!work.try_pop(r)) {
                    if (closing.load(std::memory_order_acquire)) return;
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
                }
                state(*r).worker_done.store(true, std::memory_order_release);
                signal();
            }
        }
        void disarm(request& r) noexcept {
            auto& s = state(r);
            if (s.secondary) {
                struct kevent extra;
                EV_SET(&extra, static_cast<uintptr_t>(r.file), EVFILT_READ, EV_DELETE, 0, 0, nullptr);
                while (::kevent(descriptor, &extra, 1, nullptr, 0, nullptr) < 0 && errno == EINTR) {}
                s.secondary = false;
            }
            if (!s.filter)
                return;
            struct kevent event;
            EV_SET(&event, static_cast<uintptr_t>(r.file), s.filter, EV_DELETE, 0, 0, nullptr);
            while (::kevent(descriptor, &event, 1, nullptr, 0, nullptr) < 0 && errno == EINTR) {
            }
            s.filter = 0;
        }
        void arm(request& r, short filter) {
            for (auto* other = active; other; other = other->active_next)
                if (other != &r && other->file == r.file && (state(*other).filter == filter || (filter == EVFILT_READ && state(*other).secondary)))
                    throw std::system_error(std::make_error_code(std::errc::operation_in_progress));
            struct kevent event;
            EV_SET(&event, static_cast<uintptr_t>(r.file), filter, EV_ADD | (r.kind == operation::readable && !(r.events & 3) ? EV_CLEAR : EV_ONESHOT), 0, 0, &r);
            if (::kevent(descriptor, &event, 1, nullptr, 0, nullptr) < 0)
                throw std::system_error(errno, std::generic_category(), "kevent register");
            state(r).filter = filter;
            state(r).ready = false;
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
            if (r.kind != operation::readable) disarm(r);
            s.ready = false;
            auto fd = static_cast<int>(r.file);
            std::array<iovec, max_buffers> buffers{};
            auto count = r.buffer_count;
            for (unsigned i = 0; i < count; ++i) buffers[i] = {r.buffers[i].data, r.buffers[i].size};
            if (!count) { buffers[0] = {r.buffer, r.size}; count = 1; }
            ssize_t result = 0;
            short filter = EVFILT_READ;
            switch (r.kind) {
            case operation::read:
                do {
                    result = ::readv(fd, buffers.data(), count);
                } while (result < 0 && errno == EINTR);
                break;
            case operation::write:
                filter = EVFILT_WRITE;
                do {
                    result = ::writev(fd, buffers.data(), count);
                } while (result < 0 && errno == EINTR);
                break;
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
                filter = EVFILT_WRITE;
                msghdr message{};
                message.msg_iov = buffers.data();
                message.msg_iovlen = count;
                if (r.kind == operation::send_to) {
                    message.msg_name = r.address.data();
                    message.msg_namelen = r.address.size();
                }
                do {
                    result = ::sendmsg(fd, &message, r.flags);
                } while (result < 0 && errno == EINTR);
                break;
            }
            case operation::accept: {
                int peer;
                do {
                    peer = ::accept(fd, nullptr, nullptr);
                } while (peer < 0 && errno == EINTR);
                result = peer;
                if (peer >= 0) {
                    if (::fcntl(peer, F_SETFD, FD_CLOEXEC) < 0) {
                        auto error = errno;
                        ::close(peer);
                        errno = error;
                        result = -1;
                    } else
                        configure_stream(peer);
                }
                break;
            }
            case operation::connect: {
                filter = EVFILT_WRITE;
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
            case operation::readable: {
                pollfd fd{static_cast<int>(r.file), static_cast<short>((r.events & 1 ? POLLIN : 0) | (r.events & 2 ? POLLOUT : 0)), 0};
                auto ready = ::poll(&fd, 1, 0);
                if (ready < 0) { auto error = errno; disarm(r); errno = error; result = -1; break; }
                if (ready) {
                    disarm(r);
                    result = (fd.revents & POLLIN && r.events & 1 ? 1 : 0) | (fd.revents & POLLOUT && r.events & 2 ? 2 : 0) | (fd.revents & POLLERR ? 4 : 0);
                    break;
                }
                if (!(r.events & 3) && s.filter) return;
                disarm(r);
                arm(r, r.events & 2 ? EVFILT_WRITE : EVFILT_READ);
                if ((r.events & 3) == 3) {
                    for (auto* other = active; other; other = other->active_next)
                        if (other != &r && other->file == r.file && (state(*other).filter == EVFILT_READ || state(*other).secondary))
                            throw std::system_error(std::make_error_code(std::errc::operation_in_progress));
                    struct kevent extra;
                    EV_SET(&extra, static_cast<uintptr_t>(r.file), EVFILT_READ, EV_ADD | EV_ONESHOT, 0, 0, &r);
                    if (::kevent(descriptor, &extra, 1, nullptr, 0, nullptr) < 0) throw std::system_error(errno, std::generic_category(), "kevent read wait");
                    s.secondary = true;
                }
                return;
            }
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
            auto* list = take();
            while (list) {
                auto* r = list;
                list = list->next;
                if (r->cancelled.load(std::memory_order_acquire) || r->is_closed()) {
                    finish(*r, -1);
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
                        if (r->file != invalid_handle) {
                            auto flags = ::fcntl(static_cast<int>(r->file), F_GETFL);
                            if (flags < 0 || ::fcntl(static_cast<int>(r->file), F_SETFL, flags | O_NONBLOCK) < 0)
                                throw std::system_error(errno, std::generic_category(), "nonblocking descriptor");
                        }
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
                }
                if (r->result_ready)
                    finish(*r, r->result, r->error);
                r = next;
            }
        }
    };
    template <template <class> class Queue>
    engine<Queue>::engine() : impl_(std::make_unique<impl>()) {}
    template <template <class> class Queue>
    engine<Queue>::~engine() = default;
    template <template <class> class Queue>
    auto engine<Queue>::name() noexcept -> const char* { return "kqueue-readv-writev"; }
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
        impl_->signal();
    }
    template <template <class> class Queue>
    void engine<Queue>::cancel_file(handle file) noexcept {
        impl_->mark_closed(file);
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
        for (;;) {
            impl_->submit_pending();
            impl_->progress();
            if (impl_->stopped.exchange(false, std::memory_order_acquire))
                break;
            auto ms = impl_->has_pending() ? 0 : impl_->wait_ms(1000);
            timespec timeout{ms / 1000, (ms % 1000) * 1000000};
            struct kevent events[64];
            int count;
            do {
                count = ::kevent(impl_->descriptor, nullptr, 0, events, 64, &timeout);
            } while (count < 0 && errno == EINTR);
            if (count < 0)
                throw std::system_error(errno, std::generic_category(), "kevent wait");
            for (int i = 0; i < count; ++i) {
                if (events[i].filter == EVFILT_USER)
                    continue;
                auto& r = *static_cast<request*>(events[i].udata);
                state(r).ready = true;
                if (events[i].flags & EV_ERROR) {
                    impl_->disarm(r);
                    r.error = {static_cast<int>(events[i].data), std::generic_category()};
                    r.result_ready = true;
                }
            }
        }
    }
} // namespace native_io
