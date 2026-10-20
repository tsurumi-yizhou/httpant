module;
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/event.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

module httpant.io;
import std;
import :queue;

namespace native_io {
    namespace {
        struct request_state {
            short filter = 0;
            bool ready = true;
            bool connecting = false;
            bool worker = false;
            std::atomic<bool> worker_done{false};
        };
        static_assert(sizeof(request_state) <= 128);
        auto state(request& r) noexcept -> request_state& { return *std::launder(reinterpret_cast<request_state*>(r.native.data())); }
        auto address(endpoint e) noexcept -> sockaddr_in {
            sockaddr_in a{};
            a.sin_family = AF_INET;
            a.sin_port = htons(e.port);
            auto ip = (std::uint32_t{e.ip[0]} << 24) | (std::uint32_t{e.ip[1]} << 16) | (std::uint32_t{e.ip[2]} << 8) | e.ip[3];
            a.sin_addr.s_addr = htonl(ip);
            return a;
        }
    } // namespace
    struct engine::impl : detail::queue {
        int descriptor = -1;
        std::mutex work_mutex;
        std::condition_variable work_ready;
        std::deque<request*> work;
        bool closing = false;
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
                    std::lock_guard lock{work_mutex};
                    closing = true;
                }
                work_ready.notify_all();
                workers.clear();
                ::close(descriptor);
                throw;
            }
        }
        ~impl() {
            {
                std::lock_guard lock{work_mutex};
                closing = true;
            }
            work_ready.notify_all();
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
                request* r;
                {
                    std::unique_lock lock{work_mutex};
                    work_ready.wait(lock, [this] { return closing || !work.empty(); });
                    if (work.empty())
                        return;
                    r = work.front();
                    work.pop_front();
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
                if (other != &r && other->file == r.file && state(*other).filter == filter)
                    throw std::system_error(std::make_error_code(std::errc::operation_in_progress));
            struct kevent event;
            EV_SET(&event, static_cast<uintptr_t>(r.file), filter, EV_ADD | EV_ONESHOT, 0, 0, &r);
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
            s.ready = false;
            auto fd = static_cast<int>(r.file);
            iovec buffer{r.buffer, std::min<std::size_t>(r.size, std::numeric_limits<int>::max())};
            ssize_t result = 0;
            short filter = EVFILT_READ;
            switch (r.kind) {
            case operation::read:
                do {
                    result = ::readv(fd, &buffer, 1);
                } while (result < 0 && errno == EINTR);
                break;
            case operation::write:
                filter = EVFILT_WRITE;
                do {
                    result = ::writev(fd, &buffer, 1);
                } while (result < 0 && errno == EINTR);
                break;
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
                    auto a = address(r.address);
                    result = ::connect(fd, reinterpret_cast<sockaddr*>(&a), sizeof a);
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
                    arm(r, EVFILT_READ);
                    return;
                }
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
                        std::lock_guard lock{work_mutex};
                        if (workers.empty()) {
                            workers.reserve(2);
                            for (int i = 0; i < 2; ++i)
                                workers.emplace_back([this] { run_worker(); });
                        }
                        work.push_back(r);
                        track(*r);
                        work_ready.notify_one();
                    } else {
                        if (r->file != invalid_handle) {
                            auto flags = ::fcntl(static_cast<int>(r->file), F_GETFL);
                            if (flags < 0 || ::fcntl(static_cast<int>(r->file), F_SETFL, flags | O_NONBLOCK) < 0)
                                throw std::system_error(errno, std::generic_category(), "nonblocking descriptor");
                        }
                        track(*r);
                    }
                } catch (const std::system_error& error) {
                    r->complete(*r, 0, error.code());
                } catch (...) {
                    r->complete(*r, 0, std::make_error_code(std::errc::not_enough_memory));
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
    engine::engine() : impl_(std::make_unique<impl>()) {}
    engine::~engine() = default;
    auto engine::name() noexcept -> const char* { return "kqueue-readv-writev"; }
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
            impl_->progress();
            if (impl_->stopped.exchange(false, std::memory_order_acquire))
                break;
            auto ms = impl_->wait_ms(1000);
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
                state(r).filter = 0;
                state(r).ready = true;
                if (events[i].flags & EV_ERROR) {
                    r.error = {static_cast<int>(events[i].data), std::generic_category()};
                    r.result_ready = true;
                }
            }
        }
    }
} // namespace native_io
