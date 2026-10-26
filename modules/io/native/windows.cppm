module;
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <mswsock.h>
#include <windows.h>
#include <ws2tcpip.h>

export module httpant.io:windows;
import std;
import :queue;

export namespace native_io {
    namespace detail {
        thread_local const void* running = nullptr;
        [[noreturn]] void fail_win(const char* what, DWORD error = ::GetLastError()) {
            throw std::system_error(static_cast<int>(error), std::system_category(), what);
        }
        struct winsock {
            winsock() {
                WSADATA data{};
                auto error = ::WSAStartup(MAKEWORD(2, 2), &data);
                if (error)
                    fail_win("WSAStartup", error);
            }
            ~winsock() { ::WSACleanup(); }
        };
        void start_winsock() { static winsock instance; }
        std::mutex association_mutex;
        std::map<handle, HANDLE> associations;
        struct request_state {
            OVERLAPPED overlap{};
            request* owner = nullptr;
            WSABUF buffer{};
            std::array<WSABUF, max_buffers> buffers{};
            socket_address address;
            int address_size = 32;
            DWORD flags = 0;
            SOCKET accepted = INVALID_SOCKET;
            std::unique_ptr<std::byte[]> accept_buffer;
            bool pending = false;
            bool ring = false;
        };
        static_assert(sizeof(request_state) <= sizeof(request::native));
        static_assert(offsetof(request_state, overlap) == 0);
        auto state(request& r) noexcept -> request_state& {
            return *std::launder(reinterpret_cast<request_state*>(r.native.data()));
        }
        template<class Function> auto extension(SOCKET socket, GUID id) -> Function {
            Function function = nullptr;
            DWORD bytes = 0;
            if (::WSAIoctl(socket, SIO_GET_EXTENSION_FUNCTION_POINTER, &id, sizeof id,
                           &function, sizeof function, &bytes, nullptr, nullptr) == SOCKET_ERROR)
                fail_win("Winsock extension", ::WSAGetLastError());
            return function;
        }
        auto truncated(DWORD error) noexcept -> bool {
            return error == WSAEMSGSIZE || error == ERROR_MORE_DATA;
        }
        auto io_error(DWORD error) noexcept -> std::error_code {
            if (truncated(error))
                return std::make_error_code(std::errc::message_size);
            return {static_cast<int>(error), std::system_category()};
        }
    }
    namespace detail {
    template <template <class> class Queue>
    struct windows : queue<Queue> {
        using queue<Queue>::active;
        using queue<Queue>::take;
        using queue<Queue>::track;
        using queue<Queue>::finish;
        using queue<Queue>::has_pending;
        using queue<Queue>::stopped;
        using queue<Queue>::wait_ms;
        using queue<Queue>::deadline;
        struct notification {
            handle file;
            UINT16 filter = 0;
            bool registered = false;
            bool enabled = false;
            bool removing = false;
        };
        std::map<handle, notification> notifications;
        HANDLE port = nullptr;
        HANDLE timer = nullptr;
        HANDLE timer_wait = nullptr;
        std::atomic<bool> wake_pending{false};
        bool rescan = false;
        std::chrono::steady_clock::time_point armed = std::chrono::steady_clock::time_point::max();
        static void CALLBACK timer_ready(void* self, BOOLEAN) {
            auto& loop = *static_cast<windows*>(self);
            ::PostQueuedCompletionStatus(loop.port, 0, 1, nullptr);
        }
        windows() {
            start_winsock();
            port = ::CreateIoCompletionPort(INVALID_HANDLE_VALUE, nullptr, 0, 1);
            if (!port)
                fail_win("CreateIoCompletionPort");
            try {
                timer = ::CreateWaitableTimerExW(nullptr, nullptr, CREATE_WAITABLE_TIMER_HIGH_RESOLUTION, TIMER_ALL_ACCESS);
                if (!timer)
                    fail_win("CreateWaitableTimerEx");
                if (!::RegisterWaitForSingleObject(&timer_wait, timer, timer_ready, this, INFINITE, WT_EXECUTEINWAITTHREAD))
                    fail_win("RegisterWait timer");
            } catch (...) {
                if (timer) ::CloseHandle(timer);
                ::CloseHandle(port);
                throw;
            }
        }
        virtual ~windows() {
            ::CancelWaitableTimer(timer);
            ::UnregisterWaitEx(timer_wait, INVALID_HANDLE_VALUE);
            ::CloseHandle(timer);
            std::lock_guard lock{association_mutex};
            std::erase_if(associations, [this](const auto& entry) { return entry.second == port; });
            ::CloseHandle(port);
        }
        void associate(handle file) {
            std::lock_guard lock{association_mutex};
            auto [entry, inserted] = associations.try_emplace(file, port);
            if (!inserted) {
                if (entry->second != port)
                    throw std::system_error(std::make_error_code(std::errc::invalid_argument), "resource belongs to another completion port");
                return;
            }
            if (!::CreateIoCompletionPort(reinterpret_cast<HANDLE>(file), port, 0, 0)) {
                auto error = ::GetLastError();
                associations.erase(entry);
                fail_win("associate I/O completion port", error);
            }
        }
        void signal() noexcept {
            if (running == this) {
                rescan = true;
                return;
            }
            if (wake_pending.exchange(true, std::memory_order_acq_rel))
                return;
            ::PostQueuedCompletionStatus(port, 0, 0, nullptr);
        }
        void arm() {
            auto next = deadline();
            if (next == armed)
                return;
            armed = next;
            if (next == std::chrono::steady_clock::time_point::max()) {
                ::CancelWaitableTimer(timer);
                return;
            }
            auto ns = std::chrono::duration_cast<std::chrono::nanoseconds>(next - std::chrono::steady_clock::now()).count();
            LARGE_INTEGER due{};
            due.QuadPart = -std::max<LONGLONG>(1, (ns + 99) / 100);
            if (!::SetWaitableTimerEx(timer, &due, 0, nullptr, nullptr, nullptr, 0))
                fail_win("SetWaitableTimerEx");
        }
        virtual void flush() {}
        virtual void drain() {}
        virtual void cancel(request& r) {
            if (r.kind == operation::readable) {
                r.result = -1;
                r.result_ready = true;
            } else
                ::CancelIoEx(reinterpret_cast<HANDLE>(r.file), &state(r).overlap);
        }
        void complete(request& r) noexcept {
            auto& s = state(r);
            if ((r.kind == operation::receive || r.kind == operation::receive_from) && r.error == std::errc::message_size)
                r.error.clear();
            if (!r.error && r.kind == operation::accept) {
                auto listener = static_cast<SOCKET>(r.file);
                if (::setsockopt(s.accepted, SOL_SOCKET, SO_UPDATE_ACCEPT_CONTEXT,
                                 reinterpret_cast<char*>(&listener), sizeof listener) == SOCKET_ERROR)
                    r.error = io_error(::WSAGetLastError());
                else {
                    configure_stream(static_cast<handle>(s.accepted));
                    r.result = static_cast<handle>(std::exchange(s.accepted, INVALID_SOCKET));
                }
            } else if (!r.error && r.kind == operation::connect) {
                if (::setsockopt(static_cast<SOCKET>(r.file), SOL_SOCKET, SO_UPDATE_CONNECT_CONTEXT,
                                 nullptr, 0) == SOCKET_ERROR)
                    r.error = io_error(::WSAGetLastError());
            } else if (!r.error && r.kind == operation::receive_from) {
                s.address.length = s.address_size;
                r.address = s.address;
            }
            if (s.accepted != INVALID_SOCKET)
                ::closesocket(s.accepted);
            auto value = r.result;
            auto error = r.error;
            std::destroy_at(&s);
            finish(r, value, error);
        }
        virtual void submit(request& r) {
            auto& s = state(r);
            if (r.kind == operation::post) {
                r.result_ready = true;
                return;
            }
            if (r.kind == operation::timer)
                return;
            associate(r.file);
            auto socket = static_cast<SOCKET>(r.file);
            s.flags = r.flags;
            DWORD count = 0;
            DWORD error = ERROR_SUCCESS;
            s.buffer = {static_cast<ULONG>(std::min<std::size_t>(r.size, std::numeric_limits<ULONG>::max())), static_cast<char*>(r.buffer)};
            auto buffer_count = r.buffer_count;
            for (unsigned i = 0; i < buffer_count; ++i)
                s.buffers[i] = {static_cast<ULONG>(std::min<std::size_t>(r.buffers[i].size, std::numeric_limits<ULONG>::max())), static_cast<char*>(r.buffers[i].data)};
            if (!buffer_count) { s.buffers[0] = s.buffer; buffer_count = 1; }
            int result = 0;
            switch (r.kind) {
            case operation::read_at:
            case operation::write_at: {
                s.overlap.Offset = static_cast<DWORD>(r.offset);
                s.overlap.OffsetHigh = static_cast<DWORD>(r.offset >> 32);
                auto ok = r.kind == operation::read_at
                    ? ::ReadFile(reinterpret_cast<HANDLE>(r.file), r.buffer, s.buffer.len, &count, &s.overlap)
                    : ::WriteFile(reinterpret_cast<HANDLE>(r.file), r.buffer, s.buffer.len, &count, &s.overlap);
                if (!ok)
                    error = ::GetLastError();
                break;
            }
            case operation::readable:
                notifications.try_emplace(r.file, notification{r.file});
                s.pending = true;
                return;
            case operation::read:
            case operation::receive:
                result = ::WSARecv(socket, s.buffers.data(), buffer_count, &count, &s.flags, &s.overlap, nullptr);
                break;
            case operation::receive_from:
                result = ::WSARecvFrom(socket, s.buffers.data(), buffer_count, &count, &s.flags,
                                       static_cast<sockaddr*>(s.address.data()), &s.address_size, &s.overlap, nullptr);
                break;
            case operation::write:
            case operation::send:
                result = ::WSASend(socket, s.buffers.data(), buffer_count, &count, r.flags, &s.overlap, nullptr);
                break;
            case operation::send_to:
                s.address = r.address;
                result = ::WSASendTo(socket, s.buffers.data(), buffer_count, &count, r.flags,
                                     static_cast<sockaddr*>(s.address.data()), s.address.size(), &s.overlap, nullptr);
                break;
            case operation::accept: {
                auto accept = extension<LPFN_ACCEPTEX>(socket, WSAID_ACCEPTEX);
                s.accepted = static_cast<SOCKET>(open_socket(false, is_v6(socket_endpoint(r.file))));
                constexpr DWORD address_bytes = sizeof(sockaddr_in6) + 16;
                s.accept_buffer = std::make_unique<std::byte[]>(2 * address_bytes);
                if (!accept(socket, s.accepted, s.accept_buffer.get(), 0, address_bytes, address_bytes, &count, &s.overlap))
                    error = ::WSAGetLastError();
                break;
            }
            case operation::connect: {
                auto connect = extension<LPFN_CONNECTEX>(socket, WSAID_CONNECTEX);
                socket_address local;
                int size = local.bytes.size();
                if (::getsockname(socket, static_cast<sockaddr*>(local.data()), &size) == SOCKET_ERROR) {
                    auto code = ::WSAGetLastError();
                    if (code != WSAEINVAL) fail_win("connect local address", code);
                    const unsigned char any[16]{};
                    bind(r.file, make_address(is_v6(r.address), any, 0));
                }
                s.address = r.address;
                if (!connect(socket, static_cast<sockaddr*>(s.address.data()), s.address.size(),
                             nullptr, 0, &count, &s.overlap))
                    error = ::WSAGetLastError();
                break;
            }
            case operation::post:
            case operation::timer:
                break;
            }
            if (result == SOCKET_ERROR)
                error = ::WSAGetLastError();
            // Success still queues a completion packet. Keep OVERLAPPED alive.
            if (error == ERROR_SUCCESS || error == ERROR_IO_PENDING)
                s.pending = true;
            else {
                r.result_ready = true;
                r.result = count;
                if ((r.kind == operation::read_at && error == ERROR_HANDLE_EOF) ||
                    (r.kind == operation::readable && truncated(error)))
                    r.result = 0;
                else
                    r.error = io_error(error);
            }
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
                auto* s = ::new (r->native.data()) request_state{};
                s->owner = r;
                track(*r);
                try {
                    submit(*r);
                } catch (const std::system_error& error) {
                    r->error = error.code();
                    r->result_ready = true;
                } catch (...) {
                    r->error = std::make_error_code(std::errc::not_enough_memory);
                    r->result_ready = true;
                }
            }
        }
        void progress() {
            for (auto* r = active; r;) {
                auto* next = r->active_next;
                auto& s = state(*r);
                if (r->cancelled.load(std::memory_order_acquire) || r->is_closed()) {
                    if (s.pending && !r->cancel_sent) {
                        cancel(*r);
                        r->cancel_sent = true;
                    } else if (!s.pending) {
                        r->result = -1;
                        r->result_ready = true;
                    }
                } else if (r->kind == operation::timer)
                    r->result_ready = r->deadline <= std::chrono::steady_clock::now();
                r = next;
            }
            update_notifications();
            for (auto* r = active; r;) {
                auto* next = r->active_next;
                if (r->result_ready && !state(*r).pending) complete(*r);
                r = next;
            }
        }
        void registration(notification& n, UINT8 operation, UINT16 filter = 0) {
            SOCK_NOTIFY_REGISTRATION value{};
            value.socket = static_cast<SOCKET>(n.file);
            value.completionKey = &n;
            value.eventFilter = filter;
            value.operation = operation;
            value.triggerFlags = SOCK_NOTIFY_TRIGGER_ONESHOT | SOCK_NOTIFY_TRIGGER_LEVEL;
            auto error = ::ProcessSocketNotifications(port, 1, &value, 0, 0, nullptr, nullptr);
            if (error) fail_win("ProcessSocketNotifications", error);
            if (value.registrationResult) fail_win("socket notification registration", value.registrationResult);
        }
        void update_notifications() {
            for (auto it = notifications.begin(); it != notifications.end();) {
                auto& n = it->second;
                bool needed = false, present = false;
                UINT16 filter = SOCK_NOTIFY_REGISTER_EVENT_HANGUP;
                for (auto* r = active; r; r = r->active_next) {
                    if (r->kind != operation::readable || r->file != n.file) continue;
                    present = true;
                    if (!r->result_ready) {
                        needed = true;
                        filter |= (r->events & 1 ? SOCK_NOTIFY_REGISTER_EVENT_IN : 0) |
                                  (r->events & 2 ? SOCK_NOTIFY_REGISTER_EVENT_OUT : 0);
                    }
                }
                try {
                    if (!needed && n.registered && !n.removing) {
                        registration(n, SOCK_NOTIFY_OP_REMOVE);
                        n.removing = true;
                    } else if (needed && !n.removing) {
                        if (!n.registered || !n.enabled) {
                            registration(n, SOCK_NOTIFY_OP_ENABLE, filter);
                            n.registered = n.enabled = true;
                            n.filter = filter;
                        } else if (filter != n.filter) {
                            registration(n, SOCK_NOTIFY_OP_REMOVE);
                            n.removing = true;
                        }
                    }
                } catch (const std::system_error& error) {
                    for (auto* r = active; r; r = r->active_next) {
                        if (r->kind != operation::readable || r->file != n.file) continue;
                        r->error = error.code();
                        r->result_ready = true;
                    }
                    needed = false;
                    if (n.registered && !n.removing) {
                        // The registration failed because the socket is gone; a
                        // removal then fails the same way and leaves nothing behind.
                        try {
                            registration(n, SOCK_NOTIFY_OP_REMOVE);
                            n.removing = true;
                        } catch (const std::system_error&) {
                            n.registered = n.enabled = false;
                        }
                    }
                }
                if (needed || !n.registered) {
                    for (auto* r = active; r; r = r->active_next)
                        if (r->kind == operation::readable && r->file == n.file && r->result_ready)
                            state(*r).pending = false;
                }
                if (!present && !n.registered) it = notifications.erase(it);
                else ++it;
            }
        }
        void notified(notification& n, DWORD events) {
            if (events & SOCK_NOTIFY_EVENT_REMOVE) {
                n.registered = n.enabled = n.removing = false;
                return;
            }
            n.enabled = false;
            for (auto* r = active; r; r = r->active_next) {
                if (r->kind != operation::readable || r->file != n.file || r->result_ready) continue;
                WSAPOLLFD fd{static_cast<SOCKET>(r->file), static_cast<SHORT>((r->events & 1 ? POLLIN : 0) | (r->events & 2 ? POLLOUT : 0)), 0};
                auto ready = ::WSAPoll(&fd, 1, 0);
                if (ready == SOCKET_ERROR) {
                    r->error = io_error(::WSAGetLastError());
                    r->result_ready = true;
                } else if (ready) {
                    r->result = (fd.revents & POLLIN && r->events & 1 ? 1 : 0) |
                                (fd.revents & POLLOUT && r->events & 2 ? 2 : 0) | (fd.revents & POLLERR ? 4 : 0);
                    r->result_ready = true;
                }
            }
        }
        void run() {
            if (stopped.exchange(false, std::memory_order_acquire))
                return;
            struct guard {
                const void* previous;
                ~guard() { running = previous; }
            } scope{std::exchange(running, this)};
            for (;;) {
                submit_pending();
                flush();
                drain();
                progress();
                flush();
                if (stopped.exchange(false, std::memory_order_acquire))
                    break;
                arm();
                auto rescan = std::exchange(this->rescan, false);
                auto queued = has_pending() || rescan;
                dispatch(queued ? 0 : INFINITE);
                for (int i = 1; i < 256 && queued; ++i) {
                    // A bounded drain gives queued posts and timers another turn.
                    if (!dispatch(0)) break;
                }
            }
        }
        auto dispatch(DWORD timeout) -> bool {
            DWORD bytes = 0;
            ULONG_PTR key = 0;
            OVERLAPPED* overlap = nullptr;
            auto ok = ::GetQueuedCompletionStatus(port, &bytes, &key, &overlap, timeout);
            auto error = ok ? ERROR_SUCCESS : ::GetLastError();
            if (!overlap && key > 2) {
                notified(*reinterpret_cast<notification*>(key), bytes);
                return true;
            }
            if (!overlap) {
                if (key == 0) wake_pending.store(false, std::memory_order_release);
                if (key == 1) armed = std::chrono::steady_clock::time_point::max();
                if (!ok && error != WAIT_TIMEOUT)
                    fail_win("GetQueuedCompletionStatus", error);
                return ok;
            }
            auto& s = *reinterpret_cast<request_state*>(overlap);
            auto& r = *s.owner;
            s.pending = false;
            r.result = bytes;
            if (error && !((r.kind == operation::read_at && error == ERROR_HANDLE_EOF) ||
                           (r.kind == operation::readable && truncated(error))))
                r.error = io_error(error);
            r.result_ready = true;
            complete(r);
            return true;
        }
    };
    } // namespace detail
    using namespace detail;
    auto open_socket(bool datagram, bool v6) -> handle {
        start_winsock();
        auto socket = ::WSASocketW(family(v6), datagram ? SOCK_DGRAM : SOCK_STREAM, 0, nullptr, 0, WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT);
        if (socket == INVALID_SOCKET)
            fail_win("WSASocket", ::WSAGetLastError());
        return static_cast<handle>(socket);
    }
    void configure_stream(handle h) noexcept {
        BOOL yes = TRUE;
        ::setsockopt(static_cast<SOCKET>(h), IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<char*>(&yes), sizeof yes);
        ::setsockopt(static_cast<SOCKET>(h), SOL_SOCKET, SO_KEEPALIVE, reinterpret_cast<char*>(&yes), sizeof yes);
    }
    auto family(bool v6) noexcept -> int { return v6 ? AF_INET6 : AF_INET; }
    auto make_address(bool v6, const unsigned char* bytes, std::uint16_t port, unsigned long scope) -> socket_address {
        socket_address value;
        if (v6) {
            sockaddr_in6 a{}; a.sin6_family = AF_INET6; a.sin6_port = htons(port); a.sin6_scope_id = scope;
            std::memcpy(&a.sin6_addr, bytes, 16); std::memcpy(value.data(), &a, sizeof a); value.length = sizeof a;
        } else {
            sockaddr_in a{}; a.sin_family = AF_INET; a.sin_port = htons(port);
            std::memcpy(&a.sin_addr, bytes, 4); std::memcpy(value.data(), &a, sizeof a); value.length = sizeof a;
        }
        return value;
    }
    auto is_v6(const socket_address& a) noexcept -> bool { return static_cast<const sockaddr*>(a.data())->sa_family == AF_INET6; }
    void address_bytes(const socket_address& a, unsigned char* out) noexcept {
        if (is_v6(a)) std::memcpy(out, &static_cast<const sockaddr_in6*>(a.data())->sin6_addr, 16);
        else std::memcpy(out, &static_cast<const sockaddr_in*>(a.data())->sin_addr, 4);
    }
    auto address_port(const socket_address& a) noexcept -> std::uint16_t {
        return ntohs(is_v6(a) ? static_cast<const sockaddr_in6*>(a.data())->sin6_port : static_cast<const sockaddr_in*>(a.data())->sin_port);
    }
    auto address_scope(const socket_address& a) noexcept -> unsigned long {
        return is_v6(a) ? static_cast<const sockaddr_in6*>(a.data())->sin6_scope_id : 0;
    }
    auto parse_address(std::string_view text, bool v6, std::error_code& error) noexcept -> socket_address {
        error.clear();
        try { start_winsock(); }
        catch (const std::system_error& e) { error = e.code(); return {}; }
        std::array<unsigned char, 16> bytes{};
        char input[64]{};
        unsigned long scope = 0;
        if (v6) {
            if (auto pos = text.find('%'); pos != text.npos) {
                auto part = text.substr(pos + 1);
                auto [end, code] = std::from_chars(part.data(), part.data() + part.size(), scope);
                if (code != std::errc{} || end != part.data() + part.size()) {
                    error = std::make_error_code(std::errc::invalid_argument); return {};
                }
                text = text.substr(0, pos);
            }
        }
        if (text.size() >= sizeof input || text.find('\0') != text.npos) {
            error = std::make_error_code(std::errc::invalid_argument); return {};
        }
        std::memcpy(input, text.data(), text.size());
        if (::inet_pton(family(v6), input, bytes.data()) != 1) {
            error = std::make_error_code(std::errc::invalid_argument); return {};
        }
        return make_address(v6, bytes.data(), 0, scope);
    }
    auto address_string(const socket_address& a) -> std::string {
        std::array<unsigned char, 16> bytes{}; address_bytes(a, bytes.data());
        char text[INET6_ADDRSTRLEN];
        if (!::inet_ntop(family(is_v6(a)), bytes.data(), text, sizeof text)) fail_win("inet_ntop", ::WSAGetLastError());
        if (auto scope = address_scope(a)) return std::format("{}%{}", text, scope);
        return text;
    }
    void bind(handle h, socket_address a) {
        if (::bind(static_cast<SOCKET>(h), static_cast<const sockaddr*>(a.data()), a.size()) != 0) fail_win("bind", ::WSAGetLastError());
    }
    void listen(handle h, int backlog) {
        if (::listen(static_cast<SOCKET>(h), backlog) != 0) fail_win("listen", ::WSAGetLastError());
    }
    auto socket_endpoint(handle h, bool remote) -> socket_address {
        socket_address a; int size = a.bytes.size();
        auto result = remote ? ::getpeername(static_cast<SOCKET>(h), static_cast<sockaddr*>(a.data()), &size)
                             : ::getsockname(static_cast<SOCKET>(h), static_cast<sockaddr*>(a.data()), &size);
        if (result != 0) fail_win("socket endpoint", ::WSAGetLastError());
        a.length = size; return a;
    }
    void connect_datagram(handle h, socket_address a) {
        if (::connect(static_cast<SOCKET>(h), static_cast<const sockaddr*>(a.data()), a.size()) != 0) fail_win("connect datagram", ::WSAGetLastError());
    }
    void set_option(handle h, int key, bool value) {
        int yes = value; int option = key == 0 ? SO_REUSEADDR : key == 1 ? SO_KEEPALIVE : TCP_NODELAY;
        if (::setsockopt(static_cast<SOCKET>(h), key == 2 ? IPPROTO_TCP : SOL_SOCKET, option, reinterpret_cast<const char*>(&yes), sizeof yes) != 0)
            fail_win("socket option", ::WSAGetLastError());
    }
    void shutdown(handle h, int direction) noexcept {
        if (h != invalid_handle) ::shutdown(static_cast<SOCKET>(h), direction == 0 ? SD_RECEIVE : direction == 1 ? SD_SEND : SD_BOTH);
    }
    void close_socket(handle h) noexcept {
        if (h == invalid_handle) return;
        std::lock_guard lock{association_mutex}; associations.erase(h); ::closesocket(static_cast<SOCKET>(h));
    }
    auto open_file(const char* path, bool write) -> handle {
        auto count = ::MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path, -1, nullptr, 0);
        if (!count)
            fail_win("UTF-8 file path");
        std::wstring wide(static_cast<std::size_t>(count), L'\0');
        ::MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path, -1, wide.data(), count);
        auto file = ::CreateFileW(wide.c_str(), write ? GENERIC_READ | GENERIC_WRITE : GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                  nullptr, write ? OPEN_ALWAYS : OPEN_EXISTING, FILE_FLAG_OVERLAPPED, nullptr);
        if (file == INVALID_HANDLE_VALUE)
            fail_win("CreateFile");
        return reinterpret_cast<handle>(file);
    }
    void close_file(handle h) noexcept {
        if (h != invalid_handle) {
            std::lock_guard lock{association_mutex};
            associations.erase(h);
            ::CloseHandle(reinterpret_cast<HANDLE>(h));
        }
    }
} // namespace native_io
