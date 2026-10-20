module;
#include <ioringapi.h>
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>

module httpant.io;
import std;
import :queue;

namespace native_io {
    namespace {
        [[noreturn]] void fail_win(const char* what, DWORD error = ::GetLastError()) {
            throw std::system_error(static_cast<int>(error), std::system_category(), what);
        }
        auto ring_error(HRESULT result) noexcept -> std::error_code {
            auto code = HRESULT_FACILITY(result) == FACILITY_WIN32 ? HRESULT_CODE(result) : static_cast<int>(result);
            return {code, std::system_category()};
        }
        void check(HRESULT result, const char* what) {
            if (FAILED(result))
                throw std::system_error(ring_error(result), what);
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
        std::mutex listener_mutex;
        std::map<std::uint64_t, std::vector<handle>> listeners;
        auto listener_key(endpoint e) noexcept -> std::uint64_t {
            std::uint64_t key = e.port;
            for (auto octet : e.ip)
                key = (key << 8) | octet;
            return key;
        }
        auto address(endpoint e) noexcept -> sockaddr_in {
            sockaddr_in a{};
            a.sin_family = AF_INET;
            a.sin_port = htons(e.port);
            auto ip = (std::uint32_t{e.ip[0]} << 24) | (std::uint32_t{e.ip[1]} << 16) | (std::uint32_t{e.ip[2]} << 8) | e.ip[3];
            a.sin_addr.s_addr = htonl(ip);
            return a;
        }
        void nonblocking(handle h, bool enabled) {
            u_long value = enabled;
            if (::ioctlsocket(static_cast<SOCKET>(h), FIONBIO, &value) != 0)
                fail_win("FIONBIO", ::WSAGetLastError());
        }
        struct request_state {
            OVERLAPPED overlap{};
            bool ring = false;
            bool connecting = false;
            bool pending = false;
        };
        static_assert(sizeof(request_state) <= sizeof(request::native));
        auto state(request& r) noexcept -> request_state& { return *std::launder(reinterpret_cast<request_state*>(r.native.data())); }
    } // namespace

    struct engine::impl : detail::queue {
        HIORING ring = nullptr;
        HANDLE wake = nullptr;
        HANDLE completion = nullptr;
        std::size_t ring_entries = 0;
        impl() {
            start_winsock();
            IORING_CAPABILITIES capabilities{};
            check(::QueryIoRingCapabilities(&capabilities), "QueryIoRingCapabilities");
            if (capabilities.MaxVersion < IORING_VERSION_3)
                throw std::runtime_error("I/O Ring v3 is required for native reads and writes");
            check(::CreateIoRing(IORING_VERSION_3, IORING_CREATE_FLAGS{}, 256, 512, &ring), "CreateIoRing");
            try {
                if (!::IsIoRingOpSupported(ring, IORING_OP_READ) || !::IsIoRingOpSupported(ring, IORING_OP_WRITE) ||
                    !::IsIoRingOpSupported(ring, IORING_OP_CANCEL))
                    throw std::runtime_error("I/O Ring read/write/cancel operations are required");
                wake = ::CreateEventW(nullptr, FALSE, FALSE, nullptr);
                if (!wake)
                    fail_win("CreateEvent wake");
                completion = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
                if (!completion)
                    fail_win("CreateEvent completion");
                check(::SetIoRingCompletionEvent(ring, completion), "SetIoRingCompletionEvent");
            } catch (...) {
                if (wake)
                    ::CloseHandle(wake);
                if (completion)
                    ::CloseHandle(completion);
                ::CloseIoRing(ring);
                throw;
            }
        }
        ~impl() {
            ::CloseIoRing(ring);
            ::CloseHandle(completion);
            ::CloseHandle(wake);
        }
        void signal() noexcept { ::SetEvent(wake); }
        void flush() {
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
            ++ring_entries;
        }
        void complete(request& r) noexcept {
            if (state(r).overlap.hEvent)
                ::CloseHandle(state(r).overlap.hEvent);
            finish(r, r.result, r.error);
        }
        void submit(request& r) {
            ::new (r.native.data()) request_state{};
            auto& s = state(r);
            switch (r.kind) {
            case operation::read:
            case operation::write: {
                s.overlap.hEvent = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
                if (!s.overlap.hEvent)
                    fail_win("CreateEvent overlapped I/O");
                DWORD count = 0;
                auto size = static_cast<DWORD>(std::min<std::size_t>(r.size, MAXDWORD));
                auto file = reinterpret_cast<HANDLE>(r.file);
                auto ok =
                    r.kind == operation::read ? ::ReadFile(file, r.buffer, size, &count, &s.overlap) : ::WriteFile(file, r.buffer, size, &count, &s.overlap);
                if (ok) {
                    r.result = count;
                    r.result_ready = true;
                } else {
                    auto error = ::GetLastError();
                    if (error == ERROR_IO_PENDING)
                        s.pending = true;
                    else {
                        r.result_ready = true;
                        if (r.kind != operation::read || (error != ERROR_BROKEN_PIPE && error != ERROR_HANDLE_EOF))
                            r.error = {static_cast<int>(error), std::system_category()};
                    }
                }
                break;
            }
            case operation::read_at:
            case operation::write_at: {
                auto file = IoRingHandleRefFromHandle(reinterpret_cast<HANDLE>(r.file));
                auto buffer = IoRingBufferRefFromPointer(r.buffer);
                auto size = static_cast<UINT32>(std::min<std::size_t>(r.size, std::numeric_limits<UINT32>::max()));
                auto offset = r.kind == operation::read_at || r.kind == operation::write_at ? r.offset : 0;
                auto user = reinterpret_cast<UINT_PTR>(&r);
                build([&] {
                    if (r.kind == operation::read || r.kind == operation::read_at)
                        return ::BuildIoRingReadFile(ring, file, buffer, size, offset, user, IOSQE_FLAGS_NONE);
                    return ::BuildIoRingWriteFile(ring, file, buffer, size, offset, FILE_WRITE_FLAGS_NONE, user, IOSQE_FLAGS_NONE);
                });
                s.ring = true;
                break;
            }
            case operation::connect: {
                nonblocking(r.file, true);
                auto a = address(r.address);
                if (::connect(static_cast<SOCKET>(r.file), reinterpret_cast<sockaddr*>(&a), sizeof a) == 0) {
                    nonblocking(r.file, false);
                    r.result_ready = true;
                } else {
                    auto error = ::WSAGetLastError();
                    if (error != WSAEWOULDBLOCK && error != WSAEINPROGRESS)
                        fail_win("connect", error);
                    s.connecting = true;
                }
                break;
            }
            case operation::accept:
                nonblocking(r.file, true);
                break;
            case operation::readable:
                break;
            case operation::post:
                r.result_ready = true;
                break;
            case operation::timer:
                break;
            }
            track(r);
        }
        void submit_pending() {
            auto* list = ring_entries < 128 ? take(64) : nullptr;
            while (list) {
                auto* r = list;
                list = list->next;
                if (r->cancelled.load(std::memory_order_acquire) || r->is_closed()) {
                    finish(*r, -1);
                    continue;
                }
                try {
                    submit(*r);
                } catch (const std::system_error& error) {
                    r->error = error.code();
                    complete(*r);
                }
            }
            for (auto* r = active; r; r = r->active_next) {
                if (!state(*r).ring || !(r->cancelled.load(std::memory_order_acquire) || r->is_closed()) || r->cancel_sent || r->result_ready)
                    continue;
                build([&] {
                    return ::BuildIoRingCancelRequest(ring, IoRingHandleRefFromHandle(reinterpret_cast<HANDLE>(r->file)), reinterpret_cast<UINT_PTR>(r),
                                                      reinterpret_cast<UINT_PTR>(r) | 1);
                });
                r->cancel_sent = true;
            }
            flush();
        }
        void dispatch() {
            IORING_CQE entry{};
            for (;;) {
                auto result = ::PopIoRingCompletion(ring, &entry);
                if (result == S_FALSE)
                    break;
                check(result, "PopIoRingCompletion");
                --ring_entries;
                auto* r = reinterpret_cast<request*>(entry.UserData & ~UINT_PTR{1});
                if (entry.UserData & 1)
                    r->cancel_acknowledged = true;
                else {
                    r->result_ready = true;
                    r->result = static_cast<std::int64_t>(entry.Information);
                    if ((r->kind == operation::read || r->kind == operation::read_at) && entry.ResultCode == HRESULT_FROM_WIN32(ERROR_HANDLE_EOF))
                        r->result = 0;
                    else if (FAILED(entry.ResultCode))
                        r->error = ring_error(entry.ResultCode);
                }
                if (r->result_ready && (!r->cancel_sent || r->cancel_acknowledged))
                    complete(*r);
            }
        }
        auto progress() -> bool {
            bool polling = false;
            for (auto* r = active; r;) {
                auto* next = r->active_next;
                auto& s = state(*r);
                if (!s.ring) {
                    if (s.pending) {
                        polling = true;
                        if ((r->cancelled.load(std::memory_order_acquire) || r->is_closed()) && !r->cancel_sent) {
                            ::CancelIoEx(reinterpret_cast<HANDLE>(r->file), &s.overlap);
                            r->cancel_sent = true;
                        }
                        DWORD count = 0;
                        if (::GetOverlappedResult(reinterpret_cast<HANDLE>(r->file), &s.overlap, &count, FALSE)) {
                            r->result = count;
                            r->result_ready = true;
                        } else {
                            auto error = ::GetLastError();
                            if (error != ERROR_IO_INCOMPLETE) {
                                r->result_ready = true;
                                if (r->kind != operation::read || (error != ERROR_BROKEN_PIPE && error != ERROR_HANDLE_EOF))
                                    r->error = {static_cast<int>(error), std::system_category()};
                            }
                        }
                    } else if (r->cancelled.load(std::memory_order_acquire) || r->is_closed()) {
                        if (!r->result_ready)
                            r->result = -1;
                        r->result_ready = true;
                    } else if (r->kind == operation::timer)
                        r->result_ready = r->deadline <= std::chrono::steady_clock::now();
                    else if (r->kind == operation::accept || r->kind == operation::connect || r->kind == operation::readable) {
                        polling = true;
                        WSAPOLLFD p{static_cast<SOCKET>(r->file), static_cast<SHORT>(s.connecting ? POLLWRNORM : POLLRDNORM), 0};
                        auto count = ::WSAPoll(&p, 1, 0);
                        if (count == SOCKET_ERROR) {
                            r->result_ready = true;
                            r->error = {::WSAGetLastError(), std::system_category()};
                        } else if (count > 0 && p.revents) {
                            if (r->kind == operation::accept) {
                                std::lock_guard lock{listener_mutex};
                                nonblocking(r->file, true);
                                auto peer = ::accept(static_cast<SOCKET>(r->file), nullptr, nullptr);
                                if (peer != INVALID_SOCKET) {
                                    u_long blocking = 0;
                                    ::ioctlsocket(peer, FIONBIO, &blocking);
                                    ::SetHandleInformation(reinterpret_cast<HANDLE>(peer), HANDLE_FLAG_INHERIT, 0);
                                    r->result = static_cast<handle>(peer);
                                    r->result_ready = true;
                                } else if (::WSAGetLastError() != WSAEWOULDBLOCK) {
                                    r->result_ready = true;
                                    r->error = {::WSAGetLastError(), std::system_category()};
                                }
                            } else if (s.connecting) {
                                int error = 0;
                                int size = sizeof error;
                                if (::getsockopt(p.fd, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&error), &size) != 0)
                                    error = ::WSAGetLastError();
                                if (error)
                                    r->error = {error, std::system_category()};
                                else {
                                    u_long blocking = 0;
                                    ::ioctlsocket(p.fd, FIONBIO, &blocking);
                                }
                                r->result_ready = true;
                            } else
                                r->result_ready = true;
                        }
                    }
                    if (r->result_ready)
                        complete(*r);
                }
                r = next;
            }
            return polling;
        }
    };
    engine::engine() : impl_(std::make_unique<impl>()) {}
    engine::~engine() = default;
    auto engine::name() noexcept -> const char* { return "windows-io-ring"; }
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
            ::ResetEvent(impl_->completion);
            impl_->dispatch();
            auto polling = impl_->progress();
            if (impl_->stopped.exchange(false, std::memory_order_acquire))
                break;
            HANDLE events[]{impl_->wake, impl_->completion};
            auto queued = impl_->ring_entries < 128 && impl_->has_pending();
            auto result = ::WaitForMultipleObjects(2, events, FALSE, static_cast<DWORD>(impl_->wait_ms(queued ? 0 : polling ? 1 : 1000)));
            if (result == WAIT_FAILED)
                fail_win("WaitForMultipleObjects");
        }
    }

    auto open_socket(bool datagram) -> handle {
        start_winsock();
        auto socket = ::WSASocketW(AF_INET, datagram ? SOCK_DGRAM : SOCK_STREAM, 0, nullptr, 0, WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT);
        if (socket == INVALID_SOCKET)
            fail_win("WSASocket", ::WSAGetLastError());
        return static_cast<handle>(socket);
    }
    void configure_stream(handle h) noexcept {
        BOOL yes = TRUE;
        ::setsockopt(static_cast<SOCKET>(h), IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<char*>(&yes), sizeof yes);
        ::setsockopt(static_cast<SOCKET>(h), SOL_SOCKET, SO_KEEPALIVE, reinterpret_cast<char*>(&yes), sizeof yes);
    }
    void bind(handle h, endpoint e) {
        auto a = address(e);
        if (::bind(static_cast<SOCKET>(h), reinterpret_cast<sockaddr*>(&a), sizeof a) != 0)
            fail_win("bind", ::WSAGetLastError());
    }
    auto listen(endpoint e, int backlog) -> handle {
        std::lock_guard lock{listener_mutex};
        auto key = listener_key(e);
        if (e.port) {
            if (auto it = listeners.find(key); it != listeners.end()) {
                WSAPROTOCOL_INFOW info{};
                if (::WSADuplicateSocketW(static_cast<SOCKET>(it->second.front()), ::GetCurrentProcessId(), &info))
                    fail_win("WSADuplicateSocket", ::WSAGetLastError());
                auto duplicate =
                    ::WSASocketW(FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, &info, 0, WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT);
                if (duplicate == INVALID_SOCKET)
                    fail_win("duplicate listener", ::WSAGetLastError());
                try {
                    it->second.push_back(static_cast<handle>(duplicate));
                } catch (...) {
                    ::closesocket(duplicate);
                    throw;
                }
                return static_cast<handle>(duplicate);
            }
        }
        auto h = open_socket();
        try {
            bind(h, e);
            if (::listen(static_cast<SOCKET>(h), backlog) != 0)
                fail_win("listen", ::WSAGetLastError());
            if (e.port)
                listeners.emplace(key, std::vector<handle>{h});
            return h;
        } catch (...) {
            ::closesocket(static_cast<SOCKET>(h));
            throw;
        }
    }
    auto local_port(handle h) -> std::uint16_t {
        sockaddr_in a{};
        int size = sizeof a;
        if (::getsockname(static_cast<SOCKET>(h), reinterpret_cast<sockaddr*>(&a), &size) != 0)
            fail_win("getsockname", ::WSAGetLastError());
        return ntohs(a.sin_port);
    }
    void connect_datagram(handle h, endpoint e) {
        auto a = address(e);
        if (::connect(static_cast<SOCKET>(h), reinterpret_cast<sockaddr*>(&a), sizeof a) != 0)
            fail_win("connect datagram", ::WSAGetLastError());
    }
    void shutdown(handle h) noexcept {
        if (h != invalid_handle)
            ::shutdown(static_cast<SOCKET>(h), SD_SEND);
    }
    void close_socket(handle h) noexcept {
        if (h == invalid_handle)
            return;
        std::lock_guard lock{listener_mutex};
        for (auto it = listeners.begin(); it != listeners.end(); ++it) {
            if (auto position = std::ranges::find(it->second, h); position != it->second.end()) {
                it->second.erase(position);
                if (it->second.empty())
                    listeners.erase(it);
                break;
            }
        }
        ::closesocket(static_cast<SOCKET>(h));
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
        if (h != invalid_handle)
            ::CloseHandle(reinterpret_cast<HANDLE>(h));
    }
} // namespace native_io
