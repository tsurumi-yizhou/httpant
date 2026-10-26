module;
#include <errno.h>
#include <arpa/inet.h>
#include <cstring>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>

module httpant.io;
import std;

namespace native_io {
    namespace {
        [[noreturn]] void fail(const char* what) { throw std::system_error(errno, std::generic_category(), what); }
    } // namespace
    auto open_socket(bool datagram, bool v6) -> handle {
        int fd = ::socket(family(v6), datagram ? SOCK_DGRAM : SOCK_STREAM, 0);
        if (fd < 0)
            fail("socket");
        if (::fcntl(fd, F_SETFD, FD_CLOEXEC) < 0) {
            auto error = errno;
            ::close(fd);
            errno = error;
            fail("socket cloexec");
        }
#ifdef __linux__
        if (::fcntl(fd, F_SETFL, O_NONBLOCK) < 0) {
            auto error = errno;
            ::close(fd);
            errno = error;
            fail("socket nonblocking");
        }
#endif
        return fd;
    }
    void configure_stream(handle h) noexcept {
        int yes = 1;
        ::setsockopt(static_cast<int>(h), IPPROTO_TCP, TCP_NODELAY, &yes, sizeof yes);
        ::setsockopt(static_cast<int>(h), SOL_SOCKET, SO_KEEPALIVE, &yes, sizeof yes);
#ifdef SO_NOSIGPIPE
        ::setsockopt(static_cast<int>(h), SOL_SOCKET, SO_NOSIGPIPE, &yes, sizeof yes);
#endif
    }
    auto family(bool v6) noexcept -> int { return v6 ? AF_INET6 : AF_INET; }
    auto make_address(bool v6, const unsigned char* bytes, std::uint16_t port, unsigned long scope) -> socket_address {
        socket_address value;
        if (v6) {
            sockaddr_in6 a{}; a.sin6_family = AF_INET6; a.sin6_port = htons(port); a.sin6_scope_id = scope;
            #ifdef __APPLE__
            a.sin6_len = sizeof a;
#endif
            std::memcpy(&a.sin6_addr, bytes, 16); std::memcpy(value.data(), &a, sizeof a); value.length = sizeof a;
        } else {
            sockaddr_in a{}; a.sin_family = AF_INET; a.sin_port = htons(port);
            #ifdef __APPLE__
            a.sin_len = sizeof a;
#endif
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
        if (!::inet_ntop(family(is_v6(a)), bytes.data(), text, sizeof text)) fail("inet_ntop");
        if (auto scope = address_scope(a)) return std::format("{}%{}", text, scope);
        return text;
    }
    void bind(handle h, socket_address a) {
        if (::bind(static_cast<int>(h), static_cast<const sockaddr*>(a.data()), a.size()) < 0) fail("bind");
    }
    void listen(handle h, int backlog) { if (::listen(static_cast<int>(h), backlog) < 0) fail("listen"); }
    auto socket_endpoint(handle h, bool remote) -> socket_address {
        socket_address a; socklen_t size = a.bytes.size();
        auto result = remote ? ::getpeername(static_cast<int>(h), static_cast<sockaddr*>(a.data()), &size)
                             : ::getsockname(static_cast<int>(h), static_cast<sockaddr*>(a.data()), &size);
        if (result < 0) fail("socket endpoint");
        a.length = size; return a;
    }
    void connect_datagram(handle h, socket_address a) {
        if (::connect(static_cast<int>(h), static_cast<const sockaddr*>(a.data()), a.size()) < 0) fail("connect datagram");
    }
    void set_option(handle h, int key, bool value) {
        int option = key == 0 ? SO_REUSEADDR : key == 1 ? SO_KEEPALIVE : TCP_NODELAY;
        int yes = value;
        if (::setsockopt(static_cast<int>(h), key == 2 ? IPPROTO_TCP : SOL_SOCKET, option, &yes, sizeof yes) < 0) fail("socket option");
#ifdef SO_REUSEPORT
        if (key == 0 && ::setsockopt(static_cast<int>(h), SOL_SOCKET, SO_REUSEPORT, &yes, sizeof yes) < 0) fail("SO_REUSEPORT");
#endif
    }
    void shutdown(handle h, int direction) noexcept {
        if (h != invalid_handle) ::shutdown(static_cast<int>(h), direction == 0 ? SHUT_RD : direction == 1 ? SHUT_WR : SHUT_RDWR);
    }
    void close_socket(handle h) noexcept {
        if (h != invalid_handle)
            ::close(static_cast<int>(h));
    }
    auto open_file(const char* path, bool write) -> handle {
        int fd = ::open(path, (write ? O_RDWR | O_CREAT : O_RDONLY) | O_CLOEXEC, 0644);
        if (fd < 0)
            fail("open file");
        return fd;
    }
    void close_file(handle h) noexcept { close_socket(h); }
} // namespace native_io
