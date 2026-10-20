module;
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>

module httpant.io;
import std;

namespace native_io {
    namespace {
        auto address(endpoint e) noexcept -> sockaddr_in {
            sockaddr_in a{};
            a.sin_family = AF_INET;
            a.sin_port = htons(e.port);
            auto ip = (std::uint32_t{e.ip[0]} << 24) | (std::uint32_t{e.ip[1]} << 16) | (std::uint32_t{e.ip[2]} << 8) | e.ip[3];
            a.sin_addr.s_addr = htonl(ip);
            return a;
        }
        [[noreturn]] void fail(const char* what) { throw std::system_error(errno, std::generic_category(), what); }
    } // namespace
    auto open_socket(bool datagram) -> handle {
        int fd = ::socket(AF_INET, datagram ? SOCK_DGRAM : SOCK_STREAM, 0);
        if (fd < 0)
            fail("socket");
        if (::fcntl(fd, F_SETFD, FD_CLOEXEC) < 0) {
            auto error = errno;
            ::close(fd);
            errno = error;
            fail("socket cloexec");
        }
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
    void bind(handle h, endpoint e) {
        auto a = address(e);
        if (::bind(static_cast<int>(h), reinterpret_cast<sockaddr*>(&a), sizeof a) < 0)
            fail("bind");
    }
    auto listen(endpoint e, int backlog) -> handle {
        auto h = open_socket();
        try {
            int yes = 1;
            if (::setsockopt(static_cast<int>(h), SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes) < 0)
                fail("SO_REUSEADDR");
#ifdef SO_REUSEPORT
            if (::setsockopt(static_cast<int>(h), SOL_SOCKET, SO_REUSEPORT, &yes, sizeof yes) < 0)
                fail("SO_REUSEPORT");
#endif
            bind(h, e);
            if (::listen(static_cast<int>(h), backlog) < 0)
                fail("listen");
            return h;
        } catch (...) {
            close_socket(h);
            throw;
        }
    }
    auto local_port(handle h) -> std::uint16_t {
        sockaddr_in a{};
        socklen_t size = sizeof a;
        if (::getsockname(static_cast<int>(h), reinterpret_cast<sockaddr*>(&a), &size) < 0)
            fail("getsockname");
        return ntohs(a.sin_port);
    }
    void connect_datagram(handle h, endpoint e) {
        auto a = address(e);
        if (::connect(static_cast<int>(h), reinterpret_cast<sockaddr*>(&a), sizeof a) < 0)
            fail("connect datagram");
    }
    void shutdown(handle h) noexcept {
        if (h != invalid_handle)
            ::shutdown(static_cast<int>(h), SHUT_WR);
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
