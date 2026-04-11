#pragma once

#include <asio.hpp>
#include <asio/ssl.hpp>

#include <coroutine>
#include <cstddef>
#include <exception>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

namespace httpant::examples {

using tcp = asio::ip::tcp;

class tcp_socket_stream {
public:
    explicit tcp_socket_stream(tcp::socket socket) : socket_(std::move(socket)) {}

    tcp_socket_stream(const tcp_socket_stream&) = delete;
    auto operator=(const tcp_socket_stream&) -> tcp_socket_stream& = delete;
    tcp_socket_stream(tcp_socket_stream&&) = default;
    auto operator=(tcp_socket_stream&&) -> tcp_socket_stream& = default;

    struct read_operation {
        tcp::socket& socket;
        std::span<std::byte> buffer;
        std::size_t result{0};
        std::exception_ptr error{};

        bool await_ready() const noexcept {
            return false;
        }

        void await_suspend(std::coroutine_handle<> continuation) {
            socket.async_read_some(
                asio::buffer(buffer.data(), buffer.size()),
                [this, continuation](std::error_code ec, std::size_t bytes_read) mutable {
                    if (ec && ec != asio::error::eof)
                        error = std::make_exception_ptr(std::system_error(ec, "socket read failed"));
                    result = ec == asio::error::eof ? 0 : bytes_read;
                    continuation.resume();
                });
        }

        auto await_resume() -> std::size_t {
            if (error)
                std::rethrow_exception(error);
            return result;
        }
    };

    struct write_operation {
        tcp::socket& socket;
        std::span<const std::byte> buffer;
        bool fin{false};
        std::size_t result{0};
        std::exception_ptr error{};

        bool await_ready() const noexcept {
            return false;
        }

        void await_suspend(std::coroutine_handle<> continuation) {
            asio::async_write(
                socket,
                asio::buffer(buffer.data(), buffer.size()),
                [this, continuation](std::error_code ec, std::size_t bytes_written) mutable {
                    if (ec) {
                        error = std::make_exception_ptr(std::system_error(ec, "socket write failed"));
                    } else if (fin) {
                        std::error_code shutdown_error;
                        socket.shutdown(tcp::socket::shutdown_send, shutdown_error);
                        if (shutdown_error)
                            error = std::make_exception_ptr(std::system_error(shutdown_error, "socket shutdown failed"));
                    }
                    result = bytes_written;
                    continuation.resume();
                });
        }

        auto await_resume() -> std::size_t {
            if (error)
                std::rethrow_exception(error);
            return result;
        }
    };

    auto async_read(std::span<std::byte> buffer) -> read_operation {
        return {socket_, buffer};
    }

    auto async_write(std::span<const std::byte> buffer) -> write_operation {
        return {socket_, buffer, false};
    }

    auto async_write(std::span<const std::byte> buffer, bool fin) -> write_operation {
        return {socket_, buffer, fin};
    }

    auto socket() -> tcp::socket& {
        return socket_;
    }

private:
    tcp::socket socket_;
};

class tls_socket_stream {
public:
    explicit tls_socket_stream(asio::ssl::stream<tcp::socket> socket) : socket_(std::move(socket)) {}

    tls_socket_stream(const tls_socket_stream&) = delete;
    auto operator=(const tls_socket_stream&) -> tls_socket_stream& = delete;
    tls_socket_stream(tls_socket_stream&&) = default;
    auto operator=(tls_socket_stream&&) -> tls_socket_stream& = default;

    struct read_operation {
        asio::ssl::stream<tcp::socket>& socket;
        std::span<std::byte> buffer;
        std::size_t result{0};
        std::exception_ptr error{};

        bool await_ready() const noexcept {
            return false;
        }

        void await_suspend(std::coroutine_handle<> continuation) {
            socket.async_read_some(
                asio::buffer(buffer.data(), buffer.size()),
                [this, continuation](std::error_code ec, std::size_t bytes_read) mutable {
                    if (ec && ec != asio::error::eof)
                        error = std::make_exception_ptr(std::system_error(ec, "tls socket read failed"));
                    result = ec == asio::error::eof ? 0 : bytes_read;
                    continuation.resume();
                });
        }

        auto await_resume() -> std::size_t {
            if (error)
                std::rethrow_exception(error);
            return result;
        }
    };

    struct write_operation {
        asio::ssl::stream<tcp::socket>& socket;
        std::span<const std::byte> buffer;
        std::size_t result{0};
        std::exception_ptr error{};

        bool await_ready() const noexcept {
            return false;
        }

        void await_suspend(std::coroutine_handle<> continuation) {
            asio::async_write(
                socket,
                asio::buffer(buffer.data(), buffer.size()),
                [this, continuation](std::error_code ec, std::size_t bytes_written) mutable {
                    if (ec)
                        error = std::make_exception_ptr(std::system_error(ec, "tls socket write failed"));
                    result = bytes_written;
                    continuation.resume();
                });
        }

        auto await_resume() -> std::size_t {
            if (error)
                std::rethrow_exception(error);
            return result;
        }
    };

    auto async_read(std::span<std::byte> buffer) -> read_operation {
        return {socket_, buffer};
    }

    auto async_write(std::span<const std::byte> buffer) -> write_operation {
        return {socket_, buffer};
    }

    auto socket() -> asio::ssl::stream<tcp::socket>& {
        return socket_;
    }

    auto lowest_layer() -> decltype(auto) {
        return socket_.lowest_layer();
    }

private:
    asio::ssl::stream<tcp::socket> socket_;
};

class tls_handshake_operation {
public:
    tls_handshake_operation(asio::ssl::stream<tcp::socket>& socket,
                            asio::ssl::stream_base::handshake_type type,
                            std::string what)
        : socket_(socket), type_(type), what_(std::move(what)) {}

    bool await_ready() const noexcept {
        return false;
    }

    void await_suspend(std::coroutine_handle<> continuation) {
        socket_.async_handshake(type_, [this, continuation](std::error_code ec) mutable {
            if (ec)
                error_ = std::make_exception_ptr(std::system_error(ec, what_));
            continuation.resume();
        });
    }

    void await_resume() {
        if (error_)
            std::rethrow_exception(error_);
    }

private:
    asio::ssl::stream<tcp::socket>& socket_;
    asio::ssl::stream_base::handshake_type type_;
    std::string what_;
    std::exception_ptr error_{};
};

class resolve_operation {
public:
    resolve_operation(asio::any_io_executor executor,
                      std::string host,
                      std::string port,
                      tcp::resolver::flags flags,
                      std::string what)
        : resolver_(executor), host_(std::move(host)), port_(std::move(port)), flags_(flags), what_(std::move(what)) {}

    bool await_ready() const noexcept {
        return false;
    }

    void await_suspend(std::coroutine_handle<> continuation) {
        resolver_.async_resolve(
            host_,
            port_,
            flags_,
            [this, continuation](std::error_code ec, tcp::resolver::results_type results) mutable {
                if (ec)
                    error_ = std::make_exception_ptr(std::system_error(ec, what_));
                else
                    results_ = std::move(results);
                continuation.resume();
            });
    }

    auto await_resume() -> tcp::endpoint {
        if (error_)
            std::rethrow_exception(error_);
        if (results_.empty())
            throw std::runtime_error(what_ + ": resolver returned no endpoints");
        return results_.begin()->endpoint();
    }

private:
    tcp::resolver resolver_;
    std::string host_;
    std::string port_;
    tcp::resolver::flags flags_{};
    std::string what_;
    tcp::resolver::results_type results_{};
    std::exception_ptr error_{};
};

class connect_operation {
public:
    connect_operation(tcp::socket& socket, tcp::endpoint endpoint, std::string what)
        : socket_(socket), endpoint_(endpoint), what_(std::move(what)) {}

    bool await_ready() const noexcept {
        return false;
    }

    void await_suspend(std::coroutine_handle<> continuation) {
        socket_.async_connect(endpoint_, [this, continuation](std::error_code ec) mutable {
            if (ec)
                error_ = std::make_exception_ptr(std::system_error(ec, what_));
            continuation.resume();
        });
    }

    void await_resume() {
        if (error_)
            std::rethrow_exception(error_);
    }

private:
    tcp::socket& socket_;
    tcp::endpoint endpoint_;
    std::string what_;
    std::exception_ptr error_{};
};

class accept_operation {
public:
    explicit accept_operation(tcp::acceptor& acceptor, std::string what)
        : acceptor_(acceptor), what_(std::move(what)) {}

    bool await_ready() const noexcept {
        return false;
    }

    void await_suspend(std::coroutine_handle<> continuation) {
        acceptor_.async_accept([this, continuation](std::error_code ec, tcp::socket socket) mutable {
            if (ec)
                error_ = std::make_exception_ptr(std::system_error(ec, what_));
            else
                socket_ = std::move(socket);
            continuation.resume();
        });
    }

    auto await_resume() -> tcp::socket {
        if (error_)
            std::rethrow_exception(error_);
        if (!socket_.has_value())
            throw std::runtime_error(what_ + ": accept completed without a socket");
        return std::move(*socket_);
    }

private:
    tcp::acceptor& acceptor_;
    std::string what_;
    std::optional<tcp::socket> socket_{};
    std::exception_ptr error_{};
};

[[nodiscard]] inline auto async_resolve_first(asio::any_io_executor executor,
                                              std::string host,
                                              std::string port,
                                              tcp::resolver::flags flags = tcp::resolver::flags{},
                                              std::string what = "resolver failed") -> resolve_operation {
    return resolve_operation(executor, std::move(host), std::move(port), flags, std::move(what));
}

[[nodiscard]] inline auto async_connect(tcp::socket& socket,
                                        tcp::endpoint endpoint,
                                        std::string what = "connect failed") -> connect_operation {
    return connect_operation(socket, endpoint, std::move(what));
}

[[nodiscard]] inline auto async_accept(tcp::acceptor& acceptor,
                                       std::string what = "accept failed") -> accept_operation {
    return accept_operation(acceptor, std::move(what));
}

[[nodiscard]] inline auto async_tls_handshake(asio::ssl::stream<tcp::socket>& socket,
                                              asio::ssl::stream_base::handshake_type type,
                                              std::string what = "tls handshake failed") -> tls_handshake_operation {
    return tls_handshake_operation(socket, type, std::move(what));
}

} // namespace httpant::examples