#pragma once

#include <asio.hpp>
#include <asio/ssl.hpp>

#include <coroutine>
#include <cstddef>
#include <exception>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <stop_token>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

namespace httpant::examples {

using tcp = asio::ip::tcp;

namespace detail {

class socket_operation_state : public std::enable_shared_from_this<socket_operation_state> {
public:
    explicit socket_operation_state(std::function<void()> cancel)
        : cancel_(std::move(cancel)) {}

    void set_continuation(std::coroutine_handle<> continuation) {
        std::scoped_lock lock(mutex_);
        continuation_ = continuation;
    }

    void arm_stop(std::stop_token stop) {
        if (!stop.stop_possible())
            return;
        std::scoped_lock lock(mutex_);
        if (completed_)
            return;
        auto weak = weak_from_this();
        stop_callback_.emplace(stop, [weak] {
            if (auto state = weak.lock())
                state->cancel();
        });
    }

    void cancel() noexcept {
        cancel_();
    }

    void complete(std::exception_ptr error, std::size_t result) {
        std::coroutine_handle<> continuation;
        {
            std::scoped_lock lock(mutex_);
            if (completed_)
                return;
            completed_ = true;
            error_ = std::move(error);
            result_ = result;
            continuation = std::exchange(continuation_, {});
        }
        stop_callback_.reset();
        if (continuation)
            continuation.resume();
    }

    void detach() {
        std::scoped_lock lock(mutex_);
        continuation_ = {};
    }

    auto result() -> std::size_t {
        std::scoped_lock lock(mutex_);
        if (error_)
            std::rethrow_exception(error_);
        return result_;
    }

private:
    std::mutex mutex_;
    std::function<void()> cancel_;
    std::coroutine_handle<> continuation_{};
    std::exception_ptr error_{};
    std::size_t result_{0};
    bool completed_{false};
    std::optional<std::stop_callback<std::function<void()>>> stop_callback_{};
};

template <typename Start>
class socket_operation {
public:
    socket_operation(std::shared_ptr<socket_operation_state> state,
                     std::stop_token stop,
                     Start start)
        : state_(std::move(state)), stop_(stop), start_(std::move(start)) {}

    socket_operation(const socket_operation&) = delete;
    auto operator=(const socket_operation&) -> socket_operation& = delete;
    socket_operation(socket_operation&&) = default;
    auto operator=(socket_operation&&) -> socket_operation& = default;

    ~socket_operation() {
        if (state_)
            state_->detach();
    }

    bool await_ready() const noexcept {
        return false;
    }

    void await_suspend(std::coroutine_handle<> continuation) {
        auto state = state_;
        state->set_continuation(continuation);
        start_(state);
        state->arm_stop(stop_);
    }

    auto await_resume() -> std::size_t {
        return state_->result();
    }

private:
    std::shared_ptr<socket_operation_state> state_;
    std::stop_token stop_;
    Start start_;
};

template <typename Start>
socket_operation(std::shared_ptr<socket_operation_state>, std::stop_token, Start)
    -> socket_operation<Start>;

} // namespace detail

class tcp_socket_stream {
public:
    explicit tcp_socket_stream(tcp::socket socket)
        : socket_(std::make_shared<tcp::socket>(std::move(socket))) {}

    // Copying a stream shares the underlying connection: http::byte_stream
    // requires copy_constructible, and for TCP/TLS a copy is just another
    // handle to the same socket.
    tcp_socket_stream(const tcp_socket_stream&) = default;
    auto operator=(const tcp_socket_stream&) -> tcp_socket_stream& = default;
    tcp_socket_stream(tcp_socket_stream&&) = default;
    auto operator=(tcp_socket_stream&&) -> tcp_socket_stream& = default;

    auto async_read(std::span<std::byte> buffer, std::stop_token stop) {
        auto socket = socket_;
        auto state = std::make_shared<detail::socket_operation_state>([socket] {
            std::error_code ignored;
            socket->cancel(ignored);
        });
        auto start = [socket, buffer](std::shared_ptr<detail::socket_operation_state> state) {
            socket->async_read_some(
                asio::buffer(buffer.data(), buffer.size()),
                [state = std::move(state)](std::error_code ec, std::size_t bytes_read) {
                    auto error = std::exception_ptr{};
                    if (ec && ec != asio::error::eof)
                        error = std::make_exception_ptr(std::system_error(ec, "socket read failed"));
                    state->complete(std::move(error), ec == asio::error::eof ? 0 : bytes_read);
                });
        };
        return detail::socket_operation{std::move(state), stop, std::move(start)};
    }

    auto async_read(std::span<std::byte> buffer) {
        return async_read(buffer, std::stop_token{});
    }

    auto async_write(std::span<const std::byte> buffer, bool fin, std::stop_token stop) {
        auto socket = socket_;
        auto state = std::make_shared<detail::socket_operation_state>([socket] {
            std::error_code ignored;
            socket->cancel(ignored);
        });
        auto start = [socket, buffer, fin](std::shared_ptr<detail::socket_operation_state> state) {
            asio::async_write(
                *socket,
                asio::buffer(buffer.data(), buffer.size()),
                [socket, state = std::move(state), fin](std::error_code ec, std::size_t bytes_written) {
                    auto error = std::exception_ptr{};
                    if (ec) {
                        error = std::make_exception_ptr(std::system_error(ec, "socket write failed"));
                    } else if (fin) {
                        std::error_code shutdown_error;
                        socket->shutdown(tcp::socket::shutdown_send, shutdown_error);
                        if (shutdown_error)
                            error = std::make_exception_ptr(std::system_error(shutdown_error, "socket shutdown failed"));
                    }
                    state->complete(std::move(error), bytes_written);
                });
        };
        return detail::socket_operation{std::move(state), stop, std::move(start)};
    }

    auto async_write(std::span<const std::byte> buffer, std::stop_token stop) {
        return async_write(buffer, false, stop);
    }

    auto async_write(std::span<const std::byte> buffer) {
        return async_write(buffer, false, std::stop_token{});
    }

    auto async_write(std::span<const std::byte> buffer, bool fin) {
        return async_write(buffer, fin, std::stop_token{});
    }

    auto socket() -> tcp::socket& {
        return *socket_;
    }

private:
    std::shared_ptr<tcp::socket> socket_;
};

class tls_socket_stream {
public:
    explicit tls_socket_stream(asio::ssl::stream<tcp::socket> socket)
        : socket_(std::make_shared<asio::ssl::stream<tcp::socket>>(std::move(socket))) {}

    // Copying a stream shares the underlying TLS connection (see
    // tcp_socket_stream above).
    tls_socket_stream(const tls_socket_stream&) = default;
    auto operator=(const tls_socket_stream&) -> tls_socket_stream& = default;
    tls_socket_stream(tls_socket_stream&&) = default;
    auto operator=(tls_socket_stream&&) -> tls_socket_stream& = default;

    auto async_read(std::span<std::byte> buffer, std::stop_token stop) {
        auto socket = socket_;
        auto state = std::make_shared<detail::socket_operation_state>([socket] {
            std::error_code ignored;
            socket->lowest_layer().cancel(ignored);
        });
        auto start = [socket, buffer](std::shared_ptr<detail::socket_operation_state> state) {
            socket->async_read_some(
                asio::buffer(buffer.data(), buffer.size()),
                [state = std::move(state)](std::error_code ec, std::size_t bytes_read) {
                    auto error = std::exception_ptr{};
                    if (ec && ec != asio::error::eof)
                        error = std::make_exception_ptr(std::system_error(ec, "tls socket read failed"));
                    state->complete(std::move(error), ec == asio::error::eof ? 0 : bytes_read);
                });
        };
        return detail::socket_operation{std::move(state), stop, std::move(start)};
    }

    auto async_read(std::span<std::byte> buffer) {
        return async_read(buffer, std::stop_token{});
    }

    auto async_write(std::span<const std::byte> buffer, std::stop_token stop) {
        auto socket = socket_;
        auto state = std::make_shared<detail::socket_operation_state>([socket] {
            std::error_code ignored;
            socket->lowest_layer().cancel(ignored);
        });
        auto start = [socket, buffer](std::shared_ptr<detail::socket_operation_state> state) {
            asio::async_write(
                *socket,
                asio::buffer(buffer.data(), buffer.size()),
                [state = std::move(state)](std::error_code ec, std::size_t bytes_written) {
                    auto error = std::exception_ptr{};
                    if (ec)
                        error = std::make_exception_ptr(std::system_error(ec, "tls socket write failed"));
                    state->complete(std::move(error), bytes_written);
                });
        };
        return detail::socket_operation{std::move(state), stop, std::move(start)};
    }

    auto async_write(std::span<const std::byte> buffer) {
        return async_write(buffer, std::stop_token{});
    }

    auto socket() -> asio::ssl::stream<tcp::socket>& {
        return *socket_;
    }

    auto lowest_layer() -> decltype(auto) {
        return socket_->lowest_layer();
    }

private:
    std::shared_ptr<asio::ssl::stream<tcp::socket>> socket_;
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