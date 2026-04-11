#pragma once

#include <boost/ut.hpp>

#include <asio.hpp>
#include <asio/ssl.hpp>
#include <openssl/ssl.h>

extern "C" {
#include <msquic.h>
}

#include <algorithm>
#include <array>
#include <coroutine>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <exception>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <stdexcept>
#include <system_error>
#include <type_traits>
#include <deque>
#include <unordered_map>
#include <utility>
#include <vector>

import httpant;

namespace httpant::testing {

using namespace std::literals;

struct pipe {
    std::vector<std::byte> buffer{};
    std::size_t read_pos{0};
    bool closed{false};

    void push(std::span<const std::byte> data) {
        buffer.insert(buffer.end(), data.begin(), data.end());
    }

    [[nodiscard]] auto available() const -> std::size_t {
        return buffer.size() - read_pos;
    }

    void close() {
        closed = true;
    }
};

struct mock_stream {
    pipe& input;
    pipe& output;

    struct read_awaiter {
        pipe& p;
        std::span<std::byte> buf;

        bool await_ready() noexcept {
            return p.available() > 0 || p.closed;
        }

        void await_suspend(std::coroutine_handle<> h) noexcept {
            h.resume();
        }

        auto await_resume() noexcept -> std::size_t {
            auto n = std::min(buf.size(), p.available());
            std::memcpy(buf.data(), p.buffer.data() + p.read_pos, n);
            p.read_pos += n;
            return n;
        }
    };

    struct write_awaiter {
        pipe& p;
        std::span<const std::byte> data;

        bool await_ready() noexcept {
            return true;
        }

        void await_suspend(std::coroutine_handle<>) noexcept {
        }

        auto await_resume() noexcept -> std::size_t {
            p.push(data);
            return data.size();
        }
    };

    auto async_read(std::span<std::byte> buf) -> read_awaiter {
        return {input, buf};
    }

    auto async_write(std::span<const std::byte> data) -> write_awaiter {
        return {output, data};
    }
};

struct async_pipe {
    std::vector<std::byte> buffer{};
    std::size_t read_pos{0};
    bool closed{false};
    std::coroutine_handle<> waiter{};
    void const* waiter_owner{nullptr};

    void push(std::span<const std::byte> data) {
        buffer.insert(buffer.end(), data.begin(), data.end());
        if (waiter) {
            auto handle = std::exchange(waiter, {});
            waiter_owner = nullptr;
            handle.resume();
        }
    }

    [[nodiscard]] auto available() const -> std::size_t {
        return buffer.size() - read_pos;
    }

    void close() {
        closed = true;
        if (waiter) {
            auto handle = std::exchange(waiter, {});
            waiter_owner = nullptr;
            handle.resume();
        }
    }
};

struct async_mock_stream {
    async_pipe& input;
    async_pipe& output;

    struct read_awaiter {
        async_pipe& p;
        std::span<std::byte> buf;

        ~read_awaiter() {
            if (p.waiter_owner == this) {
                p.waiter = {};
                p.waiter_owner = nullptr;
            }
        }

        bool await_ready() noexcept {
            return p.available() > 0 || p.closed;
        }

        auto await_suspend(std::coroutine_handle<> h) noexcept -> bool {
            p.waiter = h;
            p.waiter_owner = this;
            return true;
        }

        auto await_resume() noexcept -> std::size_t {
            if (p.waiter_owner == this)
                p.waiter_owner = nullptr;
            auto n = std::min(buf.size(), p.available());
            std::memcpy(buf.data(), p.buffer.data() + p.read_pos, n);
            p.read_pos += n;
            return n;
        }
    };

    struct write_awaiter {
        async_pipe& p;
        std::span<const std::byte> data;
        bool fin{false};

        bool await_ready() noexcept {
            return true;
        }

        void await_suspend(std::coroutine_handle<>) noexcept {
        }

        auto await_resume() noexcept -> std::size_t {
            p.push(data);
            if (fin)
                p.close();
            return data.size();
        }
    };

    auto async_read(std::span<std::byte> buf) -> read_awaiter {
        return {input, buf};
    }

    auto async_write(std::span<const std::byte> data) -> write_awaiter {
        return {output, data, false};
    }

    auto async_write(std::span<const std::byte> data, bool fin) -> write_awaiter {
        return {output, data, fin};
    }
};

struct mock_multiplexed_stream {
    pipe& input;
    pipe& output;

    using read_awaiter = mock_stream::read_awaiter;
    using write_awaiter = mock_stream::write_awaiter;

    struct accept_awaiter {
        pipe& input;
        pipe& output;

        bool await_ready() noexcept {
            return true;
        }

        void await_suspend(std::coroutine_handle<>) noexcept {
        }

        auto await_resume() noexcept -> mock_multiplexed_stream {
            return {input, output};
        }
    };

    struct open_awaiter {
        pipe& input;
        pipe& output;
        std::int64_t id;

        bool await_ready() noexcept {
            return true;
        }

        void await_suspend(std::coroutine_handle<>) noexcept {
        }

        auto await_resume() noexcept -> mock_multiplexed_stream {
            return {input, output};
        }
    };

    auto async_read(std::span<std::byte> buf) -> read_awaiter {
        return {input, buf};
    }

    auto async_write(std::span<const std::byte> data) -> write_awaiter {
        return {output, data};
    }

    auto async_accept() -> accept_awaiter {
        return {input, output};
    }

    auto async_open(std::int64_t id) -> open_awaiter {
        return {input, output, id};
    }
};

struct recorded_write {
    std::int64_t stream_id{-1};
    bool fin{false};
    std::vector<std::byte> data{};
};

struct recording_multiplexed_transport {
    struct stream;

    struct read_awaiter {
        bool await_ready() noexcept {
            return true;
        }

        void await_suspend(std::coroutine_handle<>) noexcept {
        }

        auto await_resume() noexcept -> std::size_t {
            return 0;
        }
    };

    struct write_awaiter {
        recording_multiplexed_transport& transport;
        std::int64_t stream_id;
        std::span<const std::byte> data;
        bool fin{false};

        bool await_ready() noexcept {
            return true;
        }

        void await_suspend(std::coroutine_handle<>) noexcept {
        }

        auto await_resume() -> std::size_t {
            transport.writes.push_back(recorded_write{
                .stream_id = stream_id,
                .fin = fin,
                .data = {data.begin(), data.end()},
            });
            return data.size();
        }
    };

    struct stream {
        recording_multiplexed_transport& transport;
        std::int64_t stream_id;

        auto async_read(std::span<std::byte>) -> read_awaiter {
            return {};
        }

        auto async_write(std::span<const std::byte> data) -> write_awaiter {
            return {transport, stream_id, data, false};
        }

        auto async_write(std::span<const std::byte> data, bool fin) -> write_awaiter {
            return {transport, stream_id, data, fin};
        }
    };

    struct accept_awaiter {
        recording_multiplexed_transport& transport;

        bool await_ready() noexcept {
            return true;
        }

        void await_suspend(std::coroutine_handle<>) noexcept {
        }

        auto await_resume() noexcept -> stream {
            return {transport, -1};
        }
    };

    struct open_awaiter {
        recording_multiplexed_transport& transport;
        std::int64_t id;

        bool await_ready() noexcept {
            return true;
        }

        void await_suspend(std::coroutine_handle<>) noexcept {
        }

        auto await_resume() noexcept -> stream {
            return {transport, id};
        }
    };

    std::deque<recorded_write> writes{};

    auto async_read(std::span<std::byte>) -> read_awaiter {
        return {};
    }

    auto async_write(std::span<const std::byte> data) -> write_awaiter {
        return {*this, -1, data, false};
    }

    auto async_write(std::span<const std::byte> data, bool fin) -> write_awaiter {
        return {*this, -1, data, fin};
    }

    auto async_accept() -> accept_awaiter {
        return {*this};
    }

    auto async_open(std::int64_t id) -> open_awaiter {
        return {*this, id};
    }

    auto take_writes() -> std::vector<recorded_write> {
        std::vector<recorded_write> out;
        while (!writes.empty()) {
            out.push_back(std::move(writes.front()));
            writes.pop_front();
        }
        return out;
    }
};

template <typename T>
auto run_sync(http::task<T> task) -> T {
    std::optional<T> result;
    std::exception_ptr error;

    struct sync_launcher {
        struct promise_type {
            auto get_return_object() -> sync_launcher { return {}; }
            auto initial_suspend() noexcept -> std::suspend_never { return {}; }
            auto final_suspend() noexcept -> std::suspend_never { return {}; }
            void return_void() {}
            void unhandled_exception() { std::rethrow_exception(std::current_exception()); }
        };
    };

    [](http::task<T> inner, std::optional<T>& out, std::exception_ptr& ex) -> sync_launcher {
        try {
            out = co_await std::move(inner);
        } catch (...) {
            ex = std::current_exception();
        }
    }(std::move(task), result, error);

    if (error) {
        std::rethrow_exception(error);
    }

    if (!result.has_value()) {
        throw std::runtime_error("task completed without a result");
    }

    return std::move(*result);
}

inline auto run_sync(http::task<void> task) -> void {
    std::exception_ptr error;

    struct sync_launcher {
        struct promise_type {
            auto get_return_object() -> sync_launcher { return {}; }
            auto initial_suspend() noexcept -> std::suspend_never { return {}; }
            auto final_suspend() noexcept -> std::suspend_never { return {}; }
            void return_void() {}
            void unhandled_exception() { std::rethrow_exception(std::current_exception()); }
        };
    };

    [](http::task<void> inner, std::exception_ptr& ex) -> sync_launcher {
        try {
            co_await std::move(inner);
        } catch (...) {
            ex = std::current_exception();
        }
    }(std::move(task), error);

    if (error) {
        std::rethrow_exception(error);
    }
}

template <typename T>
struct started_task {
    std::optional<T> result{};
    std::exception_ptr error{};
    bool done{false};

    struct launcher {
        struct promise_type;
        using handle_type = std::coroutine_handle<promise_type>;

        struct promise_type {
            auto get_return_object() -> launcher { return launcher{handle_type::from_promise(*this)}; }
            auto initial_suspend() noexcept -> std::suspend_never { return {}; }
            auto final_suspend() noexcept -> std::suspend_always { return {}; }
            void return_void() {}
            void unhandled_exception() { std::rethrow_exception(std::current_exception()); }
        };

        handle_type handle{};

        launcher() = default;
        explicit launcher(handle_type h) : handle(h) {}
        launcher(const launcher&) = delete;
        launcher& operator=(const launcher&) = delete;
        launcher(launcher&& other) noexcept : handle(std::exchange(other.handle, {})) {}
        auto operator=(launcher&& other) noexcept -> launcher& {
            if (this != &other) {
                if (handle) handle.destroy();
                handle = std::exchange(other.handle, {});
            }
            return *this;
        }
        ~launcher() {
            if (handle) handle.destroy();
        }
    };

    launcher runner_{};

    explicit started_task(http::task<T> task) {
        runner_ = [this](http::task<T> inner) -> launcher {
            try {
                result = co_await std::move(inner);
            } catch (...) {
                error = std::current_exception();
            }
            done = true;
        }(std::move(task));
    }

    auto take() -> T {
        if (!done)
            throw std::runtime_error("task has not completed");
        if (error)
            std::rethrow_exception(error);
        if (!result.has_value())
            throw std::runtime_error("task completed without a result");
        return std::move(*result);
    }
};

template <>
struct started_task<void> {
    std::exception_ptr error{};
    bool done{false};

    struct launcher {
        struct promise_type;
        using handle_type = std::coroutine_handle<promise_type>;

        struct promise_type {
            auto get_return_object() -> launcher { return launcher{handle_type::from_promise(*this)}; }
            auto initial_suspend() noexcept -> std::suspend_never { return {}; }
            auto final_suspend() noexcept -> std::suspend_always { return {}; }
            void return_void() {}
            void unhandled_exception() { std::rethrow_exception(std::current_exception()); }
        };

        handle_type handle{};

        launcher() = default;
        explicit launcher(handle_type h) : handle(h) {}
        launcher(const launcher&) = delete;
        launcher& operator=(const launcher&) = delete;
        launcher(launcher&& other) noexcept : handle(std::exchange(other.handle, {})) {}
        auto operator=(launcher&& other) noexcept -> launcher& {
            if (this != &other) {
                if (handle) handle.destroy();
                handle = std::exchange(other.handle, {});
            }
            return *this;
        }
        ~launcher() {
            if (handle) handle.destroy();
        }
    };

    launcher runner_{};

    explicit started_task(http::task<void> task) {
        runner_ = [this](http::task<void> inner) -> launcher {
            try {
                co_await std::move(inner);
            } catch (...) {
                error = std::current_exception();
            }
            done = true;
        }(std::move(task));
    }

    void join() {
        if (!done)
            throw std::runtime_error("task has not completed");
        if (error)
            std::rethrow_exception(error);
    }
};

struct tcp_stream {
    asio::ip::tcp::socket& socket;

    struct read_awaiter {
        asio::ip::tcp::socket& sock;
        std::span<std::byte> buf;
        std::size_t result{0};
        std::exception_ptr ex;

        bool await_ready() noexcept {
            return false;
        }

        void await_suspend(std::coroutine_handle<> h) {
            sock.async_read_some(
                asio::buffer(buf.data(), buf.size()),
                [this, h](std::error_code ec, std::size_t n) mutable {
                    if (ec && ec != asio::error::eof) {
                        ex = std::make_exception_ptr(std::system_error(ec));
                    }
                    result = n;
                    h.resume();
                });
        }

        auto await_resume() -> std::size_t {
            if (ex) {
                std::rethrow_exception(ex);
            }
            return result;
        }
    };

    struct write_awaiter {
        asio::ip::tcp::socket& sock;
        std::span<const std::byte> data;
        std::size_t result{0};
        std::exception_ptr ex;

        bool await_ready() noexcept {
            return false;
        }

        void await_suspend(std::coroutine_handle<> h) {
            asio::async_write(
                sock,
                asio::buffer(data.data(), data.size()),
                [this, h](std::error_code ec, std::size_t n) mutable {
                    if (ec) {
                        ex = std::make_exception_ptr(std::system_error(ec));
                    }
                    result = n;
                    h.resume();
                });
        }

        auto await_resume() -> std::size_t {
            if (ex) {
                std::rethrow_exception(ex);
            }
            return result;
        }
    };

    auto async_read(std::span<std::byte> buf) -> read_awaiter {
        return {socket, buf};
    }

    auto async_write(std::span<const std::byte> data) -> write_awaiter {
        return {socket, data};
    }
};

struct tls_stream {
    asio::ssl::stream<asio::ip::tcp::socket>& socket;

    struct read_awaiter {
        asio::ssl::stream<asio::ip::tcp::socket>& sock;
        std::span<std::byte> buf;
        std::size_t result{0};
        std::exception_ptr ex;

        bool await_ready() noexcept {
            return false;
        }

        void await_suspend(std::coroutine_handle<> h) {
            sock.async_read_some(
                asio::buffer(buf.data(), buf.size()),
                [this, h](std::error_code ec, std::size_t n) mutable {
                    if (ec && ec != asio::error::eof) {
                        ex = std::make_exception_ptr(std::system_error(ec));
                    }
                    result = n;
                    h.resume();
                });
        }

        auto await_resume() -> std::size_t {
            if (ex) {
                std::rethrow_exception(ex);
            }
            return result;
        }
    };

    struct write_awaiter {
        asio::ssl::stream<asio::ip::tcp::socket>& sock;
        std::span<const std::byte> data;
        std::size_t result{0};
        std::exception_ptr ex;

        bool await_ready() noexcept {
            return false;
        }

        void await_suspend(std::coroutine_handle<> h) {
            asio::async_write(
                sock,
                asio::buffer(data.data(), data.size()),
                [this, h](std::error_code ec, std::size_t n) mutable {
                    if (ec) {
                        ex = std::make_exception_ptr(std::system_error(ec));
                    }
                    result = n;
                    h.resume();
                });
        }

        auto await_resume() -> std::size_t {
            if (ex) {
                std::rethrow_exception(ex);
            }
            return result;
        }
    };

    auto async_read(std::span<std::byte> buf) -> read_awaiter {
        return {socket, buf};
    }

    auto async_write(std::span<const std::byte> data) -> write_awaiter {
        return {socket, data};
    }
};

struct quic_stream {
    HQUIC connection{nullptr};
    HQUIC stream_handle{nullptr};
    const QUIC_API_TABLE* api{nullptr};

    struct quic_read_awaiter {
        HQUIC stream_handle;
        std::span<std::byte> buf;
        std::size_t result{0};

        bool await_ready() noexcept {
            return false;
        }

        void await_suspend(std::coroutine_handle<> h) noexcept {
            h.resume();
        }

        auto await_resume() noexcept -> std::size_t {
            return result;
        }
    };

    struct quic_write_awaiter {
        HQUIC stream_handle;
        const QUIC_API_TABLE* api;
        std::span<const std::byte> data;
        std::size_t result{0};

        bool await_ready() noexcept {
            return false;
        }

        void await_suspend(std::coroutine_handle<> h) noexcept {
            result = data.size();
            h.resume();
        }

        auto await_resume() noexcept -> std::size_t {
            return result;
        }
    };

    struct accept_awaiter {
        HQUIC connection;
        const QUIC_API_TABLE* api;

        bool await_ready() noexcept {
            return false;
        }

        void await_suspend(std::coroutine_handle<> h) noexcept {
            h.resume();
        }

        auto await_resume() noexcept -> quic_stream {
            return {connection, nullptr, api};
        }
    };

    struct open_awaiter {
        HQUIC connection;
        const QUIC_API_TABLE* api;
        std::int64_t id;

        bool await_ready() noexcept {
            return false;
        }

        void await_suspend(std::coroutine_handle<> h) noexcept {
            h.resume();
        }

        auto await_resume() noexcept -> quic_stream {
            return {connection, nullptr, api};
        }
    };

    auto async_read(std::span<std::byte> buf) -> quic_read_awaiter {
        return {stream_handle, buf};
    }

    auto async_write(std::span<const std::byte> data) -> quic_write_awaiter {
        return {stream_handle, api, data};
    }

    auto async_accept() -> accept_awaiter {
        return {connection, api};
    }

    auto async_open(std::int64_t id) -> open_awaiter {
        return {connection, api, id};
    }
};

inline void push_text(pipe& p, std::string_view text) {
    auto bytes = std::as_bytes(std::span{text.data(), text.size()});
    p.push(bytes);
}

[[nodiscard]] inline auto bytes_to_string(std::span<const std::byte> bytes) -> std::string {
    return {reinterpret_cast<const char*>(bytes.data()), bytes.size()};
}

[[nodiscard]] inline auto bytes_to_string(const std::vector<std::byte>& bytes) -> std::string {
    return bytes_to_string(std::span<const std::byte>{bytes.data(), bytes.size()});
}

[[nodiscard]] inline auto make_body(std::string_view text) -> std::vector<std::byte> {
    auto bytes = std::as_bytes(std::span{text.data(), text.size()});
    return {bytes.begin(), bytes.end()};
}

[[nodiscard]] inline auto read_body_text(const std::vector<std::byte>& body) -> std::string {
    return bytes_to_string(body);
}

struct http1_client_fixture {
    pipe c2s{};
    pipe s2c{};
    mock_stream transport{.input = s2c, .output = c2s};
    http::client_v1<mock_stream> client{transport};

    void queue_response(std::string_view raw, bool close = false) {
        push_text(s2c, raw);
        s2c.closed = close;
    }

    auto issue(http::request request) -> http::response {
        return run_sync(client.request(std::move(request)));
    }
};

[[nodiscard]] inline auto basic_get(std::string_view target = "/") -> http::request {
    return http::request{
        .method = http::method::GET,
        .target = std::string(target),
        .scheme = "https",
        .authority = "example.com",
        .fields = {{"host", "example.com"}},
        .body = {},
    };
}

inline void push_http2_settings_frame(pipe& p) {
    constexpr std::array<std::byte, 9> frame{
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
        std::byte{0x04}, std::byte{0x00},
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
    };
    p.push(frame);
}

inline void push_http2_goaway_frame(pipe& p) {
    constexpr std::array<std::byte, 17> frame{
        std::byte{0x00}, std::byte{0x00}, std::byte{0x08},
        std::byte{0x07}, std::byte{0x00},
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
    };
    p.push(frame);
}

inline void push_http2_window_update_frame(pipe& p, std::uint32_t increment) {
    std::array<std::byte, 13> frame{
        std::byte{0x00}, std::byte{0x00}, std::byte{0x04},
        std::byte{0x08}, std::byte{0x00},
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
        std::byte{static_cast<unsigned char>((increment >> 24) & 0x7f)},
        std::byte{static_cast<unsigned char>((increment >> 16) & 0xff)},
        std::byte{static_cast<unsigned char>((increment >> 8) & 0xff)},
        std::byte{static_cast<unsigned char>(increment & 0xff)},
    };
    p.push(frame);
}

} // namespace httpant::testing