#pragma once

#include <algorithm>
#include <cstddef>
#include <coroutine>
#include <span>
#include <stop_token>
#include <string_view>
#include <vector>

namespace httpant::examples {

struct memory_stream {
    struct read_awaiter {
        memory_stream& stream;
        std::span<std::byte> buffer;

        [[nodiscard]] auto await_ready() const noexcept -> bool { return true; }
        void await_suspend(std::coroutine_handle<>) const noexcept {}
        auto await_resume() -> std::size_t {
            auto size = std::min(buffer.size(), stream.input.size());
            std::ranges::copy_n(stream.input.begin(), size, buffer.begin());
            stream.input.erase(
                stream.input.begin(),
                stream.input.begin() + static_cast<std::ptrdiff_t>(size));
            return size;
        }
    };

    struct write_awaiter {
        std::size_t size;

        [[nodiscard]] auto await_ready() const noexcept -> bool { return true; }
        void await_suspend(std::coroutine_handle<>) const noexcept {}
        [[nodiscard]] auto await_resume() const noexcept -> std::size_t { return size; }
    };

    auto async_read(std::span<std::byte> buffer, std::stop_token) -> read_awaiter {
        return {*this, buffer};
    }

    auto async_write(std::span<const std::byte> buffer, std::stop_token)
        -> write_awaiter {
        return {buffer.size()};
    }

    std::vector<std::byte> input{};
};

[[nodiscard]] inline auto example_response() -> std::vector<std::byte> {
    constexpr std::string_view wire =
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
    auto bytes = std::as_bytes(std::span{wire.data(), wire.size()});
    return {bytes.begin(), bytes.end()};
}

} // namespace httpant::examples
