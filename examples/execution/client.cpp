#include <stdexec/execution.hpp>

#include <array>
#include <cstddef>
#include <stop_token>
#include <tuple>

import httpant;

#include "../client_support.hpp"

auto main() -> int {
    httpant::examples::memory_stream transport{
        .input = httpant::examples::example_response(),
    };
    http::v1::client<httpant::examples::memory_stream> client{transport};

    auto started = stdexec::sync_wait(http::execution::start(client));
    if (!started)
        return 1;
    auto response = stdexec::sync_wait(http::execution::request(client, http::request{
        .method = http::method::GET,
        .target = "/",
        .fields = {{"host", "example.com"}},
    }));
    if (!response || std::get<0>(*response).head.status != 200)
        return 1;

    std::array<std::byte, 2> body{};
    auto size = stdexec::sync_wait(std::get<0>(*response).body.async_read(
        body, std::stop_token{}));
    return size && std::get<0>(*size) == body.size() ? 0 : 1;
}
