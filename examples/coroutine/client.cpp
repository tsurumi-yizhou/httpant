import httpant;

#include <array>
#include <cstddef>
#include <stop_token>

#include "../client_support.hpp"

namespace {

auto example() -> http::task<int> {
    httpant::examples::memory_stream transport{
        .input = httpant::examples::example_response(),
    };
    http::v1::client<httpant::examples::memory_stream> client{transport};
    co_await http::coroutine::start(client);
    auto response = co_await http::coroutine::request(client, http::request{
        .method = http::method::GET,
        .target = "/",
        .fields = {{"host", "example.com"}},
    });
    std::array<std::byte, 2> body{};
    auto size = co_await response.body.async_read(body, std::stop_token{});
    co_return response.head.status == 200 && size == body.size() ? 0 : 1;
}

} // namespace

auto main() -> int {
    auto operation = example();
    operation.start();
    return operation.done() ? 0 : 1;
}
