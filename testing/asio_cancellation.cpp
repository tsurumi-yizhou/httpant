#include <boost/ut.hpp>

#include <asio.hpp>

#include <array>
#include <cstddef>
#include <stop_token>
#include <system_error>

#include "../examples/asio_support.hpp"
#include "test_support.hpp"

namespace httpant::testing {

using namespace boost::ut;
using httpant::examples::tcp;
using httpant::examples::tcp_socket_stream;

namespace {

struct socket_pair {
    explicit socket_pair(asio::io_context& context)
        : acceptor(context, tcp::endpoint(tcp::v4(), 0)),
          client(context),
          server(context) {
        client.connect(acceptor.local_endpoint());
        acceptor.accept(server);
    }

    tcp::acceptor acceptor;
    tcp::socket client;
    tcp::socket server;
};

} // namespace

static suite<"asio cancellation"> asio_cancellation_suite = [] {
    // Internal machinery test: cancellation of a suspended transport read is
    // not HTTP RFC behavior.
    "suspended_tcp_read_is_cancelled"_test = [] {
        asio::io_context context;
        socket_pair sockets(context);
        tcp_socket_stream stream(std::move(sockets.client));
        std::stop_source stop;
        std::array<std::byte, 1> buffer{};
        auto completions = 0;
        auto cancelled = false;

        auto read = [&]() -> http::task<void> {
            try {
                static_cast<void>(co_await stream.async_read(buffer, stop.get_token()));
            } catch (const std::system_error& error) {
                cancelled = error.code() == asio::error::operation_aborted;
            }
            ++completions;
        }();

        read.start();
        expect(stop.request_stop());
        context.run();

        expect(cancelled);
        expect(completions == 1_i);
    };

    // Internal machinery test: stop and socket completion may race, but the
    // suspended coroutine has exactly one terminal resumption.
    "tcp_read_completion_stop_race_resumes_once"_test = [] {
        for (auto iteration = 0; iteration != 64; ++iteration) {
            asio::io_context context;
            socket_pair sockets(context);
            tcp_socket_stream stream(std::move(sockets.client));
            std::stop_source stop;
            std::array<std::byte, 1> input{};
            std::array<std::byte, 1> output{std::byte{0x2a}};
            auto completions = 0;

            auto read = [&]() -> http::task<void> {
                try {
                    static_cast<void>(co_await stream.async_read(input, stop.get_token()));
                } catch (const std::system_error&) {
                }
                ++completions;
            }();

            read.start();
            asio::post(context, [&] {
                std::error_code ignored;
                sockets.server.write_some(asio::buffer(output), ignored);
            });
            asio::post(context, [&] { static_cast<void>(stop.request_stop()); });
            context.run();

            expect(completions == 1_i);
        }
    };

    // Internal machinery test: destroying the awaiting coroutine detaches its
    // continuation; the backend callback retains only shared operation state.
    "destroyed_awaiter_is_not_accessed_by_cancel_callback"_test = [] {
        asio::io_context context;
        socket_pair sockets(context);
        tcp_socket_stream stream(std::move(sockets.client));
        std::stop_source stop;
        std::array<std::byte, 1> buffer{};
        auto resumed = false;

        {
            auto read = [&]() -> http::task<void> {
                try {
                    static_cast<void>(co_await stream.async_read(buffer, stop.get_token()));
                } catch (const std::system_error&) {
                }
                resumed = true;
            }();
            read.start();
        }

        expect(stop.request_stop());
        context.run();
        expect(!resumed);
    };
};

} // namespace httpant::testing
