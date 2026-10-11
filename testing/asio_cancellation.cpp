import httpant.dependencies.boost.ut;
import httpant.dependencies.asio;
import std;
import httpant.examples.asio;
import httpant;
import httpant.testing;

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
    "socket_adapter_handles_completion_during_initiation"_test = [] {
        asio::io_context context;
        auto state = std::make_shared<httpant::examples::detail::socket_operation_state>(
            context.get_executor(), [] {});
        auto initiate = [](auto state) { state->complete({}, 42); };
        auto read = [&]() -> http::task<std::size_t> {
            co_return co_await httpant::examples::detail::socket_operation{
                state, std::stop_token{}, initiate};
        };
        expect(run_sync(read()) == 42_u);
    };

    "queued_socket_cancel_does_not_affect_completed_operation"_test = [] {
        asio::io_context context;
        int cancellations = 0;
        auto state = std::make_shared<httpant::examples::detail::socket_operation_state>(
            context.get_executor(), [&] { ++cancellations; });
        state->cancel();
        state->complete({}, 1);
        context.run();
        expect(cancellations == 0_i);
    };

    "http1_real_socket_receive_cancels_from_foreign_thread"_test = [] {
        asio::io_context context;
        socket_pair sockets(context);
        tcp_socket_stream stream(std::move(sockets.client));
        http::v1::server<tcp_socket_stream> server{stream};
        std::stop_source stop;
        int completions = 0;
        bool cancelled = false;
        auto receive = [&]() -> http::task<void> {
            try { static_cast<void>(co_await http::coroutine::receive(server)); }
            catch (const http::stopped&) { cancelled = true; }
            ++completions;
        };
        auto root = receive();
        root.start(stop.get_token());
        std::thread([&] { stop.request_stop(); }).join();
        context.run();
        expect(root.done());
        root.result();
        expect(cancelled);
        expect(completions == 1_i);
    };

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

        auto make_read = [&]() -> http::task<void> {
            try {
                static_cast<void>(co_await stream.async_read(buffer, stop.get_token()));
            } catch (const http::stopped&) {
                cancelled = true;
            }
            ++completions;
        };
        auto read = make_read();

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

            auto make_read = [&]() -> http::task<void> {
                try {
                    static_cast<void>(co_await stream.async_read(input, stop.get_token()));
                } catch (const http::stopped&) {
                }
                ++completions;
            };
            auto read = make_read();

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
            auto make_read = [&]() -> http::task<void> {
                try {
                    static_cast<void>(co_await stream.async_read(buffer, stop.get_token()));
                } catch (const std::system_error&) {
                }
                resumed = true;
            };
            auto read = make_read();
            read.start();
        }

        expect(stop.request_stop());
        context.run();
        expect(!resumed);
    };
};

} // namespace httpant::testing
