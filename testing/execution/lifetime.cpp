import httpant.dependencies.boost.ut;
import std;
import httpant;
import httpant.testing;

namespace httpant::testing::execution {
using namespace boost::ut;
namespace {
struct failing_open_factory : recording_stream_factory {
    int calls{0};
    int fail_at{1};
    explicit failing_open_factory(int at) : recording_stream_factory(true), fail_at(at) {}
    auto async_open_unidirectional(std::stop_token stop) -> open_awaiter {
        if (++calls == fail_at) throw std::runtime_error("open failed");
        return recording_stream_factory::async_open_unidirectional(stop);
    }
};
struct failing_scoped_endpoint {
    int closes{0};
    friend auto operation_start(failing_scoped_endpoint&) -> http::task<void> {
        throw std::runtime_error("start failed");
        co_return;
    }
    friend auto operation_close(failing_scoped_endpoint& e) -> http::task<void> {
        ++e.closes;
        co_return;
    }
};
} // namespace
static suite<"execution lifetime"> lifetime_tests = [] {
    "http3_initialization_failure_is_terminal_and_new_endpoint_can_connect"_test = [] {
        for (int at : {1, 2, 3}) {
            failing_open_factory factory{at};
            http::v3::client<failing_open_factory> client{factory};
            for (int retry = 0; retry < 2; ++retry) {
                bool failed = false;
                try { run_sync(http::coroutine::start(client)); }
                catch (const std::runtime_error& e) { failed = std::string_view{e.what()} == "open failed"; }
                expect(failed);
                expect(factory.calls == at);
            }
            bool failed = false;
            try { static_cast<void>(run_sync(http::coroutine::request(client, basic_get("/")))); }
            catch (const std::runtime_error& e) { failed = std::string_view{e.what()} == "open failed"; }
            expect(failed);
            run_sync(http::coroutine::close(client));
        }
        recording_stream_factory transport{true};
        http::v3::client<recording_stream_factory> fresh{transport};
        run_sync(http::coroutine::start(fresh));
        expect(static_cast<bool>(transport.accept_waiter));
        run_sync(http::coroutine::close(fresh));
        expect(!transport.accept_waiter);
    };

    "http3_close_joins_driver_and_stops_parked_exchange"_test = [] {
        recording_stream_factory transport{true};
        http::v3::client<recording_stream_factory> client{transport};
        run_sync(http::coroutine::start(client));
        bool stopped = false;
        auto request = [&]() -> http::task<void> {
            try { static_cast<void>(co_await http::coroutine::request(client, basic_get("/"))); }
            catch (const http::stopped&) { stopped = true; }
        };
        auto root = request();
        root.start();
        expect(!root.done());
        run_sync(http::coroutine::close(client));
        expect(root.done());
        root.result();
        expect(stopped);
        expect(!transport.accept_waiter);
        run_sync(http::coroutine::close(client));
    };

    // HTTP/2 close fails the connection itself once the reader is joined, so
    // a parked exchange finishes with http::stopped and a later request does
    // too, instead of parking on a connection nobody reads.
    "http2_close_joins_reader_and_stops_parked_exchange"_test = [] {
        async_pipe c2s{};
        async_pipe s2c{};
        async_mock_stream transport{.input = s2c, .output = c2s};
        http::v2::client<async_mock_stream> client{transport};
        push_http2_settings_frame(s2c);
        run_sync(http::coroutine::start(client));
        bool stopped = false;
        auto request = [&]() -> http::task<void> {
            try { static_cast<void>(co_await http::coroutine::request(client, basic_get("/"))); }
            catch (const http::stopped&) { stopped = true; }
        };
        auto root = request();
        root.start();
        expect(!root.done());
        run_sync(http::coroutine::close(client));
        expect(root.done());
        root.result();
        expect(stopped);
        bool later_stopped = false;
        try { static_cast<void>(run_sync(http::coroutine::request(client, basic_get("/")))); }
        catch (const http::stopped&) { later_stopped = true; }
        expect(later_stopped);
    };

    // An unstarted HTTP/2 endpoint has no reader; close still ends it.
    "http2_close_without_start_stops_later_requests"_test = [] {
        async_pipe c2s{};
        async_pipe s2c{};
        async_mock_stream transport{.input = s2c, .output = c2s};
        http::v2::client<async_mock_stream> client{transport};
        run_sync(http::coroutine::close(client));
        bool stopped = false;
        try { static_cast<void>(run_sync(http::coroutine::request(client, basic_get("/")))); }
        catch (const http::stopped&) { stopped = true; }
        expect(stopped);
    };

    "scope_rejects_started_child"_test = [] {
        int runs = 0;
        auto work = [&]() -> http::task<void> { ++runs; co_return; };
        auto child = work();
        child.start();
        http::task_scope scope;
        bool caught = false;
        try { scope.spawn(std::move(child)); } catch (const http::usage_error&) { caught = true; }
        expect(caught);
        expect(runs == 1_i);
        expect(!scope.running());
    };

    "scoped_closes_after_start_failure_and_preserves_error"_test = [] {
        failing_scoped_endpoint endpoint;
        bool entered = false;
        bool failed = false;
        try {
            run_sync(http::coroutine::scoped(endpoint, [&](auto&) -> http::task<void> {
                entered = true;
                co_return;
            }));
        } catch (const std::runtime_error& e) { failed = std::string_view{e.what()} == "start failed"; }
        expect(failed);
        expect(!entered);
        expect(endpoint.closes == 1_i);
    };
};
} // namespace httpant::testing::execution
