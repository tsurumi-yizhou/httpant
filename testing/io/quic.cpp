import std;
import httpant;
import httpant.io;
import httpant.quic;
import httpant.examples.io;

namespace {
namespace io = http::io::net;
namespace app = httpant::example;
using http::operator co_await;

const auto engine_thread = std::this_thread::get_id();
std::atomic<std::size_t> worker_posts{0};

template <class T> class observed {
    http::queues::locked<T> items_;
public:
    auto push(T value) -> bool {
        if (std::this_thread::get_id() != engine_thread) ++worker_posts;
        return items_.push(std::move(value));
    }
    auto try_pop(T& value) -> bool { return items_.try_pop(value); }
};
template <class T> class confined {
    http::queues::local<T> items_;
    static void check() {
        app::require(std::this_thread::get_id() == engine_thread, "local queue used outside the engine thread");
    }
public:
    auto push(T value) -> bool { check(); return items_.push(std::move(value)); }
    auto try_pop(T& value) -> bool { check(); return items_.try_pop(value); }
};
using scheduler = io::basic_scheduler<observed>;
using connection = http::quic::connection<observed, confined>;
using stream = http::quic::stream<observed, confined>;

struct completion {
    using receiver_concept = stdexec::receiver_t;
    io::basic_io_context<observed>* context;
    std::exception_ptr* failure;
    bool* done;
    auto get_env() const noexcept { return stdexec::env{}; }
    void set_value() noexcept { *done = true; context->stop(); }
    void set_error(std::exception_ptr error) noexcept { *failure = error; set_value(); }
    void set_stopped() noexcept { set_error(std::make_exception_ptr(http::stopped{})); }
};
void run(io::basic_io_context<observed>& context, http::task<void> task) {
    std::exception_ptr failure;
    bool done = false;
    auto operation = stdexec::connect(std::move(task), completion{&context, &failure, &done});
    stdexec::start(operation);
    context.run();
    if (failure) std::rethrow_exception(failure);
    app::require(done, "QUIC task did not finish");
}

void on_engine() {
    app::require(std::this_thread::get_id() == engine_thread, "QUIC operation resumed outside the engine thread");
}

auto write(stream& stream, std::span<const std::byte> data, bool fin) -> http::task<void> {
    const auto& stop = co_await http::current_stop_token();
    auto result = co_await stream.async_write(data, fin, stop);
    on_engine();
    co_await std::move(result.buffer_release);
    auto acked = co_await std::move(result.acknowledgement);
    on_engine();
    app::require(acked == data.size(), "write did not await the peer acknowledgement");
}
auto read(stream& stream) -> http::task<std::vector<std::byte>> {
    const auto& stop = co_await http::current_stop_token();
    std::vector<std::byte> result;
    std::array<std::byte, 8192> buffer;
    while (auto size = co_await stream.async_read(buffer, stop)) {
        on_engine();
        result.insert(result.end(), buffer.begin(), buffer.begin() + size);
        stream.consume(size);
    }
    co_return result;
}
auto cancel_accept(connection& connection, scheduler scheduler) -> http::task<void> {
    std::stop_source cancel;
    bool stopped = false;
    co_await http::coroutine::with_scope([&](http::task_scope& scope) -> http::task<void> {
        auto stop_later = [&]() -> http::task<void> {
            co_await scheduler.schedule_after(std::chrono::milliseconds{1});
            std::jthread worker{[&] { cancel.request_stop(); }};
        };
        scope.spawn(stop_later());
        try { auto unused = co_await connection.async_accept(cancel.get_token()); }
        catch (const http::stopped&) { stopped = true; }
        co_await scope.join();
    });
    on_engine();
    app::require(stopped, "pending stream accept did not stop");
}

auto cancel_read(stream& stream, scheduler scheduler) -> http::task<void> {
    std::stop_source cancel;
    bool stopped = false;
    co_await http::coroutine::with_scope([&](http::task_scope& scope) -> http::task<void> {
        auto stop_later = [&]() -> http::task<void> {
            co_await scheduler.schedule_after(std::chrono::milliseconds{1});
            std::jthread worker{[&] { cancel.request_stop(); }};
        };
        scope.spawn(stop_later());
        std::array<std::byte, 1> buffer;
        try { co_await stream.async_read(buffer, cancel.get_token()); }
        catch (const http::stopped&) { stopped = true; }
        co_await scope.join();
    });
    on_engine();
    app::require(stopped, "pending stream read did not stop");
}

struct relay {
    using socket = io::basic_datagram_socket<io::ip::udp, observed>;
    socket front, back;
    io::ip::udp::endpoint server, client{};
    bool dropped = false;
    relay(scheduler scheduler, io::ip::udp::endpoint server)
        : front(socket{scheduler, io::ip::udp::endpoint{app::loopback.address(), app::loopback.port()}}), back(socket{scheduler, io::ip::udp::endpoint{app::loopback.address(), app::loopback.port()}}), server(server) {}
    auto upstream() -> http::task<void> {
        std::array<std::byte, 65536> packet;
        for (;;) {
            auto [size, peer] = co_await io::async_receive_from(front, io::buffer(packet), client);
            client = peer;
            if (!dropped) { dropped = true; continue; }
            co_await io::async_send_to(back, io::buffer(std::span{packet}.first(size)), server);
        }
    }
    auto downstream() -> http::task<void> {
        std::array<std::byte, 65536> packet;
        for (;;) {
            auto [size, peer] = co_await io::async_receive_from(back, io::buffer(packet), server);
            app::require(peer == server, std::format("unexpected relay peer: {}:{} expected {}:{}", peer.address().to_string(), peer.port(), server.address().to_string(), server.port()));
            co_await io::async_send_to(front, io::buffer(std::span{packet}.first(size)), client);
        }
    }
};

auto transfer(scheduler scheduler, const std::filesystem::path& directory) -> http::task<void> {
    auto cert = (directory / "quic-cert.pem").string();
    auto key = (directory / "quic-key.pem").string();
    connection server{scheduler, io::ip::udp::endpoint{app::loopback.address(), app::loopback.port()}, http::quic::credentials::server(cert, key)};
    relay network{scheduler, {app::loopback.address(), server.port()}};
    connection client{scheduler, io::ip::udp::endpoint{app::loopback.address(), app::loopback.port()}, http::quic::credentials::client(cert),
        {app::loopback.address(), network.front.local_endpoint().port()}};
    std::vector<std::byte> payload(2 * 1024 * 1024);
    for (std::size_t i = 0; i < payload.size(); ++i) payload[i] = std::byte(i % 251);
    auto serve = [&]() -> http::task<void> {
        co_await server.run([&](auto& connection) -> http::task<void> {
            const auto& stop = co_await http::current_stop_token();
            auto stream = co_await connection.async_accept(stop);
            app::require(stream.access() == http::stream_access::bidirectional, "expected bidirectional stream");
            auto bytes = co_await read(stream);
            app::require(bytes == payload, "request changed while crossing the receive window");
            co_await write(stream, bytes, false);
            co_await write(stream, {}, true);
            auto abandoned = co_await connection.async_accept(stop);
            auto empty = co_await read(abandoned);
            app::require(empty.empty(), "reset test expected an empty request");
            abandoned.shutdown(http::stream_side::sending, http::application_error{42});
            auto signal = co_await connection.async_open_unidirectional(stop);
            co_await write(signal, std::as_bytes(std::span{"done", 4}), true);
        });
    };
    auto fetch = [&]() -> http::task<void> {
        co_await client.run([&](auto& connection) -> http::task<void> {
            co_await cancel_accept(connection, scheduler);
            const auto& stop = co_await http::current_stop_token();
            auto stream = co_await connection.async_open_bidirectional(stop);
            co_await cancel_read(stream, scheduler);
            co_await write(stream, payload, false);
            co_await write(stream, {}, true);
            auto bytes = co_await read(stream);
            app::require(bytes == payload, "response changed while crossing the receive window");
            auto abandoned = co_await connection.async_open_bidirectional(stop);
            co_await write(abandoned, {}, true);
            bool reset = false;
            try { auto unused = co_await read(abandoned); }
            catch (const http::stream_reset& error) { reset = error.error_code.value == 42; }
            app::require(reset, "peer reset lost its application error code");
            auto signal = co_await connection.async_accept(stop);
            app::require(signal.access() == http::stream_access::receive_only, "expected receive-only stream");
            auto marker = co_await read(signal);
            app::require(std::string_view{reinterpret_cast<const char*>(marker.data()), marker.size()} == "done", "unidirectional stream changed");
        });
    };
    co_await http::coroutine::with_scope([&](http::task_scope& scope) -> http::task<void> {
        scope.spawn(network.upstream());
        scope.spawn(network.downstream());
        std::exception_ptr failure;
        try {
            std::vector<http::task<void>> tasks;
            tasks.push_back(serve());
            tasks.push_back(fetch());
            co_await app::parallel(std::move(tasks));
        } catch (...) { failure = std::current_exception(); }
        scope.request_stop();
        co_await scope.join();
        if (failure) std::rethrow_exception(failure);
    });
    app::require(network.dropped, "loss test did not discard the initial packet");
}

auto reject_identity(scheduler scheduler, const std::filesystem::path& directory) -> http::task<void> {
    auto cert = (directory / "quic-cert.pem").string();
    connection server{scheduler, io::ip::udp::endpoint{app::loopback.address(), app::loopback.port()},
        http::quic::credentials::server(cert, (directory / "quic-key.pem").string())};
    connection client{scheduler, io::ip::udp::endpoint{app::loopback.address(), app::loopback.port()}, http::quic::credentials::client(cert),
        {app::loopback.address(), server.port()}, "wrong.example"};
    bool entered = false, rejected = false;
    auto serve = [&]() -> http::task<void> {
        co_await server.run([](auto&) -> http::task<void> { co_return; });
    };
    auto fetch = [&]() -> http::task<void> {
        co_await client.run([&](auto&) -> http::task<void> { entered = true; co_return; });
    };
    std::vector<http::task<void>> tasks;
    tasks.push_back(serve());
    tasks.push_back(fetch());
    try { co_await app::parallel(std::move(tasks)); }
    catch (const std::exception&) { rejected = true; }
    app::require(rejected && !entered, "TLS accepted a certificate for the wrong identity");
}
auto cancel_handshake(scheduler scheduler, const std::filesystem::path& directory) -> http::task<void> {
    connection server{scheduler, {app::loopback.address(), 0}, http::quic::credentials::server(
        (directory / "quic-cert.pem").string(), (directory / "quic-key.pem").string())};
    std::stop_source cancel;
    bool entered = false, stopped = false;
    co_await http::coroutine::with_scope([&](http::task_scope& scope) -> http::task<void> {
        auto stop_later = [&]() -> http::task<void> {
            co_await scheduler.schedule_after(std::chrono::milliseconds{1});
            std::jthread worker{[&] { cancel.request_stop(); }};
        };
        scope.spawn(stop_later());
        try {
            co_await http::with_stop(cancel.get_token(), server.run([&](auto&) -> http::task<void> {
                entered = true;
                co_return;
            }));
        } catch (const http::stopped&) { stopped = true; }
        co_await scope.join();
    });
    on_engine();
    app::require(stopped && !entered, "handshake cancellation entered the connection body");
}

} // namespace

int main(int argc, char** argv) {
    try {
        app::require(argc == 2 && std::filesystem::is_directory(argv[1]), "quic-test requires the existing build directory");
        io::basic_io_context<observed> context;
        std::filesystem::path directory{argv[1]};
        run(context, transfer(context.get_scheduler(), directory));
        run(context, reject_identity(context.get_scheduler(), directory));
        run(context, cancel_handshake(context.get_scheduler(), directory));
        app::require(worker_posts.load() > 0, "QUIC events did not cross the worker queue");
        std::println("QUIC msquic: loss recovery, receive credit, ACK ownership, stream directions, reset isolation, cancellation, TLS identity passed");
        return 0;
    } catch (const std::exception& error) {
        std::println(std::cerr, "QUIC msquic: {}", error.what());
        return 1;
    }
}
