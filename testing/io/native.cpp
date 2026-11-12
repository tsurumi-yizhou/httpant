#ifndef _WIN32
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#endif

import std;
import httpant.io;

namespace {
    using namespace std::chrono_literals;
    void require(bool condition, std::string_view message) {
        if (!condition)
            throw std::runtime_error(std::string{message});
    }
    template <class T> class single {
        std::mutex mutex_;
        std::optional<T> item_;

    public:
        auto push(T value) -> bool {
            std::lock_guard lock{mutex_};
            if (item_)
                return false;
            item_.emplace(std::move(value));
            return true;
        }
        auto try_pop(T& value) -> bool {
            std::lock_guard lock{mutex_};
            if (!item_)
                return false;
            value = std::move(*item_);
            item_.reset();
            return true;
        }
    };
    void injected_queue() {
        native_io::engine<single> engine;
        struct post : native_io::request {
            native_io::engine<single>* owner;
            std::error_code failure;
            bool done = false;
            explicit post(native_io::engine<single>& engine) : owner(&engine) {
                complete = [](native_io::request& r, std::int64_t, std::error_code error) noexcept {
                    auto& self = static_cast<post&>(r);
                    self.failure = error;
                    self.done = true;
                    if (self.file == 123456)
                        self.owner->stop();
                };
            }
        } first{engine}, second{engine};
        first.file = 123456;
        engine.start(first);
        engine.start(second);
        require(second.done && second.failure == std::errc::no_buffer_space, "full submission queue");
        engine.cancel_file(first.file);
        engine.run();
        require(first.done && first.failure == std::errc::operation_canceled, "close sweep before submission");
    }
    auto address(std::uint16_t port = 0) -> native_io::socket_address {
        const unsigned char bytes[]{127, 0, 0, 1};
        return native_io::make_address(false, bytes, port);
    }
    auto listener() -> native_io::handle {
        auto h = native_io::open_socket(false, false);
        native_io::bind(h, address());
        native_io::listen(h, 1024);
        return h;
    }
    struct socket_owner {
        native_io::handle value = native_io::invalid_handle;
        native_io::engine<>* engine;
        void close() noexcept {
            if (value == native_io::invalid_handle)
                return;
            engine->cancel_file(value);
            native_io::close_socket(std::exchange(value, native_io::invalid_handle));
        }
        ~socket_owner() { close(); }
    };
    struct file_owner {
        native_io::handle value = native_io::invalid_handle;
        native_io::engine<>* engine;
        ~file_owner() {
            engine->cancel_file(value);
            native_io::close_file(value);
        }
    };
    struct result : native_io::request {
        native_io::engine<>* owner = nullptr;
        std::size_t* remaining = nullptr;
        std::int64_t value = -1;
        std::error_code failure;
        bool done = false;
        bool cancelled_at_completion = false;
        void* user = nullptr;
        result() {
            complete = [](native_io::request& request, std::int64_t value, std::error_code error) noexcept {
                auto& self = static_cast<result&>(request);
                self.value = value;
                self.failure = error;
                self.done = true;
                self.cancelled_at_completion = self.cancelled.load(std::memory_order_acquire);
                if (--*self.remaining == 0)
                    self.owner->stop();
            };
        }
    };
    void run(native_io::engine<>& engine, std::initializer_list<result*> operations) {
        std::size_t remaining = operations.size();
        for (auto* r : operations) {
            r->owner = &engine;
            r->remaining = &remaining;
            engine.start(*r);
        }
        std::atomic<bool> expired = false;
        std::condition_variable_any wake;
        std::jthread watchdog{[&](std::stop_token stop) {
            std::mutex mutex;
            std::unique_lock lock{mutex};
            wake.wait_for(lock, stop, 5s, [] { return false; });
            if (!stop.stop_requested()) {
                expired.store(true);
                for (auto* r : operations)
                    engine.cancel(*r);
            }
        }};
        engine.run();
        watchdog.request_stop();
        watchdog.join();
        require(!expired.load(), "native I/O timed out");
        require(remaining == 0, "native I/O stopped before completion");
    }
    void success(const result& r) {
        if (r.failure)
            throw std::system_error(r.failure, "native operation");
        require(r.done, "operation did not complete");
    }
    void transfer(native_io::engine<>& engine, native_io::handle sender, native_io::handle receiver, bool datagram) {
        std::array<char, 64> text{};
        std::ranges::fill(text, 'x');
        text[7] = 'y';
        std::array<char, 64> received{};
        result read, write;
        read.kind = native_io::operation::read;
        read.file = receiver;
        read.buffer = received.data();
        read.size = received.size();
        write.kind = native_io::operation::write;
        write.file = sender;
        write.buffer = text.data();
        write.size = text.size();
        run(engine, {&read, &write});
        success(read);
        success(write);
        require(write.value == 64 && read.value > 0 && read.value <= 64, "transfer byte counts");
        auto count = static_cast<std::size_t>(read.value);
        require(std::equal(received.begin(), received.begin() + count, text.begin()), "transfer contents");
        if (datagram)
            require(count == text.size(), "datagram was split");
        else if (count < text.size()) {
            result rest;
            rest.kind = native_io::operation::read;
            rest.file = receiver;
            rest.buffer = received.data() + count;
            rest.size = received.size() - count;
            run(engine, {&rest});
            success(rest);
            require(static_cast<std::size_t>(rest.value) + count == text.size() && received == text, "stream remainder");
        }
    }
    void cancel_read(native_io::engine<>&, native_io::handle);
    void tcp(native_io::engine<>& engine) {
        socket_owner listener{::listener(), &engine}, client{native_io::open_socket(false, false), &engine};
        result accept, connect;
        accept.kind = native_io::operation::accept;
        accept.file = listener.value;
        connect.kind = native_io::operation::connect;
        connect.file = client.value;
        connect.address = address(native_io::address_port(native_io::socket_endpoint(listener.value)));
        run(engine, {&accept, &connect});
        success(accept);
        success(connect);
        socket_owner peer{accept.value, &engine};
        transfer(engine, client.value, peer.value, false);
        transfer(engine, peer.value, client.value, false);
        for (int attempt = 0; attempt < 16; ++attempt)
            cancel_read(engine, peer.value);
        native_io::shutdown(client.value, 1);
        result eof;
        eof.kind = native_io::operation::read;
        eof.file = peer.value;
        char byte;
        eof.buffer = &byte;
        eof.size = 1;
        run(engine, {&eof});
        success(eof);
        require(eof.value == 0, "TCP EOF must be zero bytes");
    }
    void duplex_and_readiness(native_io::engine<>& engine) {
        socket_owner listener{::listener(), &engine}, client{native_io::open_socket(false, false), &engine};
        result accept, connect;
        accept.kind = native_io::operation::accept;
        accept.file = listener.value;
        connect.kind = native_io::operation::connect;
        connect.file = client.value;
        connect.address = address(native_io::address_port(native_io::socket_endpoint(listener.value)));
        run(engine, {&accept, &connect});
        success(accept);
        success(connect);
        socket_owner peer{accept.value, &engine};

        // Both directions on each descriptor must progress independently.
        std::vector<char> sent(262144, 'a'), received(262144), reply(262144, 'b'), echoed(262144);
        result read, write, peer_read, peer_write;
        read.kind = peer_read.kind = native_io::operation::read;
        write.kind = peer_write.kind = native_io::operation::write;
        read.file = write.file = client.value;
        peer_read.file = peer_write.file = peer.value;
        read.buffer = echoed.data();
        read.size = echoed.size();
        write.buffer = sent.data();
        write.size = sent.size();
        peer_read.buffer = received.data();
        peer_read.size = received.size();
        peer_write.buffer = reply.data();
        peer_write.size = reply.size();
        run(engine, {&read, &peer_read, &write, &peer_write});
        for (auto* r : {&read, &write, &peer_read, &peer_write})
            success(*r);
        require(read.value > 0 && peer_read.value > 0 && echoed[0] == 'b' && received[0] == 'a', "duplex readiness");

        socket_owner sender{native_io::open_socket(true, false), &engine}, receiver{native_io::open_socket(true, false), &engine};
        native_io::bind(receiver.value, address());
        char payload = 'z';
        result readable, send;
        readable.kind = native_io::operation::readable;
        readable.file = receiver.value;
        send.kind = native_io::operation::send_to;
        send.file = sender.value;
        send.address = address(native_io::address_port(native_io::socket_endpoint(receiver.value)));
        send.buffer = &payload;
        send.size = 1;
        run(engine, {&readable, &send});
        success(readable);
        success(send);
        result receive;
        char byte = 0;
        receive.kind = native_io::operation::receive_from;
        receive.file = receiver.value;
        receive.buffer = &byte;
        receive.size = 1;
        run(engine, {&receive});
        success(receive);
        require(receive.value == 1 && byte == payload, "readiness must not consume UDP input");
    }

    void failed_connect(native_io::engine<>& engine) {
        socket_owner reserved{native_io::open_socket(false, false), &engine};
        native_io::bind(reserved.value, address());
        socket_owner client{native_io::open_socket(false, false), &engine};
        result connect;
        connect.kind = native_io::operation::connect;
        connect.file = client.value;
        connect.address = address(native_io::address_port(native_io::socket_endpoint(reserved.value)));
        run(engine, {&connect});
        require(connect.done && bool(connect.failure), "refused connection must report an error");
    }
    void udp(native_io::engine<>& engine) {
        socket_owner first{native_io::open_socket(true, false), &engine}, second{native_io::open_socket(true, false), &engine};
        native_io::bind(first.value, address());
        native_io::bind(second.value, address());
        native_io::connect_datagram(first.value, address(native_io::address_port(native_io::socket_endpoint(second.value))));
        native_io::connect_datagram(second.value, address(native_io::address_port(native_io::socket_endpoint(first.value))));
        transfer(engine, first.value, second.value, true);
        transfer(engine, second.value, first.value, true);
    }
#ifndef _WIN32
    void reused_socket(native_io::engine<>& engine) {
        socket_owner listener{::listener(), &engine}, client{native_io::open_socket(false, false), &engine};
        result accept, connect;
        accept.kind = native_io::operation::accept;
        accept.file = listener.value;
        connect.kind = native_io::operation::connect;
        connect.file = client.value;
        connect.address = native_io::socket_endpoint(listener.value);
        run(engine, {&accept, &connect});
        success(accept);
        success(connect);
        socket_owner peer{accept.value, &engine};
        auto descriptor = client.value;
        std::jthread closer{[&] { client.close(); }};
        closer.join();
        socket_owner sender{native_io::open_socket(true, false), &engine};
        require(sender.value == descriptor, "UDP must reuse the closed TCP descriptor");
        socket_owner receiver{native_io::open_socket(true, false), &engine};
        native_io::bind(receiver.value, address());
        char payload = 'u', byte = 0;
        result send, receive;
        send.kind = native_io::operation::send_to;
        send.file = sender.value;
        send.address = native_io::socket_endpoint(receiver.value);
        send.buffer = &payload;
        send.size = 1;
        receive.kind = native_io::operation::receive_from;
        receive.file = receiver.value;
        receive.buffer = &byte;
        receive.size = 1;
        run(engine, {&send, &receive});
        success(send);
        success(receive);
        require(send.value == 1 && receive.value == 1 && byte == payload, "UDP after TCP descriptor reuse");
    }
#ifdef __linux__
    void unix_stream(native_io::engine<>& engine) {
        auto name = std::format("httpant-{}", ::getpid());
        sockaddr_un endpoint{};
        endpoint.sun_family = AF_UNIX;
        std::memcpy(endpoint.sun_path + 1, name.data(), name.size());
        native_io::socket_address address;
        auto size = offsetof(sockaddr_un, sun_path) + 1 + name.size();
        require(size <= address.bytes.size(), "Unix socket address length");
        std::memcpy(address.data(), &endpoint, size);
        address.length = size;
        auto open = [&] {
            auto socket = ::socket(AF_UNIX, SOCK_STREAM, 0);
            if (socket < 0)
                throw std::system_error(errno, std::generic_category());
            if (::fcntl(socket, F_SETFL, O_NONBLOCK) < 0) {
                auto error = errno;
                ::close(socket);
                throw std::system_error(error, std::generic_category());
            }
            return socket;
        };
        socket_owner listener{open(), &engine}, client{open(), &engine};
        native_io::bind(listener.value, address);
        native_io::listen(listener.value, 16);
        result accept, connect;
        accept.kind = native_io::operation::accept;
        accept.file = listener.value;
        connect.kind = native_io::operation::connect;
        connect.file = client.value;
        connect.address = address;
        run(engine, {&accept, &connect});
        success(accept);
        success(connect);
        socket_owner peer{accept.value, &engine};
        transfer(engine, client.value, peer.value, false);
        transfer(engine, peer.value, client.value, false);
    }
#endif
#endif
    void files(native_io::engine<>& engine, std::filesystem::path directory) {
        auto path = directory / "native-io-roundtrip.dat";
        auto utf8 = path.u8string();
        {
            file_owner file{native_io::open_file(reinterpret_cast<const char*>(utf8.c_str()), true), &engine};
            std::string contents = "positioned native I/O";
            result write;
            write.kind = native_io::operation::write_at;
            write.file = file.value;
            write.buffer = contents.data();
            write.size = contents.size();
            write.offset = 13;
            run(engine, {&write});
            success(write);
            require(write.value == static_cast<std::int64_t>(contents.size()), "file write count");
            std::string received(contents.size(), '\0');
            result read;
            read.kind = native_io::operation::read_at;
            read.file = file.value;
            read.buffer = received.data();
            read.size = received.size();
            read.offset = 13;
            run(engine, {&read});
            success(read);
            require(received == contents, "positioned file contents");
            result eof;
            eof.kind = native_io::operation::read_at;
            eof.file = file.value;
            eof.buffer = received.data();
            eof.size = received.size();
            eof.offset = 9999;
            run(engine, {&eof});
            success(eof);
            require(eof.value == 0, "file EOF must be zero bytes");
        }
        std::filesystem::remove(path);
    }
    void cancel_read(native_io::engine<>& engine, native_io::handle socket) {
        result read, timer;
        char buffer;
        read.kind = native_io::operation::read;
        read.file = socket;
        read.buffer = &buffer;
        read.size = 1;
        timer.kind = native_io::operation::timer;
        timer.deadline = std::chrono::steady_clock::now() + 1ms;
        timer.user = &read;
        timer.complete = [](native_io::request& request, std::int64_t value, std::error_code error) noexcept {
            auto& self = static_cast<result&>(request);
            self.owner->cancel(*static_cast<result*>(self.user));
            self.value = value;
            self.failure = error;
            self.done = true;
            if (--*self.remaining == 0)
                self.owner->stop();
        };
        run(engine, {&read, &timer});
        success(timer);
        require(read.done && read.cancelled_at_completion, "native kernel read cancellation must wait for completion");
    }
    void cancellation(native_io::engine<>& engine) {
        socket_owner listener{::listener(), &engine};
        for (int attempt = 0; attempt < 32; ++attempt) {
            result accept, timer;
            accept.kind = native_io::operation::accept;
            accept.file = listener.value;
            timer.kind = native_io::operation::timer;
            timer.deadline = std::chrono::steady_clock::now() + 1ms;
            struct trigger {
                result timer;
                result* target;
            } event;
            event.target = &accept;
            event.timer.user = &accept;
            event.timer.kind = native_io::operation::timer;
            event.timer.deadline = timer.deadline;
            event.timer.complete = [](native_io::request& request, std::int64_t value, std::error_code error) noexcept {
                auto& timer = static_cast<result&>(request);
                timer.owner->cancel(*static_cast<result*>(timer.user));
                timer.value = value;
                timer.failure = error;
                timer.done = true;
                if (--*timer.remaining == 0)
                    timer.owner->stop();
            };
            run(engine, {&accept, &event.timer});
            success(event.timer);
            require(accept.cancelled_at_completion && accept.done, "in-flight accept cancellation");
        }
        result before;
        before.kind = native_io::operation::accept;
        before.file = listener.value;
        engine.cancel(before);
        run(engine, {&before});
        require(before.done && before.cancelled_at_completion && before.value == -1, "pre-start cancellation must not fabricate an accepted handle");
    }
    void owner_completion(native_io::engine<>& engine) {
        std::size_t remaining = 1;
        result post;
        post.owner = &engine;
        post.remaining = &remaining;
        auto owner = std::this_thread::get_id();
        struct state {
            result post;
            std::thread::id completed;
        } item;
        item.post.owner = &engine;
        item.post.remaining = &remaining;
        item.post.user = &item.completed;
        item.post.complete = [](native_io::request& request, std::int64_t, std::error_code) noexcept {
            auto& post = static_cast<result&>(request);
            *static_cast<std::thread::id*>(post.user) = std::this_thread::get_id();
            post.done = true;
            post.owner->stop();
        };
        std::jthread producer{[&] { engine.start(item.post); }};
        producer.join();
        engine.run();
        require(item.post.done && item.completed == owner, "foreign posts must complete on the owner thread");
        engine.stop();
        engine.run();
        result again;
        run(engine, {&again});
        success(again);
    }
} // namespace
int main(int argc, char** argv) {
    try {
        require(argc == 2, "pass the existing build directory");
        injected_queue();
        native_io::engine<> engine;
        owner_completion(engine);
        std::cout << "PASS owner-thread posting and run/stop reuse\n";
#ifndef _WIN32
        reused_socket(engine);
        std::cout << "PASS TCP descriptor reuse by UDP\n";
#ifdef __linux__
        unix_stream(engine);
        std::cout << "PASS Unix stream connect/accept and bidirectional transfer\n";
#endif
#endif
        files(engine, argv[1]);
        std::cout << "PASS positioned file I/O and EOF\n";
        tcp(engine);
        std::cout << "PASS TCP bidirectional transfer, kernel read cancellation, and EOF\n";
        duplex_and_readiness(engine);
        failed_connect(engine);
        std::cout << "PASS duplex readiness, UDP peek, and refused connections\n";
        udp(engine);
        std::cout << "PASS connected UDP bidirectional transfer\n";
        cancellation(engine);
        std::cout << "PASS active and pre-start cancellation\n";
        std::cout << "Implementation: " << native_io::engine<>::name() << '\n';
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
