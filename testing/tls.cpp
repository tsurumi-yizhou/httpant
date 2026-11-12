import std;
import httpant;
import httpant.tls;
import httpant.dependencies.wolfssl;
import httpant.dependencies.boost.ut;
import httpant.testing;

namespace httpant::testing {
    using namespace boost::ut;
    using http::operator co_await;

    namespace {
        struct transport {
            async_mock_stream stream;
            int* write_error;
            auto async_read(std::span<std::byte> bytes, std::stop_token stop) { return stream.async_read(bytes, stop); }
            auto async_write(std::span<const std::byte> bytes, std::stop_token stop) -> http::task<std::size_t> {
                if (*write_error == 1)
                    throw http::stopped{};
                if (*write_error == 2)
                    throw std::system_error(std::make_error_code(std::errc::broken_pipe));
                co_return co_await stream.async_write(bytes, stop);
            }
        };
        static_assert(http::byte_stream<http::tls::stream<transport>>);

        struct pair {
            async_pipe incoming, outgoing;
            int client_error = 0, server_error = 0;
            static auto client_roots() -> http::tls::context {
                http::tls::context context{false};
                context.trust("quic-cert.pem");
                return context;
            }
            static auto server_identity() -> http::tls::context {
                http::tls::context context{true};
                context.certificate("quic-cert.pem", "quic-key.pem");
                return context;
            }
            http::tls::context client_context = client_roots(), server_context = server_identity();
            http::tls::stream<transport> client{{{incoming, outgoing}, &client_error}, client_context};
            http::tls::stream<transport> server{{{outgoing, incoming}, &server_error}, server_context};

            pair() { client.hostname("localhost"); }
            void handshake() {
                auto accepted = server.handshake(true);
                auto connected = client.handshake();
                accepted.start();
                connected.start();
                expect(accepted.done() && connected.done() >> fatal);
                accepted.result();
                connected.result();
            }
        };

        struct gate {
            std::coroutine_handle<> handle;
            bool await_ready() const noexcept { return false; }
            void await_suspend(std::coroutine_handle<> next) { handle = next; }
            void await_resume() const noexcept {}
        };

        void stack_position(std::uintptr_t& low, std::uintptr_t& high) {
            int value;
            auto at = reinterpret_cast<std::uintptr_t>(&value);
            low = std::min(low, at);
            high = std::max(high, at);
        }
    } // namespace

    static suite<"tls"> tls_suite = [] {
        "decrypted bytes survive a pending output cancellation"_test = [] {
            pair peers;
            peers.handshake();
            std::string payload = "response";
            run_sync(peers.server.async_write(std::as_bytes(std::span{payload})));
            std::array<std::byte, 32> bytes;
            expect(run_sync(peers.client.async_read(std::span{bytes}.first(1))) == 1_u);
            expect(wolfSSL_write(peers.client.native_handle(), "pending", 7) == 7_i);
            peers.client_error = 1;
            auto count = run_sync(peers.client.async_read(bytes));
            expect(std::string_view{reinterpret_cast<char*>(bytes.data()), count} == std::string_view{payload}.substr(1));
            peers.client_error = 0;
            run_sync(peers.client.close());
            run_sync(peers.server.close());
        };
        "only close_notify ends a TLS stream"_test = [] {
            pair peers;
            peers.handshake();
            run_sync(peers.server.close());
            std::array<std::byte, 32> bytes;
            expect(run_sync(peers.client.async_read(bytes)) == 0_u);
            run_sync(peers.client.close());

            pair interrupted;
            interrupted.handshake();
            interrupted.incoming.close();
            expect(throws<std::runtime_error>([&] { run_sync(interrupted.client.async_read(bytes)); }));
        };
        "close ignores a closed transport but propagates cancellation"_test = [] {
            pair peers;
            peers.handshake();
            peers.client_error = 2;
            expect(nothrow([&] { run_sync(peers.client.close()); }));
            peers.server_error = 1;
            expect(throws<http::stopped>([&] { run_sync(peers.server.close()); }));
        };
        "hostname failures have a distinct type"_test = [] {
            pair peers;
            peers.client.hostname("wrong.localhost");
            std::stop_source stop;
            auto accepted = peers.server.handshake(true);
            auto connected = peers.client.handshake();
            accepted.start(stop.get_token());
            connected.start();
            expect(connected.done() >> fatal);
            expect(throws<http::tls::verification_failure>([&] { connected.result(); }));
            stop.request_stop();
            expect(accepted.done());
        };
        "TLS output is bounded"_test = [] {
            http::tls::detail::buffers buffers;
            std::string bytes(128u << 10, 'x');
            expect(http::tls::detail::buffers::write(nullptr, bytes.data(), bytes.size(), &buffers) == static_cast<int>(bytes.size()));
            expect(http::tls::detail::buffers::write(nullptr, bytes.data(), 1, &buffers) == WOLFSSL_CBIO_ERR_WANT_WRITE);
            expect(buffers.output.size() == bytes.size());
        };
        "contended TLS locks dispatch on a bounded stack"_test = [] {
            http::tls::detail::mutex mutex;
            gate pending;
            auto hold = [&]() -> http::task<> { co_await pending; };
            auto first = mutex.run(hold(), {});
            first.start();
            std::uintptr_t low = std::numeric_limits<std::uintptr_t>::max(), high = 0;
            auto work = [&]() -> http::task<> {
                stack_position(low, high);
                co_return;
            };
            std::vector<http::task<>> waiting;
            for (int i = 0; i < 2048; ++i) {
                waiting.push_back(mutex.run(work(), {}));
                waiting.back().start();
            }
            pending.handle.resume();
            expect(first.done());
            for (auto& task : waiting) {
                expect(task.done() >> fatal);
                task.result();
            }
            expect(high - low < 65536u);
        };
        "a canceled TLS lock waiter does not block its successor"_test = [] {
            http::tls::detail::mutex mutex;
            gate pending;
            auto hold = [&]() -> http::task<> { co_await pending; };
            auto first = mutex.run(hold(), {});
            first.start();
            std::stop_source stop;
            auto value = []() -> http::task<int> { co_return 7; };
            auto canceled = mutex.run(value(), stop.get_token());
            canceled.start();
            auto next = mutex.run(value(), {});
            next.start();
            stop.request_stop();
            expect(canceled.done() >> fatal);
            expect(throws<http::stopped>([&] { canceled.result(); }));
            pending.handle.resume();
            expect(next.done() >> fatal);
            expect(next.result() == 7_i);
        };
    };
} // namespace httpant::testing
