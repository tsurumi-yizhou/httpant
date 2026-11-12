import httpant.dependencies.boost.ut;
import std;
import httpant.testing;
import httpant;

namespace httpant::testing {

    using namespace boost::ut;
    using namespace std::literals;

    namespace {

        // RFC 9000 §16 — "The two most significant bits of the first byte encode the
        // length of the integer in bytes: 0b00 → 1, 0b01 → 2, 0b10 → 4, 0b11 → 8."
        // Tests define the wire format locally instead of depending on nghttp3.
        inline auto decode_h3_varint(std::span<const std::byte> data, std::uint64_t& value) -> std::size_t {
            auto length = std::size_t{1} << (std::to_integer<unsigned>(data.front()) >> 6);
            value = std::to_integer<unsigned>(data.front()) & 0x3f;
            for (std::size_t index = 1; index < length; ++index)
                value = (value << 8) | std::to_integer<unsigned>(data[index]);
            return length;
        }

        // RFC 9114 §7.1 — "A frame includes the following fields: Type: A
        // variable-length integer that identifies the frame type. Length: A
        // variable-length integer that describes the length in bytes of the Frame
        // Payload." Returns the frame types of a complete frame sequence.
        [[nodiscard]] inline auto h3_frame_types(std::span<const std::byte> data) -> std::vector<std::uint64_t> {
            std::vector<std::uint64_t> types;
            while (!data.empty()) {
                std::uint64_t type = 0;
                std::uint64_t length = 0;
                data = data.subspan(decode_h3_varint(data, type));
                data = data.subspan(decode_h3_varint(data, length));
                types.push_back(type);
                data = data.subspan(length);
            }
            return types;
        }

        // A connected client/server pair over recording transports with the control
        // and QPACK stream handshake already routed in both directions.
        struct h3_pair {
            recording_stream_factory client_transport{true};
            recording_stream_factory server_transport{false};
            http::v3::client<recording_stream_factory> client{client_transport};
            http::v3::server<recording_stream_factory> server{server_transport};

            h3_pair() {
                run_sync(http::coroutine::start(client));
                route_writes_to(client_transport, server_transport);
                run_sync(http::coroutine::start(server));
                route_writes_to(server_transport, client_transport);
            }
        };

        // A body_stream that yields its chunk on the first read and then suspends
        // forever on the second, so a response built on it never reaches FIN.
        struct one_chunk_then_hang_body {
            std::vector<std::byte> chunk{};
            bool consumed{false};

            explicit one_chunk_then_hang_body(std::string_view text) {
                for (char c : text)
                    chunk.push_back(static_cast<std::byte>(c));
            }

            struct read_awaiter {
                one_chunk_then_hang_body& self;
                std::span<std::byte> buf;

                [[nodiscard]] bool await_ready() const noexcept { return !self.consumed; }
                void await_suspend(std::coroutine_handle<>) noexcept {}
                auto await_resume() noexcept -> std::size_t {
                    self.consumed = true;
                    auto n = std::min(buf.size(), self.chunk.size());
                    std::copy_n(self.chunk.data(), n, buf.data());
                    return n;
                }
            };

            auto async_read(std::span<std::byte> buf, std::stop_token) -> read_awaiter { return {*this, buf}; }
        };

        // A GET exchange whose 200 response delivers one body chunk ("hello") and
        // then never finishes: the server's respond task stays parked on the body's
        // second read, so the client's next body read stays parked until cancelled.
        struct hanging_exchange {
            recording_stream_factory client_transport{true};
            recording_stream_factory server_transport{false};
            http::v3::client<recording_stream_factory> client{client_transport};
            http::v3::server<recording_stream_factory> server{server_transport};
            one_chunk_then_hang_body body{"hello"};
            http::task<void> respond{};
            http::received<http::response, http::v3::body_reader<recording_stream_factory>> received{};

            hanging_exchange() {
                run_sync(http::coroutine::start(client));
                route_writes_to(client_transport, server_transport);
                run_sync(http::coroutine::start(server));
                route_writes_to(server_transport, client_transport);

                auto receive = http::coroutine::receive(server);
                receive.start();
                http::buffer_body empty;
                auto client_request = http::coroutine::request(client, basic_get(), empty);
                client_request.start();
                route_writes_to(client_transport, server_transport);
                auto incoming = run_sync(std::move(receive));
                static_cast<void>(run_sync(drain_body(incoming.body)));

                respond = http::coroutine::respond(server, std::move(incoming.token), http::response{.status = 200, .reason = {}, .fields = {}}, body);
                respond.start();
                route_writes_to(server_transport, client_transport);
                received = run_sync(std::move(client_request));
            }
        };

        [[nodiscard]] inline auto bytes_of(std::string_view text) -> std::vector<std::byte> {
            std::vector<std::byte> out;
            out.reserve(text.size());
            for (char c : text)
                out.push_back(static_cast<std::byte>(c));
            return out;
        }

        // A body_stream that yields one scripted chunk per read and then EOF, so an
        // upload spans several outbound batches (multi-chunk pump cycles).
        struct chunked_body {
            std::deque<std::vector<std::byte>> chunks{};

            struct read_awaiter {
                chunked_body& self;
                std::span<std::byte> buf;

                [[nodiscard]] bool await_ready() const noexcept { return true; }
                void await_suspend(std::coroutine_handle<>) noexcept {}
                auto await_resume() noexcept -> std::size_t {
                    if (self.chunks.empty())
                        return 0;
                    auto& front = self.chunks.front();
                    auto n = std::min(buf.size(), front.size());
                    std::copy_n(front.data(), n, buf.data());
                    self.chunks.pop_front();
                    return n;
                }
            };

            auto async_read(std::span<std::byte> buf, std::stop_token) -> read_awaiter { return {*this, buf}; }
        };

        // Internal-machinery test double: a recording stream factory whose stream
        // writes and acknowledgements complete only when the test opens the matching
        // gate, modeled on recording_stream_factory (test_support.ixx) but
        // self-contained here. The synchronous recording factory can never park
        // inside flush_output, so two internal paths stay unexercised without these
        // gates: the flush_gate waiter queue (a second flush() while the first is
        // suspended in async_write) and the transport ACK wait of a body batch.
        struct gated_stream_factory {
            struct stream;
            // stream_factory contract: the handle type created/accepted by this
            // connection factory.
            using stream_type = stream;
            static constexpr auto completion_order = http::stream_completion_order::serialized;

            struct inbound_queue {
                std::deque<std::vector<std::byte>> chunks{};
                bool fin{false};
                // Set when the peer resets/abandons the stream (QUIC RESET_STREAM);
                // the next read after the buffered chunks throws http::stream_reset.
                std::optional<http::application_error> reset{};
                std::coroutine_handle<> waiter{};
                const void* waiter_owner{};

                void push(std::vector<std::byte> chunk, bool f) {
                    if (!chunk.empty())
                        chunks.push_back(std::move(chunk));
                    fin = fin || f;
                    if (waiter) {
                        auto handle = std::exchange(waiter, {});
                        waiter_owner = nullptr;
                        handle.resume();
                    }
                }

                void fail(http::application_error error) {
                    reset = error;
                    if (waiter) {
                        auto handle = std::exchange(waiter, {});
                        waiter_owner = nullptr;
                        handle.resume();
                    }
                }
            };

            struct read_awaiter {
                inbound_queue& queue;
                std::span<std::byte> buf;
                std::stop_token stop{};
                parked_stop on_stop{};

                read_awaiter(inbound_queue& value, std::span<std::byte> buffer, std::stop_token token) : queue(value), buf(buffer), stop(std::move(token)) {}
                read_awaiter(const read_awaiter&) = delete;
                auto operator=(const read_awaiter&) -> read_awaiter& = delete;
                read_awaiter(read_awaiter&& other) noexcept : queue(other.queue), buf(other.buf), stop(std::move(other.stop)) {
                    if (queue.waiter_owner == &other)
                        queue.waiter_owner = this;
                }
                auto operator=(read_awaiter&&) -> read_awaiter& = delete;

                ~read_awaiter() {
                    if (queue.waiter_owner == this) {
                        queue.waiter = {};
                        queue.waiter_owner = nullptr;
                    }
                }

                // The endpoint driver's unbounded read loop must suspend when no
                // data or terminal event exists; it never fabricates a ready EOF.
                [[nodiscard]] bool await_ready() const noexcept { return !queue.chunks.empty() || queue.fin || queue.reset.has_value(); }
                auto await_suspend(std::coroutine_handle<> handle) -> bool {
                    queue.waiter = handle;
                    queue.waiter_owner = this;
                    return on_stop.arm(stop, queue.waiter);
                }
                auto await_resume() -> std::size_t {
                    if (queue.waiter_owner == this)
                        queue.waiter_owner = nullptr;
                    on_stop.finish();
                    if (!queue.chunks.empty()) {
                        auto& front = queue.chunks.front();
                        auto n = std::min(buf.size(), front.size());
                        std::copy_n(front.data(), n, buf.data());
                        if (n == front.size())
                            queue.chunks.pop_front();
                        else
                            front.erase(front.begin(), front.begin() + static_cast<std::ptrdiff_t>(n));
                        return n;
                    }
                    if (queue.reset)
                        throw http::stream_reset{*queue.reset};
                    return 0;
                }
            };

            struct release_awaiter {
                bool await_ready() const noexcept { return true; }
                void await_suspend(std::coroutine_handle<>) const noexcept {}
                void await_resume() const noexcept {}
            };

            // Like a QUIC transport's, a parked acknowledgement completes stopped once
            // the write's stop token is requested.
            struct ack_awaiter {
                gated_stream_factory& transport;
                std::size_t count{0};
                std::stop_token stop{};
                std::coroutine_handle<> parked{};
                parked_stop on_stop{};

                ack_awaiter(gated_stream_factory& value, std::size_t bytes, std::stop_token token) : transport(value), count(bytes), stop(std::move(token)) {}
                ack_awaiter(const ack_awaiter&) = delete;
                auto operator=(const ack_awaiter&) -> ack_awaiter& = delete;
                ack_awaiter(ack_awaiter&& other) noexcept : transport(other.transport), count(other.count), stop(std::move(other.stop)) {}
                auto operator=(ack_awaiter&&) -> ack_awaiter& = delete;

                [[nodiscard]] bool await_ready() const noexcept { return transport.ack_gate_open; }
                auto await_suspend(std::coroutine_handle<> handle) -> bool {
                    parked = handle;
                    transport.pending_acks.push_back(this);
                    if (on_stop.arm(stop, parked))
                        return true;
                    std::erase(transport.pending_acks, this);
                    return false;
                }
                auto await_resume() -> std::size_t {
                    std::erase(transport.pending_acks, this);
                    on_stop.finish();
                    return count;
                }
            };

            struct write_awaiter {
                gated_stream_factory& transport;
                std::int64_t stream_id;
                std::span<const std::byte> data;
                bool fin{false};
                std::stop_token stop{};
                std::coroutine_handle<> parked{};

                [[nodiscard]] bool await_ready() const noexcept { return transport.write_gate_open; }
                void await_suspend(std::coroutine_handle<> handle) {
                    parked = handle;
                    transport.pending_writes.push_back(this);
                }
                auto await_resume() -> http::stream_write_result<release_awaiter, ack_awaiter> {
                    transport.writes.push_back(recorded_write{
                        .stream_id = stream_id,
                        .fin = fin,
                        .data = {data.begin(), data.end()},
                    });
                    return {
                        .accepted = data.size(),
                        .buffer_release = {},
                        .acknowledgement = {transport, data.size(), stop},
                    };
                }
            };

            struct stream {
                gated_stream_factory* transport{nullptr};
                std::int64_t stream_id{-1};
                http::stream_access access_{http::stream_access::bidirectional};

                stream() = default;
                stream(gated_stream_factory* value, std::int64_t id, http::stream_access access) : transport(value), stream_id(id), access_(access) {}
                stream(const stream&) = delete;
                auto operator=(const stream&) -> stream& = delete;
                stream(stream&&) noexcept = default;
                auto operator=(stream&&) noexcept -> stream& = default;

                auto identifier() const -> http::stream_identifier { return {static_cast<std::uint64_t>(stream_id)}; }
                auto access() const -> http::stream_access { return access_; }
                auto async_read(std::span<std::byte> buf, std::stop_token stop) -> read_awaiter {
                    return {transport->inbound(stream_id), buf, std::move(stop)};
                }
                auto async_write(std::span<const std::byte> data, bool fin, std::stop_token stop) -> write_awaiter {
                    return {*transport, stream_id, data, fin, std::move(stop)};
                }
                void consume(std::size_t) {}
                void shutdown(http::stream_side side, http::application_error error) { transport->shutdowns.push_back({stream_id, side, error}); }
            };

            struct open_awaiter {
                gated_stream_factory& transport;
                std::int64_t id{-1};
                http::stream_access access_{http::stream_access::bidirectional};

                [[nodiscard]] bool await_ready() const noexcept { return true; }
                void await_suspend(std::coroutine_handle<>) const noexcept {}
                auto await_resume() noexcept -> stream { return {&transport, id, access_}; }
            };

            struct accept_awaiter {
                gated_stream_factory& transport;
                std::stop_token stop{};
                parked_stop on_stop{};

                accept_awaiter(gated_stream_factory& value, std::stop_token token) : transport(value), stop(std::move(token)) {}
                accept_awaiter(const accept_awaiter&) = delete;
                auto operator=(const accept_awaiter&) -> accept_awaiter& = delete;
                accept_awaiter(accept_awaiter&& other) noexcept : transport(other.transport), stop(std::move(other.stop)) {
                    if (transport.accept_waiter_owner == &other)
                        transport.accept_waiter_owner = this;
                }
                auto operator=(accept_awaiter&&) -> accept_awaiter& = delete;

                ~accept_awaiter() {
                    if (transport.accept_waiter_owner == this) {
                        transport.accept_waiter = {};
                        transport.accept_waiter_owner = nullptr;
                    }
                }

                [[nodiscard]] auto await_ready() const noexcept -> bool { return !transport.accept_queue.empty(); }
                auto await_suspend(std::coroutine_handle<> handle) -> bool {
                    transport.accept_waiter = handle;
                    transport.accept_waiter_owner = this;
                    return on_stop.arm(stop, transport.accept_waiter);
                }
                auto await_resume() -> stream {
                    if (transport.accept_waiter_owner == this)
                        transport.accept_waiter_owner = nullptr;
                    on_stop.finish();
                    auto id = transport.accept_queue.front();
                    auto access = transport.accept_access_queue.front();
                    transport.accept_queue.pop_front();
                    transport.accept_access_queue.pop_front();
                    return {&transport, id, access};
                }
            };

            struct close_awaiter {
                bool await_ready() const noexcept { return true; }
                void await_suspend(std::coroutine_handle<>) const noexcept {}
                void await_resume() const noexcept {}
            };

            std::deque<recorded_write> writes{};
            std::vector<recorded_shutdown> shutdowns{};
            std::vector<http::application_error> closes{};
            std::unordered_map<std::int64_t, inbound_queue> inbound_{};
            std::deque<std::int64_t> accept_queue{};
            std::deque<http::stream_access> accept_access_queue{};
            std::coroutine_handle<> accept_waiter{};
            const void* accept_waiter_owner{};
            std::int64_t next_bidi{0};
            std::int64_t next_uni{0};
            bool client_role{false};
            // Stream ids this factory opened locally; peer ids are announced to the
            // accept loop, local ids are read by the owning operation only.
            std::unordered_set<std::int64_t> local_ids{};
            std::unordered_set<std::int64_t> announced_ids{};

            // The two gates: while closed, stream writes / acknowledgements park
            // instead of completing, and the parked awaiters queue here until the
            // test releases them.
            bool write_gate_open{true};
            bool ack_gate_open{true};
            std::deque<write_awaiter*> pending_writes{};
            std::deque<ack_awaiter*> pending_acks{};

            explicit gated_stream_factory(bool is_client = false) : client_role(is_client) {
                // RFC 9000 §2.1 — client-initiated streams start at 0, server at 1.
                next_bidi = client_role ? 0 : 1;
                next_uni = client_role ? 2 : 3;
            }

            auto inbound(std::int64_t id) -> inbound_queue& { return inbound_[id]; }

            // RFC 9000 §2.1 — see mock_stream_factory (test_support.ixx) for the id
            // scheme: per-role spaces so both sides of a test can coexist.
            auto async_open_bidirectional(std::stop_token) -> open_awaiter {
                auto id = next_bidi;
                next_bidi += 4;
                local_ids.insert(id);
                return {*this, id, http::stream_access::bidirectional};
            }
            auto async_open_unidirectional(std::stop_token) -> open_awaiter {
                auto id = next_uni;
                next_uni += 4;
                local_ids.insert(id);
                return {*this, id, http::stream_access::send_only};
            }
            auto async_accept(std::stop_token stop) -> accept_awaiter { return {*this, std::move(stop)}; }
            auto async_close(http::application_error error) -> close_awaiter {
                closes.push_back(error);
                return {};
            }

            // Announce a peer-initiated stream to the accept loop and deliver its bytes.
            void announce(std::int64_t id, http::stream_access access) {
                accept_queue.push_back(id);
                accept_access_queue.push_back(access);
                if (accept_waiter) {
                    auto handle = std::exchange(accept_waiter, {});
                    accept_waiter_owner = nullptr;
                    handle.resume();
                }
            }

            void feed(std::int64_t id, std::span<const std::byte> data, bool fin) { inbound(id).push({data.begin(), data.end()}, fin); }

            // Delivers a peer stream reset (QUIC RESET_STREAM with an H3 application
            // error code, RFC 9114 §8) on the stream's inbound queue.
            void feed_reset(std::int64_t id, std::uint64_t error_code) { inbound(id).fail(http::application_error{error_code}); }

            // Opens the write gate and completes every parked write in arrival order.
            void open_write_gate() {
                write_gate_open = true;
                while (!pending_writes.empty()) {
                    auto* awaiter = pending_writes.front();
                    pending_writes.pop_front();
                    awaiter->parked.resume();
                }
            }

            // Completes the oldest parked acknowledgement, overriding the acknowledged
            // byte count when given (the default acknowledges everything accepted).
            auto release_next_ack(std::optional<std::size_t> count = std::nullopt) -> bool {
                if (pending_acks.empty())
                    return false;
                auto* awaiter = pending_acks.front();
                pending_acks.pop_front();
                if (count)
                    awaiter->count = *count;
                std::exchange(awaiter->parked, {}).resume();
                return true;
            }
        };

        // Same routing behavior as route_writes_to (test_support.ixx), for the gated
        // factory: locally opened streams are announced to the peer's accept loop and
        // every recorded write is fed to the peer's inbound queue.
        inline void route_gated_writes_to(gated_stream_factory& from, gated_stream_factory& to) {
            std::deque<recorded_write> drained;
            std::swap(drained, from.writes);
            std::vector<recorded_write> ordered{std::make_move_iterator(drained.begin()), std::make_move_iterator(drained.end())};
            std::stable_sort(ordered.begin(), ordered.end(),
                             [](const auto& left, const auto& right) { return (left.stream_id & 0x2) < (right.stream_id & 0x2); });
            for (auto& write : ordered) {
                if (from.local_ids.contains(write.stream_id) && to.announced_ids.insert(write.stream_id).second) {
                    auto access = (write.stream_id & 0x2) != 0 ? http::stream_access::receive_only : http::stream_access::bidirectional;
                    to.announce(write.stream_id, access);
                }
                to.feed(write.stream_id, std::span<const std::byte>{write.data.data(), write.data.size()}, write.fin);
            }
        }

        // A connected client/server pair over gated transports with the control and
        // QPACK stream handshake already routed in both directions.
        struct h3_gated_pair {
            gated_stream_factory client_transport{true};
            gated_stream_factory server_transport{false};
            http::v3::client<gated_stream_factory> client{client_transport};
            http::v3::server<gated_stream_factory> server{server_transport};

            h3_gated_pair() {
                run_sync(http::coroutine::start(client));
                route_gated_writes_to(client_transport, server_transport);
                run_sync(http::coroutine::start(server));
                route_gated_writes_to(server_transport, client_transport);
            }
        };

        [[nodiscard]] inline auto count_payload_occurrences(const std::deque<recorded_write>& writes, std::string_view payload) -> std::size_t {
            auto needle = bytes_of(payload);
            std::size_t count = 0;
            for (auto& write : writes) {
                auto haystack = std::span<const std::byte>{write.data};
                while (true) {
                    auto it = std::search(haystack.begin(), haystack.end(), needle.begin(), needle.end());
                    if (it == haystack.end())
                        break;
                    ++count;
                    haystack = haystack.subspan(static_cast<std::size_t>(it - haystack.begin()) + 1);
                }
            }
            return count;
        }

    } // namespace

    static suite<"h3 cancellation and respond validation"> h3_cancellation_suite = [] {
        // Internal machinery test: cancellation of a suspended HTTP/3 body read
        // is not HTTP RFC behavior.
        "http3_body_read_cancelled_mid_wait_resumes_once"_test = [] {
            hanging_exchange exchange;
            expect(exchange.received.head.status == 200_u);

            std::array<std::byte, 64> buffer{};
            expect(run_sync(exchange.received.body.async_read(buffer, {})) == 5_u);

            std::stop_source stop;
            auto completions = 0;
            auto cancelled = false;
            auto make_read = [&]() -> http::task<void> {
                try {
                    static_cast<void>(co_await exchange.received.body.async_read(buffer, stop.get_token()));
                } catch (const http::stopped&) {
                    cancelled = true;
                }
                ++completions;
            };
            auto read = make_read();
            read.start();
            // No data, no FIN, no abort: the read parked on the stream.
            expect(completions == 0_i);

            expect(stop.request_stop());
            expect(completions == 1_i);
            expect(cancelled);
        };

        // Internal machinery test: an already-cancelled stop token fails the body
        // read before it ever suspends — not HTTP RFC behavior.
        "http3_body_read_pre_cancelled_throws_without_suspending"_test = [] {
            hanging_exchange exchange;

            std::array<std::byte, 64> buffer{};
            expect(run_sync(exchange.received.body.async_read(buffer, {})) == 5_u);

            std::stop_source stop;
            static_cast<void>(stop.request_stop());
            auto completions = 0;
            auto cancelled = false;
            auto make_read = [&]() -> http::task<void> {
                try {
                    static_cast<void>(co_await exchange.received.body.async_read(buffer, stop.get_token()));
                } catch (const http::stopped&) {
                    cancelled = true;
                }
                ++completions;
            };
            auto read = make_read();
            read.start();
            // The pre-suspend fast path threw synchronously instead of parking.
            expect(completions == 1_i);
            expect(cancelled);
        };

        // RFC 9110 §15.3.5 — "A 204 response is terminated by the end of the
        // header section; it cannot contain content or trailers." RFC 9114 §4.1 —
        // message content is sent as DATA frames (§7.2.1 — "DATA frames
        // (type=0x00)"), so a 204 response ends at the header section even for a
        // GET request: the attached body is dropped and no DATA frame is emitted.
        "http3_server_204_response_has_no_data"_test = [] {
            h3_pair pair;

            auto receive = http::coroutine::receive(pair.server);
            receive.start();
            http::buffer_body empty;
            auto client_request = http::coroutine::request(pair.client, basic_get(), empty);
            client_request.start();
            route_writes_to(pair.client_transport, pair.server_transport);
            auto incoming = run_sync(std::move(receive));
            static_cast<void>(run_sync(drain_body(incoming.body)));

            auto body = make_body("must not be sent");
            run_sync(http::coroutine::respond(pair.server, std::move(incoming.token), http::response{.status = 204, .reason = {}, .fields = {}}, body));
            auto response_writes = pair.server_transport.take_writes();

            // No DATA frame (type 0x00) on the request stream (id 0), a HEADERS
            // frame (type 0x01, RFC 9114 §7.2.2) for the response head, and the
            // stream still terminated (fin on the final write).
            auto fin_seen = false;
            auto headers_seen = false;
            for (auto& write : response_writes) {
                if (write.stream_id != 0)
                    continue;
                fin_seen = fin_seen || write.fin;
                for (auto type : h3_frame_types(write.data)) {
                    expect(type != 0_u);
                    headers_seen = headers_seen || type == 1;
                }
            }
            expect(fin_seen);
            expect(headers_seen);

            for (auto& write : response_writes)
                pair.client_transport.feed(write.stream_id, std::span<const std::byte>{write.data.data(), write.data.size()}, write.fin);
            auto received = run_sync(std::move(client_request));
            expect(received.head.status == 204_u);
            expect(read_body_text(received.body).empty());
        };
    };

    static suite<"h3 driver internals"> h3_internals_suite = [] {
        "http3_completed_stream_handles_are_released"_test = [] {
            h3_pair pair;
            for (int index = 0; index < 4; ++index) {
                auto receive = http::coroutine::receive(pair.server);
                receive.start();
                http::buffer_body empty;
                auto request = http::coroutine::request(pair.client, basic_get(), empty);
                request.start();
                route_writes_to(pair.client_transport, pair.server_transport);
                auto incoming = run_sync(std::move(receive));
                static_cast<void>(run_sync(drain_body(incoming.body)));
                auto body = make_body("done");
                run_sync(http::coroutine::respond(pair.server, std::move(incoming.token), http::response{.status = 200}, body));
                route_writes_to(pair.server_transport, pair.client_transport);
                auto received = run_sync(std::move(request));
                expect(read_body_text(received.body) == "done");
            }
            // Subsequent requests also reap the completed reader coroutine frames.
            expect(pair.client_transport.stream_lifetimes.at(0).expired());
            expect(pair.server_transport.stream_lifetimes.at(0).expired());
            expect(!pair.client_transport.stream_lifetimes.at(2).expired());
            expect(!pair.server_transport.stream_lifetimes.at(3).expired());
            run_sync(http::coroutine::close(pair.client));
            run_sync(http::coroutine::close(pair.server));
        };

        // RFC 9114 §5.2 — "Upon receipt of a GOAWAY frame, if the client has
        // already sent requests with a stream ID greater than or equal to the
        // identifier contained in the GOAWAY frame, those requests will not be
        // processed. Clients can safely retry unprocessed requests on a different
        // HTTP connection." A request parked on its response headers must fail
        // fast with the retryable rejection once a GOAWAY covering its stream
        // arrives — not hang until the connection fails.
        "http3_goaway_rejects_pending_request"_test = [] {
            h3_pair pair;

            http::buffer_body empty;
            auto client_request = http::coroutine::request(pair.client, basic_get("/pending"), empty);
            client_request.start();
            expect(!client_request.done());

            // RFC 9114 §7.2.6 — "GOAWAY Frame { Type (i) = 0x07, Length (i),
            // Stream ID (i) }"; stream id 0 means no request was processed, so it
            // covers the pending request on stream 0. The server's control stream
            // is stream 3 on the client side.
            const std::array goaway{std::byte{0x07}, std::byte{0x01}, std::byte{0x00}};
            pair.client_transport.feed(3, goaway, false);

            expect(client_request.done());
            auto threw = false;
            try {
                static_cast<void>(run_sync(std::move(client_request)));
            } catch (const http::protocol_error& failure) {
                expect(failure.info().condition == http::error_condition::goaway_rejected);
                expect(http::retryable(failure.info()));
                threw = true;
            }
            expect(threw);
        };

        // Internal machinery test: a respond parked on its FIN acknowledgement
        // completes when the connection fails. RFC 9114 §7.2.4 — "If an endpoint
        // receives a second SETTINGS frame on the control stream, the endpoint
        // MUST respond with a connection error of type H3_FRAME_UNEXPECTED."
        // Not HTTP RFC behavior otherwise.
        "http3_connection_failure_completes_fin_parked_respond"_test = [] {
            h3_gated_pair pair;
            http::buffer_body empty;
            auto request = http::coroutine::request(pair.client, basic_get("/fail"), empty);
            request.start();
            route_gated_writes_to(pair.client_transport, pair.server_transport);
            auto receive = http::coroutine::receive(pair.server);
            receive.start();
            auto incoming = run_sync(std::move(receive));

            pair.server_transport.ack_gate_open = false;
            chunked_body body{{bytes_of("response-chunk")}};
            auto respond = http::coroutine::respond(pair.server, std::move(incoming.token), http::response{.status = 200, .reason = {}, .fields = {}}, body);
            respond.start();
            expect(!respond.done());

            // A duplicate SETTINGS frame (type 0x04, empty payload) on the
            // client's control stream (id 2).
            const std::array duplicate_settings{std::byte{0x04}, std::byte{0x00}};
            pair.server_transport.feed(2, duplicate_settings, false);

            expect(respond.done());
            if (respond.done())
                run_sync(std::move(respond));
        };

        // Internal machinery test: a respond parked on its FIN acknowledgement
        // completes when the peer resets the still-open request stream: the read
        // driver closes the stream, which ends the respond's sending side. The
        // reset itself is RFC 9114 §4.1.1 — "Once a request stream has been
        // opened, the request MAY be cancelled by either endpoint." — a
        // stream-level event that leaves the connection alive.
        "http3_peer_reset_completes_fin_parked_respond"_test = [] {
            h3_gated_pair pair;

            // The upload never reaches FIN, so the server's read driver for
            // stream 0 stays active.
            one_chunk_then_hang_body request_body{"reset-upload"};
            auto request = http::coroutine::request(pair.client, basic_get("/upload"), request_body);
            request.start();
            route_gated_writes_to(pair.client_transport, pair.server_transport);
            auto receive = http::coroutine::receive(pair.server);
            receive.start();
            auto incoming = run_sync(std::move(receive));
            expect(incoming.head.target == "/upload"sv);

            pair.server_transport.ack_gate_open = false;
            chunked_body response_body{{bytes_of("response-first-chunk"), bytes_of("response-second-chunk")}};
            auto respond =
                http::coroutine::respond(pair.server, std::move(incoming.token), http::response{.status = 200, .reason = {}, .fields = {}}, response_body);
            respond.start();
            expect(!respond.done());

            // RFC 9114 §8.1 — H3_REQUEST_CANCELLED (0x010c).
            pair.server_transport.feed_reset(0, 0x010c);

            expect(respond.done());
            auto completed = false;
            if (respond.done()) {
                run_sync(std::move(respond));
                completed = true;
            }
            expect(completed);

            // The reset surfaces on the exchange's read side as the typed stream
            // error with the peer's error code; the connection survives it.
            auto body_threw = false;
            try {
                static_cast<void>(run_sync(drain_body(incoming.body)));
            } catch (const http::protocol_error& failure) {
                expect(failure.info().condition == http::error_condition::stream_reset);
                expect(http::retryable(failure.info()));
                const auto& reset = std::get<http::reset_stream>(failure.action());
                // 268 = 0x010c = H3_REQUEST_CANCELLED, the code fed above.
                expect(reset.code == 268_u);
                body_threw = true;
            }
            expect(body_threw);
            expect(pair.server_transport.closes.empty());
        };

        // Internal machinery test: flush_gate serializes flush_output. With the
        // write gate closed, the first request's flush holds the gate suspended
        // mid-write; the second request's flush must queue on the gate instead of
        // entering nghttp3_conn_writev_stream concurrently. nghttp3 has not
        // advanced the write offset for the first batch, so a concurrent flush
        // would receive the same unsent batch and duplicate it on the wire —
        // without the gate, the "each payload exactly once" assertions below
        // fail. Not HTTP RFC behavior.
        "http3_flush_gate_serializes_concurrent_flushes"_test = [] {
            h3_gated_pair pair;

            pair.client_transport.write_gate_open = false;
            auto first_body = make_body("first-body-payload");
            auto first = http::coroutine::request(pair.client, basic_get("/first"), first_body);
            first.start();
            expect(!first.done());
            // The first flush holds the gate suspended inside async_write.
            expect(pair.client_transport.pending_writes.size() == 1_u);

            auto second_body = make_body("second-body-payload");
            auto second = http::coroutine::request(pair.client, basic_get("/second"), second_body);
            second.start();
            expect(!second.done());
            // The second flush queued on the gate: it never reached the wire.
            expect(pair.client_transport.pending_writes.size() == 1_u);

            pair.client_transport.open_write_gate();
            // Both exchanges finished their uploads and park on response headers.
            expect(!first.done());
            expect(!second.done());
            expect(pair.client_transport.pending_writes.empty());

            // Each batch's bytes appear exactly once: no duplicated batch.
            expect(count_payload_occurrences(pair.client_transport.writes, "first-body-payload") == 1_u);
            expect(count_payload_occurrences(pair.client_transport.writes, "second-body-payload") == 1_u);

            route_gated_writes_to(pair.client_transport, pair.server_transport);
            auto receive_first = http::coroutine::receive(pair.server);
            receive_first.start();
            auto incoming_first = run_sync(std::move(receive_first));
            expect(incoming_first.head.target == "/first"sv);
            expect(read_body_text(incoming_first.body) == "first-body-payload"sv);

            auto receive_second = http::coroutine::receive(pair.server);
            receive_second.start();
            auto incoming_second = run_sync(std::move(receive_second));
            expect(incoming_second.head.target == "/second"sv);
            expect(read_body_text(incoming_second.body) == "second-body-payload"sv);

            http::buffer_body empty_first;
            run_sync(
                http::coroutine::respond(pair.server, std::move(incoming_first.token), http::response{.status = 200, .reason = {}, .fields = {}}, empty_first));
            http::buffer_body empty_second;
            run_sync(http::coroutine::respond(pair.server, std::move(incoming_second.token), http::response{.status = 200, .reason = {}, .fields = {}},
                                              empty_second));
            route_gated_writes_to(pair.server_transport, pair.client_transport);

            auto received_first = run_sync(std::move(first));
            expect(received_first.head.status == 200_u);
            auto received_second = run_sync(std::move(second));
            expect(received_second.head.status == 200_u);
        };

        // Internal machinery test: peer acknowledgements never pace the writes.
        // With the ACK gate closed, a multi-chunk upload and its FIN all reach the
        // transport; the respond, though, completes only once the peer
        // acknowledges its FIN, since closing the connection earlier would
        // discard the response. Not HTTP RFC behavior.
        "http3_writes_do_not_wait_for_ack"_test = [] {
            h3_gated_pair pair;
            chunked_body body{{bytes_of("ack-first-chunk"), bytes_of("ack-second-chunk")}};

            pair.client_transport.ack_gate_open = false;
            auto request = http::coroutine::request(pair.client, basic_get("/upload"), body);
            request.start();
            expect(!request.done());
            expect(!pair.client_transport.writes.empty() && pair.client_transport.writes.back().fin);

            route_gated_writes_to(pair.client_transport, pair.server_transport);
            auto receive = http::coroutine::receive(pair.server);
            receive.start();
            auto incoming = run_sync(std::move(receive));
            expect(incoming.head.target == "/upload"sv);
            expect(read_body_text(incoming.body) == "ack-first-chunkack-second-chunk"sv);

            pair.server_transport.ack_gate_open = false;
            http::buffer_body response_body;
            auto respond =
                http::coroutine::respond(pair.server, std::move(incoming.token), http::response{.status = 200, .reason = {}, .fields = {}}, response_body);
            respond.start();
            expect(!respond.done());
            expect(!pair.server_transport.writes.empty() && pair.server_transport.writes.back().fin);
            while (pair.server_transport.release_next_ack()) {
            }
            expect(respond.done());
            run_sync(std::move(respond));
            route_gated_writes_to(pair.server_transport, pair.client_transport);

            auto received = run_sync(std::move(request));
            expect(received.head.status == 200_u);
            expect(read_body_text(received.body).empty());
        };
    };

} // namespace httpant::testing
