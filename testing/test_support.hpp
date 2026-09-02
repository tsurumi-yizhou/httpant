#pragma once

#include <boost/ut.hpp>

#include <asio.hpp>
#include <asio/ssl.hpp>
#include <openssl/ssl.h>

extern "C" {
#include <msquic.h>
}

#include <algorithm>
#include <array>
#include <coroutine>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <exception>
#include <optional>
#include <span>
#include <stop_token>
#include <string>
#include <string_view>
#include <stdexcept>
#include <system_error>
#include <type_traits>
#include <deque>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

import httpant;

namespace httpant::testing {

using namespace std::literals;

struct pipe {
    std::vector<std::byte> buffer{};
    std::size_t read_pos{0};
    bool closed{false};

    void push(std::span<const std::byte> data) {
        buffer.insert(buffer.end(), data.begin(), data.end());
    }

    [[nodiscard]] auto available() const -> std::size_t {
        return buffer.size() - read_pos;
    }

    void close() {
        closed = true;
    }
};

struct mock_stream {
    pipe& input;
    pipe& output;

    struct read_awaiter {
        pipe& p;
        std::span<std::byte> buf;

        bool await_ready() noexcept {
            return p.available() > 0 || p.closed;
        }

        void await_suspend(std::coroutine_handle<> h) noexcept {
            h.resume();
        }

        auto await_resume() noexcept -> std::size_t {
            auto n = std::min(buf.size(), p.available());
            std::memcpy(buf.data(), p.buffer.data() + p.read_pos, n);
            p.read_pos += n;
            return n;
        }
    };

    struct write_awaiter {
        pipe& p;
        std::span<const std::byte> data;

        bool await_ready() noexcept {
            return true;
        }

        void await_suspend(std::coroutine_handle<>) noexcept {
        }

        auto await_resume() noexcept -> std::size_t {
            p.push(data);
            return data.size();
        }
    };

    auto async_read(std::span<std::byte> buf) -> read_awaiter {
        return {input, buf};
    }

    auto async_read(std::span<std::byte> buf, std::stop_token) -> read_awaiter {
        return {input, buf};
    }

    auto async_write(std::span<const std::byte> data) -> write_awaiter {
        return {output, data};
    }

    auto async_write(std::span<const std::byte> data, std::stop_token) -> write_awaiter {
        return {output, data};
    }
};

// A byte_stream mock whose writes throw std::runtime_error once the scripted
// number of successful writes has been used up (default: every write fails);
// reads behave exactly like mock_stream. Internal machinery for the
// connection-desync latches (v1 closed_, v2 start failure) — no RFC behavior.
struct write_failing_stream {
    pipe& input;
    pipe& output;
    std::size_t writes_before_failure{0};

    using read_awaiter = mock_stream::read_awaiter;

    struct write_awaiter {
        write_failing_stream& self;
        std::span<const std::byte> data;

        bool await_ready() noexcept { return true; }
        void await_suspend(std::coroutine_handle<>) noexcept {}
        auto await_resume() -> std::size_t {
            if (self.writes_before_failure == 0)
                throw std::runtime_error("write_failing_stream: scripted write failure");
            --self.writes_before_failure;
            self.output.push(data);
            return data.size();
        }
    };

    auto async_read(std::span<std::byte> buf) -> read_awaiter {
        return {input, buf};
    }

    auto async_read(std::span<std::byte> buf, std::stop_token) -> read_awaiter {
        return {input, buf};
    }

    auto async_write(std::span<const std::byte> data) -> write_awaiter {
        return {*this, data};
    }

    auto async_write(std::span<const std::byte> data, std::stop_token) -> write_awaiter {
        return {*this, data};
    }
};

struct async_pipe {
    std::vector<std::byte> buffer{};
    std::size_t read_pos{0};
    bool closed{false};
    std::coroutine_handle<> waiter{};
    void const* waiter_owner{nullptr};

    void push(std::span<const std::byte> data) {
        buffer.insert(buffer.end(), data.begin(), data.end());
        if (waiter) {
            auto handle = std::exchange(waiter, {});
            waiter_owner = nullptr;
            handle.resume();
        }
    }

    [[nodiscard]] auto available() const -> std::size_t {
        return buffer.size() - read_pos;
    }

    void close() {
        closed = true;
        if (waiter) {
            auto handle = std::exchange(waiter, {});
            waiter_owner = nullptr;
            handle.resume();
        }
    }
};

struct async_mock_stream {
    async_pipe& input;
    async_pipe& output;

    struct read_awaiter {
        async_pipe& p;
        std::span<std::byte> buf;
        std::stop_token stop{};
        bool cancelled{false};

        struct on_stop {
            read_awaiter* self;
            void operator()() const noexcept {
                // Exchange-claim the pipe's single waiter slot: a push/close
                // and the stop callback race; the loser observes an empty slot
                // and must not resume the coroutine a second time.
                if (self->p.waiter_owner != self) return;
                auto handle = std::exchange(self->p.waiter, {});
                if (!handle) return;
                self->p.waiter_owner = nullptr;
                self->cancelled = true;
                handle.resume();
            }
        };

        ~read_awaiter() {
            if (p.waiter_owner == this) {
                p.waiter = {};
                p.waiter_owner = nullptr;
            }
        }

        bool await_ready() noexcept {
            return p.available() > 0 || p.closed || stop.stop_requested();
        }

        auto await_suspend(std::coroutine_handle<> h) noexcept -> bool {
            if (stop.stop_possible())
                cancel.emplace(stop, on_stop{this});
            // A stop racing the registration claimed the (still empty) slot;
            // never park in that case.
            if (cancelled)
                return false;
            p.waiter = h;
            p.waiter_owner = this;
            return true;
        }

        auto await_resume() -> std::size_t {
            if (p.waiter_owner == this)
                p.waiter_owner = nullptr;
            // Data or EOF completes the read normally even when a stop raced
            // it; cancellation only wins an otherwise-unresolved wait.
            if (p.available() > 0 || p.closed) {
                auto n = std::min(buf.size(), p.available());
                std::memcpy(buf.data(), p.buffer.data() + p.read_pos, n);
                p.read_pos += n;
                return n;
            }
            // Cancellation delivery convention: a cancelled read throws
            // std::system_error{operation_canceled} (as a real backend would).
            throw std::system_error(
                std::make_error_code(std::errc::operation_canceled));
        }

        std::optional<std::stop_callback<on_stop>> cancel{};
    };

    struct write_awaiter {
        async_pipe& p;
        std::span<const std::byte> data;
        bool fin{false};

        bool await_ready() noexcept {
            return true;
        }

        void await_suspend(std::coroutine_handle<>) noexcept {
        }

        auto await_resume() noexcept -> std::size_t {
            p.push(data);
            if (fin)
                p.close();
            return data.size();
        }
    };

    auto async_read(std::span<std::byte> buf) -> read_awaiter {
        return {input, buf};
    }

    auto async_read(std::span<std::byte> buf, std::stop_token stop) -> read_awaiter {
        return {input, buf, stop};
    }

    auto async_write(std::span<const std::byte> data) -> write_awaiter {
        return {output, data, false};
    }

    auto async_write(std::span<const std::byte> data, std::stop_token) -> write_awaiter {
        return {output, data, false};
    }

    auto async_write(std::span<const std::byte> data, bool fin) -> write_awaiter {
        return {output, data, fin};
    }

    auto async_write(std::span<const std::byte> data, bool fin, std::stop_token) -> write_awaiter {
        return {output, data, fin};
    }
};

// ─── HTTP/3 stream-factory test mocks ───────────────────────

// A pipe-based stream factory model: every stream shares one input pipe and one
// output pipe, which keeps the
// wire-level tests asserting on a single buffer. The factory assigns a fresh
// sequential identity per stream and reports the direction on the handle.
struct mock_factory_stream {
    pipe* input{nullptr};
    pipe* output{nullptr};
    std::int64_t id{-1};
    http::stream_access access_{http::stream_access::bidirectional};

    using read_awaiter = mock_stream::read_awaiter;

    struct release_awaiter {
        bool await_ready() const noexcept { return true; }
        void await_suspend(std::coroutine_handle<>) const noexcept {}
        void await_resume() const noexcept {}
    };

    struct ack_awaiter {
        std::size_t count{0};
        bool await_ready() const noexcept { return true; }
        void await_suspend(std::coroutine_handle<>) const noexcept {}
        auto await_resume() const noexcept -> std::size_t { return count; }
    };

    struct write_awaiter {
        pipe& output;
        std::span<const std::byte> data;
        bool fin{false};

        bool await_ready() noexcept { return true; }
        void await_suspend(std::coroutine_handle<>) noexcept {}
        auto await_resume() noexcept
            -> http::stream_write_result<release_awaiter, ack_awaiter> {
            output.push(data);
            if (fin)
                output.close();
            return {
                .accepted = data.size(),
                .buffer_release = {},
                .acknowledgement = {.count = data.size()},
            };
        }
    };

    auto identifier() const -> http::stream_identifier {
        return {static_cast<std::uint64_t>(id)};
    }
    auto access() const -> http::stream_access {
        return access_;
    }
    auto async_read(std::span<std::byte> buf) -> read_awaiter {
        return {*input, buf};
    }
    auto async_read(std::span<std::byte> buf, std::stop_token) -> read_awaiter {
        return {*input, buf};
    }
    auto async_write(std::span<const std::byte> data) -> write_awaiter {
        return {*output, data, false};
    }
    auto async_write(std::span<const std::byte> data, std::stop_token)
        -> mock_stream::write_awaiter {
        return {*output, data};
    }
    auto async_write(std::span<const std::byte> data, bool fin, std::stop_token) -> write_awaiter {
        return {*output, data, fin};
    }
    void consume(std::size_t) {}
    void shutdown(http::stream_side, http::application_error) {}
};

struct mock_stream_factory {
    using stream_type = mock_factory_stream;
    static constexpr auto completion_order =
        http::stream_completion_order::serialized;

    pipe& input;
    pipe& output;
    std::deque<std::int64_t> accept_queue{};
    std::deque<http::stream_access> accept_access_queue{};
    std::coroutine_handle<> accept_waiter{};
    const void* accept_waiter_owner{};
    std::stop_token accept_stop{};
    std::int64_t next_bidi{0};
    std::int64_t next_uni{0};
    bool client_role{true};

    explicit mock_stream_factory(pipe& in, pipe& out, bool is_client = true)
        : input(in), output(out), client_role(is_client) {
        // RFC 9000 §2.1 — client-initiated streams start at 0, server at 1.
        next_bidi = client_role ? 0 : 1;
        next_uni = client_role ? 2 : 3;
    }

    struct open_awaiter {
        pipe& input;
        pipe& output;
        std::int64_t id;
        http::stream_access access_;

        bool await_ready() noexcept { return true; }
        void await_suspend(std::coroutine_handle<>) noexcept {}
        auto await_resume() noexcept -> mock_factory_stream {
            return {&input, &output, id, access_};
        }
    };

    struct accept_awaiter {
        mock_stream_factory& transport;

        accept_awaiter(mock_stream_factory& value) : transport(value) {}
        accept_awaiter(const accept_awaiter&) = delete;
        auto operator=(const accept_awaiter&) -> accept_awaiter& = delete;
        accept_awaiter(accept_awaiter&& other) noexcept : transport(other.transport) {
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

        [[nodiscard]] auto await_ready() const noexcept -> bool {
            return !transport.accept_queue.empty();
        }
        void await_suspend(std::coroutine_handle<> handle) noexcept {
            transport.accept_waiter = handle;
            transport.accept_waiter_owner = this;
        }
        auto await_resume() noexcept -> mock_factory_stream {
            if (transport.accept_waiter_owner == this)
                transport.accept_waiter_owner = nullptr;
            auto id = transport.accept_queue.front();
            auto access = transport.accept_access_queue.front();
            transport.accept_queue.pop_front();
            transport.accept_access_queue.pop_front();
            return {&transport.input, &transport.output, id, access};
        }
    };

    struct close_awaiter {
        bool await_ready() const noexcept { return true; }
        void await_suspend(std::coroutine_handle<>) const noexcept {}
        void await_resume() const noexcept {}
    };

    // RFC 9000 §2.1 — client-initiated bidirectional streams start at 0,
    // unidirectional at 2, each advancing by 4; the uni/bidi bit is what the
    // H3 layer uses to classify streams, so the mock must preserve it.
    auto async_open_bidirectional(std::stop_token) -> open_awaiter {
        auto id = next_bidi;
        next_bidi += 4;
        return {input, output, id, http::stream_access::bidirectional};
    }
    auto async_open_unidirectional(std::stop_token) -> open_awaiter {
        auto id = next_uni;
        next_uni += 4;
        return {input, output, id, http::stream_access::send_only};
    }
    auto async_accept(std::stop_token stop) -> accept_awaiter {
        accept_stop = stop;
        return {*this};
    }
    auto async_close(http::application_error) -> close_awaiter {
        return {};
    }

    void announce(std::int64_t id, http::stream_access access) {
        accept_queue.push_back(id);
        accept_access_queue.push_back(access);
        if (accept_waiter) {
            auto handle = std::exchange(accept_waiter, {});
            accept_waiter_owner = nullptr;
            handle.resume();
        }
    }
};

struct recorded_write {
    std::int64_t stream_id{-1};
    bool fin{false};
    std::vector<std::byte> data{};
};

struct recorded_shutdown {
    std::int64_t stream_id{-1};
    http::stream_side side{http::stream_side::both};
    http::application_error error{};
};

// A recording stream factory for two-sided HTTP/3 tests. Each factory owns:
//   - writes_ (every async_write, keyed by stream id, for the test to route to
//     the peer's recorded inbound/accept queues),
//   - an inbound queue per stream id (populated by the test harness), from
//     which the driver/operation reads,
//   - an accept queue of peer-initiated stream ids.
// The test bridges two factories: route(client.take_writes(), server, first_id)
// feeds the client's request stream bytes into the server and announces the
// stream to the server's accept loop.
struct recording_stream_factory {
    struct stream;
    // stream_factory contract: the handle type created/accepted by this
    // connection factory.
    using stream_type = stream;
    static constexpr auto completion_order =
        http::stream_completion_order::serialized;

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
        std::size_t result{0};

        read_awaiter(inbound_queue& value, std::span<std::byte> buffer)
            : queue(value), buf(buffer) {}
        read_awaiter(const read_awaiter&) = delete;
        auto operator=(const read_awaiter&) -> read_awaiter& = delete;
        read_awaiter(read_awaiter&& other) noexcept
            : queue(other.queue), buf(other.buf), result(other.result) {
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

        [[nodiscard]] bool await_ready() const noexcept {
            return !queue.chunks.empty() || queue.fin || queue.reset.has_value();
        }
        void await_suspend(std::coroutine_handle<> handle) noexcept {
            queue.waiter = handle;
            queue.waiter_owner = this;
        }
        auto await_resume() -> std::size_t {
            if (queue.waiter_owner == this)
                queue.waiter_owner = nullptr;
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

    struct ack_awaiter {
        std::size_t count{0};
        bool await_ready() const noexcept { return true; }
        void await_suspend(std::coroutine_handle<>) const noexcept {}
        auto await_resume() const noexcept -> std::size_t { return count; }
    };

    struct write_awaiter {
        recording_stream_factory& transport;
        std::int64_t stream_id;
        std::span<const std::byte> data;
        bool fin{false};

        bool await_ready() noexcept { return true; }
        void await_suspend(std::coroutine_handle<>) noexcept {}
        auto await_resume() -> http::stream_write_result<release_awaiter, ack_awaiter> {
            // Scripted partial acceptance (see script_acceptance): consume the
            // next scripted limit, otherwise accept the whole buffer.
            auto accepted = data.size();
            if (auto it = transport.acceptance_limits.find(stream_id);
                it != transport.acceptance_limits.end() && !it->second.empty()) {
                accepted = std::min(it->second.front(), data.size());
                it->second.pop_front();
            }
            // The FIN only takes effect once the whole buffer was accepted;
            // the protocol layer retries the unaccepted tail with fin again.
            auto effective_fin = fin && (accepted == data.size());
            transport.writes.push_back(recorded_write{
                .stream_id = stream_id,
                .fin = effective_fin,
                .data = {data.begin(), data.begin() + static_cast<std::ptrdiff_t>(accepted)},
            });
            return {
                .accepted = accepted,
                .buffer_release = {},
                .acknowledgement = {.count = accepted},
            };
        }
    };

    struct byte_write_awaiter {
        recording_stream_factory& transport;
        std::int64_t stream_id;
        std::span<const std::byte> data;

        bool await_ready() noexcept { return true; }
        void await_suspend(std::coroutine_handle<>) noexcept {}
        auto await_resume() -> std::size_t {
            transport.writes.push_back(recorded_write{
                .stream_id = stream_id,
                .fin = false,
                .data = {data.begin(), data.end()},
            });
            return data.size();
        }
    };

    struct stream {
        recording_stream_factory* transport{nullptr};
        std::int64_t stream_id{-1};
        http::stream_access access_{http::stream_access::bidirectional};

        stream() = default;
        stream(recording_stream_factory* value, std::int64_t id, http::stream_access access)
            : transport(value), stream_id(id), access_(access) {}
        stream(const stream&) = delete;
        auto operator=(const stream&) -> stream& = delete;
        stream(stream&&) noexcept = default;
        auto operator=(stream&&) noexcept -> stream& = default;

        auto identifier() const -> http::stream_identifier {
            return {static_cast<std::uint64_t>(stream_id)};
        }
        auto access() const -> http::stream_access {
            return access_;
        }
        auto async_read(std::span<std::byte> buf) -> read_awaiter {
            return {transport->inbound(stream_id), buf};
        }
        auto async_read(std::span<std::byte> buf, std::stop_token) -> read_awaiter {
            return {transport->inbound(stream_id), buf};
        }
        auto async_write(std::span<const std::byte> data) -> write_awaiter {
            return {*transport, stream_id, data, false};
        }
        auto async_write(std::span<const std::byte> data, std::stop_token)
            -> byte_write_awaiter {
            return {*transport, stream_id, data};
        }
        auto async_write(std::span<const std::byte> data, bool fin, std::stop_token) -> write_awaiter {
            return {*transport, stream_id, data, fin};
        }
        void consume(std::size_t consumed) {
            transport->consumed[stream_id] += consumed;
        }
        void shutdown(http::stream_side side, http::application_error error) {
            transport->shutdowns.push_back({stream_id, side, error});
        }
    };

    struct open_awaiter {
        recording_stream_factory& transport;
        std::int64_t id{-1};
        http::stream_access access_{http::stream_access::bidirectional};

        [[nodiscard]] bool await_ready() const noexcept { return true; }
        void await_suspend(std::coroutine_handle<>) const noexcept {}
        auto await_resume() noexcept -> stream {
            return {&transport, id, access_};
        }
    };

    struct accept_awaiter {
        recording_stream_factory& transport;

        accept_awaiter(recording_stream_factory& value) : transport(value) {}
        accept_awaiter(const accept_awaiter&) = delete;
        auto operator=(const accept_awaiter&) -> accept_awaiter& = delete;
        accept_awaiter(accept_awaiter&& other) noexcept : transport(other.transport) {
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

        [[nodiscard]] bool await_ready() const noexcept {
            return !transport.accept_queue.empty();
        }
        void await_suspend(std::coroutine_handle<> handle) noexcept {
            transport.accept_waiter = handle;
            transport.accept_waiter_owner = this;
        }
        auto await_resume() noexcept -> stream {
            if (transport.accept_waiter_owner == this)
                transport.accept_waiter_owner = nullptr;
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
    // Per-stream scripted partial-write acceptance (REFACTOR.md §9.3): each
    // write consumes the front limit and accepts at most that many bytes; an
    // empty/absent queue accepts the whole buffer (the default behavior).
    std::unordered_map<std::int64_t, std::deque<std::size_t>> acceptance_limits{};
    std::unordered_map<std::int64_t, std::size_t> consumed{};
    std::unordered_map<std::int64_t, inbound_queue> inbound_{};
    std::deque<std::int64_t> accept_queue{};
    std::deque<http::stream_access> accept_access_queue{};
    std::coroutine_handle<> accept_waiter{};
    const void* accept_waiter_owner{};
    std::stop_token accept_stop{};
    std::int64_t next_bidi{0};
    std::int64_t next_uni{0};
    bool client_role{false};
    // Stream ids this factory opened locally; peer ids are announced to the
    // accept loop, local ids are read by the owning operation only.
    std::unordered_set<std::int64_t> local_ids{};
    std::unordered_set<std::int64_t> announced_ids{};

    explicit recording_stream_factory(bool is_client = false) : client_role(is_client) {
        // RFC 9000 §2.1 — client-initiated streams start at 0, server at 1.
        next_bidi = client_role ? 0 : 1;
        next_uni = client_role ? 2 : 3;
    }

    auto inbound(std::int64_t id) -> inbound_queue& {
        return inbound_[id];
    }

    // RFC 9000 §2.1 — see mock_stream_factory for the id scheme. The stream
    // id space is per-role: the client uses even stream ids (0, 4, ... for
    // bidirectional; 2, 6, ... for unidirectional) and the server uses odd ids
    // (1, 5, ... / 3, 7, ...), so both sides of a test can coexist.
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
    auto async_accept(std::stop_token stop) -> accept_awaiter {
        accept_stop = stop;
        return {*this};
    }
    auto async_close(http::application_error error) -> close_awaiter {
        closes.push_back(error);
        return {};
    }

    // Announce a peer-initiated stream to the accept loop and deliver its bytes.
    // The direction follows QUIC: a peer uni stream is receive-only from our
    // side; anything else is bidirectional.
    void announce(std::int64_t id, http::stream_access access) {
        accept_queue.push_back(id);
        accept_access_queue.push_back(access);
        if (accept_waiter) {
            auto handle = std::exchange(accept_waiter, {});
            accept_waiter_owner = nullptr;
            handle.resume();
        }
    }

    void feed(std::int64_t id, std::span<const std::byte> data, bool fin) {
        inbound(id).push({data.begin(), data.end()}, fin);
    }

    // Delivers a peer stream reset (QUIC RESET_STREAM with an H3 application
    // error code, RFC 9114 §8) on the stream's inbound queue.
    void feed_reset(std::int64_t id, std::uint64_t error_code) {
        inbound(id).fail(http::application_error{error_code});
    }

    // Script partial-write acceptance for a stream (REFACTOR.md §9.3
    // partial-write retry tests): each async_write consumes one limit.
    void script_acceptance(std::int64_t stream_id, std::deque<std::size_t> limits) {
        acceptance_limits[stream_id] = std::move(limits);
    }

    auto take_writes() -> std::vector<recorded_write> {
        std::vector<recorded_write> out;
        while (!writes.empty()) {
            out.push_back(std::move(writes.front()));
            writes.pop_front();
        }
        return out;
    }
};

// Route every recorded write of |from| into |to|'s inbound queues. Writes on
// locally opened streams (|from|'s own request streams) are delivered to the
// peer's accept loop as peer-initiated streams; the direction follows QUIC
// (a peer uni stream is receive-only for |to|).
inline void route_writes_to(recording_stream_factory& from, recording_stream_factory& to) {
    auto writes = from.take_writes();
    // Preserve the causal ordering needed by the synchronous test driver:
    // request-stream PUSH_PROMISE/response bytes are delivered before the
    // associated push stream, whose callbacks expect that state to exist.
    std::stable_sort(writes.begin(), writes.end(), [](const auto& left, const auto& right) {
        return (left.stream_id & 0x2) < (right.stream_id & 0x2);
    });
    for (auto& write : writes) {
        if (from.local_ids.contains(write.stream_id) &&
            to.announced_ids.insert(write.stream_id).second) {
            auto access = (write.stream_id & 0x2) != 0
                ? http::stream_access::receive_only
                : http::stream_access::bidirectional;
            to.announce(write.stream_id, access);
        }
        to.feed(write.stream_id, std::span<const std::byte>{write.data.data(), write.data.size()}, write.fin);
    }
}

template <typename T>
auto run_sync(http::task<T> task) -> T {
    std::optional<T> result;
    std::exception_ptr error;

    struct sync_launcher {
        struct promise_type {
            auto get_return_object() -> sync_launcher { return {}; }
            auto initial_suspend() noexcept -> std::suspend_never { return {}; }
            auto final_suspend() noexcept -> std::suspend_never { return {}; }
            void return_void() {}
            void unhandled_exception() { std::rethrow_exception(std::current_exception()); }
        };
    };

    [](http::task<T> inner, std::optional<T>& out, std::exception_ptr& ex) -> sync_launcher {
        try {
            out.emplace(co_await std::move(inner));
        } catch (...) {
            ex = std::current_exception();
        }
    }(std::move(task), result, error);

    if (error) {
        std::rethrow_exception(error);
    }

    if (!result.has_value()) {
        throw std::runtime_error("task completed without a result");
    }

    return std::move(*result);
}

inline auto run_sync(http::task<void> task) -> void {
    std::exception_ptr error;

    struct sync_launcher {
        struct promise_type {
            auto get_return_object() -> sync_launcher { return {}; }
            auto initial_suspend() noexcept -> std::suspend_never { return {}; }
            auto final_suspend() noexcept -> std::suspend_never { return {}; }
            void return_void() {}
            void unhandled_exception() { std::rethrow_exception(std::current_exception()); }
        };
    };

    [](http::task<void> inner, std::exception_ptr& ex) -> sync_launcher {
        try {
            co_await std::move(inner);
        } catch (...) {
            ex = std::current_exception();
        }
    }(std::move(task), error);

    if (error) {
        std::rethrow_exception(error);
    }
}

struct tcp_stream {
    asio::ip::tcp::socket& socket;

    struct read_awaiter {
        asio::ip::tcp::socket& sock;
        std::span<std::byte> buf;
        std::size_t result{0};
        std::exception_ptr ex;

        bool await_ready() noexcept {
            return false;
        }

        void await_suspend(std::coroutine_handle<> h) {
            sock.async_read_some(
                asio::buffer(buf.data(), buf.size()),
                [this, h](std::error_code ec, std::size_t n) mutable {
                    if (ec && ec != asio::error::eof) {
                        ex = std::make_exception_ptr(std::system_error(ec));
                    }
                    result = n;
                    h.resume();
                });
        }

        auto await_resume() -> std::size_t {
            if (ex) {
                std::rethrow_exception(ex);
            }
            return result;
        }
    };

    struct write_awaiter {
        asio::ip::tcp::socket& sock;
        std::span<const std::byte> data;
        std::size_t result{0};
        std::exception_ptr ex;

        bool await_ready() noexcept {
            return false;
        }

        void await_suspend(std::coroutine_handle<> h) {
            asio::async_write(
                sock,
                asio::buffer(data.data(), data.size()),
                [this, h](std::error_code ec, std::size_t n) mutable {
                    if (ec) {
                        ex = std::make_exception_ptr(std::system_error(ec));
                    }
                    result = n;
                    h.resume();
                });
        }

        auto await_resume() -> std::size_t {
            if (ex) {
                std::rethrow_exception(ex);
            }
            return result;
        }
    };

    auto async_read(std::span<std::byte> buf) -> read_awaiter {
        return {.sock = socket, .buf = buf, .result = 0, .ex = {}};
    }

    auto async_read(std::span<std::byte> buf, std::stop_token) -> read_awaiter {
        return {.sock = socket, .buf = buf, .result = 0, .ex = {}};
    }

    auto async_write(std::span<const std::byte> data) -> write_awaiter {
        return {.sock = socket, .data = data, .result = 0, .ex = {}};
    }

    auto async_write(std::span<const std::byte> data, std::stop_token) -> write_awaiter {
        return {.sock = socket, .data = data, .result = 0, .ex = {}};
    }
};

struct tls_stream {
    asio::ssl::stream<asio::ip::tcp::socket>& socket;

    struct read_awaiter {
        asio::ssl::stream<asio::ip::tcp::socket>& sock;
        std::span<std::byte> buf;
        std::size_t result{0};
        std::exception_ptr ex;

        bool await_ready() noexcept {
            return false;
        }

        void await_suspend(std::coroutine_handle<> h) {
            sock.async_read_some(
                asio::buffer(buf.data(), buf.size()),
                [this, h](std::error_code ec, std::size_t n) mutable {
                    if (ec && ec != asio::error::eof) {
                        ex = std::make_exception_ptr(std::system_error(ec));
                    }
                    result = n;
                    h.resume();
                });
        }

        auto await_resume() -> std::size_t {
            if (ex) {
                std::rethrow_exception(ex);
            }
            return result;
        }
    };

    struct write_awaiter {
        asio::ssl::stream<asio::ip::tcp::socket>& sock;
        std::span<const std::byte> data;
        std::size_t result{0};
        std::exception_ptr ex;

        bool await_ready() noexcept {
            return false;
        }

        void await_suspend(std::coroutine_handle<> h) {
            asio::async_write(
                sock,
                asio::buffer(data.data(), data.size()),
                [this, h](std::error_code ec, std::size_t n) mutable {
                    if (ec) {
                        ex = std::make_exception_ptr(std::system_error(ec));
                    }
                    result = n;
                    h.resume();
                });
        }

        auto await_resume() -> std::size_t {
            if (ex) {
                std::rethrow_exception(ex);
            }
            return result;
        }
    };

    auto async_read(std::span<std::byte> buf) -> read_awaiter {
        return {.sock = socket, .buf = buf, .result = 0, .ex = {}};
    }

    auto async_read(std::span<std::byte> buf, std::stop_token) -> read_awaiter {
        return {.sock = socket, .buf = buf, .result = 0, .ex = {}};
    }

    auto async_write(std::span<const std::byte> data) -> write_awaiter {
        return {.sock = socket, .data = data, .result = 0, .ex = {}};
    }

    auto async_write(std::span<const std::byte> data, std::stop_token) -> write_awaiter {
        return {.sock = socket, .data = data, .result = 0, .ex = {}};
    }
};

struct quic_stream {
    HQUIC connection{nullptr};
    HQUIC stream_handle{nullptr};
    const QUIC_API_TABLE* api{nullptr};

    struct quic_read_awaiter {
        HQUIC stream_handle;
        std::span<std::byte> buf;
        std::size_t result{0};

        bool await_ready() noexcept {
            return false;
        }

        void await_suspend(std::coroutine_handle<> h) noexcept {
            h.resume();
        }

        auto await_resume() noexcept -> std::size_t {
            return result;
        }
    };

    struct quic_write_awaiter {
        HQUIC stream_handle;
        const QUIC_API_TABLE* api;
        std::span<const std::byte> data;
        std::size_t result{0};

        bool await_ready() noexcept {
            return false;
        }

        void await_suspend(std::coroutine_handle<> h) noexcept {
            result = data.size();
            h.resume();
        }

        auto await_resume() noexcept -> std::size_t {
            return result;
        }
    };

    struct accept_awaiter {
        HQUIC connection;
        const QUIC_API_TABLE* api;

        bool await_ready() noexcept {
            return false;
        }

        void await_suspend(std::coroutine_handle<> h) noexcept {
            h.resume();
        }

        auto await_resume() noexcept -> quic_stream {
            return {connection, nullptr, api};
        }
    };

    struct open_awaiter {
        HQUIC connection;
        const QUIC_API_TABLE* api;
        std::int64_t id;

        bool await_ready() noexcept {
            return false;
        }

        void await_suspend(std::coroutine_handle<> h) noexcept {
            h.resume();
        }

        auto await_resume() noexcept -> quic_stream {
            return {connection, nullptr, api};
        }
    };

    auto async_read(std::span<std::byte> buf) -> quic_read_awaiter {
        return {stream_handle, buf};
    }

    auto async_read(std::span<std::byte> buf, std::stop_token) -> quic_read_awaiter {
        return {stream_handle, buf};
    }

    auto async_write(std::span<const std::byte> data) -> quic_write_awaiter {
        return {stream_handle, api, data};
    }

    auto async_write(std::span<const std::byte> data, std::stop_token) -> quic_write_awaiter {
        return {stream_handle, api, data};
    }

    auto async_accept() -> accept_awaiter {
        return {connection, api};
    }

    auto async_open(std::int64_t id) -> open_awaiter {
        return {connection, api, id};
    }
};

inline void push_text(pipe& p, std::string_view text) {
    auto bytes = std::as_bytes(std::span{text.data(), text.size()});
    p.push(bytes);
}

[[nodiscard]] inline auto bytes_to_string(std::span<const std::byte> bytes) -> std::string {
    return {reinterpret_cast<const char*>(bytes.data()), bytes.size()};
}

[[nodiscard]] inline auto bytes_to_string(const std::vector<std::byte>& bytes) -> std::string {
    return bytes_to_string(std::span<const std::byte>{bytes.data(), bytes.size()});
}

[[nodiscard]] inline auto make_body(std::string_view text) -> http::buffer_body {
    auto bytes = std::as_bytes(std::span{text.data(), text.size()});
    return http::buffer_body{{bytes.begin(), bytes.end()}};
}

// Drain a streaming body into an in-memory buffer. Works for both the lazy
// protocol body readers and http::buffer_body.
template <http::body_stream Body>
[[nodiscard]] auto drain_body(Body& body) -> http::task<std::vector<std::byte>> {
    std::vector<std::byte> out;
    std::array<std::byte, 8192> buf;
    for (;;) {
        auto n = co_await body.async_read(buf, std::stop_token{});
        if (n == 0) break;
        out.insert(out.end(), buf.data(), buf.data() + n);
    }
    co_return out;
}

[[nodiscard]] inline auto read_body_text(const std::vector<std::byte>& body) -> std::string {
    return bytes_to_string(body);
}

// Read a streaming body to completion and return it as text.
template <http::body_stream Body>
[[nodiscard]] auto read_body_text(Body& body) -> std::string {
    return bytes_to_string(run_sync(drain_body(body)));
}

// A fully buffered response for tests that read the whole body at once. The
// library's http::response carries no body (it is streamed); this test-only
// view pairs a head with its drained body.
struct buffered_response {
    http::status status{200};
    std::string reason{};
    http::headers fields{};
    std::vector<std::byte> body{};
};

struct http1_client_fixture {
    pipe c2s{};
    pipe s2c{};
    mock_stream transport{.input = s2c, .output = c2s};
    http::v1::client<mock_stream> client{transport};

    void queue_response(std::string_view raw, bool close = false) {
        push_text(s2c, raw);
        s2c.closed = close;
    }

    auto issue(http::request request) -> buffered_response {
        auto received = run_sync(http::coroutine::request(client, std::move(request)));
        auto body = run_sync(drain_body(received.body));
        return buffered_response{
            .status = received.head.status,
            .reason = std::move(received.head.reason),
            .fields = std::move(received.head.fields),
            .body = std::move(body),
        };
    }
};

[[nodiscard]] inline auto basic_get(std::string_view target = "/") -> http::request {
    return http::request{
        .method = http::method::GET,
        .target = std::string(target),
        .scheme = "https",
        .authority = "example.com",
        .fields = {{"host", "example.com"}},
    };
}

template <typename Pipe>
inline void push_http2_settings_frame(Pipe& p) {
    constexpr std::array<std::byte, 9> frame{
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
        std::byte{0x04}, std::byte{0x00},
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
    };
    p.push(frame);
}

template <typename Pipe>
inline void push_http2_settings_ack_frame(Pipe& p) {
    // RFC 9113 §6.5 — "The ACK flag indicates that this frame acknowledges
    // receipt and application of the peer's SETTINGS frame."
    constexpr std::array<std::byte, 9> frame{
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
        std::byte{0x04}, std::byte{0x01},
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
    };
    p.push(frame);
}

template <typename Pipe>
inline void push_http2_setting_frame(
    Pipe& pipe,
    std::uint16_t identifier,
    std::uint32_t value)
{
    // RFC 9113 §6.5.1 — "Each parameter in a SETTINGS frame consists of an
    // unsigned 16-bit setting identifier and an unsigned 32-bit value."
    const std::array frame{
        std::byte{0x00}, std::byte{0x00}, std::byte{0x06},
        std::byte{0x04}, std::byte{0x00},
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
        std::byte{static_cast<std::uint8_t>(identifier >> 8)},
        std::byte{static_cast<std::uint8_t>(identifier)},
        std::byte{static_cast<std::uint8_t>(value >> 24)},
        std::byte{static_cast<std::uint8_t>(value >> 16)},
        std::byte{static_cast<std::uint8_t>(value >> 8)},
        std::byte{static_cast<std::uint8_t>(value)},
    };
    pipe.push(frame);
}

// RFC 9113 §4.1 — "Frame Layout": a 24-bit length, an 8-bit type, 8-bit flags,
// and a 31-bit stream identifier precede the frame payload.
template <typename Pipe>
inline void push_http2_frame(
    Pipe& p,
    std::uint8_t type,
    std::uint8_t flags,
    std::uint32_t stream_id,
    std::span<const std::byte> payload)
{
    std::vector<std::byte> frame;
    frame.reserve(9 + payload.size());
    frame.push_back(std::byte{static_cast<std::uint8_t>(payload.size() >> 16)});
    frame.push_back(std::byte{static_cast<std::uint8_t>(payload.size() >> 8)});
    frame.push_back(std::byte{static_cast<std::uint8_t>(payload.size())});
    frame.push_back(std::byte{type});
    frame.push_back(std::byte{flags});
    frame.push_back(std::byte{static_cast<std::uint8_t>(stream_id >> 24)});
    frame.push_back(std::byte{static_cast<std::uint8_t>(stream_id >> 16)});
    frame.push_back(std::byte{static_cast<std::uint8_t>(stream_id >> 8)});
    frame.push_back(std::byte{static_cast<std::uint8_t>(stream_id)});
    frame.insert(frame.end(), payload.begin(), payload.end());
    p.push(frame);
}

template <typename Pipe>
inline void push_http2_goaway_frame(Pipe& p, std::uint32_t last_stream_id) {
    // RFC 9113 §6.8 — "The GOAWAY frame (type=0x7) ... contains the stream
    // identifier of the last peer-initiated stream that was or might be
    // processed" followed by the 32-bit error code.
    const std::array payload{
        std::byte{static_cast<std::uint8_t>(last_stream_id >> 24)},
        std::byte{static_cast<std::uint8_t>(last_stream_id >> 16)},
        std::byte{static_cast<std::uint8_t>(last_stream_id >> 8)},
        std::byte{static_cast<std::uint8_t>(last_stream_id)},
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
    };
    push_http2_frame(p, 0x07, 0x00, 0, payload);
}

inline void push_http2_goaway_frame(pipe& p) {
    push_http2_goaway_frame(p, 0);
}

inline void push_http2_window_update_frame(pipe& p, std::uint32_t increment) {
    std::array<std::byte, 13> frame{
        std::byte{0x00}, std::byte{0x00}, std::byte{0x04},
        std::byte{0x08}, std::byte{0x00},
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
        std::byte{static_cast<unsigned char>((increment >> 24) & 0x7f)},
        std::byte{static_cast<unsigned char>((increment >> 16) & 0xff)},
        std::byte{static_cast<unsigned char>((increment >> 8) & 0xff)},
        std::byte{static_cast<unsigned char>(increment & 0xff)},
    };
    p.push(frame);
}

} // namespace httpant::testing
