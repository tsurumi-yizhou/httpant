#include <boost/ut.hpp>

#include <coroutine>
#include <cstdint>
#include <span>
#include <stop_token>
#include <type_traits>

#include "test_support.hpp"

namespace httpant::testing {

using namespace boost::ut;

namespace {

// A minimal stream_factory model used only to verify the transport abstraction.
// It is not a protocol test: no RFC-mandated behavior is exercised here.
struct model_factory_stream {
    std::int64_t id{-1};
    http::stream_access access_{http::stream_access::bidirectional};

    model_factory_stream() = default;
    model_factory_stream(std::int64_t value, http::stream_access access)
        : id(value), access_(access) {}
    model_factory_stream(const model_factory_stream&) = delete;
    auto operator=(const model_factory_stream&) -> model_factory_stream& = delete;
    model_factory_stream(model_factory_stream&&) noexcept = default;
    auto operator=(model_factory_stream&&) noexcept -> model_factory_stream& = default;

    struct read_awaiter {
        std::size_t value{0};
        bool await_ready() const noexcept { return true; }
        void await_suspend(std::coroutine_handle<>) noexcept {}
        auto await_resume() const noexcept -> std::size_t { return value; }
    };

    struct release_awaiter {
        bool await_ready() const noexcept { return true; }
        void await_suspend(std::coroutine_handle<>) noexcept {}
        void await_resume() const noexcept {}
    };

    struct ack_awaiter {
        bool await_ready() const noexcept { return true; }
        void await_suspend(std::coroutine_handle<>) noexcept {}
        auto await_resume() const noexcept -> std::size_t { return 0; }
    };

    struct write_awaiter {
        std::size_t accepted{0};
        bool await_ready() const noexcept { return true; }
        void await_suspend(std::coroutine_handle<>) noexcept {}
        auto await_resume() const noexcept
            -> http::stream_write_result<release_awaiter, ack_awaiter> {
            return {.accepted = accepted, .buffer_release = {}, .acknowledgement = {}};
        }
    };

    auto identifier() const -> http::stream_identifier {
        return {static_cast<std::uint64_t>(id)};
    }
    auto access() const -> http::stream_access {
        return access_;
    }
    auto async_read(std::span<std::byte>, std::stop_token) -> read_awaiter {
        return {};
    }
    auto async_write(std::span<const std::byte>, bool, std::stop_token) -> write_awaiter {
        return {};
    }
    void consume(std::size_t) {}
    void shutdown(http::stream_side, http::application_error) {}
};

struct factory_open_awaiter {
    http::stream_identifier id{};
    http::stream_access access_{http::stream_access::bidirectional};

    bool await_ready() const noexcept { return true; }
    void await_suspend(std::coroutine_handle<>) noexcept {}
    auto await_resume() const -> model_factory_stream {
        return model_factory_stream{static_cast<std::int64_t>(id.value), access_};
    }
};

struct factory_close_awaiter {
    bool await_ready() const noexcept { return true; }
    void await_suspend(std::coroutine_handle<>) noexcept {}
    void await_resume() const noexcept {}
};

// The factory models a QUIC-style connection: it has no connection-level
// byte read/write, only stream construction/acceptance. Its copy constructor
// is deleted so copying can never implicitly create a stream.
struct model_stream_factory {
    using stream_type = model_factory_stream;
    static constexpr auto completion_order =
        http::stream_completion_order::serialized;

    std::uint64_t next_id{0};

    model_stream_factory() = default;
    model_stream_factory(const model_stream_factory&) = delete;
    auto operator=(const model_stream_factory&) -> model_stream_factory& = delete;

    auto async_open_bidirectional(std::stop_token) -> factory_open_awaiter {
        return {.id = {next_id++}, .access_ = http::stream_access::bidirectional};
    }
    auto async_open_unidirectional(std::stop_token) -> factory_open_awaiter {
        return {.id = {next_id++}, .access_ = http::stream_access::send_only};
    }
    auto async_accept(std::stop_token) -> factory_open_awaiter {
        return {.id = {next_id++}, .access_ = http::stream_access::receive_only};
    }
    auto async_close(http::application_error) -> factory_close_awaiter {
        return {};
    }
};

// Negative models: each removes one capability and must fail the matching
// concept. Bodies are never linked (concept evaluation is unevaluated), but
// inline bodies keep the types complete and self-contained.
struct missing_stream_type {
    auto async_open_bidirectional(std::stop_token) -> factory_open_awaiter { return {}; }
    auto async_open_unidirectional(std::stop_token) -> factory_open_awaiter { return {}; }
    auto async_accept(std::stop_token) -> factory_open_awaiter { return {}; }
    auto async_close(http::application_error) -> factory_close_awaiter { return {}; }
};

struct missing_uni_open {
    using stream_type = model_factory_stream;
    auto async_open_bidirectional(std::stop_token) -> factory_open_awaiter { return {}; }
    auto async_accept(std::stop_token) -> factory_open_awaiter { return {}; }
    auto async_close(http::application_error) -> factory_close_awaiter { return {}; }
};

struct missing_bidi_open {
    using stream_type = model_factory_stream;
    auto async_open_unidirectional(std::stop_token) -> factory_open_awaiter { return {}; }
    auto async_accept(std::stop_token) -> factory_open_awaiter { return {}; }
    auto async_close(http::application_error) -> factory_close_awaiter { return {}; }
};

struct missing_accept {
    using stream_type = model_factory_stream;
    auto async_open_bidirectional(std::stop_token) -> factory_open_awaiter { return {}; }
    auto async_open_unidirectional(std::stop_token) -> factory_open_awaiter { return {}; }
    auto async_close(http::application_error) -> factory_close_awaiter { return {}; }
};

struct unconstrained_completion_factory : model_stream_factory {
    static constexpr auto completion_order =
        http::stream_completion_order::unconstrained;
};

} // namespace

static suite<"transport"> transport_suite = [] {
    // Internal machinery test: the factory satisfies all three concepts even
    // though it has no connection-level byte read/write — the connection is a
    // stream factory, not a byte_stream.
    "stream_factory_connection_without_byte_stream"_test = [] {
        static_assert(!std::copy_constructible<model_factory_stream>);
        static_assert(http::stream_constructible<model_stream_factory>);
        static_assert(http::stream_accepting<model_stream_factory>);
        static_assert(http::stream_factory<model_stream_factory>);
    };

    // Internal machinery test: each capability is checked independently so a
    // factory missing one open direction, accept, or the stream_type alias
    // fails the matching concept.
    "stream_factory_requires_each_capability"_test = [] {
        static_assert(!http::stream_constructible<missing_stream_type>);
        static_assert(!http::stream_accepting<missing_stream_type>);

        static_assert(!http::stream_constructible<missing_uni_open>);
        static_assert(http::stream_accepting<missing_uni_open>);
        static_assert(!http::stream_factory<missing_uni_open>);

        static_assert(!http::stream_constructible<missing_bidi_open>);
        static_assert(!http::stream_factory<missing_bidi_open>);

        static_assert(http::stream_constructible<missing_accept>);
        static_assert(!http::stream_accepting<missing_accept>);
        static_assert(!http::stream_factory<missing_accept>);

        static_assert(http::stream_constructible<unconstrained_completion_factory>);
        static_assert(http::stream_accepting<unconstrained_completion_factory>);
        static_assert(!http::stream_factory<unconstrained_completion_factory>);
    };

    // Internal machinery test: opening streams through the factory assigns a
    // distinct identity to each handle.
    "factory_assigns_unique_stream_identity"_test = [] {
        model_stream_factory factory;
        auto first = factory.async_open_bidirectional(std::stop_token{}).await_resume();
        auto second = factory.async_open_bidirectional(std::stop_token{}).await_resume();
        expect(first.identifier().value != second.identifier().value);
    };

    // Internal machinery test: direction is carried on the returned handle,
    // not inferred from a numeric id by the application.
    "factory_reports_stream_direction"_test = [] {
        model_stream_factory factory;
        auto bidi = factory.async_open_bidirectional(std::stop_token{}).await_resume();
        auto uni = factory.async_open_unidirectional(std::stop_token{}).await_resume();
        auto accepted = factory.async_accept(std::stop_token{}).await_resume();

        expect(bidi.access() == http::stream_access::bidirectional);
        expect(uni.access() == http::stream_access::send_only);
        expect(accepted.access() == http::stream_access::receive_only);
    };

    // Internal machinery test: an accept operation must report ready only
    // after a peer stream has actually been announced. Returning a fabricated
    // stream from an empty queue would make an endpoint accept loop spin.
    "mock_factory_accept_waits_for_announced_stream"_test = [] {
        pipe input, output;
        mock_stream_factory factory{input, output};

        auto pending = factory.async_accept(std::stop_token{});
        expect(!pending.await_ready());

        factory.announce(3, http::stream_access::receive_only);
        expect(pending.await_ready());
        auto accepted = pending.await_resume();
        expect(accepted.identifier().value == 3_u);
        expect(accepted.access() == http::stream_access::receive_only);
    };

    // Internal machinery test: the factory is not copyable, so no copy path
    // can implicitly create a stream.
    "factory_copy_does_not_open_streams"_test = [] {
        static_assert(!std::copy_constructible<model_stream_factory>);
    };
};

} // namespace httpant::testing
