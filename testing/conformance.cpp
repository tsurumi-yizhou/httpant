#include <boost/ut.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "test_support.hpp"

import httpant;

namespace httpant::testing {

using namespace boost::ut;
using namespace std::literals;

namespace {

inline void append_bytes(std::vector<std::byte>& dst, std::span<const std::byte> src) {
    dst.insert(dst.end(), src.begin(), src.end());
}

[[nodiscard]] auto encode_h3_varint(std::uint64_t value) -> std::vector<std::byte> {
    std::vector<std::byte> out;
    if (value < (1ull << 6)) {
        out.push_back(std::byte{static_cast<unsigned char>(value)});
        return out;
    }
    if (value < (1ull << 14)) {
        auto encoded = static_cast<std::uint16_t>(value) | 0x4000u;
        out.push_back(std::byte{static_cast<unsigned char>((encoded >> 8) & 0xff)});
        out.push_back(std::byte{static_cast<unsigned char>(encoded & 0xff)});
        return out;
    }
    if (value < (1ull << 30)) {
        auto encoded = static_cast<std::uint32_t>(value) | 0x80000000u;
        for (int shift = 24; shift >= 0; shift -= 8)
            out.push_back(std::byte{static_cast<unsigned char>((encoded >> shift) & 0xff)});
        return out;
    }

    auto encoded = value | 0xc000000000000000ull;
    for (int shift = 56; shift >= 0; shift -= 8)
        out.push_back(std::byte{static_cast<unsigned char>((encoded >> shift) & 0xff)});
    return out;
}

[[nodiscard]] auto make_h3_frame(std::uint64_t type, std::span<const std::byte> payload) -> std::vector<std::byte> {
    auto out = encode_h3_varint(type);
    auto length = encode_h3_varint(payload.size());
    append_bytes(out, length);
    append_bytes(out, payload);
    return out;
}

[[nodiscard]] auto make_h3_frame(std::uint64_t type, std::uint64_t value) -> std::vector<std::byte> {
    auto payload = encode_h3_varint(value);
    return make_h3_frame(type, std::span<const std::byte>{payload.data(), payload.size()});
}

[[nodiscard]] auto make_h3_control_stream(std::span<const std::byte> frames) -> std::vector<std::byte> {
    auto out = encode_h3_varint(0x00);
    append_bytes(out, frames);
    return out;
}

inline void feed_recorded_writes(auto& endpoint, const std::vector<recorded_write>& writes) {
    for (auto& write : writes)
        endpoint.feed(write.stream_id, std::span<const std::byte>{write.data.data(), write.data.size()}, write.fin);
}

} // namespace

static suite<"conformance"> conformance_suite = [] {
    "request_serializer_does_not_add_content_length_when_transfer_encoding_exists"_test = [] {
        auto wire = bytes_to_string(http::serialize(http::request{
            .method = http::method::POST,
            .target = "/submit",
            .fields = {{"host", "example.com"}, {"transfer-encoding", "chunked"}},
            .body = make_body("payload"),
        }));

        expect(!wire.contains("content-length:"sv));
    };

    "response_serializer_does_not_add_content_length_when_transfer_encoding_exists"_test = [] {
        auto wire = bytes_to_string(http::serialize(http::response{
            .status = 200,
            .reason = {},
            .fields = {{"transfer-encoding", "chunked"}},
            .body = make_body("payload"),
        }));

        expect(!wire.contains("content-length:"sv));
    };

    "requests_without_host_are_rejected"_test = [] {
        pipe c2s, s2c;
        mock_stream transport{.input = c2s, .output = s2c};

        push_text(c2s, "GET / HTTP/1.1\r\n\r\n");
        c2s.closed = true;

        http::server_v1<mock_stream> server{transport};
        auto threw = false;
        try {
            static_cast<void>(run_sync(server.receive()));
        } catch (...) {
            threw = true;
        }

        expect(threw);
    };

    "requests_with_multiple_host_fields_are_rejected"_test = [] {
        pipe c2s, s2c;
        mock_stream transport{.input = c2s, .output = s2c};

        push_text(c2s,
            "GET / HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "Host: duplicate.example.com\r\n\r\n");
        c2s.closed = true;

        http::server_v1<mock_stream> server{transport};
        auto threw = false;
        try {
            static_cast<void>(run_sync(server.receive()));
        } catch (...) {
            threw = true;
        }

        expect(threw);
    };

    "incomplete_content_length_responses_fail"_test = [] {
        pipe c2s, s2c;
        mock_stream transport{.input = s2c, .output = c2s};
        http::client_v1<mock_stream> client{transport};

        push_text(s2c, "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhi");
        s2c.closed = true;

        auto threw = false;
        try {
            static_cast<void>(run_sync(client.request(basic_get("/partial"))));
        } catch (...) {
            threw = true;
        }

        expect(threw);
    };

    "http2_client_handshake_requires_server_settings"_test = [] {
        pipe c2s, s2c;
        mock_stream transport{.input = s2c, .output = c2s};

        http::client_v2<mock_stream> client{transport};
        auto threw = false;
        try {
            run_sync(client.handshake());
        } catch (...) {
            threw = true;
        }

        expect(threw);
    };

    "http2_server_handshake_requires_client_preface"_test = [] {
        pipe c2s, s2c;
        mock_stream transport{.input = c2s, .output = s2c};

        http::server_v2<mock_stream> server{transport};
        auto threw = false;
        try {
            run_sync(server.handshake());
        } catch (...) {
            threw = true;
        }

        expect(threw);
    };

    "http2_requests_require_complete_final_responses"_test = [] {
        pipe c2s, s2c;
        mock_stream transport{.input = s2c, .output = c2s};

        http::client_v2<mock_stream> client{transport};
        auto threw = false;
        try {
            auto response = run_sync(client.request(basic_get("/h2")));
            expect(response.status == 200_u);
        } catch (...) {
            threw = true;
        }

        expect(threw);
    };

    "http2_goaway_handling_is_implemented"_test = [] {
        pipe c2s, s2c;
        mock_stream transport{.input = s2c, .output = c2s};

        push_http2_settings_frame(s2c);
        push_http2_goaway_frame(s2c);
        s2c.closed = true;

        http::client_v2<mock_stream> client{transport};
        run_sync(client.handshake());

        expect(client.goaway_received());

        auto threw = false;
        try {
            static_cast<void>(run_sync(client.request(basic_get("/after-goaway"))));
        } catch (...) {
            threw = true;
        }

        expect(threw);
    };

    "http2_server_push_is_implemented"_test = [] {
        async_pipe c2s{};
        async_pipe s2c{};
        async_mock_stream client_transport{.input = s2c, .output = c2s};
        async_mock_stream server_transport{.input = c2s, .output = s2c};

        http::client_v2<async_mock_stream> client{client_transport};
        http::server_v2<async_mock_stream> server{server_transport};

        auto accept_request = [&]() -> http::task<http::request> {
            co_await server.handshake();
            co_return co_await server.receive();
        };

        auto server_request = accept_request();
        server_request.start();
        run_sync(client.handshake());

        auto client_request = client.request(basic_get("/index.html"));
        client_request.start();

        auto request = run_sync([&]() -> http::task<http::request> {
            co_return co_await std::move(server_request);
        }());
        expect(request.target == "/index.html"sv);
        expect(server.last_stream_id() == 1_i);

        auto promised_stream_id = run_sync(server.push(
            server.last_stream_id(),
            basic_get("/style.css"),
            http::response{
                .status = 200,
                .reason = {},
                .fields = {{"content-type", "text/css"}},
                .body = make_body("body{}"),
            }));
        expect(promised_stream_id > 1_i);

        run_sync(server.respond(
            server.last_stream_id(),
            http::response{
                .status = 200,
                .reason = {},
                .fields = {{"content-type", "text/html"}},
                .body = make_body("<html/>"),
            }));

        auto response = run_sync([&]() -> http::task<http::response> {
            co_return co_await std::move(client_request);
        }());
        expect(response.status == 200_u);
        expect(read_body_text(response.body) == "<html/>"sv);

        auto pushed = client.take_push();
        expect(static_cast<bool>(pushed));
        expect(pushed->associated_stream_id == 1_i);
        expect(pushed->stream_id == promised_stream_id);
        expect(pushed->promised_request.target == "/style.css"sv);
        expect(pushed->pushed_response.status == 200_u);
        expect(read_body_text(pushed->pushed_response.body) == "body{}"sv);
    };

    "http2_flow_control_state_is_implemented"_test = [] {
        pipe c2s, s2c;
        mock_stream transport{.input = s2c, .output = c2s};

        push_http2_settings_frame(s2c);
        push_http2_window_update_frame(s2c, 1024);
        s2c.closed = true;

        http::client_v2<mock_stream> client{transport};
        run_sync(client.handshake());

        expect(client.remote_window_size() == 66559_i);
    };

    "http3_requests_do_not_complete_before_a_response_arrives"_test = [] {
        pipe c2s, s2c;
        mock_multiplexed_stream transport{.input = s2c, .output = c2s};

        http::client_v3<mock_multiplexed_stream> client{transport};
        run_sync(client.handshake(2, 6, 10));

        auto threw = false;
        try {
            auto response = run_sync(client.request(basic_get("/h3"), 0));
            expect(response.status == 200_u);
        } catch (...) {
            threw = true;
        }

        expect(threw);
    };

    "http3_max_push_id_management_is_implemented"_test = [] {
        recording_multiplexed_transport client_transport{};
        recording_multiplexed_transport server_transport{};

        http::client_v3<recording_multiplexed_transport> client{client_transport};
        http::server_v3<recording_multiplexed_transport> server{server_transport};

        run_sync(client.handshake(2, 6, 10));
        auto client_handshake = client_transport.take_writes();
        run_sync(server.handshake(3, 7, 11));
        auto server_handshake = server_transport.take_writes();

        feed_recorded_writes(server, client_handshake);
        feed_recorded_writes(client, server_handshake);

        run_sync(client.allow_pushes(4));
        auto max_push_update = client_transport.take_writes();
        feed_recorded_writes(server, max_push_update);

        auto threw = false;
        try {
            auto lower = make_h3_frame(0x0d, 3);
            server.feed(2, std::span<const std::byte>{lower.data(), lower.size()}, false);
        } catch (...) {
            threw = true;
        }

        expect(threw);
    };

    "http3_goaway_support_is_implemented"_test = [] {
        recording_multiplexed_transport transport{};
        http::client_v3<recording_multiplexed_transport> client{transport};
        run_sync(client.handshake(2, 6, 10));
        static_cast<void>(transport.take_writes());

        auto settings = make_h3_frame(0x04, std::span<const std::byte>{});
        auto goaway = make_h3_frame(0x07, 0);
        std::vector<std::byte> frames;
        append_bytes(frames, settings);
        append_bytes(frames, goaway);
        auto control = make_h3_control_stream(std::span<const std::byte>{frames.data(), frames.size()});

        client.feed(3, std::span<const std::byte>{control.data(), control.size()}, false);
        expect(client.goaway_received());

        auto threw = false;
        try {
            static_cast<void>(run_sync(client.request(basic_get("/after-goaway"), 0)));
        } catch (...) {
            threw = true;
        }

        expect(threw);
    };

    "http3_push_stream_roundtrip_is_implemented"_test = [] {
        recording_multiplexed_transport client_transport{};
        recording_multiplexed_transport server_transport{};

        http::client_v3<recording_multiplexed_transport> client{client_transport};
        http::server_v3<recording_multiplexed_transport> server{server_transport};

        run_sync(client.handshake(2, 6, 10));
        auto client_handshake = client_transport.take_writes();
        run_sync(server.handshake(3, 7, 11));
        auto server_handshake = server_transport.take_writes();

        feed_recorded_writes(server, client_handshake);
        feed_recorded_writes(client, server_handshake);

        run_sync(client.allow_pushes(4));
        auto push_budget = client_transport.take_writes();
        feed_recorded_writes(server, push_budget);

        auto push_id = run_sync(server.push(
            0,
            15,
            basic_get("/style.css"),
            http::response{
                .status = 200,
                .reason = {},
                .fields = {{"content-type", "text/css"}},
                .body = make_body("body{}"),
            }));
        expect(push_id == 0_u);

        auto pushed_writes = server_transport.take_writes();
        feed_recorded_writes(client, pushed_writes);

        auto pushed = client.take_push();
        expect(static_cast<bool>(pushed));
        expect(pushed->push_id == 0_u);
        expect(pushed->associated_stream_id == 0_i);
        expect(pushed->stream_id == 15_i);
        expect(pushed->promised_request.target == "/style.css"sv);
        expect(pushed->promised_request.authority == "example.com"sv);
        expect(pushed->pushed_response.status == 200_u);
        expect(read_body_text(pushed->pushed_response.body) == "body{}"sv);
    };

    "http3_control_stream_validation_is_implemented"_test = [] {
        recording_multiplexed_transport transport{};
        http::client_v3<recording_multiplexed_transport> client{transport};

        auto goaway = make_h3_frame(0x07, 0);
        auto invalid = make_h3_control_stream(std::span<const std::byte>{goaway.data(), goaway.size()});

        auto threw = false;
        try {
            client.feed(3, std::span<const std::byte>{invalid.data(), invalid.size()}, false);
        } catch (...) {
            threw = true;
        }

        expect(threw);
    };
};

} // namespace httpant::testing