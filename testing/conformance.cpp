#include <boost/ut.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

#include "test_support.hpp"

import httpant;

namespace httpant::testing {

using namespace boost::ut;
using namespace std::literals;

namespace {

// RFC 9114 §8.1 — HTTP/3 application error codes used at the public
// transport boundary. Tests intentionally define the wire values locally
// instead of depending on nghttp3's implementation headers.
inline constexpr std::uint64_t h3_request_incomplete = 0x010d;
inline constexpr std::uint64_t h3_message_error = 0x010e;
inline constexpr std::uint64_t h3_stream_creation_error = 0x0103;
inline constexpr std::uint64_t h3_closed_critical_stream = 0x0104;
inline constexpr std::uint64_t h3_excessive_load = 0x0107;
inline constexpr std::uint64_t h3_frame_error = 0x0106;
inline constexpr std::uint64_t h3_id_error = 0x0108;
inline constexpr std::uint64_t h3_missing_settings = 0x010a;
inline constexpr std::uint64_t qpack_decompression_failed = 0x0200;
inline constexpr std::uint64_t qpack_encoder_stream_error = 0x0201;
inline constexpr std::uint64_t qpack_decoder_stream_error = 0x0202;

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

struct parsed_h2_frame {
    std::uint8_t type{0};
    std::uint8_t flags{0};
    std::uint32_t stream_id{0};
    std::vector<std::byte> payload{};
};

// Parses the client's output bytes: the 24-octet client connection preface
// (RFC 9113 §3.4 — "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n") followed by frames in
// the §4.1 layout.
[[nodiscard]] inline auto parse_h2_client_output(std::span<const std::byte> data) -> std::vector<parsed_h2_frame> {
    std::vector<parsed_h2_frame> frames;
    std::size_t pos = 24;
    while (pos + 9 <= data.size()) {
        auto length = (static_cast<std::size_t>(data[pos]) << 16) |
                      (static_cast<std::size_t>(data[pos + 1]) << 8) |
                      static_cast<std::size_t>(data[pos + 2]);
        parsed_h2_frame frame;
        frame.type = static_cast<std::uint8_t>(data[pos + 3]);
        frame.flags = static_cast<std::uint8_t>(data[pos + 4]);
        frame.stream_id = (static_cast<std::uint32_t>(data[pos + 5]) << 24) |
                          (static_cast<std::uint32_t>(data[pos + 6]) << 16) |
                          (static_cast<std::uint32_t>(data[pos + 7]) << 8) |
                          static_cast<std::uint32_t>(data[pos + 8]);
        frame.payload.assign(
            data.begin() + static_cast<std::ptrdiff_t>(pos + 9),
            data.begin() + static_cast<std::ptrdiff_t>(pos + 9 + length));
        frames.push_back(std::move(frame));
        pos += 9 + length;
    }
    return frames;
}

// QPACK field line with a literal name (RFC 9204 §4.5.6): 001 + N(0) + H(0) +
// 3-bit name length prefix, the name bytes, then a 7-bit value length prefix
// and the value. Prefix integers follow RFC 7541 §5.1 continuation.
[[nodiscard]] inline auto make_h3_field_line(std::string_view name, std::string_view value) -> std::vector<std::byte> {
    std::vector<std::byte> out;
    auto append_prefix = [&out](std::uint8_t lead_bits, std::uint8_t prefix_max, std::size_t value) {
        if (value < prefix_max) {
            out.push_back(std::byte{static_cast<std::uint8_t>(lead_bits | value)});
            return;
        }
        out.push_back(std::byte{static_cast<std::uint8_t>(lead_bits | prefix_max)});
        auto rest = value - prefix_max;
        while (rest >= 128) {
            out.push_back(std::byte{static_cast<std::uint8_t>(0x80 | (rest & 0x7f))});
            rest >>= 7;
        }
        out.push_back(std::byte{static_cast<std::uint8_t>(rest)});
    };
    append_prefix(0x20, 7, name.size());
    for (char c : name) out.push_back(static_cast<std::byte>(c));
    append_prefix(0x00, 127, value.size());
    for (char c : value) out.push_back(static_cast<std::byte>(c));
    return out;
}

// A QPACK field section: a two-byte zero prefix (RFC 9204 §4.5.1 — no
// dynamic-table references, base 0) followed by the field lines.
[[nodiscard]] inline auto make_h3_field_section(
    std::initializer_list<std::pair<std::string_view, std::string_view>> fields)
    -> std::vector<std::byte> {
    std::vector<std::byte> out{std::byte{0x00}, std::byte{0x00}};
    for (auto [name, value] : fields)
        append_bytes(out, make_h3_field_line(name, value));
    return out;
}

struct parsed_h3_frame {
    std::uint64_t type{0};
    std::vector<std::byte> payload{};
};

struct measured_body {
    std::vector<std::byte> data{};
    std::size_t offset{0};
    std::size_t largest_request{0};
    std::size_t reads{0};

    struct read_awaiter {
        measured_body& body;
        std::span<std::byte> output;

        bool await_ready() const noexcept { return true; }
        void await_suspend(std::coroutine_handle<>) const noexcept {}
        auto await_resume() -> std::size_t {
            body.largest_request = std::max(body.largest_request, output.size());
            ++body.reads;
            auto size = std::min(output.size(), body.data.size() - body.offset);
            std::copy_n(body.data.data() + body.offset, size, output.data());
            body.offset += size;
            return size;
        }
    };

    auto async_read(std::span<std::byte> output, std::stop_token) -> read_awaiter {
        return {*this, output};
    }
};

[[nodiscard]] inline auto decode_h3_varint(std::span<const std::byte> bytes, std::size_t& len) -> std::uint64_t {
    auto first = static_cast<unsigned char>(bytes[0]);
    auto prefix = static_cast<std::uint64_t>(first & 0x3f);
    switch (first >> 6) {
        case 0: len = 1; return prefix;
        case 1: len = 2; return (prefix << 8) | static_cast<unsigned char>(bytes[1]);
        case 2:
            len = 4;
            break;
        default:
            len = 8;
            break;
    }
    std::uint64_t value = prefix;
    for (std::size_t i = 1; i < len; ++i)
        value = (value << 8) | static_cast<unsigned char>(bytes[i]);
    return value;
}

[[nodiscard]] inline auto parse_h3_frames(std::span<const std::byte> data) -> std::vector<parsed_h3_frame> {
    std::vector<parsed_h3_frame> frames;
    std::size_t pos = 0;
    while (pos < data.size()) {
        std::size_t type_len = 0;
        auto type = decode_h3_varint(data.subspan(pos), type_len);
        pos += type_len;
        std::size_t len_len = 0;
        auto len = decode_h3_varint(data.subspan(pos), len_len);
        pos += len_len;
        parsed_h3_frame frame;
        frame.type = type;
        frame.payload.assign(
            data.begin() + static_cast<std::ptrdiff_t>(pos),
            data.begin() + static_cast<std::ptrdiff_t>(pos + len));
        frames.push_back(std::move(frame));
        pos += len;
    }
    return frames;
}

using h2_server = http::v2::server<async_mock_stream>;
using h2_req = h2_server::incoming_request;
using h2_res = http::received<http::response, http::v2::body_reader>;

// Drives |operation| and expects it to surface a recorded H3 connection
// failure as a protocol_error whose action closes the connection carrying
// |expected_code| (RFC 9114 §8.1).
template <typename Operation>
void expect_h3_connection_close(Operation&& operation, std::uint64_t expected_code) {
    auto threw = false;
    try {
        static_cast<void>(run_sync(operation()));
    } catch (const http::protocol_error& failure) {
        expect(std::holds_alternative<http::close_connection>(failure.action()));
        const auto& close = std::get<http::close_connection>(failure.action());
        expect(close.code.has_value());
        expect(std::holds_alternative<http::v3::error_code>(*close.code));
        expect(std::get<http::v3::error_code>(*close.code).value == expected_code);
        threw = true;
    }
    expect(threw);
}

} // namespace

static suite<"conformance"> conformance_suite = [] {
    // RFC 9112 §6.2 — "A sender MUST NOT send a Content-Length header field in any
    // message that contains a Transfer-Encoding header field."
    "request_serializer_does_not_add_content_length_when_transfer_encoding_exists"_test = [] {
        auto body = make_body("payload");
        auto wire = bytes_to_string(run_sync(http::v1::serialize(http::request{
            .method = http::method::POST,
            .target = "/submit",
            .fields = {{"host", "example.com"}, {"transfer-encoding", "chunked"}},
        }, body)));

        expect(!wire.contains("content-length:"sv));
    };

    // RFC 9112 §6.2 — "A sender MUST NOT send a Content-Length header field in any
    // message that contains a Transfer-Encoding header field."
    "response_serializer_does_not_add_content_length_when_transfer_encoding_exists"_test = [] {
        auto body = make_body("payload");
        auto wire = bytes_to_string(run_sync(http::v1::serialize(http::response{
            .status = 200,
            .reason = {},
            .fields = {{"transfer-encoding", "chunked"}},
        }, body)));

        expect(!wire.contains("content-length:"sv));
    };

    // RFC 9112 §3.2 — "A server MUST respond with a 400 (Bad Request) status code to any
    // HTTP/1.1 request message that lacks a Host header field ..."
    "requests_without_host_are_rejected"_test = [] {
        pipe c2s, s2c;
        mock_stream transport{.input = c2s, .output = s2c};

        push_text(c2s, "GET / HTTP/1.1\r\n\r\n");
        c2s.closed = true;

        http::v1::server<mock_stream> server{transport};
        auto threw = false;
        try {
            static_cast<void>(run_sync(http::coroutine::receive(server)));
        } catch (...) {
            threw = true;
        }

        expect(threw);
    };

    // RFC 9112 §3.2 — "A server MUST respond with a 400 (Bad Request) status code to any
    // ... request message that contains more than one Host header field line ..."
    "requests_with_multiple_host_fields_are_rejected"_test = [] {
        pipe c2s, s2c;
        mock_stream transport{.input = c2s, .output = s2c};

        push_text(c2s,
            "GET / HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "Host: duplicate.example.com\r\n\r\n");
        c2s.closed = true;

        http::v1::server<mock_stream> server{transport};
        auto threw = false;
        try {
            static_cast<void>(run_sync(http::coroutine::receive(server)));
        } catch (...) {
            threw = true;
        }

        expect(threw);
    };

    // RFC 9112 §6.3 — "If a valid Content-Length header field is present without
    // Transfer-Encoding, its decimal value defines the expected message body length in
    // octets. If the sender closes the connection or the recipient times out before the
    // indicated number of octets are received, the recipient MUST consider the message to
    // be incomplete and close the connection."
    "incomplete_content_length_responses_fail"_test = [] {
        pipe c2s, s2c;
        mock_stream transport{.input = s2c, .output = c2s};
        http::v1::client<mock_stream> client{transport};

        push_text(s2c, "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhi");
        s2c.closed = true;

        // The head is returned once headers arrive; the truncation surfaces when
        // the body is drained to completion.
        auto received = run_sync(http::coroutine::request(client, basic_get("/partial")));
        auto threw = false;
        try {
            static_cast<void>(run_sync(drain_body(received.body)));
        } catch (...) {
            threw = true;
        }

        expect(threw);
    };

    // RFC 9113 §3.4 — "The server connection preface consists of a potentially empty
    // SETTINGS frame ... that MUST be the first frame the server sends in the HTTP/2
    // connection."
    "http2_client_handshake_requires_server_settings"_test = [] {
        pipe c2s, s2c;
        mock_stream transport{.input = s2c, .output = c2s};

        http::v2::client<mock_stream> client{transport};
        auto threw = false;
        try {
            run_sync(http::coroutine::start(client));
        } catch (...) {
            threw = true;
        }

        expect(threw);
    };

    // RFC 9113 §3.4 — "The client connection preface starts with a sequence of 24 octets
    // ... This sequence MUST be followed by a SETTINGS frame ..." An HTTP/2 server must
    // receive the client preface before it can complete its handshake.
    "http2_server_handshake_requires_client_preface"_test = [] {
        pipe c2s, s2c;
        mock_stream transport{.input = c2s, .output = s2c};

        http::v2::server<mock_stream> server{transport};
        auto threw = false;
        try {
            run_sync(http::coroutine::start(server));
        } catch (...) {
            threw = true;
        }

        expect(threw);
    };

    // RFC 9113 §8.1 — "An HTTP response is complete after the server sends -- or the client
    // receives -- a frame with the END_STREAM flag set ..." A request whose response stream
    // is closed without a complete response is aborted.
    "http2_requests_require_complete_final_responses"_test = [] {
        pipe c2s, s2c;
        mock_stream transport{.input = s2c, .output = c2s};

        http::v2::client<mock_stream> client{transport};
        auto threw = false;
        try {
            auto response = run_sync(http::coroutine::request(client, basic_get("/h2")));
            static_cast<void>(run_sync(drain_body(response.body)));
            expect(response.head.status == 200_u);
        } catch (...) {
            threw = true;
        }

        expect(threw);
    };

    // RFC 9113 §6.8 — "Receivers of a GOAWAY frame MUST NOT open additional streams on the
    // connection, although a new connection can be established for new streams."
    "http2_goaway_handling_is_implemented"_test = [] {
        pipe c2s, s2c;
        mock_stream transport{.input = s2c, .output = c2s};

        push_http2_settings_frame(s2c);
        push_http2_goaway_frame(s2c);
        s2c.closed = true;

        http::v2::client<mock_stream> client{transport};
        run_sync(http::coroutine::start(client));

        expect(client.goaway_received());

        auto threw = false;
        try {
            static_cast<void>(run_sync(http::coroutine::request(client, basic_get("/after-goaway"))));
        } catch (const http::protocol_error& failure) {
            expect(failure.info().condition == http::error_condition::goaway_rejected);
            expect(failure.info().retryable);
            expect(!failure.info().exchange_identity.has_value());
            expect(std::holds_alternative<http::no_action>(failure.action()));
            threw = true;
        }

        expect(threw);
    };

    // RFC 9113 §8.1 — "For a response only, a server MAY send any number of interim
    // responses before the HEADERS frame containing a final response." The client must
    // not complete the exchange on an interim (1xx) header block: the final response's
    // status and fields are the ones delivered, and interim fields never leak into it.
    "http2_client_skips_interim_responses"_test = [] {
        async_pipe c2s{};
        async_pipe s2c{};
        async_mock_stream transport{.input = s2c, .output = c2s};

        http::v2::client<async_mock_stream> client{transport};
        push_http2_settings_frame(s2c);
        run_sync(http::coroutine::start(client));

        auto client_request = http::coroutine::request(client, basic_get("/early"));
        client_request.start();

        // HPACK (RFC 7541 §6.2.2): 0x08 is a literal without indexing whose name
        // is static index 8 (:status); 0x00 starts a literal without indexing
        // with a literal name. RFC 7541 §6.1: 0x88 is the indexed ":status: 200".
        const std::vector<std::byte> interim{
            std::byte{0x08}, std::byte{0x03}, std::byte{'1'}, std::byte{'0'}, std::byte{'3'},
            std::byte{0x00}, std::byte{0x06},
            std::byte{'x'}, std::byte{'-'}, std::byte{'h'}, std::byte{'i'}, std::byte{'n'}, std::byte{'t'},
            std::byte{0x01}, std::byte{'y'},
        };
        const std::vector<std::byte> final_block{
            std::byte{0x88},
            std::byte{0x00}, std::byte{0x07},
            std::byte{'x'}, std::byte{'-'}, std::byte{'f'}, std::byte{'i'},
            std::byte{'n'}, std::byte{'a'}, std::byte{'l'},
            std::byte{0x01}, std::byte{'z'},
        };
        // HEADERS (type 0x1): END_HEADERS (0x4) on the interim block, plus
        // END_STREAM (0x1) on the final one.
        push_http2_frame(s2c, 0x01, 0x04, 1, interim);
        push_http2_frame(s2c, 0x01, 0x05, 1, final_block);

        expect(client_request.done());
        auto response = run_sync(std::move(client_request));
        expect(response.head.status == 200_u);
        expect(!http::find_header(response.head.fields, "x-hint").has_value());
        auto final_field = http::find_header(response.head.fields, "x-final");
        expect(final_field.has_value());
        expect(*final_field == "z"sv);
    };

    // RFC 9113 §6.8 — "If the receiver of the GOAWAY has sent data on streams with a
    // higher stream identifier than what is indicated in the GOAWAY frame, those streams
    // are not or will not be processed." A request still waiting for its response when
    // GOAWAY covers its stream is rejected with the typed goaway_rejected condition
    // immediately, without waiting for the connection to close.
    "http2_goaway_rejects_pending_request"_test = [] {
        async_pipe c2s{};
        async_pipe s2c{};
        async_mock_stream transport{.input = s2c, .output = c2s};

        http::v2::client<async_mock_stream> client{transport};
        push_http2_settings_frame(s2c);
        run_sync(http::coroutine::start(client));

        auto client_request = http::coroutine::request(client, basic_get("/pending"));
        client_request.start();
        expect(!client_request.done());

        // last_stream_id 0: the pending request on stream 1 was not processed.
        push_http2_goaway_frame(s2c, 0);

        expect(client_request.done());
        auto threw = false;
        try {
            static_cast<void>(run_sync(std::move(client_request)));
        } catch (const http::protocol_error& failure) {
            expect(failure.info().condition == http::error_condition::goaway_rejected);
            expect(failure.info().retryable);
            threw = true;
        }
        expect(threw);
    };

    // RFC 9113 §8.1.1 — "Malformed requests or responses that are detected MUST be
    // treated as a stream error (Section 5.4.2) of type PROTOCOL_ERROR." A response
    // whose :status is not a 3-digit integer is rejected by nghttp2's own HTTP
    // messaging validation before httpant's :status parser can run, so the stream
    // reset asserted here is emitted by the backend, not by httpant. httpant's own
    // :status guard (a well-formed but out-of-range value, RFC 9110 §15) is covered
    // by http2_out_of_range_status_resets_stream_with_protocol_error.
    "http2_malformed_status_resets_stream_with_protocol_error"_test = [] {
        async_pipe c2s{};
        async_pipe s2c{};
        async_mock_stream transport{.input = s2c, .output = c2s};

        http::v2::client<async_mock_stream> client{transport};
        push_http2_settings_frame(s2c);
        run_sync(http::coroutine::start(client));

        auto client_request = http::coroutine::request(client, basic_get("/bad-status"));
        client_request.start();

        // ":status: abc" — literal without indexing, static name index 8.
        const std::vector<std::byte> malformed{
            std::byte{0x08}, std::byte{0x03}, std::byte{'a'}, std::byte{'b'}, std::byte{'c'},
        };
        push_http2_frame(s2c, 0x01, 0x05, 1, malformed);

        auto threw = false;
        try {
            static_cast<void>(run_sync(std::move(client_request)));
        } catch (...) {
            threw = true;
        }
        expect(threw);

        // The client output carries RST_STREAM (type 0x3) on stream 1 with
        // error code PROTOCOL_ERROR (0x1).
        auto reset_found = false;
        for (const auto& frame : parse_h2_client_output(c2s.buffer)) {
            if (frame.type != 0x03 || frame.stream_id != 1)
                continue;
            const std::vector<std::byte> protocol_error{
                std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x01}};
            expect(frame.payload == protocol_error);
            reset_found = true;
        }
        expect(reset_found);
    };

    // Internal machinery test: a transport that fails the very first write is
    // not RFC behavior. endpoint_runtime::start() must treat the flush failure
    // as terminal — the read driver never launches, so peer SETTINGS can never
    // arrive — and latch it as the connection error: start() throws, a retried
    // start() stays latched (no driver relaunch) and its handshake phase
    // rethrows the recorded error instead of parking, and a request fails fast
    // instead of writing onto the broken transport.
    "http2_failed_start_latches_connection_error"_test = [] {
        pipe c2s{};
        pipe s2c{};
        write_failing_stream transport{.input = s2c, .output = c2s};

        http::v2::client<write_failing_stream> client{transport};

        auto threw = false;
        try {
            run_sync(http::coroutine::start(client));
        } catch (const std::runtime_error& failure) {
            expect(std::string_view{failure.what()} ==
                   "write_failing_stream: scripted write failure"sv);
            threw = true;
        }
        expect(threw);

        // The retried start() is a no-op on the started_ latch; the handshake
        // phase then fails fast with the recorded connection error.
        threw = false;
        try {
            run_sync(http::coroutine::start(client));
        } catch (const std::runtime_error& failure) {
            expect(std::string_view{failure.what()} ==
                   "write_failing_stream: scripted write failure"sv);
            threw = true;
        }
        expect(threw);

        threw = false;
        try {
            static_cast<void>(run_sync(http::coroutine::request(
                client, basic_get("/after-failure"))));
        } catch (const std::runtime_error&) {
            threw = true;
        }
        expect(threw);
    };

    // RFC 9113 §6.9.1 — "The receiver of a frame sends a WINDOW_UPDATE frame as it
    // consumes data and frees up space in flow-control windows." Credit follows the
    // application's body reads, so an unread body cannot consume unbounded memory.
    // The peer's batching strategy is its own business, so the client advertises a
    // 10-octet initial window (RFC 9113 §6.5.2 SETTINGS_INITIAL_WINDOW_SIZE): a
    // 5-octet read must then free half the window and surface as WINDOW_UPDATE.
    "http2_flow_control_credit_follows_body_reads"_test = [] {
        async_pipe c2s{};
        async_pipe s2c{};
        async_mock_stream transport{.input = s2c, .output = c2s};

        http::v2::client<async_mock_stream> client{transport};
        push_http2_settings_frame(s2c);
        run_sync(http::coroutine::start(client));

        const std::array window{
            http::v2::setting{
                .name = http::v2::setting_name::initial_window_size,
                .value = 10,
            },
        };
        static_cast<void>(run_sync(client.update_settings(window)));
        // Local settings apply as the peer acknowledges them, oldest first:
        // the first ACK settles the handshake SETTINGS, the second the window.
        push_http2_settings_ack_frame(s2c);
        push_http2_settings_ack_frame(s2c);

        auto client_request = http::coroutine::request(client, basic_get("/window"));
        client_request.start();

        // Final 200 (no END_STREAM yet), then a 5-octet DATA frame (type 0x0).
        const std::vector<std::byte> final_block{std::byte{0x88}};
        push_http2_frame(s2c, 0x01, 0x04, 1, final_block);
        expect(client_request.done());
        auto response = run_sync(std::move(client_request));

        const std::vector<std::byte> content{
            std::byte{'h'}, std::byte{'e'}, std::byte{'l'}, std::byte{'l'}, std::byte{'o'}};
        push_http2_frame(s2c, 0x00, 0x00, 1, content);

        // WINDOW_UPDATE (type 0x8) is absent until the application reads.
        for (const auto& frame : parse_h2_client_output(c2s.buffer))
            expect(frame.type != std::uint8_t{0x08});

        std::array<std::byte, 8> output{};
        auto size = run_sync(response.body.async_read(output, std::stop_token{}));
        expect(size == 5_u);
        expect(bytes_to_string(std::span{output}.first(size)) == "hello"sv);

        auto update_found = false;
        for (const auto& frame : parse_h2_client_output(c2s.buffer)) {
            if (frame.type != 0x08)
                continue;
            const std::vector<std::byte> increment{
                std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x05}};
            expect(frame.payload == increment);
            update_found = true;
        }
        expect(update_found);

        // END_STREAM on an empty DATA frame completes the body.
        push_http2_frame(s2c, 0x00, 0x01, 1, std::span<const std::byte>{});
        auto rest = run_sync(response.body.async_read(output, std::stop_token{}));
        expect(rest == 0_u);
    };

    // Internal machinery test: cancellation of a suspended body read is not
    // HTTP RFC behavior. The wait must resolve exactly once, throwing
    // std::system_error{operation_canceled} — the transport cancellation
    // delivery convention.
    "http2_cancelled_body_read_throws_operation_canceled"_test = [] {
        async_pipe c2s{};
        async_pipe s2c{};
        async_mock_stream transport{.input = s2c, .output = c2s};

        http::v2::client<async_mock_stream> client{transport};
        push_http2_settings_frame(s2c);
        run_sync(http::coroutine::start(client));

        auto client_request = http::coroutine::request(client, basic_get("/hang"));
        client_request.start();

        // Final 200 header block (0x88: indexed ":status: 200", RFC 7541 §6.1)
        // without END_STREAM; the response body never arrives.
        const std::vector<std::byte> final_block{std::byte{0x88}};
        push_http2_frame(s2c, 0x01, 0x04, 1, final_block);
        expect(client_request.done());
        auto response = run_sync(std::move(client_request));

        std::stop_source stop;
        std::array<std::byte, 8> output{};
        auto completions = 0;
        auto cancelled = false;
        auto read = [&]() -> http::task<void> {
            try {
                static_cast<void>(co_await response.body.async_read(output, stop.get_token()));
            } catch (const std::system_error& error) {
                cancelled = error.code() == std::errc::operation_canceled;
            }
            ++completions;
        };
        auto pending = read();
        pending.start();
        expect(!pending.done());

        expect(stop.request_stop());
        expect(pending.done());
        expect(cancelled);
        expect(completions == 1_i);

        // A terminal frame arriving after the cancellation must not resume the
        // finished read a second time (the stop callback claimed the waiter
        // slot, so the driver's notify finds it empty).
        push_http2_frame(s2c, 0x00, 0x01, 1, std::span<const std::byte>{});
        expect(completions == 1_i);
    };

    // RFC 9113 §8.4 — "HTTP/2 allows a server to preemptively send (or "push") responses
    // (along with corresponding "promised" requests) to a client in association with a
    // previous client-initiated request."
    "http2_server_push_is_implemented"_test = [] {
        async_pipe c2s{};
        async_pipe s2c{};
        async_mock_stream client_transport{.input = s2c, .output = c2s};
        async_mock_stream server_transport{.input = c2s, .output = s2c};

        http::v2::client<async_mock_stream> client{client_transport};
        http::v2::server<async_mock_stream> server{server_transport};

        auto accept_request = [&]() -> http::task<h2_req> {
            co_await http::coroutine::start(server);
            co_return co_await http::coroutine::receive(server);
        };

        auto server_request = accept_request();
        server_request.start();
        run_sync(http::coroutine::start(client));

        auto client_request = http::coroutine::request(client, basic_get("/index.html"));
        client_request.start();

        auto received = run_sync([&]() -> http::task<h2_req> {
            co_return co_await std::move(server_request);
        }());
        expect(received.head.target == "/index.html"sv);
        static_cast<void>(run_sync(drain_body(received.body)));

        auto push_body = make_body("body{}");
        run_sync(server.push(
            received.token,
            basic_get("/style.css"),
            http::response{
                .status = 200,
                .reason = {},
                .fields = {{"content-type", "text/css"}},
            },
            push_body));

        auto response_body = make_body("<html/>");
        run_sync(http::coroutine::respond(server,
            std::move(received.token),
            http::response{
                .status = 200,
                .reason = {},
                .fields = {{"content-type", "text/html"}},
            },
            response_body));

        auto response = run_sync([&]() -> http::task<h2_res> {
            co_return co_await std::move(client_request);
        }());
        expect(response.head.status == 200_u);
        expect(read_body_text(response.body) == "<html/>"sv);

        auto pushed = client.take_push();
        expect(static_cast<bool>(pushed));
        expect(pushed->promised_request.target == "/style.css"sv);
        expect(pushed->pushed_response.status == 200_u);
        expect(read_body_text(pushed->body) == "body{}"sv);
    };

    // RFC 9113 §8.4 — "The server MUST include a value in the ":authority"
    // pseudo-header field for which the server is authoritative ... A client MUST
    // treat a PUSH_PROMISE for which the server is not authoritative as a stream
    // error ... of type PROTOCOL_ERROR." The client records the origin of its
    // first request and resets (and never delivers) a push for a different origin.
    "http2_client_rejects_non_authoritative_push"_test = [] {
        async_pipe c2s{};
        async_pipe s2c{};
        async_mock_stream client_transport{.input = s2c, .output = c2s};
        async_mock_stream server_transport{.input = c2s, .output = s2c};

        http::v2::client<async_mock_stream> client{client_transport};
        http::v2::server<async_mock_stream> server{server_transport};

        auto accept_request = [&]() -> http::task<h2_req> {
            co_await http::coroutine::start(server);
            co_return co_await http::coroutine::receive(server);
        };
        auto server_request = accept_request();
        server_request.start();
        run_sync(http::coroutine::start(client));

        auto client_request = http::coroutine::request(client, basic_get("/index.html"));
        client_request.start();

        auto received = run_sync([&]() -> http::task<h2_req> {
            co_return co_await std::move(server_request);
        }());
        expect(received.head.target == "/index.html"sv);
        static_cast<void>(run_sync(drain_body(received.body)));

        // A pushed request for a different authority than the connection origin.
        auto non_authoritative = basic_get("/evil.css");
        non_authoritative.authority = "evil.com";
        auto evil_body = make_body("evil{}");
        run_sync(server.push(
            received.token,
            std::move(non_authoritative),
            http::response{
                .status = 200,
                .reason = {},
                .fields = {{"content-type", "text/css"}},
            },
            evil_body));

        auto html_body = make_body("<html/>");
        run_sync(http::coroutine::respond(server,
            std::move(received.token),
            http::response{
                .status = 200,
                .reason = {},
                .fields = {{"content-type", "text/html"}},
            },
            html_body));

        auto response = run_sync([&]() -> http::task<h2_res> {
            co_return co_await std::move(client_request);
        }());
        expect(response.head.status == 200_u);

        // The non-authoritative push is reset, never delivered to take_push().
        expect(!client.take_push().has_value());
    };

    // RFC 9110 §9.3.2 — "The HEAD method is identical to GET except that the server MUST
    // NOT send content in the response."
    "http2_server_head_response_has_no_body"_test = [] {
        async_pipe c2s{};
        async_pipe s2c{};
        async_mock_stream client_transport{.input = s2c, .output = c2s};
        async_mock_stream server_transport{.input = c2s, .output = s2c};

        http::v2::client<async_mock_stream> client{client_transport};
        http::v2::server<async_mock_stream> server{server_transport};

        auto accept_request = [&]() -> http::task<h2_req> {
            co_await http::coroutine::start(server);
            co_return co_await http::coroutine::receive(server);
        };
        auto server_request = accept_request();
        server_request.start();
        run_sync(http::coroutine::start(client));

        auto client_request = http::coroutine::request(client, http::request{
            .method = http::method::HEAD,
            .target = "/resource",
            .scheme = "https",
            .authority = "example.com",
            .fields = {{"host", "example.com"}},
        });
        client_request.start();

        auto received = run_sync([&]() -> http::task<h2_req> {
            co_return co_await std::move(server_request);
        }());
        expect(received.head.method == http::method::HEAD);
        static_cast<void>(run_sync(drain_body(received.body)));

        auto html_body = make_body("<html/>");
        run_sync(http::coroutine::respond(server,
            std::move(received.token),
            http::response{
                .status = 200,
                .reason = {},
                .fields = {{"content-type", "text/html"}},
            },
            html_body));

        auto response = run_sync([&]() -> http::task<h2_res> {
            co_return co_await std::move(client_request);
        }());
        expect(response.head.status == 200_u);
        auto body = run_sync(drain_body(response.body));
        expect(body.empty());
    };

    // RFC 9113 §6.7 — "Receivers of a PING frame that does not include an ACK flag MUST send
    // a PING frame with the ACK flag set in response, with an identical frame payload."
    "http2_ping_round_trip_is_implemented"_test = [] {
        async_pipe c2s{};
        async_pipe s2c{};
        async_mock_stream client_transport{.input = s2c, .output = c2s};
        async_mock_stream server_transport{.input = c2s, .output = s2c};

        http::v2::client<async_mock_stream> client{client_transport};
        http::v2::server<async_mock_stream> server{server_transport};

        auto accept_request = [&]() -> http::task<h2_req> {
            co_await http::coroutine::start(server);
            co_return co_await http::coroutine::receive(server);
        };
        auto server_request = accept_request();
        server_request.start();
        run_sync(http::coroutine::start(client));

        run_sync(client.ping());

        // The server output must now hold the PING ACK: a 9-octet frame header (length 8,
        // type 0x06, flags ACK (0x01), stream identifier 0) followed by the echoed 8-octet
        // payload (the client sent an all-zero opaque payload).
        auto wire = s2c.buffer;
        auto ack_seen = false;
        for (std::size_t i = 0; i + 17 <= wire.size(); ++i) {
            auto p = reinterpret_cast<const std::uint8_t*>(wire.data() + i);
            if (p[0] == 0 && p[1] == 0 && p[2] == 8 && p[3] == 6 && p[4] == 1 &&
                p[5] == 0 && p[6] == 0 && p[7] == 0 && p[8] == 0) {
                auto payload_zero = true;
                for (std::size_t k = 9; k < 17; ++k) payload_zero = payload_zero && (p[k] == 0);
                if (payload_zero) {
                    ack_seen = true;
                    break;
                }
            }
        }
        expect(ack_seen);

        // A subsequent request/response exchange forces the client to read and process the
        // ACK before the response, proving the round trip left the session healthy.
        auto client_request = http::coroutine::request(client, basic_get("/ping"));
        client_request.start();
        auto received = run_sync([&]() -> http::task<h2_req> {
            co_return co_await std::move(server_request);
        }());
        expect(received.head.target == "/ping"sv);
        static_cast<void>(run_sync(drain_body(received.body)));
        run_sync(http::coroutine::respond(server, std::move(received.token), http::response{
            .status = 200, .reason = {}, .fields = {}}));
        auto response = run_sync([&]() -> http::task<h2_res> {
            co_return co_await std::move(client_request);
        }());
        expect(response.head.status == 200_u);
    };

    // RFC 9113 §6.9.2 — "When an HTTP/2 connection is first established, new streams are
    // created with an initial flow-control window size of 65,535 octets. The connection
    // flow-control window is also 65,535 octets." The WINDOW_UPDATE frame (§6.9) increments
    // that window by the advertised amount.
    "http2_flow_control_state_is_implemented"_test = [] {
        pipe c2s, s2c;
        mock_stream transport{.input = s2c, .output = c2s};

        push_http2_settings_frame(s2c);
        push_http2_window_update_frame(s2c, 1024);
        s2c.closed = true;

        http::v2::client<mock_stream> client{transport};
        run_sync(http::coroutine::start(client));

        expect(client.remote_window_size() == 66559_i);
    };

    // This is an internal concurrency invariant rather than RFC wire
    // behavior: one endpoint-owned driver is the only operation permitted to
    // call the connection transport's async_read.
    "http2_concurrent_requests_share_one_connection_reader"_test = [] {
        async_pipe c2s{};
        async_pipe s2c{};
        async_mock_stream client_transport{.input = s2c, .output = c2s};
        async_mock_stream server_transport{.input = c2s, .output = s2c};
        http::v2::client<async_mock_stream> client{client_transport};
        http::v2::server<async_mock_stream> server{server_transport};

        auto serve = [&]() -> http::task<void> {
            co_await http::coroutine::start(server);
            auto first = co_await http::coroutine::receive(server);
            auto second = co_await http::coroutine::receive(server);
            co_await http::coroutine::respond(server,
                std::move(first.token),
                http::response{.status = 200, .reason = {}, .fields = {}});
            co_await http::coroutine::respond(server,
                std::move(second.token),
                http::response{.status = 204, .reason = {}, .fields = {}});
        };
        auto server_operation = serve();
        server_operation.start();
        run_sync(http::coroutine::start(client));

        auto first = http::coroutine::request(client, basic_get("/first"));
        auto second = http::coroutine::request(client, basic_get("/second"));
        first.start();
        second.start();

        auto first_response = run_sync(std::move(first));
        auto second_response = run_sync(std::move(second));
        run_sync(std::move(server_operation));
        expect(first_response.head.status == 200_u);
        expect(second_response.head.status == 204_u);
        expect(s2c.waiter_owner != nullptr);
    };

    // RFC 9113 §6.5 — "The ACK flag indicates that this frame acknowledges
    // receipt and application of the peer's SETTINGS frame." Each ACK applies
    // to the oldest SETTINGS that has not yet been acknowledged.
    "http2_settings_acknowledgements_are_fifo"_test = [] {
        async_pipe c2s{};
        async_pipe s2c{};
        async_mock_stream transport{.input = s2c, .output = c2s};
        http::v2::client<async_mock_stream> client{transport};

        push_http2_settings_frame(s2c);
        run_sync(http::coroutine::start(client));
        push_http2_settings_ack_frame(s2c);

        const std::array first{
            http::v2::setting{
                .name = http::v2::setting_name::maximum_concurrent_streams,
                .value = 32,
            },
        };
        const std::array second{
            http::v2::setting{
                .name = http::v2::setting_name::maximum_field_section_size,
                .value = 8192,
            },
        };
        auto first_ticket = run_sync(client.update_settings(first));
        auto second_ticket = run_sync(client.update_settings(second));

        push_http2_settings_ack_frame(s2c);
        expect(client.acknowledged(first_ticket));
        expect(!client.acknowledged(second_ticket));

        push_http2_settings_ack_frame(s2c);
        expect(client.acknowledged(second_ticket));
    };

    // RFC 9113 §6.5.3 — "If the sender of a SETTINGS frame does not receive
    // an acknowledgment within a reasonable amount of time, it MAY issue a
    // connection error ... of type SETTINGS_TIMEOUT." External timer expiry
    // remains tied to the ticket even after unrelated frames arrive.
    "http2_settings_timeout_is_independent_of_input_activity"_test = [] {
        async_pipe c2s{};
        async_pipe s2c{};
        async_mock_stream transport{.input = s2c, .output = c2s};
        http::v2::client<async_mock_stream> client{transport};

        push_http2_settings_frame(s2c);
        run_sync(http::coroutine::start(client));
        push_http2_settings_ack_frame(s2c);
        const std::array update{
            http::v2::setting{
                .name = http::v2::setting_name::maximum_concurrent_streams,
                .value = 16,
            },
        };
        auto ticket = run_sync(client.update_settings(update));

        // RFC 9113 §6.7 — PING is unrelated connection activity and cannot
        // acknowledge or renew a SETTINGS generation deadline.
        constexpr std::array<std::byte, 17> ping{
            std::byte{0x00}, std::byte{0x00}, std::byte{0x08},
            std::byte{0x06}, std::byte{0x00},
            std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
            std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
            std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
        };
        s2c.push(ping);

        auto threw = false;
        try {
            run_sync(client.expire_settings(ticket));
        } catch (const http::protocol_error& failure) {
            const auto& close = std::get<http::close_connection>(failure.action());
            expect(std::get<http::v2::error_code>(*close.code).value == 4_u);
            threw = true;
        }
        expect(threw);
    };

    // RFC 7541 §4.2 — "The size of the dynamic table is the sum of the size
    // of its entries." Configuration constrains the decoder setting and the
    // encoder hard maximum while snapshots remain value-semantic.
    "http2_hpack_configuration_is_observable"_test = [] {
        pipe c2s{};
        pipe s2c{};
        mock_stream transport{.input = s2c, .output = c2s};
        // RFC 9113 §6.5.2 — SETTINGS_HEADER_TABLE_SIZE "allows the sender to
        // inform the remote endpoint of the maximum size of the field section
        // compression table used to decode field blocks, in units of octets."
        push_http2_setting_frame(s2c, 0x01, 512);
        s2c.closed = true;

        http::v2::client<mock_stream> client{
            transport,
            http::v2::configuration{
                .compression = {
                    .decoder_capacity = 2048,
                    .encoder_capacity = 1024,
                },
            }};
        run_sync(http::coroutine::start(client));
        auto state = client.compression_state();
        expect(state.decoder_capacity == 2048_u);
        expect(state.peer_decoder_capacity == 512_u);
        expect(state.encoder_capacity == 1024_u);
        expect(state.decoder_size == 0_u);
        expect(state.encoder_size == 0_u);
    };

    // RFC 7541 §7.1.3 — "The literal representation of a header field never
    // indexed is used when a header field is not to be inserted in a dynamic
    // table by an encoder." Authorization is sensitive and must not grow the
    // encoder table, while an ordinary extension field remains compressible.
    "http2_sensitive_fields_are_never_indexed"_test = [] {
        async_pipe c2s{};
        async_pipe s2c{};
        async_mock_stream client_transport{.input = s2c, .output = c2s};
        async_mock_stream server_transport{.input = c2s, .output = s2c};
        http::v2::client<async_mock_stream> client{client_transport};
        http::v2::server<async_mock_stream> server{server_transport};

        auto serve = [&]() -> http::task<void> {
            co_await http::coroutine::start(server);
            for (auto status : std::array<http::status, 3>{200, 200, 200}) {
                auto incoming = co_await http::coroutine::receive(server);
                co_await http::coroutine::respond(server,
                    std::move(incoming.token),
                    http::response{.status = status, .reason = {}, .fields = {}});
            }
        };
        auto server_operation = serve();
        server_operation.start();
        run_sync(http::coroutine::start(client));

        auto baseline_response = run_sync(http::coroutine::request(client, basic_get("/stable")));
        static_cast<void>(run_sync(drain_body(baseline_response.body)));
        auto baseline = client.compression_state().encoder_size;

        auto sensitive = basic_get("/stable");
        sensitive.fields.push_back({"authorization", "Bearer secret"});
        auto sensitive_response = run_sync(http::coroutine::request(client, std::move(sensitive)));
        static_cast<void>(run_sync(drain_body(sensitive_response.body)));
        auto after_sensitive = client.compression_state().encoder_size;

        auto ordinary = basic_get("/stable");
        ordinary.fields.push_back({"x-session", "compressible"});
        auto ordinary_response = run_sync(http::coroutine::request(client, std::move(ordinary)));
        static_cast<void>(run_sync(drain_body(ordinary_response.body)));
        auto after_ordinary = client.compression_state().encoder_size;
        run_sync(std::move(server_operation));

        expect(after_sensitive == baseline);
        expect(after_ordinary > after_sensitive);
    };

    // RFC 9113 §5.1 — "reserved (remote): A stream in the "reserved (remote)"
    // state has been reserved by a remote peer. ... Either endpoint can send a
    // RST_STREAM frame to cause the stream to become "closed". This releases
    // the stream reservation." — when the server resets a promised stream, the
    // push is cancelled and the client must learn why: RFC 9113 §6.4 —
    // "RST_STREAM (type=0x3) ... contains a single unsigned, 32-bit integer
    // identifying the error code (Section 7)" — take_push surfaces the abort as
    // a typed stream error carrying the peer's code, with RFC 9113 §8.7 — "The
    // REFUSED_STREAM error code can be included in a RST_STREAM frame to
    // indicate that the stream is being closed prior to any processing having
    // occurred. Any request that was sent on the reset stream can be safely
    // retried." — retry semantics.
    "http2_peer_reset_of_promised_stream_surfaces_typed_error"_test = [] {
        async_pipe c2s{};
        async_pipe s2c{};
        async_mock_stream transport{.input = s2c, .output = c2s};

        http::v2::client<async_mock_stream> client{transport};
        push_http2_settings_frame(s2c);
        run_sync(http::coroutine::start(client));

        auto client_request = http::coroutine::request(client, basic_get("/index.html"));
        client_request.start();

        // RFC 9113 §8.4.1 — "The PUSH_PROMISE frame includes a field block that
        // contains control data and a complete set of request header fields that
        // the server attributes to the request." — the promised request field
        // block: ":method GET" (0x82) and ":scheme https" (0x87) as static-table
        // indices (RFC 7541 §6.1), then ":authority example.com" and ":path
        // /style.css" as literal-without-indexing fields (RFC 7541 §6.2.2, name
        // indices 1 and 4).
        const std::vector<std::byte> promised_request{
            std::byte{0x82}, std::byte{0x87},
            std::byte{0x01}, std::byte{0x0b},
            std::byte{'e'}, std::byte{'x'}, std::byte{'a'}, std::byte{'m'},
            std::byte{'p'}, std::byte{'l'}, std::byte{'e'}, std::byte{'.'},
            std::byte{'c'}, std::byte{'o'}, std::byte{'m'},
            std::byte{0x04}, std::byte{0x0a},
            std::byte{'/'}, std::byte{'s'}, std::byte{'t'}, std::byte{'y'},
            std::byte{'l'}, std::byte{'e'}, std::byte{'.'}, std::byte{'c'},
            std::byte{'s'}, std::byte{'s'},
        };
        // RFC 9113 §6.6 — "The PUSH_PROMISE frame includes a 31-bit unsigned
        // integer that identifies the stream that is reserved by the PUSH_PROMISE."
        // The payload starts with the promised stream identifier 2, followed by
        // the field block. RFC 9113 §6.6 also defines PUSH_PROMISE's END_HEADERS
        // flag (0x4): it must be set because the complete field block is in this
        // frame; otherwise nghttp2 waits for a CONTINUATION frame that never
        // comes. PUSH_PROMISE (type 0x5) is sent on the associated request stream 1.
        const std::vector<std::byte> push_promise{
            std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x02},
        };
        auto push_promise_payload = push_promise;
        push_promise_payload.insert(
            push_promise_payload.end(), promised_request.begin(), promised_request.end());
        push_http2_frame(s2c, 0x05, 0x04, 1, push_promise_payload);

        // The server cancels the push: RST_STREAM (type 0x3) on stream 2 with
        // REFUSED_STREAM (0x7) before any response is sent (RFC 9113 §7 —
        // "REFUSED_STREAM (0x07): The endpoint refused the stream prior to
        // performing any application processing").
        const std::vector<std::byte> refused_code{
            std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x07}};
        push_http2_frame(s2c, 0x03, 0x00, 2, refused_code);

        // The associated request still completes normally: ":status 200" — a
        // literal-without-indexing response field block (RFC 7541 §6.2.2, name
        // index 8) with END_STREAM on the HEADERS frame.
        const std::vector<std::byte> ok_status{
            std::byte{0x08}, std::byte{0x03},
            std::byte{'2'}, std::byte{'0'}, std::byte{'0'}};
        push_http2_frame(s2c, 0x01, 0x05, 1, ok_status);

        auto response = run_sync([&]() -> http::task<h2_res> {
            co_return co_await std::move(client_request);
        }());
        expect(response.head.status == 200_u);

        // take_push surfaces the cancelled promise as the typed stream error
        // carrying the peer's REFUSED_STREAM code, retryable per RFC 9113 §8.7.
        auto threw = false;
        try {
            static_cast<void>(client.take_push());
        } catch (const http::protocol_error& failure) {
            expect(failure.info().condition == http::error_condition::stream_reset);
            expect(failure.info().scope == http::error_scope::stream);
            expect(failure.info().retryable);
            expect(failure.info().exchange_identity.has_value());
            expect(*failure.info().exchange_identity == 2_u);
            expect(std::holds_alternative<http::reset_stream>(failure.action()));
            const auto& reset = std::get<http::reset_stream>(failure.action());
            expect(std::holds_alternative<http::v2::error_code>(reset.code));
            expect(std::get<http::v2::error_code>(reset.code).value == 7_u);
            threw = true;
        }
        expect(threw);

        // The cancelled promise is never delivered as an exchange.
        expect(!client.take_push().has_value());
    };

    // RFC 9113 §7 — "REFUSED_STREAM (0x07): The endpoint refused the stream
    // prior to performing any application processing" and RFC 9113 §8.7 — "The
    // REFUSED_STREAM error code can be included in a RST_STREAM frame to
    // indicate that the stream is being closed prior to any processing having
    // occurred. Any request that was sent on the reset stream can be safely
    // retried." — the peer's RST_STREAM error code must surface as a typed
    // stream error carrying the wire code (RFC 9113 §6.4 — "RST_STREAM
    // (type=0x3) ... contains a single unsigned, 32-bit integer identifying the
    // error code"), so retry semantics are reachable instead of a bare
    // runtime_error.
    "http2_peer_rst_stream_carries_typed_error_code"_test = [] {
        async_pipe c2s{};
        async_pipe s2c{};
        async_mock_stream transport{.input = s2c, .output = c2s};

        http::v2::client<async_mock_stream> client{transport};
        push_http2_settings_frame(s2c);
        run_sync(http::coroutine::start(client));

        // RST_STREAM (type 0x3) with REFUSED_STREAM (0x7) closes stream 1
        // before any response; the request must fail with the typed code and
        // retryable=true per RFC 9113 §8.7.
        auto refused = http::coroutine::request(client, basic_get("/retryable"));
        refused.start();
        const std::vector<std::byte> refused_code{
            std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x07}};
        push_http2_frame(s2c, 0x03, 0x00, 1, refused_code);

        auto threw = false;
        try {
            static_cast<void>(run_sync(std::move(refused)));
        } catch (const http::protocol_error& failure) {
            expect(failure.info().condition == http::error_condition::stream_reset);
            expect(failure.info().retryable);
            expect(failure.info().exchange_identity.has_value());
            expect(*failure.info().exchange_identity == 1_u);
            expect(std::holds_alternative<http::reset_stream>(failure.action()));
            const auto& reset = std::get<http::reset_stream>(failure.action());
            expect(std::holds_alternative<http::v2::error_code>(reset.code));
            expect(std::get<http::v2::error_code>(reset.code).value == 7_u);
            threw = true;
        }
        expect(threw);

        // RFC 9113 §7 — "CANCEL (0x08): The endpoint uses this error code to
        // indicate that the stream is no longer needed." — CANCEL is not a
        // "safe to retry" signal, so the typed error reports retryable=false.
        auto cancelled = http::coroutine::request(client, basic_get("/cancelled"));
        cancelled.start();
        const std::vector<std::byte> cancel_code{
            std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x08}};
        push_http2_frame(s2c, 0x03, 0x00, 3, cancel_code);

        threw = false;
        try {
            static_cast<void>(run_sync(std::move(cancelled)));
        } catch (const http::protocol_error& failure) {
            expect(failure.info().condition == http::error_condition::stream_reset);
            expect(!failure.info().retryable);
            const auto& reset = std::get<http::reset_stream>(failure.action());
            expect(std::get<http::v2::error_code>(reset.code).value == 8_u);
            threw = true;
        }
        expect(threw);
    };

    // RFC 9110 §15 — "All valid status codes are within the range of 100 to
    // 599, inclusive." / "Values outside the range 100..599 are invalid."
    // RFC 9113 §8.3.2 — a response carries its status in the single ':status'
    // pseudo-header field. A well-formed but out-of-range value (e.g. "700")
    // is therefore a malformed response, so the client resets the stream with
    // PROTOCOL_ERROR (0x1, Section 7) instead of accepting the status. The
    // locally reset stream surfaces as a typed stream error carrying the wire
    // code — RFC 9113 §8.1.1 — "Malformed requests or responses that are
    // detected MUST be treated as a stream error (Section 5.4.2) of type
    // PROTOCOL_ERROR." — mirroring the RFC 9114 §4.1.2 treatment in v3.
    "http2_out_of_range_status_resets_stream_with_protocol_error"_test = [] {
        async_pipe c2s{};
        async_pipe s2c{};
        async_mock_stream transport{.input = s2c, .output = c2s};

        http::v2::client<async_mock_stream> client{transport};
        push_http2_settings_frame(s2c);
        run_sync(http::coroutine::start(client));

        auto client_request = http::coroutine::request(client, basic_get("/status-700"));
        client_request.start();

        // ":status: 700" — literal without indexing, static name index 8
        // (RFC 7541 §6.2.2).
        const std::vector<std::byte> out_of_range{
            std::byte{0x08}, std::byte{0x03},
            std::byte{'7'}, std::byte{'0'}, std::byte{'0'}};
        push_http2_frame(s2c, 0x01, 0x05, 1, out_of_range);

        auto threw = false;
        try {
            static_cast<void>(run_sync(std::move(client_request)));
        } catch (const http::protocol_error& failure) {
            expect(failure.info().condition == http::error_condition::malformed_message);
            expect(failure.info().scope == http::error_scope::stream);
            expect(failure.info().exchange_identity.has_value());
            expect(*failure.info().exchange_identity == 1_u);
            expect(!failure.info().retryable);
            expect(std::holds_alternative<http::reset_stream>(failure.action()));
            const auto& reset = std::get<http::reset_stream>(failure.action());
            expect(std::holds_alternative<http::v2::error_code>(reset.code));
            expect(std::get<http::v2::error_code>(reset.code).value == 1_u);
            threw = true;
        }
        expect(threw);

        // The client output carries RST_STREAM (type 0x3) on stream 1 with
        // error code PROTOCOL_ERROR (0x1).
        auto reset_found = false;
        for (const auto& frame : parse_h2_client_output(c2s.buffer)) {
            if (frame.type != 0x03 || frame.stream_id != 1)
                continue;
            const std::vector<std::byte> protocol_error{
                std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x01}};
            expect(frame.payload == protocol_error);
            reset_found = true;
        }
        expect(reset_found);
    };

    // RFC 9110 §15 — "All valid status codes are within the range of 100 to
    // 599, inclusive." — an application answering with a status outside that
    // range would put an invalid ':status' value on the wire (RFC 9113 §8.3.2),
    // so the send path rejects it locally before any frame is submitted,
    // mirroring the inbound :status validation. The connection and its other
    // streams survive.
    "http2_out_of_range_status_rejected_on_send"_test = [] {
        async_pipe c2s{};
        async_pipe s2c{};
        async_mock_stream client_transport{.input = s2c, .output = c2s};
        async_mock_stream server_transport{.input = c2s, .output = s2c};

        http::v2::client<async_mock_stream> client{client_transport};
        http::v2::server<async_mock_stream> server{server_transport};

        auto accept_request = [&]() -> http::task<h2_req> {
            co_await http::coroutine::start(server);
            co_return co_await http::coroutine::receive(server);
        };
        auto server_request = accept_request();
        server_request.start();
        run_sync(http::coroutine::start(client));

        auto client_request = http::coroutine::request(client, basic_get("/status-700"));
        client_request.start();

        auto received = run_sync([&]() -> http::task<h2_req> {
            co_return co_await std::move(server_request);
        }());
        expect(received.head.target == "/status-700"sv);
        static_cast<void>(run_sync(drain_body(received.body)));

        auto threw = false;
        try {
            http::buffer_body body;
            run_sync(http::coroutine::respond(server,
                std::move(received.token),
                http::response{.status = 700, .reason = {}, .fields = {}},
                body));
        } catch (const std::runtime_error& failure) {
            expect(std::string_view{failure.what()}.contains("http/2:"sv));
            threw = true;
        }
        expect(threw);

        // The rejected response never reaches the wire, and the connection
        // survives: a second exchange with a valid status completes normally.
        auto server_request_2 = accept_request();
        server_request_2.start();
        auto good_request = http::coroutine::request(client, basic_get("/fine"));
        good_request.start();

        auto received_2 = run_sync([&]() -> http::task<h2_req> {
            co_return co_await std::move(server_request_2);
        }());
        expect(received_2.head.target == "/fine"sv);
        static_cast<void>(run_sync(drain_body(received_2.body)));
        http::buffer_body response_body;
        run_sync(http::coroutine::respond(server,
            std::move(received_2.token),
            http::response{.status = 200, .reason = {}, .fields = {}},
            response_body));

        auto good_response = run_sync([&]() -> http::task<h2_res> {
            co_return co_await std::move(good_request);
        }());
        expect(good_response.head.status == 200_u);
        static_cast<void>(run_sync(drain_body(good_response.body)));
    };

    // RFC 9113 §8.3.1 — "A server SHOULD treat a request as malformed if it
    // contains a Host header field that identifies an entity that differs from
    // the entity in the ":authority" pseudo-header field. The values of fields
    // need to be normalized to compare them (see Section 6.2 of [RFC3986])."
    // RFC 9113 §8.1.1 — "Malformed requests or responses that are detected
    // MUST be treated as a stream error (Section 5.4.2) of type PROTOCOL_ERROR."
    // — nghttp2 checks Host presence and uniqueness only, never value
    // equality, so the disagreement must be caught by the server and answered
    // with RST_STREAM PROTOCOL_ERROR while other streams keep running.
    "http2_host_authority_disagreement_resets_stream_with_protocol_error"_test = [] {
        async_pipe c2s{};
        async_pipe s2c{};
        async_mock_stream transport{.input = c2s, .output = s2c};

        http::v2::server<async_mock_stream> server{transport};

        // RFC 9113 §3.4 — "The client connection preface starts with a sequence
        // of 24 octets ... "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" ... This sequence
        // MUST be followed by a SETTINGS frame."
        constexpr std::array<std::byte, 24> magic{
            std::byte{'P'}, std::byte{'R'}, std::byte{'I'}, std::byte{' '},
            std::byte{'*'}, std::byte{' '}, std::byte{'H'}, std::byte{'T'},
            std::byte{'T'}, std::byte{'P'}, std::byte{'/'}, std::byte{'2'},
            std::byte{'.'}, std::byte{'0'}, std::byte{'\r'}, std::byte{'\n'},
            std::byte{'\r'}, std::byte{'\n'}, std::byte{'S'}, std::byte{'M'},
            std::byte{'\r'}, std::byte{'\n'}, std::byte{'\r'}, std::byte{'\n'},
        };
        c2s.push(magic);
        push_http2_settings_frame(c2s);
        run_sync(http::coroutine::start(server));

        // HPACK field block (RFC 7541 §6.1 static table): indexed ":method GET"
        // (0x82), ":scheme https" (0x87), ":path /" (0x84), then a literal
        // ":authority: example.com" (name index 1, 11 bytes) followed by a
        // "host: other.example" field (literal name, 4 + 13 bytes) that
        // identifies a different entity.
        const std::vector<std::byte> disagreeing{
            std::byte{0x82}, std::byte{0x87}, std::byte{0x84},
            std::byte{0x01}, std::byte{0x0b},
            std::byte{'e'}, std::byte{'x'}, std::byte{'a'}, std::byte{'m'},
            std::byte{'p'}, std::byte{'l'}, std::byte{'e'}, std::byte{'.'},
            std::byte{'c'}, std::byte{'o'}, std::byte{'m'},
            std::byte{0x00}, std::byte{0x04},
            std::byte{'h'}, std::byte{'o'}, std::byte{'s'}, std::byte{'t'},
            std::byte{0x0d},
            std::byte{'o'}, std::byte{'t'}, std::byte{'h'}, std::byte{'e'},
            std::byte{'r'}, std::byte{'.'}, std::byte{'e'}, std::byte{'x'},
            std::byte{'a'}, std::byte{'m'}, std::byte{'p'}, std::byte{'l'},
            std::byte{'e'},
        };
        push_http2_frame(c2s, 0x01, 0x05, 1, disagreeing);

        // The server output must carry RST_STREAM (type 0x3) on stream 1 with
        // error code PROTOCOL_ERROR (0x1): 3-byte length 4, type 0x03, flags
        // 0x00, stream identifier 1, then the 32-bit error code.
        const std::array<std::byte, 13> reset{
            std::byte{0x00}, std::byte{0x00}, std::byte{0x04},
            std::byte{0x03}, std::byte{0x00},
            std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x01},
            std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x01},
        };
        auto wire = s2c.buffer;
        auto reset_found = std::ranges::search(wire, reset).begin() != wire.end();
        expect(reset_found);

        // The malformed stream must not poison the connection: a subsequent
        // request whose Host agrees with its ":authority" is delivered
        // normally.
        const std::vector<std::byte> agreeing{
            std::byte{0x82}, std::byte{0x87}, std::byte{0x84},
            std::byte{0x01}, std::byte{0x0b},
            std::byte{'e'}, std::byte{'x'}, std::byte{'a'}, std::byte{'m'},
            std::byte{'p'}, std::byte{'l'}, std::byte{'e'}, std::byte{'.'},
            std::byte{'c'}, std::byte{'o'}, std::byte{'m'},
            std::byte{0x00}, std::byte{0x04},
            std::byte{'h'}, std::byte{'o'}, std::byte{'s'}, std::byte{'t'},
            std::byte{0x0b},
            std::byte{'e'}, std::byte{'x'}, std::byte{'a'}, std::byte{'m'},
            std::byte{'p'}, std::byte{'l'}, std::byte{'e'}, std::byte{'.'},
            std::byte{'c'}, std::byte{'o'}, std::byte{'m'},
        };
        push_http2_frame(c2s, 0x01, 0x05, 3, agreeing);

        auto received = run_sync(http::coroutine::receive(server));
        expect(received.head.authority == "example.com"sv);
        expect(received.head.target == "/"sv);
        static_cast<void>(run_sync(drain_body(received.body)));
    };

    // RFC 9113 §8.3.1 — "A request in asterisk form (for OPTIONS) includes the
    // value '*' for the ':path' pseudo-header field." — asterisk-form targets
    // are defined only for OPTIONS; any other method with ':path: *' carries an
    // invalid pseudo-header value, making the request malformed. RFC 9113
    // §8.1.1 — "Malformed requests or responses that are detected MUST be
    // treated as a stream error (Section 5.4.2) of type PROTOCOL_ERROR." —
    // nghttp2 enforces the cross-check when the header block completes, so the
    // request is never delivered to the application: the server answers
    // RST_STREAM PROTOCOL_ERROR and keeps serving the connection.
    "http2_asterisk_form_non_options_never_reaches_application"_test = [] {
        async_pipe c2s{};
        async_pipe s2c{};
        async_mock_stream transport{.input = c2s, .output = s2c};

        http::v2::server<async_mock_stream> server{transport};

        // RFC 9113 §3.4 — "The client connection preface starts with a sequence
        // of 24 octets ... "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" ... This sequence
        // MUST be followed by a SETTINGS frame."
        constexpr std::array<std::byte, 24> magic{
            std::byte{'P'}, std::byte{'R'}, std::byte{'I'}, std::byte{' '},
            std::byte{'*'}, std::byte{' '}, std::byte{'H'}, std::byte{'T'},
            std::byte{'T'}, std::byte{'P'}, std::byte{'/'}, std::byte{'2'},
            std::byte{'.'}, std::byte{'0'}, std::byte{'\r'}, std::byte{'\n'},
            std::byte{'\r'}, std::byte{'\n'}, std::byte{'S'}, std::byte{'M'},
            std::byte{'\r'}, std::byte{'\n'}, std::byte{'\r'}, std::byte{'\n'},
        };
        c2s.push(magic);
        push_http2_settings_frame(c2s);
        run_sync(http::coroutine::start(server));

        // ":method GET" (indexed 0x82), ":scheme https" (indexed 0x87),
        // ":authority example.com" (literal name index 1, 11 bytes), then
        // ":path: *" — literal without indexing (RFC 7541 §6.2.2), name index
        // 4, value "*" — an asterisk-form target with a non-OPTIONS method.
        const std::vector<std::byte> asterisk_get{
            std::byte{0x82}, std::byte{0x87},
            std::byte{0x01}, std::byte{0x0b},
            std::byte{'e'}, std::byte{'x'}, std::byte{'a'}, std::byte{'m'},
            std::byte{'p'}, std::byte{'l'}, std::byte{'e'}, std::byte{'.'},
            std::byte{'c'}, std::byte{'o'}, std::byte{'m'},
            std::byte{0x04}, std::byte{0x01}, std::byte{'*'},
        };
        push_http2_frame(c2s, 0x01, 0x05, 1, asterisk_get);

        // The server output must carry RST_STREAM (type 0x3) on stream 1 with
        // error code PROTOCOL_ERROR (0x1): 3-byte length 4, type 0x03, flags
        // 0x00, stream identifier 1, then the 32-bit error code.
        const std::array<std::byte, 13> reset{
            std::byte{0x00}, std::byte{0x00}, std::byte{0x04},
            std::byte{0x03}, std::byte{0x00},
            std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x01},
            std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x01},
        };
        auto reset_found = std::ranges::search(s2c.buffer, reset).begin() != s2c.buffer.end();
        expect(reset_found);

        // The malformed stream is never delivered and must not poison the
        // connection: a subsequent server-wide OPTIONS with ':path: *' is
        // delivered normally, proving receive() skipped the invalid request.
        // ":method OPTIONS" — literal without indexing (RFC 7541 §6.2.2), name
        // index 2, value 7 bytes.
        const std::vector<std::byte> asterisk_options{
            std::byte{0x02}, std::byte{0x07},
            std::byte{'O'}, std::byte{'P'}, std::byte{'T'}, std::byte{'I'},
            std::byte{'O'}, std::byte{'N'}, std::byte{'S'},
            std::byte{0x87},
            std::byte{0x01}, std::byte{0x0b},
            std::byte{'e'}, std::byte{'x'}, std::byte{'a'}, std::byte{'m'},
            std::byte{'p'}, std::byte{'l'}, std::byte{'e'}, std::byte{'.'},
            std::byte{'c'}, std::byte{'o'}, std::byte{'m'},
            std::byte{0x04}, std::byte{0x01}, std::byte{'*'},
        };
        push_http2_frame(c2s, 0x01, 0x05, 3, asterisk_options);

        auto received = run_sync(http::coroutine::receive(server));
        expect(received.head.method == http::method::OPTIONS);
        expect(received.head.target == "*"sv);
        static_cast<void>(run_sync(drain_body(received.body)));
    };

    // RFC 9110 §15.3.5 — "A 204 response is terminated by the end of the
    // header section; it cannot contain content or trailers." and RFC 9110
    // §15.4.5 — "A 304 response is terminated by the end of the header
    // section; it cannot contain content or trailers." RFC 9113 §8.1 — "HTTP/2
    // uses DATA frames to carry message content." — a 204 or 304 response ends
    // at the header section even for a GET request, so a body attached by the
    // application must never reach the wire as DATA.
    "http2_server_204_and_304_responses_carry_no_data"_test = [] {
        async_pipe c2s{};
        async_pipe s2c{};
        async_mock_stream client_transport{.input = s2c, .output = c2s};
        async_mock_stream server_transport{.input = c2s, .output = s2c};

        http::v2::client<async_mock_stream> client{client_transport};
        http::v2::server<async_mock_stream> server{server_transport};

        auto accept_request = [&]() -> http::task<h2_req> {
            co_await http::coroutine::start(server);
            co_return co_await http::coroutine::receive(server);
        };
        auto server_request = accept_request();
        server_request.start();
        run_sync(http::coroutine::start(client));

        auto client_request = http::coroutine::request(client, basic_get("/empty"));
        client_request.start();

        auto received = run_sync([&]() -> http::task<h2_req> {
            co_return co_await std::move(server_request);
        }());
        expect(received.head.target == "/empty"sv);
        static_cast<void>(run_sync(drain_body(received.body)));

        // A 204 response with a non-empty body attached: the body must be
        // suppressed, and the client must receive the 204 with no content.
        auto body_204 = make_body("must not be sent");
        run_sync(http::coroutine::respond(server,
            std::move(received.token),
            http::response{.status = 204, .reason = {}, .fields = {}},
            body_204));

        auto response = run_sync([&]() -> http::task<h2_res> {
            co_return co_await std::move(client_request);
        }());
        expect(response.head.status == 204_u);
        auto body = run_sync(drain_body(response.body));
        expect(body.empty());

        // No DATA frame carrying content (length > 0) may appear on a stream
        // whose response ended at the header section.
        auto nonempty_data_on = [&](std::uint32_t stream_id) -> bool {
            auto server_wire = s2c.buffer;
            std::size_t pos = 0;
            while (pos + 9 <= server_wire.size()) {
                auto length = (static_cast<std::size_t>(server_wire[pos]) << 16) |
                              (static_cast<std::size_t>(server_wire[pos + 1]) << 8) |
                              static_cast<std::size_t>(server_wire[pos + 2]);
                auto type = static_cast<std::uint8_t>(server_wire[pos + 3]);
                auto sid = (static_cast<std::uint32_t>(server_wire[pos + 5]) << 24) |
                           (static_cast<std::uint32_t>(server_wire[pos + 6]) << 16) |
                           (static_cast<std::uint32_t>(server_wire[pos + 7]) << 8) |
                           static_cast<std::uint32_t>(server_wire[pos + 8]);
                if (type == 0x00 && sid == stream_id && length > 0)
                    return true;
                pos += 9 + length;
            }
            return false;
        };
        expect(!nonempty_data_on(1));

        // The same suppression applies to a 304 (RFC 9110 §15.4.5 — "A 304
        // response is terminated by the end of the header section; it cannot
        // contain content or trailers."): a conditional GET answered with 304
        // must not deliver the attached body either.
        auto conditional = basic_get("/cached");
        conditional.fields.push_back({"if-none-match", R"("v1")"});
        auto client_request_304 = http::coroutine::request(client, std::move(conditional));
        client_request_304.start();

        auto server_request_2 = accept_request();
        server_request_2.start();
        auto received_304 = run_sync([&]() -> http::task<h2_req> {
            co_return co_await std::move(server_request_2);
        }());
        expect(received_304.head.target == "/cached"sv);
        expect(http::find_header(received_304.head.fields, "if-none-match") == R"("v1")"sv);
        static_cast<void>(run_sync(drain_body(received_304.body)));

        auto body_304 = make_body("must not be sent either");
        run_sync(http::coroutine::respond(server,
            std::move(received_304.token),
            http::response{.status = 304, .reason = {}, .fields = {}},
            body_304));

        auto response_304 = run_sync([&]() -> http::task<h2_res> {
            co_return co_await std::move(client_request_304);
        }());
        expect(response_304.head.status == 304_u);
        auto body_304_out = run_sync(drain_body(response_304.body));
        expect(body_304_out.empty());
        expect(!nonempty_data_on(3));
    };

    // RFC 9113 §8.1 — "HTTP/2 uses DATA frames to carry message content." with
    // RFC 9110 §15.3.5 — "A 204 response is terminated by the end of the
    // header section" — the same suppression applies to a pushed response: a
    // 204 push with an attached body must not deliver content to the client.
    "http2_pushed_204_response_carries_no_body"_test = [] {
        async_pipe c2s{};
        async_pipe s2c{};
        async_mock_stream client_transport{.input = s2c, .output = c2s};
        async_mock_stream server_transport{.input = c2s, .output = s2c};

        http::v2::client<async_mock_stream> client{client_transport};
        http::v2::server<async_mock_stream> server{server_transport};

        auto accept_request = [&]() -> http::task<h2_req> {
            co_await http::coroutine::start(server);
            co_return co_await http::coroutine::receive(server);
        };
        auto server_request = accept_request();
        server_request.start();
        run_sync(http::coroutine::start(client));

        auto client_request = http::coroutine::request(client, basic_get("/index.html"));
        client_request.start();

        auto received = run_sync([&]() -> http::task<h2_req> {
            co_return co_await std::move(server_request);
        }());
        expect(received.head.target == "/index.html"sv);
        static_cast<void>(run_sync(drain_body(received.body)));

        auto push_body = make_body("must not be pushed");
        run_sync(server.push(
            received.token,
            basic_get("/style.css"),
            http::response{.status = 204, .reason = {}, .fields = {}},
            push_body));

        auto response_body = make_body("<html/>");
        run_sync(http::coroutine::respond(server,
            std::move(received.token),
            http::response{.status = 200, .reason = {}, .fields = {}},
            response_body));

        auto response = run_sync([&]() -> http::task<h2_res> {
            co_return co_await std::move(client_request);
        }());
        expect(response.head.status == 200_u);

        auto pushed = client.take_push();
        expect(static_cast<bool>(pushed));
        expect(pushed->pushed_response.status == 204_u);
        expect(pushed->body.empty());
    };

    // RFC 9204 §2.1.2 — "When the decoder receives an encoded field section
    // with a Required Insert Count greater than its own Insert Count, the stream
    // cannot be processed immediately and is considered 'blocked'".
    // Request-stream bytes are deliberately routed before
    // the encoder stream; the single nghttp3 QPACK owner blocks, consumes the
    // delayed encoder instructions, and resumes the request.
    "http3_qpack_dynamic_reference_blocks_and_resumes"_test = [] {
        recording_stream_factory client_transport{true};
        recording_stream_factory server_transport{false};
        auto config = http::v3::configuration{
            .compression = {
                .decoder_capacity = 4096,
                .blocked_streams = 8,
                .encoder_capacity = 4096,
            },
            .maximum_field_section_size = 16 * 1024,
        };
        http::v3::client<recording_stream_factory> client{
            client_transport, config};
        http::v3::server<recording_stream_factory> server{
            server_transport, config};

        run_sync(http::coroutine::start(client));
        route_writes_to(client_transport, server_transport);
        run_sync(http::coroutine::start(server));
        route_writes_to(server_transport, client_transport);

        auto client_state = client.compression_state();
        auto server_state = server.compression_state();
        expect(client_state.decoder_capacity == 4096_u);
        expect(client_state.blocked_streams == 8_u);
        expect(client_state.encoder_capacity == 4096_u);
        expect(client_state.peer_decoder_capacity == 4096_u);
        expect(client_state.peer_blocked_streams == 8_u);
        expect(server_state.peer_decoder_capacity == 4096_u);
        expect(server_state.peer_blocked_streams == 8_u);

        auto receive = http::coroutine::receive(server);
        receive.start();
        auto request = basic_get("/dynamic");
        request.fields.push_back({
            "x-dynamic-field",
            "a value long enough to benefit from a dynamic reference",
        });
        http::buffer_body empty;
        auto response = http::coroutine::request(
            client, std::move(request), empty);
        response.start();

        // Client stream 6 is the locally opened QPACK encoder stream. A write
        // after SETTINGS proves this field section generated encoder-stream
        // instructions rather than remaining literal-only.
        auto encoder_instruction_seen = false;
        for (const auto& write : client_transport.writes) {
            if (write.stream_id == 6 && !write.data.empty())
                encoder_instruction_seen = true;
        }
        expect(encoder_instruction_seen);

        // route_writes_to orders bidirectional request stream 0 before
        // unidirectional encoder stream 6, exercising blocked/unblocked input.
        route_writes_to(client_transport, server_transport);
        auto incoming = run_sync(std::move(receive));
        expect(incoming.head.target == "/dynamic"sv);
        expect(http::find_header(incoming.head.fields, "x-dynamic-field").has_value());
        static_cast<void>(run_sync(drain_body(incoming.body)));

        run_sync(http::coroutine::respond(
            server,
            std::move(incoming.token),
            http::response{.status = 200, .reason = {}, .fields = {}}));
        route_writes_to(server_transport, client_transport);
        auto received = run_sync(std::move(response));
        expect(received.head.status == 200_u);
        static_cast<void>(run_sync(drain_body(received.body)));
    };

    // RFC 9204 §4.5.4 — "When the 'N' bit is set, the encoded field line MUST
    // always be encoded with a literal representation." With identical connection state, adding an
    // Authorization field must not add an encoder-stream insertion, while an
    // ordinary extension field does.
    "http3_qpack_sensitive_fields_are_never_indexed"_test = [] {
        auto encoder_instructions = [](http::request request) {
            recording_stream_factory client_transport{true};
            recording_stream_factory server_transport{false};
            auto config = http::v3::configuration{
                .compression = {
                    .decoder_capacity = 4096,
                    .blocked_streams = 8,
                    .encoder_capacity = 4096,
                },
            };
            http::v3::client<recording_stream_factory> client{
                client_transport, config};
            http::v3::server<recording_stream_factory> server{
                server_transport, config};
            run_sync(http::coroutine::start(client));
            route_writes_to(client_transport, server_transport);
            run_sync(http::coroutine::start(server));
            route_writes_to(server_transport, client_transport);

            http::buffer_body empty;
            auto operation = http::coroutine::request(
                client, std::move(request), empty);
            operation.start();

            std::vector<std::byte> instructions;
            for (const auto& write : client_transport.writes) {
                // RFC 9000 §2.1 — the client's second locally opened
                // unidirectional stream is QPACK encoder stream 6.
                if (write.stream_id == 6)
                    append_bytes(instructions, write.data);
            }
            return instructions;
        };

        auto baseline = encoder_instructions(basic_get("/stable"));
        auto sensitive_request = basic_get("/stable");
        sensitive_request.fields.push_back({
            "authorization", "Bearer connection-secret"});
        auto sensitive = encoder_instructions(std::move(sensitive_request));
        auto ordinary_request = basic_get("/stable");
        ordinary_request.fields.push_back({
            "x-session", "compressible connection value"});
        auto ordinary = encoder_instructions(std::move(ordinary_request));

        auto sensitive_matches_baseline = static_cast<bool>(sensitive == baseline);
        expect(sensitive_matches_baseline);
        expect(ordinary.size() > baseline.size());
    };

    // RFC 9114 §4.2.2 — "An HTTP/3 implementation MAY impose a limit on the
    // maximum size of the message header it will accept on an individual HTTP
    // message." The configured limit applies to the decompressed field section
    // size, including the per-field 32-byte overhead. The typed
    // H3_EXCESSIVE_LOAD reset below is httpant's explicit resource policy, not
    // an additional RFC requirement.
    //
    // The oversized request is fed directly through the transport because a
    // compliant peer refuses to send a field section above the advertised
    // SETTINGS_MAX_FIELD_SECTION_SIZE (RFC 9114 §4.2.2 — "SHOULD NOT send an
    // HTTP message header that exceeds the indicated size"); the reset below
    // covers a non-compliant peer instead.
    "http3_field_section_limit_resets_stream"_test = [] {
        recording_stream_factory transport{false};
        http::v3::server<recording_stream_factory> server{
            transport,
            http::v3::configuration{
                .maximum_field_section_size = 256,
            }};
        run_sync(http::coroutine::start(server));
        static_cast<void>(transport.take_writes());

        auto receive = http::coroutine::receive(server);
        receive.start();

        // A request whose decoded field section exceeds the configured limit
        // (RFC 9114 §4.2.2 — "the size of a field list is calculated based on
        // the uncompressed size of fields, including the length of the name
        // and value in bytes plus an overhead of 32 bytes for each field").
        auto headers = make_h3_frame(
            0x01, make_h3_field_section({
                {":method", "GET"},
                {":scheme", "https"},
                {":path", "/limited"},
                {":authority", "example.com"},
                {"host", "example.com"},
                {"x-oversized", std::string(256, 'x')},
            }));
        transport.announce(0, http::stream_access::bidirectional);
        transport.feed(
            0,
            std::span<const std::byte>{headers.data(), headers.size()},
            true);

        auto threw = false;
        try {
            static_cast<void>(run_sync(std::move(receive)));
        } catch (const http::protocol_error& failure) {
            expect(failure.info().scope == http::error_scope::stream);
            expect(failure.info().condition == http::error_condition::resource_limit);
            expect(std::holds_alternative<http::reset_stream>(failure.action()));
            const auto& reset = std::get<http::reset_stream>(failure.action());
            expect(std::get<http::v3::error_code>(reset.code).value == h3_excessive_load);
            threw = true;
        }
        expect(threw);
        expect(transport.closes.empty());
        expect(transport.shutdowns.size() == 1_u);
        expect(transport.shutdowns.front().stream_id == 0_i);
        expect(transport.shutdowns.front().side == http::stream_side::both);
        expect(transport.shutdowns.front().error.value == h3_excessive_load);
    };

    // RFC 9114 §4.1 — "After sending a request, a client MUST close the stream for sending.
    // ... After sending a final response, the server MUST close the stream for sending. At
    // this point, the QUIC stream is fully closed." A request that never receives a final
    // response cannot complete.
    "http3_requests_do_not_complete_before_a_response_arrives"_test = [] {
        pipe c2s, s2c;
        mock_stream_factory transport{s2c, c2s};

        http::v3::client<mock_stream_factory> client{transport};
        run_sync(http::coroutine::start(client));

        auto threw = false;
        try {
            http::buffer_body empty;
            auto response = run_sync(http::coroutine::request(client, basic_get("/h3"), empty));
            expect(response.head.status == 200_u);
        } catch (...) {
            threw = true;
        }

        expect(threw);
    };

    // Internal lifecycle test: the endpoint owns its accept driver and destroys
    // the suspended accept operation before its protocol state.
    "http3_endpoint_owns_and_cancels_accept_driver"_test = [] {
        recording_stream_factory transport{true};

        {
            http::v3::client<recording_stream_factory> client{transport};
            run_sync(http::coroutine::start(client));
            expect(transport.accept_waiter != std::coroutine_handle<>{});
            expect(transport.accept_stop.stop_possible());
            expect(!transport.accept_stop.stop_requested());
        }

        expect(transport.accept_waiter == std::coroutine_handle<>{});
        expect(transport.accept_waiter_owner == nullptr);
    };

    // RFC 9114 §7.2.7 — "A MAX_PUSH_ID frame cannot reduce the maximum push ID; receipt of a
    // MAX_PUSH_ID frame that contains a smaller value than previously received MUST be
    // treated as a connection error of type H3_ID_ERROR."
    "http3_max_push_id_management_is_implemented"_test = [] {
        recording_stream_factory client_transport{true};
        recording_stream_factory server_transport{false};

        http::v3::client<recording_stream_factory> client{client_transport};
        http::v3::server<recording_stream_factory> server{server_transport};

        run_sync(http::coroutine::start(client));
        route_writes_to(client_transport, server_transport);
        run_sync(http::coroutine::start(server));
        route_writes_to(server_transport, client_transport);

        auto initial = make_h3_frame(0x0d, 4);
        // The backend does not expose H3 push, but MAX_PUSH_ID remains peer
        // protocol input and its monotonic invariant is still enforced.
        server_transport.feed(
            2,
            std::span<const std::byte>{initial.data(), initial.size()},
            false);

        auto lower = make_h3_frame(0x0d, 3);
        // Stream 2 is the client's control stream (client uni streams start
        // at 2 in the factory scheme); the reduced MAX_PUSH_ID arrives on it
        // and the endpoint-owned driver records the connection failure inline.
        server_transport.feed(2, std::span<const std::byte>{lower.data(), lower.size()}, false);

        // RFC 9114 §7.2.7 — "A MAX_PUSH_ID frame cannot reduce the maximum push
        // ID; receipt of a MAX_PUSH_ID frame that contains a smaller value than
        // previously received MUST be treated as a connection error of type
        // H3_ID_ERROR." The typed error surfaces on the next server operation
        // as a connection-close action carrying the H3_ID_ERROR code.
        auto threw = false;
        try {
            static_cast<void>(run_sync(http::coroutine::receive(server)));
        } catch (const http::protocol_error& failure) {
            expect(std::holds_alternative<http::close_connection>(failure.action()));
            const auto& close = std::get<http::close_connection>(failure.action());
            expect(close.code.has_value());
            expect(std::holds_alternative<http::v3::error_code>(*close.code));
            expect(std::get<http::v3::error_code>(*close.code).value == h3_id_error);
            threw = true;
        }

        expect(threw);
    };

    // RFC 9114 §5.2 — "Endpoints initiate the graceful shutdown of an HTTP/3 connection by
    // sending a GOAWAY frame. ... Requests or pushes with the indicated identifier or greater
    // are rejected ... by the sender of the GOAWAY."
    "http3_goaway_support_is_implemented"_test = [] {
        recording_stream_factory transport{true};
        http::v3::client<recording_stream_factory> client{transport};
        run_sync(http::coroutine::start(client));
        static_cast<void>(transport.take_writes());

        auto settings = make_h3_frame(0x04, std::span<const std::byte>{});
        auto goaway = make_h3_frame(0x07, 0);
        std::vector<std::byte> frames;
        append_bytes(frames, settings);
        append_bytes(frames, goaway);
        auto control = make_h3_control_stream(std::span<const std::byte>{frames.data(), frames.size()});

        // Stream 3 is the server-initiated control stream received by this
        // client (RFC 9000 §2.1: server unidirectional streams start at 3).
        transport.announce(3, http::stream_access::receive_only);
        transport.feed(3, std::span<const std::byte>{control.data(), control.size()}, false);
        expect(client.goaway_received());

        auto threw = false;
        try {
            http::buffer_body empty;
            static_cast<void>(run_sync(http::coroutine::request(client, basic_get("/after-goaway"), empty)));
        } catch (const http::protocol_error& failure) {
            expect(failure.info().condition == http::error_condition::goaway_rejected);
            expect(failure.info().retryable);
            expect(!failure.info().exchange_identity.has_value());
            expect(std::holds_alternative<http::no_action>(failure.action()));
            threw = true;
        }

        expect(threw);
    };

    // RFC 9114 §4.1 — "A response MAY consist of multiple messages when and only when
    // one or more interim responses (1xx; see Section 15.2 of [HTTP]) precede a final
    // response to the same request." The client must not complete the exchange on an
    // interim header block: it is discarded and the final response is delivered.
    "http3_client_skips_interim_responses"_test = [] {
        recording_stream_factory transport{true};
        http::v3::client<recording_stream_factory> client{transport};
        run_sync(http::coroutine::start(client));
        static_cast<void>(transport.take_writes());

        http::buffer_body empty;
        auto client_request = http::coroutine::request(client, basic_get("/early"), empty);
        client_request.start();

        // HEADERS frame (type 0x1) carrying the interim 103 block, then the
        // final 200 block with FIN.
        auto interim = make_h3_frame(
            0x01, make_h3_field_section({{":status", "103"}, {"x-hint", "y"}}));
        transport.feed(0, interim, false);
        expect(!client_request.done());

        auto final_response = make_h3_frame(
            0x01, make_h3_field_section({{":status", "200"}, {"x-final", "z"}}));
        transport.feed(0, final_response, true);

        expect(client_request.done());
        auto response = run_sync(std::move(client_request));
        expect(response.head.status == 200_u);
        expect(!http::find_header(response.head.fields, "x-hint").has_value());
        auto final_field = http::find_header(response.head.fields, "x-final");
        expect(final_field.has_value());
        expect(*final_field == "z"sv);
    };

    // RFC 9114 §4.1 — "A response MAY consist of multiple messages when and only when
    // one or more interim responses (1xx; see Section 15.2 of [HTTP]) precede a final
    // response to the same request." A stream that terminates after only an interim
    // (1xx) header block never carried a final response, so the response is
    // incomplete; RFC 9114 §4.1.2 — "Malformed requests or responses that are
    // detected MUST be treated as a stream error of type H3_MESSAGE_ERROR" — makes
    // the truncated response a stream error of type H3_MESSAGE_ERROR. The client
    // must fail fast with that typed stream error instead of waiting forever for a
    // final response that can never arrive. nghttp3 records the 1xx status as
    // NGHTTP3_HTTP_FLAG_EXPECT_FINAL_RESPONSE and its end-of-message validation
    // (nghttp3_http_on_remote_end_stream) reports the missing final response as
    // NGHTTP3_ERR_MALFORMED_HTTP_MESSAGING, which httpant maps to H3_MESSAGE_ERROR.
    // The failure reaches the request through the client's stream-aborted branch
    // (condition stream_reset, action reset_stream{H3_MESSAGE_ERROR}), the same
    // delivery as http3_out_of_range_status_is_a_stream_error.
    "http3_interim_only_response_ending_with_fin_is_a_message_error"_test = [] {
        recording_stream_factory transport{true};
        http::v3::client<recording_stream_factory> client{transport};
        run_sync(http::coroutine::start(client));
        static_cast<void>(transport.take_writes());

        http::buffer_body empty;
        auto client_request = http::coroutine::request(client, basic_get("/interim-only"), empty);
        client_request.start();

        // A single interim 103 header block, then the stream terminates cleanly
        // with FIN and no final response (RFC 9114 §4.1).
        auto interim = make_h3_frame(
            0x01, make_h3_field_section({{":status", "103"}, {"x-hint", "y"}}));
        transport.feed(0, interim, false);
        expect(!client_request.done());

        transport.feed(0, std::span<const std::byte>{}, true);
        expect(client_request.done());

        auto threw = false;
        try {
            static_cast<void>(run_sync(std::move(client_request)));
        } catch (const http::protocol_error& failure) {
            expect(failure.info().scope == http::error_scope::stream);
            expect(failure.info().condition == http::error_condition::stream_reset);
            expect(std::holds_alternative<http::reset_stream>(failure.action()));
            const auto& reset = std::get<http::reset_stream>(failure.action());
            expect(std::get<http::v3::error_code>(reset.code).value == h3_message_error);
            threw = true;
        }
        expect(threw);

        // RFC 9114 §8 — "Stream errors are expressed as ... resets; they do
        // not affect other streams or the connection." The connection stays
        // open; the typed action reset exactly the offending stream.
        expect(transport.closes.empty());
        expect(transport.shutdowns.size() == 1_u);
        expect(transport.shutdowns.front().stream_id == 0_i);
        expect(transport.shutdowns.front().error.value == h3_message_error);
    };

    // RFC 9114 §4.1.1 — "Once a request stream has been opened, the request MAY be
    // cancelled by either endpoint. ... an implementation resets the sending parts of
    // streams and aborts reading on the receiving parts of streams." A peer reset is a
    // stream-level event: the reset request fails, but the connection and the requests
    // that follow it are unaffected.
    "http3_peer_stream_reset_is_stream_scoped"_test = [] {
        recording_stream_factory transport{true};
        http::v3::client<recording_stream_factory> client{transport};
        run_sync(http::coroutine::start(client));
        static_cast<void>(transport.take_writes());

        http::buffer_body empty;
        auto first = http::coroutine::request(client, basic_get("/cancelled"), empty);
        first.start();

        // RFC 9114 §8.1 — H3_REQUEST_CANCELLED (0x010c).
        transport.feed_reset(0, 0x010c);

        expect(first.done());
        auto threw = false;
        try {
            static_cast<void>(run_sync(std::move(first)));
        } catch (...) {
            threw = true;
        }
        expect(threw);

        // The connection survives: the next request (stream 4) completes.
        http::buffer_body second_empty;
        auto second = http::coroutine::request(client, basic_get("/alive"), second_empty);
        second.start();

        auto final_response = make_h3_frame(
            0x01, make_h3_field_section({{":status", "200"}}));
        transport.feed(4, final_response, true);

        expect(second.done());
        auto response = run_sync(std::move(second));
        expect(response.head.status == 200_u);
    };

    // RFC 9114 §5.2 — "An endpoint sends a GOAWAY frame to initiate graceful
    // shutdown of an HTTP/3 connection." RFC 9114 §8.1 — "H3_NO_ERROR (0x100):
    // No error. This is used when the connection or stream needs to be closed,
    // but there is no error to signal."
    "http3_graceful_shutdown_closes_the_factory_once"_test = [] {
        constexpr auto h3_no_error = std::uint64_t{0x100};
        recording_stream_factory transport{true};
        http::v3::client<recording_stream_factory> client{transport};
        run_sync(http::coroutine::start(client));

        run_sync(client.shutdown());

        expect(transport.closes.size() == 1_u);
        expect(transport.closes.front().value == h3_no_error);
    };

    // RFC 9110 §9.3.2 — "The HEAD method is identical to GET except that the server MUST
    // NOT send content in the response."
    "http3_server_head_response_has_no_body"_test = [] {
        recording_stream_factory client_transport{true};
        recording_stream_factory server_transport{false};

        http::v3::client<recording_stream_factory> client{client_transport};
        http::v3::server<recording_stream_factory> server{server_transport};

        run_sync(http::coroutine::start(client));
        route_writes_to(client_transport, server_transport);
        run_sync(http::coroutine::start(server));
        route_writes_to(server_transport, client_transport);

        // The recording transport's read side blocks until fed, so the client
        // request coroutine suspends on its response stream; the response
        // framing is asserted from the server's recorded writes below.
        http::buffer_body empty;
        auto client_request = http::coroutine::request(client, http::request{
            .method = http::method::HEAD,
            .target = "/resource",
            .scheme = "https",
            .authority = "example.com",
            .fields = {{"host", "example.com"}},
        }, empty);
        client_request.start();
        route_writes_to(client_transport, server_transport);

        auto request = run_sync(http::coroutine::receive(server));
        expect(request.head.method == http::method::HEAD);

        auto html_body = make_body("<html/>");
        run_sync(http::coroutine::respond(server,
            std::move(request.token),
            http::response{
                .status = 200,
                .reason = {},
                .fields = {{"content-type", "text/html"}},
            },
            html_body));
        auto response_writes = server_transport.take_writes();

        // RFC 9114 §4.1 — "DATA frames MUST NOT be sent on the request stream"
        // for a HEAD response: no DATA frame (type 0x00) may appear in the
        // server's writes for the request stream (id 0), and the stream must
        // still be terminated (END_STREAM via fin on the final write).
        auto fin_seen = false;
        for (auto& write : response_writes) {
            if (write.stream_id != 0) continue;
            fin_seen = fin_seen || write.fin;
            for (auto& frame : parse_h3_frames(write.data))
                expect(frame.type != 0_u);
        }
        expect(fin_seen);
    };

    // RFC 9114 §4.1 — "A server sends zero or more interim HTTP responses on the same stream
    // as the request, followed by a single final HTTP response" and response content, if
    // present, is "sent as a series of DATA frames."
    "http3_server_non_empty_response_body_is_framed"_test = [] {
        recording_stream_factory client_transport{true};
        recording_stream_factory server_transport{false};

        http::v3::client<recording_stream_factory> client{client_transport};
        http::v3::server<recording_stream_factory> server{server_transport};

        run_sync(http::coroutine::start(client));
        route_writes_to(client_transport, server_transport);
        run_sync(http::coroutine::start(server));
        route_writes_to(server_transport, client_transport);

        http::buffer_body empty;
        auto client_request = http::coroutine::request(client, basic_get("/body"), empty);
        client_request.start();
        route_writes_to(client_transport, server_transport);

        auto request = run_sync(http::coroutine::receive(server));
        expect(request.head.target == "/body"sv);

        auto response_body = make_body("payload");
        run_sync(http::coroutine::respond(server,
            std::move(request.token),
            http::response{
                .status = 200,
                .reason = {},
                .fields = {{"content-type", "text/plain"}},
            },
            response_body));
        auto response_writes = server_transport.take_writes();

        auto data_seen = false;
        for (auto& write : response_writes) {
            if (write.stream_id != 0) continue;
            for (auto& frame : parse_h3_frames(write.data)) {
                if (frame.type == 0_u) {
                    data_seen = true;
                    expect(bytes_to_string(frame.payload) == "payload"sv);
                }
            }
        }
        expect(data_seen);
    };

    // RFC 9114 §4.1 — "The response header section is sent before the
    // content, if any." A response becomes available when its HEADERS frame
    // completes; neither DATA nor FIN is required to deliver the head.
    // RFC 9114 §4.1 — "Receipt of an invalid sequence of frames MUST be
    // treated as a connection error of type H3_FRAME_UNEXPECTED"; this test
    // feeds the valid HEADERS → DATA sequence in separate transport events.
    "http3_headers_are_delivered_before_body_and_credit_follows_reads"_test = [] {
        recording_stream_factory client_transport{true};
        recording_stream_factory server_transport{false};
        http::v3::client<recording_stream_factory> client{client_transport};
        http::v3::server<recording_stream_factory> server{server_transport};

        run_sync(http::coroutine::start(client));
        route_writes_to(client_transport, server_transport);
        run_sync(http::coroutine::start(server));
        route_writes_to(server_transport, client_transport);

        http::buffer_body empty;
        auto client_request = http::coroutine::request(client, basic_get("/lazy"), empty);
        client_request.start();
        route_writes_to(client_transport, server_transport);
        auto request = run_sync(http::coroutine::receive(server));

        auto response_body = make_body("deferred-body");
        run_sync(http::coroutine::respond(server,
            std::move(request.token),
            http::response{.status = 200},
            response_body));

        std::vector<std::byte> headers;
        std::vector<std::byte> data;
        for (auto& write : server_transport.take_writes()) {
            if (write.stream_id != 0)
                continue;
            for (auto& frame : parse_h3_frames(write.data)) {
                auto encoded = make_h3_frame(frame.type, frame.payload);
                if (frame.type == 0x01)
                    append_bytes(headers, encoded);
                else if (frame.type == 0x00)
                    append_bytes(data, encoded);
            }
        }
        expect(!headers.empty());
        expect(!data.empty());

        client_transport.feed(0, headers, false);
        expect(client_request.done());
        auto response = run_sync(std::move(client_request));
        expect(response.head.status == 200_u);

        auto credit_after_headers = client_transport.consumed[0];
        client_transport.feed(0, data, false);
        auto credit_before_body_read = client_transport.consumed[0];
        expect(credit_before_body_read > credit_after_headers);

        std::array<std::byte, 32> output{};
        auto body_size = run_sync(response.body.async_read(output, std::stop_token{}));
        expect(bytes_to_string(std::span{output}.first(body_size)) == "deferred-body"sv);
        expect(client_transport.consumed[0] == credit_before_body_read + body_size);
    };

    // RFC 9114 §4.1 — "When a stream is canceled, this indicates that the
    // request or response was not transferred in full." Destroying an unread
    // lazy body explicitly cancels the receiving side instead of silently
    // abandoning flow-control state.
    "http3_unread_body_destruction_cancels_receiving_side"_test = [] {
        recording_stream_factory client_transport{true};
        recording_stream_factory server_transport{false};
        http::v3::client<recording_stream_factory> client{client_transport};
        http::v3::server<recording_stream_factory> server{server_transport};

        run_sync(http::coroutine::start(client));
        route_writes_to(client_transport, server_transport);
        run_sync(http::coroutine::start(server));
        route_writes_to(server_transport, client_transport);

        http::buffer_body empty;
        auto operation = http::coroutine::request(client, basic_get("/cancel"), empty);
        operation.start();
        route_writes_to(client_transport, server_transport);
        auto request = run_sync(http::coroutine::receive(server));

        auto body = make_body("not-read");
        run_sync(http::coroutine::respond(server,
            std::move(request.token), http::response{.status = 200}, body));
        auto writes = server_transport.take_writes();
        for (auto& write : writes) {
            if (write.stream_id != 0)
                continue;
            for (auto& frame : parse_h3_frames(write.data)) {
                if (frame.type != 0x01)
                    continue;
                auto headers = make_h3_frame(frame.type, frame.payload);
                client_transport.feed(0, headers, false);
            }
        }

        {
            auto response = run_sync(std::move(operation));
            expect(response.head.status == 200_u);
        }
        expect(client_transport.shutdowns.size() == 1_u);
        expect(client_transport.shutdowns.front().stream_id == 0_i);
        expect(client_transport.shutdowns.front().side == http::stream_side::receiving);
    };

    // RFC 9114 §8 — "When an entire connection needs to be terminated, QUIC
    // allows an endpoint to abruptly terminate a connection and communicate a
    // reason to the peer." Every operation waiting on that connection must
    // complete; a lazy body read must not remain suspended after failure.
    "http3_connection_failure_completes_lazy_body_waiter"_test = [] {
        recording_stream_factory client_transport{true};
        recording_stream_factory server_transport{false};
        http::v3::client<recording_stream_factory> client{client_transport};
        http::v3::server<recording_stream_factory> server{server_transport};

        run_sync(http::coroutine::start(client));
        route_writes_to(client_transport, server_transport);
        run_sync(http::coroutine::start(server));
        route_writes_to(server_transport, client_transport);

        http::buffer_body empty;
        auto operation = http::coroutine::request(client, basic_get("/failure"), empty);
        operation.start();
        route_writes_to(client_transport, server_transport);
        auto request = run_sync(http::coroutine::receive(server));
        run_sync(http::coroutine::respond(server,
            std::move(request.token), http::response{.status = 200}, empty));

        for (auto& write : server_transport.take_writes()) {
            if (write.stream_id != 0)
                continue;
            for (auto& frame : parse_h3_frames(write.data)) {
                if (frame.type == 0x01) {
                    auto headers = make_h3_frame(frame.type, frame.payload);
                    client_transport.feed(0, headers, false);
                }
            }
        }
        auto response = run_sync(std::move(operation));
        std::array<std::byte, 1> output{};
        auto read = response.body.async_read(output, std::stop_token{});
        read.start();
        expect(!read.done());

        // RFC 9114 §6.1 — server-created bidirectional streams are an
        // H3_STREAM_CREATION_ERROR, which terminates this client connection.
        client_transport.announce(1, http::stream_access::bidirectional);
        expect(read.done());
    };

    // RFC 9114 §4.1 — "Request and response content is sent as a series of
    // DATA frames." This implementation limits each body-source pull to one
    // 16 KiB retained chunk so acknowledgement, not total body size, controls
    // memory retention.
    "http3_outbound_body_is_pulled_in_bounded_chunks"_test = [] {
        recording_stream_factory client_transport{true};
        recording_stream_factory server_transport{false};
        http::v3::client<recording_stream_factory> client{client_transport};
        http::v3::server<recording_stream_factory> server{server_transport};

        run_sync(http::coroutine::start(client));
        route_writes_to(client_transport, server_transport);
        run_sync(http::coroutine::start(server));
        route_writes_to(server_transport, client_transport);

        measured_body body;
        body.data.resize(48 * 1024, std::byte{'x'});
        auto request_operation = http::coroutine::request(client, http::request{
            .method = http::method::POST,
            .target = "/bounded",
            .scheme = "https",
            .authority = "example.com",
            .fields = {{"host", "example.com"}},
        }, body);
        request_operation.start();
        route_writes_to(client_transport, server_transport);

        auto request = run_sync(http::coroutine::receive(server));
        expect(body.largest_request == 16u * 1024u);
        expect(body.reads >= 4_u);
        expect(read_body_text(request.body).size() == body.data.size());
    };

    // REFACTOR.md §9.3 — partial-write acceptance. The next four tests target
    // the transport write contract (stream_write_result::accepted) and the
    // internal nghttp3 write-offset retry machinery, not an RFC-mandated wire
    // behavior; the RFC 9114 §4.1 request/response stream semantics they touch
    // are quoted inline where asserted.
    "http3_client_request_body_survives_partial_write_acceptance"_test = [] {
        recording_stream_factory client_transport{true};
        recording_stream_factory server_transport{false};

        http::v3::client<recording_stream_factory> client{client_transport};
        http::v3::server<recording_stream_factory> server{server_transport};

        run_sync(http::coroutine::start(client));
        route_writes_to(client_transport, server_transport);
        run_sync(http::coroutine::start(server));
        route_writes_to(server_transport, client_transport);

        // The request operation opens the client's first bidirectional stream
        // (id 0); do not pre-open a stream and consume that identity in the
        // test. The scripted limits sum to 6 bytes, below the head+body wire
        // size, so flush_output must retry the unaccepted tail several times
        // before the script is exhausted and whole-buffer acceptance resumes.
        client_transport.script_acceptance(0, {1, 3, 2});

        auto body = make_body("partial-request-body");
        auto client_request = http::coroutine::request(client, http::request{
            .method = http::method::POST,
            .target = "/upload",
            .scheme = "https",
            .authority = "example.com",
            .fields = {{"host", "example.com"}},
        }, body);
        client_request.start();
        route_writes_to(client_transport, server_transport);

        auto request = run_sync(http::coroutine::receive(server));
        expect(request.head.method == http::method::POST);
        expect(request.head.target == "/upload"sv);
        // Core regression (REFACTOR.md §9.3): advancing the nghttp3 write
        // offset before the transport accepted the bytes dropped the
        // unaccepted tail, so the server reassembled a truncated body.
        expect(read_body_text(request.body) == "partial-request-body"sv);

        http::buffer_body empty;
        run_sync(http::coroutine::respond(server,
            std::move(request.token),
            http::response{
                .status = 200,
                .reason = {},
                .fields = {{"content-type", "text/plain"}},
            },
            empty));
        route_writes_to(server_transport, client_transport);

        auto response = run_sync(std::move(client_request));
        expect(response.head.status == 200_u);
    };

    // REFACTOR.md §9.3 — see the partial-write note above; same retry
    // machinery, exercised on the server's response path. RFC 9114 §4.1 — "A
    // server sends zero or more interim HTTP responses on the same stream as
    // the request, followed by a single final HTTP response": the response
    // bytes travel on the client's request stream (wire id 0).
    "http3_server_response_body_survives_partial_write_acceptance"_test = [] {
        recording_stream_factory client_transport{true};
        recording_stream_factory server_transport{false};

        http::v3::client<recording_stream_factory> client{client_transport};
        http::v3::server<recording_stream_factory> server{server_transport};

        run_sync(http::coroutine::start(client));
        route_writes_to(client_transport, server_transport);
        run_sync(http::coroutine::start(server));
        route_writes_to(server_transport, client_transport);

        http::buffer_body empty;
        auto client_request = http::coroutine::request(client, basic_get("/download"), empty);
        client_request.start();
        route_writes_to(client_transport, server_transport);

        auto request = run_sync(http::coroutine::receive(server));
        expect(request.head.target == "/download"sv);

        // The scripted limits sum to 3 bytes, below the head+body wire size,
        // so the response is only fully written after several retries.
        server_transport.script_acceptance(0, {2, 1});

        auto body = make_body("partial-response-body");
        run_sync(http::coroutine::respond(server,
            std::move(request.token),
            http::response{
                .status = 200,
                .reason = {},
                .fields = {{"content-type", "text/plain"}},
            },
            body));
        route_writes_to(server_transport, client_transport);

        auto response = run_sync(std::move(client_request));
        expect(response.head.status == 200_u);
        expect(read_body_text(response.body) == "partial-response-body"sv);
    };

    // REFACTOR.md §9.3 — transport FIN contract under partial acceptance (not
    // an RFC behavior): the transport applies FIN only once the whole buffer
    // handed to it was accepted, so flush_output's same-fin retries must
    // surface exactly one fin=true write, on the last chunk. RFC 9114 §4.1 —
    // "After sending a request, a client MUST close the stream for sending."
    "http3_partial_write_fin_is_delayed_until_final_chunk"_test = [] {
        auto make_post = [] {
            return http::request{
                .method = http::method::POST,
                .target = "/fin",
                .scheme = "https",
                .authority = "example.com",
                .fields = {{"host", "example.com"}},
            };
        };

        // Control run without scripted acceptance: capture the exact request
        // stream byte sequence for comparison.
        std::vector<std::byte> control;
        {
            recording_stream_factory transport{true};
            http::v3::client<recording_stream_factory> client{transport};
            run_sync(http::coroutine::start(client));
            static_cast<void>(transport.take_writes());

            auto body = make_body("fin-payload");
            auto client_request = http::coroutine::request(client, make_post(), body);
            client_request.start();
            for (auto& write : transport.take_writes()) {
                if (write.stream_id != 0) continue;
                append_bytes(control, write.data);
            }
        }
        expect(!control.empty());

        recording_stream_factory transport{true};
        http::v3::client<recording_stream_factory> client{transport};
        run_sync(http::coroutine::start(client));
        static_cast<void>(transport.take_writes());

        // The scripted limits sum to 3 bytes, below the head+body wire size,
        // forcing multiple partial writes on the request stream (id 0).
        transport.script_acceptance(0, {1, 2});
        auto body = make_body("fin-payload");
        auto client_request = http::coroutine::request(client, make_post(), body);
        client_request.start();

        std::vector<std::byte> scripted;
        std::vector<bool> fins;
        for (auto& write : transport.take_writes()) {
            if (write.stream_id != 0) continue;
            append_bytes(scripted, write.data);
            fins.push_back(write.fin);
        }

        // Partial acceptance must not alter the wire bytes: the accepted
        // prefixes concatenate to the same stream contents as the control run.
        // (Compared as text because boost::ut cannot print std::byte.)
        expect(bytes_to_string(scripted) == bytes_to_string(control));
        expect(fins.size() > 1_u);
        for (std::size_t i = 0; i + 1 < fins.size(); ++i)
            expect(!fins[i]);
        expect(fins.back());
    };

    // REFACTOR.md §9.3 — a transport that accepts zero bytes must not spin the
    // retry loop forever (not an RFC behavior): flush_output fails the
    // operation, and the exception reaches the request() caller directly
    // because the flush runs inline in the request operation.
    "http3_zero_write_acceptance_fails_with_no_progress_error"_test = [] {
        recording_stream_factory transport{true};
        http::v3::client<recording_stream_factory> client{transport};
        run_sync(http::coroutine::start(client));
        static_cast<void>(transport.take_writes());

        // The request operation opens the client's first bidirectional stream
        // (id 0); its first write accepts nothing.
        transport.script_acceptance(0, {0});

        auto threw = false;
        try {
            auto body = make_body("payload");
            static_cast<void>(run_sync(http::coroutine::request(client, http::request{
                .method = http::method::POST,
                .target = "/blocked",
                .scheme = "https",
                .authority = "example.com",
                .fields = {{"host", "example.com"}},
            }, body)));
        } catch (const std::runtime_error& failure) {
            expect(std::string_view{failure.what()}.contains("no progress"sv));
            threw = true;
        }

        expect(threw);
    };

    // RFC 9114 §6.2.1 — "Each side MUST initiate a single control stream at the beginning of
    // the connection and send its SETTINGS frame as the first frame on this stream. If the
    // first frame of the control stream is any other frame type, this MUST be treated as a
    // connection error of type H3_MISSING_SETTINGS."
    "http3_control_stream_validation_is_implemented"_test = [] {
        recording_stream_factory transport{true};
        http::v3::client<recording_stream_factory> client{transport};
        run_sync(http::coroutine::start(client));
        static_cast<void>(transport.take_writes());

        auto goaway = make_h3_frame(0x07, 0);
        auto invalid = make_h3_control_stream(std::span<const std::byte>{goaway.data(), goaway.size()});

        // Stream 3 is the server-initiated control stream received by this
        // client; it must start with SETTINGS. The endpoint-owned driver records the
        // connection failure inline.
        transport.announce(3, http::stream_access::receive_only);
        transport.feed(3, std::span<const std::byte>{invalid.data(), invalid.size()}, false);

        // RFC 9114 §6.2.1 — "... MUST be treated as a connection error of type
        // H3_MISSING_SETTINGS." The typed error surfaces on the next client
        // operation as a connection-close action with the H3_MISSING_SETTINGS
        // application code.
        auto threw = false;
        try {
            http::buffer_body empty;
            static_cast<void>(run_sync(http::coroutine::request(client, basic_get("/h3"), empty)));
        } catch (const http::protocol_error& failure) {
            expect(std::holds_alternative<http::close_connection>(failure.action()));
            const auto& close = std::get<http::close_connection>(failure.action());
            expect(close.code.has_value());
            expect(std::holds_alternative<http::v3::error_code>(*close.code));
            expect(std::get<http::v3::error_code>(*close.code).value == h3_missing_settings);
            threw = true;
        }

        expect(threw);
    };

    // RFC 9114 §6.1 — "HTTP/3 does not use server-initiated bidirectional streams, though an
    // extension could define a use for these streams. Clients MUST treat receipt of a
    // server-initiated bidirectional stream as a connection error of type
    // H3_STREAM_CREATION_ERROR unless such an extension has been negotiated."
    "http3_client_rejects_server_initiated_bidirectional_stream"_test = [] {
        recording_stream_factory transport{true};
        http::v3::client<recording_stream_factory> client{transport};
        run_sync(http::coroutine::start(client));
        static_cast<void>(transport.take_writes());

        // Stream 1 is a server-initiated bidirectional stream (RFC 9000 §2.1).
        // The driver classifies accepted streams by the handle's declared
        // access, so the direction check does not guess from the numeric id.
        transport.announce(1, http::stream_access::bidirectional);

        expect_h3_connection_close(
            [&] {
                http::buffer_body empty;
                return http::coroutine::request(client, basic_get("/h3"), empty);
            },
            h3_stream_creation_error);
    };

    // RFC 9114 §6.2.1 — "Only one control stream per peer is permitted; receipt of a second
    // stream claiming to be a control stream MUST be treated as a connection error of type
    // H3_STREAM_CREATION_ERROR."
    "http3_duplicate_control_stream_is_stream_creation_error"_test = [] {
        recording_stream_factory transport{true};
        http::v3::client<recording_stream_factory> client{transport};
        run_sync(http::coroutine::start(client));
        static_cast<void>(transport.take_writes());

        auto settings = make_h3_frame(0x04, std::span<const std::byte>{});
        auto control = make_h3_control_stream(std::span<const std::byte>{settings.data(), settings.size()});

        // Streams 3 and 7 are server-initiated unidirectional streams received
        // by this client (RFC 9000 §2.1); both claim to be the control stream.
        transport.announce(3, http::stream_access::receive_only);
        transport.feed(3, std::span<const std::byte>{control.data(), control.size()}, false);
        transport.announce(7, http::stream_access::receive_only);
        transport.feed(7, std::span<const std::byte>{control.data(), control.size()}, false);

        expect_h3_connection_close(
            [&] {
                http::buffer_body empty;
                return http::coroutine::request(client, basic_get("/h3"), empty);
            },
            h3_stream_creation_error);
    };

    // RFC 9204 §4.2 — "Each endpoint MUST initiate, at most, one encoder stream and, at most,
    // one decoder stream. Receipt of a second instance of either stream type MUST be treated
    // as a connection error of type H3_STREAM_CREATION_ERROR."
    "http3_duplicate_qpack_encoder_stream_is_stream_creation_error"_test = [] {
        recording_stream_factory transport{true};
        http::v3::client<recording_stream_factory> client{transport};
        run_sync(http::coroutine::start(client));
        static_cast<void>(transport.take_writes());

        // 0x02 is the QPACK encoder stream type (RFC 9204 §4.2); streams 3 and
        // 7 are server-initiated unidirectional streams (RFC 9000 §2.1).
        auto encoder_header = encode_h3_varint(0x02);
        transport.announce(3, http::stream_access::receive_only);
        transport.feed(3, std::span<const std::byte>{encoder_header.data(), encoder_header.size()}, false);
        transport.announce(7, http::stream_access::receive_only);
        transport.feed(7, std::span<const std::byte>{encoder_header.data(), encoder_header.size()}, false);

        expect_h3_connection_close(
            [&] {
                http::buffer_body empty;
                return http::coroutine::request(client, basic_get("/h3"), empty);
            },
            h3_stream_creation_error);
    };

    // RFC 9204 §6 — "QPACK_DECODER_STREAM_ERROR (0x0202): The encoder failed
    // to interpret a decoder instruction received on the decoder stream."
    // An Insert Count Increment of zero is forbidden by RFC 9204 §4.4.3.
    "http3_qpack_decoder_stream_error_closes_transport"_test = [] {
        recording_stream_factory transport{true};
        http::v3::client<recording_stream_factory> client{transport};
        run_sync(http::coroutine::start(client));
        static_cast<void>(transport.take_writes());

        auto decoder = encode_h3_varint(0x03);
        decoder.push_back(std::byte{0x00});
        transport.announce(3, http::stream_access::receive_only);
        transport.feed(
            3,
            std::span<const std::byte>{decoder.data(), decoder.size()},
            false);

        expect(transport.closes.size() == 1_u);
        expect(transport.closes.front().value == qpack_decoder_stream_error);
        expect_h3_connection_close(
            [&] {
                http::buffer_body empty;
                return http::coroutine::request(
                    client, basic_get("/qpack-error"), empty);
            },
            qpack_decoder_stream_error);
    };

    // RFC 9204 §6 — "QPACK_ENCODER_STREAM_ERROR (0x0201): The decoder failed
    // to interpret an encoder instruction received on the encoder stream."
    // Duplicate index zero is invalid while the dynamic table is empty
    // (RFC 9204 §4.3.4 requires an existing entry).
    "http3_qpack_encoder_stream_error_closes_transport"_test = [] {
        recording_stream_factory transport{true};
        http::v3::client<recording_stream_factory> client{
            transport,
            http::v3::configuration{
                .compression = {
                    .decoder_capacity = 4096,
                    .blocked_streams = 8,
                    .encoder_capacity = 4096,
                },
            }};
        run_sync(http::coroutine::start(client));
        static_cast<void>(transport.take_writes());

        auto encoder = encode_h3_varint(0x02);
        encoder.push_back(std::byte{0x00});
        transport.announce(3, http::stream_access::receive_only);
        transport.feed(
            3,
            std::span<const std::byte>{encoder.data(), encoder.size()},
            false);

        expect(transport.closes.size() == 1_u);
        expect(transport.closes.front().value == qpack_encoder_stream_error);
        expect_h3_connection_close(
            [&] {
                http::buffer_body empty;
                return http::coroutine::request(
                    client, basic_get("/qpack-error"), empty);
            },
            qpack_encoder_stream_error);
    };

    // RFC 9204 §6 — "QPACK_DECOMPRESSION_FAILED (0x0200): The decoder failed
    // to interpret an encoded field section and is not able to continue
    // decoding that field section." The field section below is truncated after
    // an invalid prefix and is complete at the HTTP/3 frame boundary.
    "http3_qpack_decompression_failure_closes_transport"_test = [] {
        recording_stream_factory transport{false};
        http::v3::server<recording_stream_factory> server{
            transport,
            http::v3::configuration{
                .compression = {
                    .decoder_capacity = 4096,
                    .blocked_streams = 8,
                    .encoder_capacity = 4096,
                },
            }};
        run_sync(http::coroutine::start(server));
        static_cast<void>(transport.take_writes());

        auto settings = make_h3_frame(0x04, std::span<const std::byte>{});
        auto control = make_h3_control_stream(
            std::span<const std::byte>{settings.data(), settings.size()});
        transport.announce(2, http::stream_access::receive_only);
        transport.feed(
            2,
            std::span<const std::byte>{control.data(), control.size()},
            false);

        constexpr std::array invalid_field_section{std::byte{0xff}};
        auto headers = make_h3_frame(0x01, invalid_field_section);
        transport.announce(0, http::stream_access::bidirectional);
        transport.feed(
            0,
            std::span<const std::byte>{headers.data(), headers.size()},
            true);

        expect(transport.closes.size() == 1_u);
        expect(transport.closes.front().value == qpack_decompression_failed);
        expect_h3_connection_close(
            [&] { return http::coroutine::receive(server); },
            qpack_decompression_failed);
    };

    // RFC 9204 §4.2 — "The sender MUST NOT close either of these streams, and the receiver
    // MUST NOT request that the sender close either of these streams. Closure of either
    // unidirectional stream type MUST be treated as a connection error of type
    // H3_CLOSED_CRITICAL_STREAM."
    "http3_qpack_stream_close_is_closed_critical_stream"_test = [] {
        recording_stream_factory transport{true};
        http::v3::client<recording_stream_factory> client{transport};
        run_sync(http::coroutine::start(client));
        static_cast<void>(transport.take_writes());

        // 0x02 is the QPACK encoder stream type (RFC 9204 §4.2); the peer then
        // closes this critical stream with FIN.
        auto encoder_header = encode_h3_varint(0x02);
        transport.announce(3, http::stream_access::receive_only);
        transport.feed(3, std::span<const std::byte>{encoder_header.data(), encoder_header.size()}, true);

        expect_h3_connection_close(
            [&] {
                http::buffer_body empty;
                return http::coroutine::request(client, basic_get("/h3"), empty);
            },
            h3_closed_critical_stream);
    };

    // RFC 9114 §6.2.1 — "The sender MUST NOT close the control stream, and the receiver MUST
    // NOT request that the sender close the control stream. If either control stream is closed
    // at any point, this MUST be treated as a connection error of type
    // H3_CLOSED_CRITICAL_STREAM."
    "http3_control_stream_close_is_closed_critical_stream"_test = [] {
        recording_stream_factory transport{true};
        http::v3::client<recording_stream_factory> client{transport};
        run_sync(http::coroutine::start(client));
        static_cast<void>(transport.take_writes());

        auto settings = make_h3_frame(0x04, std::span<const std::byte>{});
        auto control = make_h3_control_stream(std::span<const std::byte>{settings.data(), settings.size()});

        // Stream 3 is the server-initiated control stream received by this
        // client; the peer closes it with FIN after a valid SETTINGS frame.
        transport.announce(3, http::stream_access::receive_only);
        transport.feed(3, std::span<const std::byte>{control.data(), control.size()}, true);

        expect_h3_connection_close(
            [&] {
                http::buffer_body empty;
                return http::coroutine::request(client, basic_get("/h3"), empty);
            },
            h3_closed_critical_stream);
    };

    // RFC 9114 §4.1.2 — "Malformed requests or responses that are detected
    // MUST be treated as a stream error of type H3_MESSAGE_ERROR." A request
    // whose pseudo-header field section is missing :scheme and :path (RFC
    // 9114 §4.3.1 — "the request ... MUST contain the :method, :scheme, and
    // :path pseudo-header fields") is malformed; the server resets only the
    // offending stream with H3_MESSAGE_ERROR and keeps the connection and its
    // concurrent exchanges alive.
    "http3_malformed_request_is_a_stream_error_not_a_connection_error"_test = [] {
        recording_stream_factory transport{false};
        http::v3::server<recording_stream_factory> server{transport};
        run_sync(http::coroutine::start(server));
        static_cast<void>(transport.take_writes());

        auto receive = http::coroutine::receive(server);
        receive.start();

        // Malformed request: missing :scheme and :path.
        auto malformed = make_h3_frame(
            0x01, make_h3_field_section({
                {":method", "GET"},
                {":authority", "example.com"},
                {"host", "example.com"},
            }));
        transport.announce(0, http::stream_access::bidirectional);
        transport.feed(
            0,
            std::span<const std::byte>{malformed.data(), malformed.size()},
            true);

        auto threw = false;
        try {
            static_cast<void>(run_sync(std::move(receive)));
        } catch (const http::protocol_error& failure) {
            expect(failure.info().scope == http::error_scope::stream);
            expect(failure.info().condition == http::error_condition::malformed_message);
            expect(std::holds_alternative<http::reset_stream>(failure.action()));
            const auto& reset = std::get<http::reset_stream>(failure.action());
            expect(std::get<http::v3::error_code>(reset.code).value == h3_message_error);
            threw = true;
        }
        expect(threw);

        // RFC 9114 §8 — "Stream errors are expressed as ... resets; they do
        // not affect other streams or the connection." The connection stays
        // open: the server's factory has not closed it, and the transport
        // recorded the reset of exactly the malformed stream.
        expect(transport.closes.empty());
        expect(transport.shutdowns.size() == 1_u);
        expect(transport.shutdowns.front().stream_id == 0_i);
        expect(transport.shutdowns.front().error.value == h3_message_error);
    };
    // RFC 9114 §4.3.1 — "If both fields are present, they MUST contain the
    // same value." nghttp3 validates pseudo-header presence but does not
    // compare Host with :authority; httpant must reject the mismatch as a
    // stream-scoped H3_MESSAGE_ERROR rather than deliver an ambiguous request.
    "http3_host_authority_mismatch_is_a_stream_error"_test = [] {
        recording_stream_factory transport{false};
        http::v3::server<recording_stream_factory> server{transport};
        run_sync(http::coroutine::start(server));
        static_cast<void>(transport.take_writes());

        auto receive = http::coroutine::receive(server);
        receive.start();

        auto mismatched = make_h3_frame(
            0x01, make_h3_field_section({
                {":method", "GET"},
                {":scheme", "https"},
                {":path", "/"},
                {":authority", "example.com"},
                {"host", "other.example"},
            }));
        transport.announce(0, http::stream_access::bidirectional);
        transport.feed(
            0,
            std::span<const std::byte>{mismatched.data(), mismatched.size()},
            true);

        auto threw = false;
        try {
            static_cast<void>(run_sync(std::move(receive)));
        } catch (const http::protocol_error& failure) {
            expect(failure.info().scope == http::error_scope::stream);
            expect(failure.info().condition == http::error_condition::malformed_message);
            expect(std::holds_alternative<http::reset_stream>(failure.action()));
            const auto& reset = std::get<http::reset_stream>(failure.action());
            expect(std::get<http::v3::error_code>(reset.code).value == h3_message_error);
            threw = true;
        }
        expect(threw);

        // The stream error must not close the connection.
        expect(transport.closes.empty());
        expect(transport.shutdowns.size() == 1_u);
        expect(transport.shutdowns.front().stream_id == 0_i);
        expect(transport.shutdowns.front().error.value == h3_message_error);
    };




    // RFC 9114 §7.1 — "When a stream terminates cleanly, if the last frame on
    // the stream was truncated, this MUST be treated as a connection error of
    // type H3_FRAME_ERROR." The rule is generic over streams, so a request
    // stream whose HEADERS frame is truncated by FIN (the frame declares more
    // QPACK bytes than the stream carries) closes the connection — httpant
    // buffers partial frames and only forwards complete ones to nghttp3, so
    // the truncation is intercepted here before the library ever sees the
    // frame. A stream that instead terminates at a frame boundary without a
    // complete message keeps the §4.1 H3_REQUEST_INCOMPLETE stream error
    // (see http3_request_incomplete_at_frame_boundary_fin).
    "http3_truncated_request_is_a_connection_error"_test = [] {
        recording_stream_factory transport{false};
        http::v3::server<recording_stream_factory> server{transport};
        run_sync(http::coroutine::start(server));
        static_cast<void>(transport.take_writes());

        // A HEADERS frame (type 0x01, RFC 9114 §7.1) whose declared length
        // is 80 bytes but which carries only 7 payload bytes before FIN: the
        // frame is truncated mid-payload, so the stream terminated cleanly
        // with a truncated last frame.
        std::vector<std::byte> truncated{
            std::byte{0x01},             // HEADERS type
            std::byte{0x40}, std::byte{0x50}, // length 80 (2-byte varint)
            std::byte{0x00}, std::byte{0x00}, // QPACK field-section prefix
            std::byte{0x2a}, std::byte{0x07}, // literal ":status"...
        };
        truncated.resize(9); // only 7 payload bytes

        transport.announce(0, http::stream_access::bidirectional);
        transport.feed(
            0,
            std::span<const std::byte>{truncated.data(), truncated.size()},
            true);

        // RFC 9114 §8 — "If an entire connection needs to be terminated, QUIC
        // ... provides mechanisms to communicate a reason ... using an error
        // code from Section 8.1." The typed connection action carries
        // H3_FRAME_ERROR and the factory performs the QUIC close.
        expect(transport.closes.size() == 1_u);
        expect(transport.closes.front().value == h3_frame_error);
        expect_h3_connection_close(
            [&] { return http::coroutine::receive(server); },
            h3_frame_error);

        // The failed request stream was never delivered to receive(): the
        // queued failure is the connection error, and no body_reader exists to
        // release the stream's state.
        expect(transport.shutdowns.empty());
    };

    // RFC 9114 §4.1 — "If a client-initiated stream terminates without enough
    // of the HTTP message to provide a complete response, the server SHOULD
    // abort its response stream with the error code H3_REQUEST_INCOMPLETE."
    // RFC 9114 §8.1 — "H3_REQUEST_INCOMPLETE (0x010d): The client's stream
    // terminated without containing a fully formed request." A request stream
    // that terminates at a frame boundary (no frame in progress) without a
    // complete message keeps the §4.1 stream error and is distinct from a
    // truncated last frame, which RFC 9114 §7.1 — "When a stream terminates
    // cleanly, if the last frame on the stream was truncated, this MUST be
    // treated as a connection error of type H3_FRAME_ERROR" — makes a
    // connection error (see http3_truncated_request_is_a_connection_error).
    // nghttp3 classifies a FIN with no frame started as H3_FRAME_UNEXPECTED,
    // which httpant maps to the §4.1 stream error (verified against the
    // library source: a request stream that reaches FIN at its initial state
    // reports NGHTTP3_ERR_H3_FRAME_UNEXPECTED with fin set).
    "http3_request_incomplete_at_frame_boundary_fin"_test = [] {
        recording_stream_factory transport{false};
        http::v3::server<recording_stream_factory> server{transport};
        run_sync(http::coroutine::start(server));
        static_cast<void>(transport.take_writes());

        auto receive = http::coroutine::receive(server);
        receive.start();

        // The client opens a request stream and immediately closes it with
        // FIN: the stream terminates at a frame boundary with zero bytes —
        // no frame ever started, so there is no complete message and no
        // truncated frame (RFC 9114 §4.1 / §8.1).
        transport.announce(0, http::stream_access::bidirectional);
        transport.feed(0, std::span<const std::byte>{}, true);

        auto threw = false;
        try {
            static_cast<void>(run_sync(std::move(receive)));
        } catch (const http::protocol_error& failure) {
            expect(failure.info().scope == http::error_scope::stream);
            expect(std::holds_alternative<http::reset_stream>(failure.action()));
            const auto& reset = std::get<http::reset_stream>(failure.action());
            expect(std::get<http::v3::error_code>(reset.code).value == h3_request_incomplete);
            threw = true;
        }
        expect(threw);

        // RFC 9114 §8 — "Stream errors are expressed as ... resets; they do
        // not affect other streams or the connection." The connection stays
        // open; the reset named only the request stream.
        expect(transport.closes.empty());
        expect(transport.shutdowns.size() == 1_u);
        expect(transport.shutdowns.front().stream_id == 0_i);
        expect(transport.shutdowns.front().error.value == h3_request_incomplete);
    };

    // RFC 9114 §4.3.1 — "An OPTIONS request that does not include a path
    // component includes the value * (ASCII 0x2a) for the :path pseudo-header
    // field." Asterisk-form targets are defined only for OPTIONS; RFC 9110
    // §7.1 — "These forms MUST NOT be used with other methods." A GET with
    // ':path: *' is therefore malformed, and RFC 9114 §4.1.2 — "Malformed
    // requests or responses that are detected MUST be treated as a stream
    // error of type H3_MESSAGE_ERROR" — requires the server to reset the
    // offending stream; the connection and its other exchanges keep running.
    "http3_asterisk_form_path_with_non_options_method_is_malformed"_test = [] {
        recording_stream_factory transport{false};
        http::v3::server<recording_stream_factory> server{transport};
        run_sync(http::coroutine::start(server));
        static_cast<void>(transport.take_writes());

        auto receive = http::coroutine::receive(server);
        receive.start();

        auto malformed = make_h3_frame(
            0x01, make_h3_field_section({
                {":method", "GET"},
                {":scheme", "http"},
                {":authority", "example.com"},
                {":path", "*"},
            }));
        transport.announce(0, http::stream_access::bidirectional);
        transport.feed(
            0,
            std::span<const std::byte>{malformed.data(), malformed.size()},
            true);

        auto threw = false;
        try {
            static_cast<void>(run_sync(std::move(receive)));
        } catch (const http::protocol_error& failure) {
            expect(failure.info().scope == http::error_scope::stream);
            expect(failure.info().condition == http::error_condition::malformed_message);
            expect(std::holds_alternative<http::reset_stream>(failure.action()));
            const auto& reset = std::get<http::reset_stream>(failure.action());
            expect(std::get<http::v3::error_code>(reset.code).value == h3_message_error);
            threw = true;
        }
        expect(threw);

        // RFC 9114 §8 — "Stream errors are expressed as ... resets; they do
        // not affect other streams or the connection." The connection stays
        // open; the reset named only the malformed stream.
        expect(transport.closes.empty());
        expect(transport.shutdowns.size() == 1_u);
        expect(transport.shutdowns.front().stream_id == 0_i);
        expect(transport.shutdowns.front().error.value == h3_message_error);
    };

    // RFC 9114 §7.2.3 — "If the client receives a CANCEL_PUSH frame, that
    // frame might identify a push ID that has not yet been mentioned by a
    // PUSH_PROMISE frame due to reordering." The client must tolerate such a
    // cancellation instead of erroring; only a server's CANCEL_PUSH for an
    // unmentioned push ID is an H3_ID_ERROR (same section: "If a server
    // receives a CANCEL_PUSH frame for a push ID that has not yet been
    // mentioned by a PUSH_PROMISE frame, this MUST be treated as a connection
    // error of type H3_ID_ERROR").
    "http3_client_tolerates_cancel_push_for_unknown_push_id"_test = [] {
        recording_stream_factory transport{true};
        http::v3::client<recording_stream_factory> client{transport};
        run_sync(http::coroutine::start(client));
        static_cast<void>(transport.take_writes());

        auto settings = make_h3_frame(0x04, std::span<const std::byte>{});
        // CANCEL_PUSH (type 0x03, RFC 9114 §7.2.3) for push ID 7, which no
        // PUSH_PROMISE has ever mentioned.
        auto cancel = make_h3_frame(0x03, 7);
        std::vector<std::byte> control;
        append_bytes(control, settings);
        append_bytes(control, cancel);
        auto bytes = make_h3_control_stream(
            std::span<const std::byte>{control.data(), control.size()});

        transport.announce(3, http::stream_access::receive_only);
        transport.feed(3, std::span<const std::byte>{bytes.data(), bytes.size()}, false);

        // No error is recorded and the connection remains usable: a request
        // on stream 0 completes normally.
        http::buffer_body empty;
        auto request = http::coroutine::request(client, basic_get("/after-cancel"), empty);
        request.start();

        auto response = make_h3_frame(
            0x01, make_h3_field_section({{":status", "200"}}));
        transport.feed(0, response, true);

        auto received = run_sync(std::move(request));
        expect(received.head.status == 200_u);
        expect(transport.closes.empty());
    };

    // RFC 9114 §7.2.3 — "If a server receives a CANCEL_PUSH frame for a push
    // ID that has not yet been mentioned by a PUSH_PROMISE frame, this MUST be
    // treated as a connection error of type H3_ID_ERROR." httpant never sends
    // PUSH_PROMISE, so a server receiving CANCEL_PUSH always errors.
    "http3_server_rejects_cancel_push_for_unknown_push_id"_test = [] {
        recording_stream_factory transport{false};
        http::v3::server<recording_stream_factory> server{transport};
        run_sync(http::coroutine::start(server));
        static_cast<void>(transport.take_writes());

        auto settings = make_h3_frame(0x04, std::span<const std::byte>{});
        auto cancel = make_h3_frame(0x03, 7);
        std::vector<std::byte> control;
        append_bytes(control, settings);
        append_bytes(control, cancel);
        auto bytes = make_h3_control_stream(
            std::span<const std::byte>{control.data(), control.size()});

        // Stream 2 is the client's control stream (RFC 9000 §2.1 — client
        // unidirectional streams start at 2); the server treats the unknown
        // push ID as an H3_ID_ERROR connection error.
        transport.announce(2, http::stream_access::receive_only);
        transport.feed(2, std::span<const std::byte>{bytes.data(), bytes.size()}, false);

        expect_h3_connection_close(
            [&] { return http::coroutine::receive(server); },
            h3_id_error);
    };

    // RFC 9114 §6.2 — "Recipients of unknown stream types MUST either abort
    // reading of the stream or discard incoming data without further
    // processing." httpant discards: every chunk on an unknown unidirectional
    // stream is dropped and granted as flow-control credit immediately rather
    // than buffered to FIN, so the peer's credit keeps advancing and memory
    // stays bounded.
    "http3_unknown_unidirectional_stream_data_is_discarded_and_consumed"_test = [] {
        recording_stream_factory transport{true};
        http::v3::client<recording_stream_factory> client{transport};
        run_sync(http::coroutine::start(client));
        static_cast<void>(transport.take_writes());

        // Stream 3 carries an unknown stream type (0x3f), then 4 KiB of
        // payload delivered in two chunks, then FIN.
        std::vector<std::byte> unknown;
        auto type = encode_h3_varint(0x3f);
        append_bytes(unknown, type);
        std::vector<std::byte> payload(4096, std::byte{'x'});
        append_bytes(unknown, payload);
        transport.announce(3, http::stream_access::receive_only);
        transport.feed(
            3,
            std::span<const std::byte>{unknown.data(), unknown.size()},
            false);

        std::vector<std::byte> tail(4096, std::byte{'y'});
        transport.feed(3, tail, true);

        // RFC 9114 §6.2 — "The recipient MUST NOT consider unknown stream
        // types to be a connection error of any kind." The connection stays
        // usable and every discarded byte was granted credit: consumed[3]
        // covers the stream-type varint plus both payload chunks.
        http::buffer_body empty;
        auto request = http::coroutine::request(client, basic_get("/after-unknown"), empty);
        request.start();
        auto response = make_h3_frame(
            0x01, make_h3_field_section({{":status", "200"}}));
        transport.feed(0, response, true);
        auto received = run_sync(std::move(request));
        expect(received.head.status == 200_u);
        expect(transport.closes.empty());
        expect(transport.consumed[3] == unknown.size() + tail.size());
    };

    // RFC 9114 §4.2.2 — "An implementation that has received this parameter
    // SHOULD NOT send an HTTP message header that exceeds the indicated size,
    // as the peer will likely refuse to process it." (RFC 9114 §7.2.4.2 — "An
    // HTTP implementation MUST NOT send frames or requests that would be
    // invalid based on its current understanding of the peer's settings.")
    // The peer's SETTINGS_MAX_FIELD_SECTION_SIZE (0x06) is honored on the
    // client's outbound field sections.
    "http3_outbound_field_section_honors_peer_max_field_section_size"_test = [] {
        recording_stream_factory transport{true};
        http::v3::client<recording_stream_factory> client{transport};
        run_sync(http::coroutine::start(client));
        static_cast<void>(transport.take_writes());

        // SETTINGS_MAX_FIELD_SECTION_SIZE = 200 (RFC 9114 §7.2.4.1: the
        // parameter id is 0x06; the value counts each field's name + value +
        // 32 bytes of overhead per RFC 9114 §4.2.2).
        auto settings = make_h3_frame(
            0x04,
            std::array{std::byte{0x06}, std::byte{0x40}, std::byte{0xc8}});
        auto control = make_h3_control_stream(
            std::span<const std::byte>{settings.data(), settings.size()});
        transport.announce(3, http::stream_access::receive_only);
        transport.feed(3, std::span<const std::byte>{control.data(), control.size()}, false);

        auto request = basic_get("/oversized");
        // The request line fields amount to roughly 2 * (name + value) + 32
        // per field for the pseudo-header block; adding a 500-byte field
        // value clearly exceeds the advertised 200-byte limit.
        request.fields.push_back({"x-big", std::string(500, 'x')});

        auto threw = false;
        try {
            http::buffer_body empty;
            static_cast<void>(run_sync(http::coroutine::request(client, std::move(request), empty)));
        } catch (const std::runtime_error& failure) {
            expect(std::string_view{failure.what()}.contains(
                "peer SETTINGS_MAX_FIELD_SECTION_SIZE"sv));
            threw = true;
        }
        expect(threw);
        expect(transport.closes.empty());
    };

    // RFC 9110 §15 — "All valid status codes are within the range of 100 to
    // 599, inclusive." A client receiving ":status: 700" is receiving a
    // malformed response, which RFC 9114 §4.1.2 requires to be "a stream
    // error of type H3_MESSAGE_ERROR" — not a connection error. The request
    // fails with the typed reset action and the connection survives.
    "http3_out_of_range_status_is_a_stream_error"_test = [] {
        recording_stream_factory transport{true};
        http::v3::client<recording_stream_factory> client{transport};
        run_sync(http::coroutine::start(client));
        static_cast<void>(transport.take_writes());

        http::buffer_body empty;
        auto request = http::coroutine::request(client, basic_get("/bad-status"), empty);
        request.start();

        auto response = make_h3_frame(
            0x01, make_h3_field_section({{":status", "700"}}));
        transport.feed(0, response, true);

        auto threw = false;
        try {
            static_cast<void>(run_sync(std::move(request)));
        } catch (const http::protocol_error& failure) {
            expect(failure.info().scope == http::error_scope::stream);
            expect(failure.info().condition == http::error_condition::stream_reset);
            expect(std::holds_alternative<http::reset_stream>(failure.action()));
            const auto& reset = std::get<http::reset_stream>(failure.action());
            expect(std::get<http::v3::error_code>(reset.code).value == h3_message_error);
            threw = true;
        }
        expect(threw);
        expect(transport.closes.empty());
        expect(transport.shutdowns.size() == 1_u);
        expect(transport.shutdowns.front().stream_id == 0_i);
        expect(transport.shutdowns.front().error.value == h3_message_error);
    };
};

} // namespace httpant::testing
