#include <boost/ut.hpp>

#include "test_support.hpp"
#include "../examples/quic_support.hpp"

namespace httpant::testing {

using namespace boost::ut;
using namespace std::literals;

inline void push_http2_client_preface(pipe& p) {
    push_text(p, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
    push_http2_settings_frame(p);
}

struct byte_fragment_stream {
    pipe& input;
    pipe& output;

    struct read_awaiter {
        pipe& input;
        std::span<std::byte> buffer;
        auto await_ready() noexcept -> bool { return input.available() > 0 || input.closed; }
        void await_suspend(std::coroutine_handle<> continuation) noexcept { continuation.resume(); }
        auto await_resume() noexcept -> std::size_t {
            if (input.available() == 0) return 0;
            buffer[0] = input.buffer[input.read_pos++];
            return 1;
        }
    };

    auto async_read(std::span<std::byte> buffer) -> read_awaiter { return {input, buffer}; }
    auto async_read(std::span<std::byte> buffer, std::stop_token) -> read_awaiter { return {input, buffer}; }
    auto async_write(std::span<const std::byte> data) -> mock_stream::write_awaiter {
        return {output, data};
    }
    auto async_write(std::span<const std::byte> data, std::stop_token) -> mock_stream::write_awaiter {
        return {output, data};
    }
};

static suite<"protocol"> protocol_suite = [] {
    // Internal machinery test: each real transport wrapper must satisfy the
    // transport concepts it advertises (no RFC-mandated behavior here).
    "concept_tcp_stream"_test = [] {
        expect(http::byte_stream<tcp_stream>);
    };

    "concept_tls_stream"_test = [] {
        expect(http::byte_stream<tls_stream>);
    };

    // The QUIC stream handle is a byte_stream; the connection is a
    // stream_factory (it constructs/accepts stream handles and is not itself a
    // byte_stream — REFACTOR §2.2).
    "concept_quic_stream"_test = [] {
        expect(http::byte_stream<quic_stream>);
        expect(http::stream_factory<::httpant::examples::quic_connection_transport>);
    };

    "concept_mock_stream_factory"_test = [] {
        expect(http::byte_stream<mock_factory_stream>);
        expect(http::stream_constructible<mock_stream_factory>);
        expect(http::stream_accepting<mock_stream_factory>);
        expect(http::stream_factory<mock_stream_factory>);
    };

    "concept_recording_stream_factory"_test = [] {
        expect(http::byte_stream<recording_stream_factory::stream>);
        expect(http::stream_constructible<recording_stream_factory>);
        expect(http::stream_accepting<recording_stream_factory>);
        expect(http::stream_factory<recording_stream_factory>);
    };

    // RFC 9113 §3.4 — "The client connection preface starts with the string
    // "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".  This sequence MUST be followed by a
    // SETTINGS frame (Section 6.5), which MAY be empty."
    "http2_client_handshake_writes_preface"_test = [] {
        pipe c2s, s2c;
        mock_stream transport{.input = s2c, .output = c2s};
        push_http2_settings_frame(s2c);
        s2c.closed = true;

        http::v2::client<mock_stream> client{transport};
        run_sync(http::coroutine::start(client));

        auto wire = bytes_to_string(c2s.buffer);
        expect(c2s.buffer.size() >= 28_u);
        expect(wire.starts_with("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"sv));
        expect(static_cast<unsigned>(std::to_integer<std::uint8_t>(c2s.buffer[27])) == 4_u);
    };

    // RFC 9113 §3.4 — "The SETTINGS frames received from a peer as part of the connection
    // preface MUST be acknowledged ... after sending the connection preface." A complete frame
    // remains recognizable when every transport read supplies only one octet.
    "http2_client_handshake_accepts_byte_fragments"_test = [] {
        pipe c2s, s2c;
        byte_fragment_stream transport{.input = s2c, .output = c2s};
        push_http2_settings_frame(s2c);
        s2c.closed = true;

        http::v2::client<byte_fragment_stream> client{transport};
        run_sync(http::coroutine::start(client));
        expect(c2s.buffer.size() >= 28_u);
    };

    // RFC 9113 §3.4 — "The server connection preface consists of a potentially
    // empty SETTINGS frame (Section 6.5) that MUST be the first frame the server
    // sends in the HTTP/2 connection."
    "http2_server_handshake_writes_settings"_test = [] {
        pipe c2s, s2c;
        mock_stream transport{.input = c2s, .output = s2c};
        push_http2_client_preface(c2s);
        c2s.closed = true;

        http::v2::server<mock_stream> server{transport};
        run_sync(http::coroutine::start(server));

        expect(s2c.buffer.size() >= 9_u);
        expect(static_cast<unsigned>(std::to_integer<std::uint8_t>(s2c.buffer[3])) == 4_u);
    };

    // RFC 9113 §3.4 — "This sequence MUST be followed by a SETTINGS frame ..." The server
    // waits through all 24 preface octets and the complete frame when reads are byte-fragmented.
    "http2_server_handshake_accepts_byte_fragments"_test = [] {
        pipe c2s, s2c;
        byte_fragment_stream transport{.input = c2s, .output = s2c};
        push_http2_client_preface(c2s);
        c2s.closed = true;

        http::v2::server<byte_fragment_stream> server{transport};
        run_sync(http::coroutine::start(server));
        expect(s2c.buffer.size() >= 9_u);
    };

    // RFC 9114 §6.2.1 — "Each side MUST initiate a single control stream at the
    // beginning of the connection and send its SETTINGS frame as the first frame
    // on this stream." The control stream type is 0x00 and the SETTINGS frame
    // type is 0x04; mock_stream_factory writes every stream into one pipe, so
    // buffer[0..1] are the control stream's type byte followed by the first frame
    // type byte.
    "http3_client_handshake_writes_settings"_test = [] {
        pipe c2s, s2c;
        mock_stream_factory transport{s2c, c2s};

        http::v3::client<mock_stream_factory> client{transport};
        run_sync(http::coroutine::start(client));

        expect(c2s.buffer.size() >= 2_u);
        expect(static_cast<unsigned>(std::to_integer<std::uint8_t>(c2s.buffer[0])) == 0_u);
        expect(static_cast<unsigned>(std::to_integer<std::uint8_t>(c2s.buffer[1])) == 4_u);
    };

    // RFC 9114 §6.2.1 — "Each side MUST initiate a single control stream at the
    // beginning of the connection and send its SETTINGS frame as the first frame
    // on this stream." (See the client test above for the byte-layout rationale.)
    "http3_server_handshake_writes_settings"_test = [] {
        pipe c2s, s2c;
        mock_stream_factory transport{c2s, s2c, false};

        http::v3::server<mock_stream_factory> server{transport};
        run_sync(http::coroutine::start(server));

        expect(s2c.buffer.size() >= 2_u);
        expect(static_cast<unsigned>(std::to_integer<std::uint8_t>(s2c.buffer[0])) == 0_u);
        expect(static_cast<unsigned>(std::to_integer<std::uint8_t>(s2c.buffer[1])) == 4_u);
    };

};

} // namespace httpant::testing
