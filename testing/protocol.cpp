#include <boost/ut.hpp>

#include "test_support.hpp"

namespace httpant::testing {

using namespace boost::ut;
using namespace std::literals;

inline void push_http2_client_preface(pipe& p) {
    push_text(p, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
    push_http2_settings_frame(p);
}

static suite<"protocol"> protocol_suite = [] {
    "concept_tcp_stream"_test = [] {
        expect(http::duplex<tcp_stream>);
        expect(!http::multiplexed<tcp_stream>);
    };

    "concept_tls_stream"_test = [] {
        expect(http::duplex<tls_stream>);
        expect(!http::multiplexed<tls_stream>);
    };

    "concept_quic_stream"_test = [] {
        expect(http::duplex<quic_stream>);
        expect(http::multiplexed<quic_stream>);
    };

    "concept_mock_multiplexed_stream"_test = [] {
        expect(http::duplex<mock_multiplexed_stream>);
        expect(http::multiplexed<mock_multiplexed_stream>);
    };

    "http2_client_handshake_writes_preface"_test = [] {
        pipe c2s, s2c;
        mock_stream transport{.input = s2c, .output = c2s};
        push_http2_settings_frame(s2c);
        s2c.closed = true;

        http::client_v2<mock_stream> client{transport};
        run_sync(client.handshake());

        auto wire = bytes_to_string(c2s.buffer);
        expect(c2s.buffer.size() >= 28_u);
        expect(wire.starts_with("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"sv));
        expect(static_cast<unsigned>(std::to_integer<std::uint8_t>(c2s.buffer[27])) == 4_u);
    };

    "http2_server_handshake_writes_settings"_test = [] {
        pipe c2s, s2c;
        mock_stream transport{.input = c2s, .output = s2c};
        push_http2_client_preface(c2s);
        c2s.closed = true;

        http::server_v2<mock_stream> server{transport};
        run_sync(server.handshake());

        expect(s2c.buffer.size() >= 9_u);
        expect(static_cast<unsigned>(std::to_integer<std::uint8_t>(s2c.buffer[3])) == 4_u);
    };

    "http3_client_handshake_writes_settings"_test = [] {
        pipe c2s, s2c;
        mock_multiplexed_stream transport{.input = s2c, .output = c2s};

        http::client_v3<mock_multiplexed_stream> client{transport};
        run_sync(client.handshake(2, 6, 10));

        expect(c2s.buffer.size() > 0_u);
    };

    "http3_server_handshake_writes_settings"_test = [] {
        pipe c2s, s2c;
        mock_multiplexed_stream transport{.input = c2s, .output = s2c};

        http::server_v3<mock_multiplexed_stream> server{transport};
        run_sync(server.handshake(3, 7, 11));

        expect(s2c.buffer.size() > 0_u);
    };

    "http_protocol_alias"_test = [] {
        using h1_client = http::stream<1>::client<mock_stream>;
        using h1_server = http::stream<1>::server<mock_stream>;
        using h2_client = http::stream<2>::client<mock_stream>;
        using h2_server = http::stream<2>::server<mock_stream>;
        using h3_client = http::stream<3>::client<mock_multiplexed_stream>;
        using h3_server = http::stream<3>::server<mock_multiplexed_stream>;

        expect(std::is_same_v<h1_client, http::client_v1<mock_stream>>);
        expect(std::is_same_v<h1_server, http::server_v1<mock_stream>>);
        expect(std::is_same_v<h2_client, http::client_v2<mock_stream>>);
        expect(std::is_same_v<h2_server, http::server_v2<mock_stream>>);
        expect(std::is_same_v<h3_client, http::client_v3<mock_multiplexed_stream>>);
        expect(std::is_same_v<h3_server, http::server_v3<mock_multiplexed_stream>>);
    };
};

} // namespace httpant::testing
