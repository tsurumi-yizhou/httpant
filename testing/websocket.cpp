import std;
import httpant.dependencies.boost.ut;
import httpant;

namespace {
using namespace boost::ut;
namespace ws = http::websocket;
auto bytes(std::string_view text) { return std::as_bytes(std::span{text}); }
auto rejected(std::vector<std::byte> input, std::uint16_t status,
              ws::limits limits = {}) -> bool {
  try {
    ws::decoder decoder{ws::side::server, limits};
    decoder.feed(input);
    while (decoder.next()) {
    }
  } catch (const ws::failure &failure) {
    return failure.status == status;
  }
  return false;
}
const ws::mask masking{std::byte{0x37}, std::byte{0xfa}, std::byte{0x21},
                       std::byte{0x3d}};
suite websocket_suite = [] {
  "websocket_rfc_handshake"_test = [] {
    expect(ws::accept("dGhlIHNhbXBsZSBub25jZQ==") ==
           "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    http::request request{
        .method = http::method::GET,
        .target = "/tunnel",
        .fields = {{"connection", "keep-alive, Upgrade"},
                   {"upgrade", "websocket"},
                   {"sec-websocket-version", "13"},
                   {"sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ=="},
                   {"sec-websocket-protocol", "other, fughetta-worker.v1"}}};
    auto response = ws::opening_response(request, "fughetta-worker.v1");
    expect(nothrow([&] {
      ws::check_response(response,
                         "dGhlIHNhbXBsZSBub25jZQ==", "fughetta-worker.v1");
    }));
    response.fields.push_back({"sec-websocket-accept", "repeated"});
    expect(throws<ws::failure>([&] {
      ws::check_response(response,
                         "dGhlIHNhbXBsZSBub25jZQ==", "fughetta-worker.v1");
    }));
    request.fields.push_back(
        {"sec-websocket-extensions", "permessage-deflate"});
    expect(throws<ws::failure>(
        [&] { ws::opening_response(request, "fughetta-worker.v1"); }));
    expect(throws<ws::failure>([] { ws::accept("dGhlIHNhbXBsZSBub25jZR=="); }));
  };
  "websocket_partial_and_coalesced_binary"_test = [] {
    auto first = ws::encode(ws::opcode::binary, bytes("first"), true, masking);
    auto second =
        ws::encode(ws::opcode::binary, bytes("second"), true, masking);
    ws::decoder decoder{ws::side::server};
    for (std::size_t i = 0; i < first.size() - 1; ++i) {
      decoder.feed(std::span{first}.subspan(i, 1));
      expect(!decoder.next());
    }
    decoder.feed(std::span{first}.last(1));
    decoder.feed(second);
    auto a = decoder.next(), b = decoder.next();
    expect(a.has_value() && b.has_value() >> fatal);
    expect(std::ranges::equal(a->payload, bytes("first")));
    expect(std::ranges::equal(b->payload, bytes("second")));
    expect(decoder.complete());
    ws::decoder client{ws::side::client};
    client.feed(
        ws::encode(ws::opcode::binary, bytes("unmasked"), true, std::nullopt));
    expect(client.next().has_value());
  };
  "websocket_fragmented_message_and_control"_test = [] {
    ws::decoder decoder{ws::side::server};
    decoder.feed(
        ws::encode(ws::opcode::binary, bytes("begin"), false, masking));
    expect(decoder.next()->kind == ws::opcode::binary);
    expect(!decoder.complete());
    decoder.feed(ws::encode(ws::opcode::ping, bytes("probe"), true, masking));
    expect(decoder.next()->kind == ws::opcode::ping);
    decoder.feed(
        ws::encode(ws::opcode::continuation, bytes("end"), true, masking));
    expect(decoder.next()->kind == ws::opcode::continuation);
    expect(decoder.complete());
    expect(rejected(ws::encode(ws::opcode::continuation, {}, true, masking),
                    1002));
    auto invalid = ws::encode(ws::opcode::binary, {}, false, masking);
    auto next = ws::encode(ws::opcode::binary, {}, true, masking);
    invalid.insert(invalid.end(), next.begin(), next.end());
    expect(rejected(invalid, 1002));
  };
  "websocket_rejects_invalid_frame_headers"_test = [] {
    expect(
        rejected(ws::encode(ws::opcode::binary, {}, true, std::nullopt), 1002));
    expect(rejected(ws::encode(ws::opcode::text, bytes("text"), true, masking),
                    1003));
    auto reserved = ws::encode(ws::opcode::binary, {}, true, masking);
    reserved[0] |= std::byte{0x40};
    expect(rejected(reserved, 1002));
    expect(rejected(
        {std::byte{0x82}, std::byte{0xfe}, std::byte{}, std::byte{125}}, 1002));
    expect(rejected({std::byte{0x82}, std::byte{0xff}, std::byte{0x80},
                     std::byte{}, std::byte{}, std::byte{}, std::byte{},
                     std::byte{}, std::byte{}, std::byte{}},
                    1002));
    expect(rejected({std::byte{0x09}, std::byte{0x80}}, 1002));
    expect(rejected(
        {std::byte{0x89}, std::byte{0xfe}, std::byte{}, std::byte{126}}, 1002));
    expect(rejected({std::byte{0x82}, std::byte{0xff}, std::byte{}, std::byte{},
                     std::byte{}, std::byte{}, std::byte{}, std::byte{1},
                     std::byte{}, std::byte{1}},
                    1009));
  };
  "websocket_lengths_and_budgets"_test = [] {
    for (auto length : {125u, 126u, 65535u, 65536u}) {
      std::vector<std::byte> payload(length, std::byte{0xa5});
      auto encoded = ws::encode(ws::opcode::binary, payload, true, masking);
      ws::decoder decoder{ws::side::server};
      decoder.feed(encoded);
      auto frame = decoder.next();
      expect(frame.has_value() >> fatal);
            expect(std::ranges::equal(frame->payload, payload));
    }
    ws::limits limits{
        .frame_bytes = 128, .message_bytes = 128, .buffer_bytes = 512};
    auto joined = ws::encode(ws::opcode::binary, std::vector<std::byte>(100),
                             false, masking);
    auto end = ws::encode(ws::opcode::continuation, std::vector<std::byte>(100),
                          true, masking);
    joined.insert(joined.end(), end.begin(), end.end());
    expect(rejected(joined, 1009, limits));
    ws::decoder decoder{ws::side::server, limits};
    expect(throws<ws::failure>(
        [&] { decoder.feed(std::vector<std::byte>(513)); }));
  };
  "websocket_close_validation"_test = [] {
    for (auto payload :
         {std::vector{std::byte{1}}, std::vector{std::byte{3}, std::byte{0xed}},
          std::vector{std::byte{3}, std::byte{0xe8}, std::byte{0xc0},
                      std::byte{0xaf}}})
      expect(throws<ws::failure>(
          [&] { ws::encode(ws::opcode::close, payload, true, masking); }));
    std::array normal{std::byte{3}, std::byte{0xe8}};
    ws::decoder decoder{ws::side::server};
    decoder.feed(ws::encode(ws::opcode::close, normal, true, masking));
    expect(decoder.next()->kind == ws::opcode::close);
  };
};
} // namespace
