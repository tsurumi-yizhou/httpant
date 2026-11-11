export module httpant:websocket;
import httpant.exception;
import std;
import :message;

// RFC 6455 framing and opening handshake. The caller owns transport, entropy,
// scheduling, and the response to control frames. No extensions are negotiated.
export namespace http::websocket {
enum class side { client, server };
enum class opcode : std::uint8_t {
  continuation = 0,
  text = 1,
  binary = 2,
  close = 8,
  ping = 9,
  pong = 10
};
struct limits {
  std::size_t frame_bytes = 64u << 10;
  std::size_t message_bytes = 8u << 20;
  std::size_t buffer_bytes = 80u << 10;
};
struct failure : std::runtime_error, public http::exceptions::exception_capture {
  auto capture() const noexcept -> std::exception_ptr override { return http::exceptions::capture(*this); }
  std::uint16_t status;
  failure(std::uint16_t status, std::string_view message)
      : std::runtime_error(std::string{message}), status(status) {}
};
struct frame {
  opcode kind = opcode::binary;
  bool final = true;
  std::vector<std::byte> payload;
};
using mask = std::array<std::byte, 4>;

namespace detail {
inline auto number(std::byte b) -> unsigned {
  return std::to_integer<unsigned>(b);
}
inline auto control(opcode kind) -> bool {
  return (static_cast<unsigned>(kind) & 8u) != 0;
}
inline auto utf8(std::span<const std::byte> bytes) -> bool {
  for (std::size_t i = 0; i < bytes.size();) {
    auto first = number(bytes[i++]);
    if (first < 0x80)
      continue;
    unsigned following, value, minimum;
    if (first >= 0xc2 && first <= 0xdf) {
      following = 1;
      value = first & 0x1f;
      minimum = 0x80;
    } else if (first >= 0xe0 && first <= 0xef) {
      following = 2;
      value = first & 0xf;
      minimum = 0x800;
    } else if (first >= 0xf0 && first <= 0xf4) {
      following = 3;
      value = first & 7;
      minimum = 0x10000;
    } else
      return false;
    if (following > bytes.size() - i)
      return false;
    for (unsigned j = 0; j < following; ++j) {
      auto next = number(bytes[i++]);
      if ((next & 0xc0) != 0x80)
        return false;
      value = (value << 6) | (next & 0x3f);
    }
    if (value < minimum || value > 0x10ffff ||
        (value >= 0xd800 && value <= 0xdfff))
      return false;
  }
  return true;
}
inline void check_close(std::span<const std::byte> bytes) {
  if (bytes.size() == 1)
    throw failure(1002, "WebSocket close payload has one byte");
  if (bytes.empty())
    return;
  auto status = (number(bytes[0]) << 8) | number(bytes[1]);
  if (!((status >= 1000 && status <= 1014 && status != 1004 && status != 1005 &&
         status != 1006) ||
        (status >= 3000 && status <= 4999)))
    throw failure(1002, "WebSocket close status is invalid");
  if (!utf8(bytes.subspan(2)))
    throw failure(1007, "WebSocket close reason is not UTF-8");
}
inline auto base64(std::span<const std::byte> bytes) -> std::string {
  constexpr std::string_view alphabet =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::string out;
  for (std::size_t i = 0; i < bytes.size(); i += 3) {
    auto value = number(bytes[i]) << 16;
    if (i + 1 < bytes.size())
      value |= number(bytes[i + 1]) << 8;
    if (i + 2 < bytes.size())
      value |= number(bytes[i + 2]);
    out += alphabet[(value >> 18) & 63];
    out += alphabet[(value >> 12) & 63];
    out += i + 1 < bytes.size() ? alphabet[(value >> 6) & 63] : '=';
    out += i + 2 < bytes.size() ? alphabet[value & 63] : '=';
  }
  return out;
}
// SHA-1 is mandated by the opening handshake; it is not an authenticator.
inline auto sha1(std::string_view text) -> std::array<std::byte, 20> {
  auto raw = std::as_bytes(std::span{text});
  std::vector<std::byte> bytes(raw.begin(), raw.end());
  bytes.push_back(std::byte{0x80});
  while (bytes.size() % 64 != 56)
    bytes.push_back(std::byte{});
  auto bits = static_cast<std::uint64_t>(text.size()) * 8;
  for (int shift = 56; shift >= 0; shift -= 8)
    bytes.push_back(std::byte((bits >> shift) & 255));
  std::array<std::uint32_t, 5> hash{0x67452301, 0xefcdab89, 0x98badcfe,
                                    0x10325476, 0xc3d2e1f0};
  for (std::size_t offset = 0; offset < bytes.size(); offset += 64) {
    std::array<std::uint32_t, 80> words{};
    for (std::size_t i = 0; i < 16; ++i)
      for (std::size_t j = 0; j < 4; ++j)
        words[i] = (words[i] << 8) | number(bytes[offset + i * 4 + j]);
    for (std::size_t i = 16; i < 80; ++i)
      words[i] = std::rotl(
          words[i - 3] ^ words[i - 8] ^ words[i - 14] ^ words[i - 16], 1);
    auto [a, b, c, d, e] = hash;
    for (std::size_t i = 0; i < 80; ++i) {
      std::uint32_t f, k;
      if (i < 20) {
        f = (b & c) | (~b & d);
        k = 0x5a827999;
      } else if (i < 40) {
        f = b ^ c ^ d;
        k = 0x6ed9eba1;
      } else if (i < 60) {
        f = (b & c) | (b & d) | (c & d);
        k = 0x8f1bbcdc;
      } else {
        f = b ^ c ^ d;
        k = 0xca62c1d6;
      }
      auto next = std::rotl(a, 5) + f + e + k + words[i];
      e = d;
      d = c;
      c = std::rotl(b, 30);
      b = a;
      a = next;
    }
    hash[0] += a;
    hash[1] += b;
    hash[2] += c;
    hash[3] += d;
    hash[4] += e;
  }
  std::array<std::byte, 20> out{};
  for (std::size_t i = 0; i < 5; ++i)
    for (int j = 0; j < 4; ++j)
      out[i * 4 + j] = std::byte((hash[i] >> (24 - j * 8)) & 255);
  return out;
}
inline auto equal_name(std::string_view a, std::string_view b) -> bool {
  return std::ranges::equal(
      a, b, {},
      [](unsigned char c) {
        return c >= 'A' && c <= 'Z' ? c + ('a' - 'A') : c;
      },
      [](unsigned char c) {
        return c >= 'A' && c <= 'Z' ? c + ('a' - 'A') : c;
      });
}
inline auto single(const headers &fields, std::string_view name)
    -> std::optional<std::string_view> {
  std::optional<std::string_view> value;
  for (const auto &field : fields)
    if (equal_name(field.name, name)) {
      if (value)
        throw failure(1002, "WebSocket handshake contains a repeated header");
      value = field.value;
    }
  return value;
}
inline auto offered(std::string_view values, std::string_view desired) -> bool {
  for (auto part : std::views::split(values, ',')) {
    std::string_view value{part.begin(), part.end()};
    while (!value.empty() && (value.front() == ' ' || value.front() == '\t'))
      value.remove_prefix(1);
    while (!value.empty() && (value.back() == ' ' || value.back() == '\t'))
      value.remove_suffix(1);
    if (value == desired)
      return true;
  }
  return false;
}
} // namespace detail

inline auto key(std::span<const std::byte, 16> entropy) -> std::string {
  return detail::base64(entropy);
}
inline auto accept(std::string_view nonce) -> std::string {
  constexpr std::string_view alphabet =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  if (nonce.size() != 24 || !nonce.ends_with("==") ||
      !std::ranges::all_of(nonce.substr(0, 22),
                           [&](char c) { return alphabet.contains(c); }) ||
      (alphabet.find(nonce[21]) & 15) != 0)
    throw failure(1002, "WebSocket key must encode 16 bytes");
  return detail::base64(detail::sha1(std::string{nonce} +
                                     "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"));
}
inline auto opening_response(const request &head, std::string_view subprotocol)
    -> response {
  if (head.method != method::GET ||
      !field_contains_token(head.fields, "connection", "upgrade") ||
      !detail::equal_name(detail::single(head.fields, "upgrade").value_or(""),
                          "websocket") ||
      detail::single(head.fields, "sec-websocket-version") !=
          std::optional<std::string_view>{"13"} ||
      !detail::offered(
          detail::single(head.fields, "sec-websocket-protocol").value_or(""),
          subprotocol) ||
      detail::single(head.fields, "sec-websocket-extensions"))
    throw failure(1002, "WebSocket handshake was refused");
  return {.status = 101,
          .fields = {{"upgrade", "websocket"},
                     {"connection", "Upgrade"},
                     {"sec-websocket-accept",
                      accept(detail::single(head.fields, "sec-websocket-key")
                                 .value_or(""))},
                     {"sec-websocket-protocol", std::string{subprotocol}}}};
}
inline void check_response(const response &head, std::string_view nonce,
                           std::string_view subprotocol) {
  if (head.status != 101 ||
      !field_contains_token(head.fields, "connection", "upgrade") ||
      !detail::equal_name(detail::single(head.fields, "upgrade").value_or(""),
                          "websocket") ||
      detail::single(head.fields, "sec-websocket-accept") !=
          std::optional<std::string_view>{accept(nonce)} ||
      detail::single(head.fields, "sec-websocket-protocol") !=
          std::optional<std::string_view>{subprotocol} ||
      detail::single(head.fields, "sec-websocket-extensions"))
    throw failure(1002, "WebSocket opening response is invalid");
}

inline auto encode(opcode kind, std::span<const std::byte> payload, bool final,
                   std::optional<mask> masking) -> std::vector<std::byte> {
  if (detail::control(kind) && (!final || payload.size() > 125))
    throw failure(1002, "WebSocket control frame is invalid");
  if (kind == opcode::close)
    detail::check_close(payload);
  std::vector<std::byte> out;
  out.push_back(std::byte((final ? 128 : 0) | static_cast<unsigned>(kind)));
  auto masked = masking ? 128u : 0u;
  if (payload.size() < 126)
    out.push_back(std::byte(masked | payload.size()));
  else if (payload.size() <= 65535) {
    out.push_back(std::byte(masked | 126));
    out.push_back(std::byte((payload.size() >> 8) & 255));
    out.push_back(std::byte(payload.size() & 255));
  } else {
    out.push_back(std::byte(masked | 127));
    for (int shift = 56; shift >= 0; shift -= 8)
      out.push_back(std::byte(
          (static_cast<std::uint64_t>(payload.size()) >> shift) & 255));
  }
  if (masking)
    out.insert(out.end(), masking->begin(), masking->end());
  for (std::size_t i = 0; i < payload.size(); ++i)
    out.push_back(payload[i] ^ (masking ? (*masking)[i % 4] : std::byte{}));
  return out;
}

class decoder {
public:
  explicit decoder(side receiver, limits budget = {})
      : receiver_(receiver), budget_(budget) {
    if (!budget.frame_bytes ||
        budget.frame_bytes > std::numeric_limits<std::size_t>::max() - 14 ||
        budget.buffer_bytes < budget.frame_bytes + 14 ||
        budget.message_bytes < budget.frame_bytes)
      throw std::invalid_argument("WebSocket limits are inconsistent");
    bytes_.reserve(budget.buffer_bytes);
  }
  auto buffered() const noexcept -> std::size_t {
    return bytes_.size() - offset_;
  }
  auto available() const noexcept -> std::size_t {
    return budget_.buffer_bytes - buffered();
  }
  auto complete() const noexcept -> bool { return !buffered() && !fragmented_; }
  void feed(std::span<const std::byte> bytes) {
    if (bytes.size() > budget_.buffer_bytes - buffered())
      throw failure(1009, "WebSocket receive buffer is full");
    if (offset_) {
      bytes_.erase(bytes_.begin(),
                   bytes_.begin() + static_cast<std::ptrdiff_t>(offset_));
      offset_ = 0;
    }
    bytes_.insert(bytes_.end(), bytes.begin(), bytes.end());
  }
  auto next() -> std::optional<frame> {
    auto input = std::span{bytes_}.subspan(offset_);
    if (input.size() < 2)
      return std::nullopt;
    auto first = detail::number(input[0]), second = detail::number(input[1]);
    auto kind = static_cast<opcode>(first & 15);
    if ((first & 0x70) ||
        (kind != opcode::continuation && kind != opcode::binary &&
         kind != opcode::text && kind != opcode::close &&
         kind != opcode::ping && kind != opcode::pong))
      throw failure(1002, "WebSocket opcode or reserved bits are invalid");
    if (kind == opcode::text)
      throw failure(1003, "WebSocket tunnel accepts binary data only");
    auto final = (first & 128) != 0, masked = (second & 128) != 0;
    if (masked != (receiver_ == side::server))
      throw failure(1002, "WebSocket masking direction is invalid");
    std::uint64_t length = second & 127;
    std::size_t header = 2;
    if (length == 126 || length == 127) {
      auto width = length == 126 ? 2u : 8u;
      if (input.size() < 2 + width)
        return std::nullopt;
      length = 0;
      for (std::size_t i = 0; i < width; ++i)
        length = (length << 8) | detail::number(input[2 + i]);
      if ((width == 2 && length < 126) ||
          (width == 8 && (length < 65536 || (detail::number(input[2]) & 128))))
        throw failure(1002, "WebSocket length encoding is invalid");
      header += width;
    }
    if (detail::control(kind) && (!final || length > 125))
      throw failure(1002, "WebSocket control frame is invalid");
    if (length > budget_.frame_bytes)
      throw failure(1009, "WebSocket frame exceeds its limit");
    if (masked)
      header += 4;
    if (input.size() < header || length > input.size() - header)
      return std::nullopt;
    frame out{.kind = kind, .final = final};
    out.payload.reserve(static_cast<std::size_t>(length));
    for (std::size_t i = 0; i < length; ++i)
      out.payload.push_back(input[header + i] ^
                            (masked ? input[header - 4 + i % 4] : std::byte{}));
    if (kind == opcode::close)
      detail::check_close(out.payload);
    if (!detail::control(kind)) {
      if ((kind == opcode::continuation) != fragmented_)
        throw failure(1002, "WebSocket continuation sequence is invalid");
      if (length > budget_.message_bytes - message_bytes_)
        throw failure(1009, "WebSocket message exceeds its limit");
      message_bytes_ += static_cast<std::size_t>(length);
      fragmented_ = !final;
      if (final)
        message_bytes_ = 0;
    }
    offset_ += header + static_cast<std::size_t>(length);
    return out;
  }

private:
  side receiver_;
  limits budget_;
  std::vector<std::byte> bytes_;
  std::size_t offset_ = 0, message_bytes_ = 0;
  bool fragmented_ = false;
};
} // namespace http::websocket
