module;

#include <nghttp3/nghttp3.h>

export module httpant:channel;

import std;
import :trait;
import :message;

export namespace http {

namespace h3 {

inline constexpr std::size_t io_buffer_size = 16 * 1024;
inline constexpr std::uint64_t data_frame_type = 0x00;
inline constexpr std::uint64_t headers_frame_type = 0x01;
inline constexpr std::uint64_t cancel_push_frame_type = 0x03;
inline constexpr std::uint64_t settings_frame_type = 0x04;
inline constexpr std::uint64_t push_promise_frame_type = 0x05;
inline constexpr std::uint64_t goaway_frame_type = 0x07;
inline constexpr std::uint64_t max_push_id_frame_type = 0x0d;

inline constexpr std::uint64_t control_stream_type = 0x00;
inline constexpr std::uint64_t push_stream_type = 0x01;
inline constexpr std::uint64_t qpack_encoder_stream_type = 0x02;
inline constexpr std::uint64_t qpack_decoder_stream_type = 0x03;

enum class stream_kind {
    request,
    control,
    push,
    qpack,
    ignored,
};

inline auto make_error(std::string_view op, int rc) -> std::runtime_error {
    return std::runtime_error(
        std::string("http/3: ") + std::string(op) +
        " failed (" + std::to_string(rc) + ")");
}

inline void check(int rc, std::string_view op) {
    if (rc != 0) throw make_error(op, rc);
}

struct stream_data {
    std::int64_t id{0};
    bool headers_done{false};
    bool complete{false};
    bool closed{false};
    bool aborted{false};
    headers fields{};
    http::status status_code{0};
    std::string method_str{};
    std::string path{};
    std::string scheme{};
    std::string authority{};
    std::vector<std::byte> body{};
    std::uint64_t close_error_code{0};
};

struct outbound_body_state {
    std::vector<std::byte> data{};
    std::size_t offset{0};
};

struct pending_write {
    std::int64_t stream_id{-1};
    bool fin{false};
    std::vector<std::byte> data{};
};

struct push_state {
    std::uint64_t push_id{0};
    std::int64_t associated_stream_id{0};
    std::int64_t stream_id{-1};
    bool promise_received{false};
    bool complete{false};
    bool cancelled{false};
    bool delivered{false};
    http::request promised_request{};
    http::response pushed_response{};
};

struct stream_input_state {
    stream_kind kind{stream_kind::request};
    bool stream_type_known{false};
    bool settings_seen{false};
    std::uint64_t stream_type{0};
    std::optional<std::uint64_t> push_id{};
    std::vector<std::byte> buffer{};
    bool closed{false};
};

struct conn_context {
    std::unordered_map<std::int64_t, std::shared_ptr<stream_data>> streams{};
    std::unordered_map<std::int64_t, std::shared_ptr<outbound_body_state>> outbound_bodies{};
    std::deque<std::shared_ptr<stream_data>> completed_server_streams{};
    bool goaway_received{false};
    std::int64_t goaway_id{-1};
    std::int64_t last_completed_stream_id{-1};

    bool is_client{false};
    bool peer_settings_received{false};
    std::int64_t local_control_stream_id{-1};
    std::optional<std::int64_t> remote_control_stream_id{};
    std::optional<std::uint64_t> advertised_max_push_id{};
    std::optional<std::uint64_t> peer_max_push_id{};
    std::optional<std::uint64_t> peer_goaway_push_id{};
    std::uint64_t next_push_id{0};
    std::unordered_map<std::int64_t, stream_input_state> inputs{};
    std::unordered_map<std::uint64_t, std::shared_ptr<push_state>> pushes{};
    std::deque<http::pushed_exchange> completed_pushes{};
    std::deque<pending_write> manual_writes{};
};

struct nv_block {
    std::vector<std::string> storage{};
    std::vector<nghttp3_nv> fields{};

    explicit nv_block(std::size_t count = 0) {
        storage.reserve(count * 2);
        fields.reserve(count);
    }

    void push(std::string_view name, std::string_view value) {
        storage.emplace_back(name);
        storage.emplace_back(value);
        auto& sn = storage[storage.size() - 2];
        auto& sv = storage[storage.size() - 1];
        fields.push_back({
            .name = reinterpret_cast<const uint8_t*>(sn.data()),
            .value = reinterpret_cast<const uint8_t*>(sv.data()),
            .namelen = sn.size(),
            .valuelen = sv.size(),
            .flags = NGHTTP3_NV_FLAG_NONE,
        });
    }
};

inline auto rcbuf_to_string(nghttp3_rcbuf* buf) -> std::string {
    auto vec = nghttp3_rcbuf_get_buf(buf);
    return std::string(reinterpret_cast<const char*>(vec.base), vec.len);
}

inline auto span_bytes(const std::vector<std::byte>& bytes) -> std::span<const std::byte> {
    return {bytes.data(), bytes.size()};
}

inline void append_bytes(std::vector<std::byte>& dst, std::span<const std::byte> src) {
    dst.insert(dst.end(), src.begin(), src.end());
}

inline auto is_unidirectional_stream(std::int64_t stream_id) -> bool {
    return (stream_id & 0x2) != 0;
}

inline auto encode_varint(std::uint64_t value) -> std::vector<std::byte> {
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
    if (value >= (1ull << 62))
        throw std::runtime_error("http/3: varint overflow");

    auto encoded = value | 0xc000000000000000ull;
    for (int shift = 56; shift >= 0; shift -= 8)
        out.push_back(std::byte{static_cast<unsigned char>((encoded >> shift) & 0xff)});
    return out;
}

inline auto try_decode_varint(std::span<const std::byte> src, std::size_t& consumed, std::uint64_t& value) -> bool {
    if (src.empty()) return false;

    auto first = std::to_integer<std::uint8_t>(src.front());
    auto prefix = first >> 6;
    auto length = std::size_t{1} << prefix;
    if (src.size() < length) return false;

    value = first & 0x3f;
    for (std::size_t i = 1; i < length; ++i)
        value = (value << 8) | std::to_integer<std::uint8_t>(src[i]);

    consumed = length;
    return true;
}

inline auto decode_exact_varint(std::span<const std::byte> src, std::string_view what) -> std::uint64_t {
    std::size_t consumed = 0;
    std::uint64_t value = 0;
    if (!try_decode_varint(src, consumed, value) || consumed != src.size())
        throw std::runtime_error(std::string("http/3: malformed ") + std::string(what));
    return value;
}

inline auto make_frame(std::uint64_t type, std::span<const std::byte> payload) -> std::vector<std::byte> {
    auto out = encode_varint(type);
    auto len = encode_varint(payload.size());
    append_bytes(out, len);
    append_bytes(out, payload);
    return out;
}

inline auto make_frame(std::uint64_t type, const std::vector<std::byte>& payload) -> std::vector<std::byte> {
    return make_frame(type, span_bytes(payload));
}

struct parsed_frame {
    std::uint64_t type{0};
    std::vector<std::byte> payload{};
    std::vector<std::byte> raw{};
};

inline auto try_pop_frame(std::vector<std::byte>& buffer, parsed_frame& frame) -> bool {
    std::size_t type_len = 0;
    std::uint64_t type = 0;
    if (!try_decode_varint(span_bytes(buffer), type_len, type)) return false;

    std::size_t length_len = 0;
    std::uint64_t payload_length = 0;
    auto rest = span_bytes(buffer).subspan(type_len);
    if (!try_decode_varint(rest, length_len, payload_length)) return false;

    auto frame_length = type_len + length_len + static_cast<std::size_t>(payload_length);
    if (buffer.size() < frame_length) return false;

    frame.type = type;
    frame.raw.assign(buffer.begin(), buffer.begin() + frame_length);
    frame.payload.assign(buffer.begin() + type_len + length_len, buffer.begin() + frame_length);
    buffer.erase(buffer.begin(), buffer.begin() + frame_length);
    return true;
}

inline auto request_blocks_equal(const http::request& lhs, const http::request& rhs) -> bool {
    if (lhs.method != rhs.method || lhs.target != rhs.target ||
        lhs.scheme != rhs.scheme || lhs.authority != rhs.authority ||
        lhs.fields.size() != rhs.fields.size())
        return false;

    for (std::size_t i = 0; i < lhs.fields.size(); ++i) {
        if (lhs.fields[i].name != rhs.fields[i].name || lhs.fields[i].value != rhs.fields[i].value)
            return false;
    }
    return true;
}

inline void queue_write(conn_context& ctx, std::int64_t stream_id, std::vector<std::byte> data, bool fin = false) {
    ctx.manual_writes.push_back({.stream_id = stream_id, .fin = fin, .data = std::move(data)});
}

inline void queue_control_frame(conn_context& ctx, std::vector<std::byte> data) {
    if (ctx.local_control_stream_id < 0)
        throw std::runtime_error("http/3: control stream is not bound");
    queue_write(ctx, ctx.local_control_stream_id, std::move(data), false);
}

inline auto take_manual_writes(conn_context& ctx) -> std::vector<pending_write> {
    std::vector<pending_write> writes;
    while (!ctx.manual_writes.empty()) {
        writes.push_back(std::move(ctx.manual_writes.front()));
        ctx.manual_writes.pop_front();
    }
    return writes;
}

inline void maybe_queue_push(conn_context& ctx, const std::shared_ptr<push_state>& push) {
    if (!push || push->delivered || push->cancelled || !push->promise_received || !push->complete)
        return;

    ctx.completed_pushes.push_back(http::pushed_exchange{
        .push_id = push->push_id,
        .associated_stream_id = push->associated_stream_id,
        .stream_id = push->stream_id,
        .promised_request = push->promised_request,
        .pushed_response = push->pushed_response,
    });
    push->delivered = true;
}

inline auto encode_field_section(std::int64_t stream_id, const std::vector<nghttp3_nv>& fields) -> std::vector<std::byte> {
    nghttp3_qpack_encoder* encoder = nullptr;
    check(nghttp3_qpack_encoder_new(&encoder, 0, nghttp3_mem_default()), "qpack_encoder_new");

    nghttp3_buf prefix{};
    nghttp3_buf request{};
    nghttp3_buf encoder_stream{};
    nghttp3_buf_init(&prefix);
    nghttp3_buf_init(&request);
    nghttp3_buf_init(&encoder_stream);

    auto* mem = nghttp3_mem_default();
    auto cleanup_buffers = [&] {
        nghttp3_buf_free(&prefix, mem);
        nghttp3_buf_free(&request, mem);
        nghttp3_buf_free(&encoder_stream, mem);
    };

    try {
        check(nghttp3_qpack_encoder_encode(
            encoder,
            &prefix,
            &request,
            &encoder_stream,
            stream_id,
            fields.data(),
            fields.size()),
            "qpack_encoder_encode");

        if (nghttp3_buf_len(&encoder_stream) != 0)
            throw std::runtime_error("http/3: manual push encoding unexpectedly produced encoder stream data");

        std::vector<std::byte> out;
        auto prefix_bytes = std::span<const std::byte>{reinterpret_cast<const std::byte*>(prefix.pos), nghttp3_buf_len(&prefix)};
        auto request_bytes = std::span<const std::byte>{reinterpret_cast<const std::byte*>(request.pos), nghttp3_buf_len(&request)};
        append_bytes(out, prefix_bytes);
        append_bytes(out, request_bytes);
        cleanup_buffers();
        nghttp3_qpack_encoder_del(encoder);
        return out;
    } catch (...) {
        cleanup_buffers();
        nghttp3_qpack_encoder_del(encoder);
        throw;
    }
}

inline auto decode_field_section(std::int64_t stream_id, std::span<const std::byte> block) -> std::vector<header> {
    nghttp3_qpack_decoder* decoder = nullptr;
    check(nghttp3_qpack_decoder_new(&decoder, 0, 0, nghttp3_mem_default()), "qpack_decoder_new");
    nghttp3_qpack_stream_context* stream_ctx = nullptr;
    check(nghttp3_qpack_stream_context_new(&stream_ctx, stream_id, nghttp3_mem_default()), "qpack_stream_context_new");

    auto decoder_cleanup = std::unique_ptr<nghttp3_qpack_decoder, decltype([](nghttp3_qpack_decoder* p) {
        nghttp3_qpack_decoder_del(p);
    })>{decoder};
    auto stream_cleanup = std::unique_ptr<nghttp3_qpack_stream_context, decltype([](nghttp3_qpack_stream_context* p) {
        nghttp3_qpack_stream_context_del(p);
    })>{stream_ctx};

    std::vector<header> decoded;
    std::size_t offset = 0;
    bool final = false;
    while (offset < block.size() || !final) {
        nghttp3_qpack_nv nv{};
        std::uint8_t flags = 0;
        auto remaining = block.subspan(offset);
        auto consumed = nghttp3_qpack_decoder_read_request(
            decoder,
            stream_ctx,
            &nv,
            &flags,
            reinterpret_cast<const uint8_t*>(remaining.data()),
            remaining.size(),
            1);
        if (consumed < 0)
            throw make_error("qpack_decoder_read_request", static_cast<int>(consumed));

        offset += static_cast<std::size_t>(consumed);

        if (flags & NGHTTP3_QPACK_DECODE_FLAG_EMIT) {
            decoded.push_back({rcbuf_to_string(nv.name), rcbuf_to_string(nv.value)});
            nghttp3_rcbuf_decref(nv.name);
            nghttp3_rcbuf_decref(nv.value);
        }

        final = (flags & NGHTTP3_QPACK_DECODE_FLAG_FINAL) != 0;
        if (consumed == 0 && !final)
            break;
    }

    if (!final)
        throw std::runtime_error("http/3: incomplete QPACK field section");

    return decoded;
}

inline auto decode_request_block(std::int64_t stream_id, std::span<const std::byte> block) -> http::request {
    auto fields = decode_field_section(stream_id, block);
    http::request req{};
    req.target.clear();
    for (auto& field : fields) {
        if (field.name == ":method")
            req.method = from_string(field.value);
        else if (field.name == ":scheme")
            req.scheme = field.value;
        else if (field.name == ":authority")
            req.authority = field.value;
        else if (field.name == ":path")
            req.target = field.value;
        else if (!field.name.starts_with(':'))
            req.fields.push_back(std::move(field));
    }

    if (req.method == method::UNKNOWN || req.scheme.empty() || req.authority.empty() || req.target.empty())
        throw std::runtime_error("http/3: malformed pushed request header block");

    return req;
}

inline auto decode_response_block(std::int64_t stream_id, std::span<const std::byte> block) -> http::response {
    auto fields = decode_field_section(stream_id, block);
    http::response res{};
    res.status = 0;
    res.reason.clear();
    res.fields.clear();
    res.body.clear();
    for (auto& field : fields) {
        if (field.name == ":status")
            res.status = static_cast<http::status>(std::stoi(field.value));
        else if (!field.name.starts_with(':'))
            res.fields.push_back(std::move(field));
    }

    if (res.status == 0)
        throw std::runtime_error("http/3: malformed pushed response header block");

    return res;
}

inline auto make_request_block(const http::request& req, std::int64_t stream_id) -> std::vector<std::byte> {
    auto authority = request_authority(req);
    auto path = request_path(req);
    auto scheme = request_scheme(req);
    if (!authority || !path || !scheme)
        throw std::runtime_error("http/3: pushed requests require scheme, authority, and path");

    auto nva = nv_block{req.fields.size() + 4};
    nva.push(":method", to_string(req.method));
    nva.push(":scheme", *scheme);
    nva.push(":authority", *authority);
    nva.push(":path", *path);
    for (auto& h : req.fields) {
        if (iequal(h.name, "host")) continue;
        nva.push(h.name, h.value);
    }
    return encode_field_section(stream_id, nva.fields);
}

inline auto make_response_block(const http::response& res, std::int64_t stream_id) -> std::vector<std::byte> {
    auto nva = nv_block{res.fields.size() + 1};
    nva.push(":status", std::to_string(res.status));
    for (auto& h : res.fields)
        nva.push(h.name, h.value);
    return encode_field_section(stream_id, nva.fields);
}

inline void forward_stream_input(nghttp3_conn* conn, std::int64_t stream_id, std::span<const std::byte> data, bool fin) {
    static constexpr std::array<std::byte, 1> empty{std::byte{0}};
    auto bytes = data.empty() ? std::span<const std::byte>{empty.data(), 0} : data;
    auto consumed = nghttp3_conn_read_stream(
        conn,
        stream_id,
        reinterpret_cast<const uint8_t*>(bytes.data()),
        bytes.size(),
        fin ? 1 : 0);
    if (consumed < 0)
        throw make_error("read_stream", static_cast<int>(consumed));
}

inline auto make_frame_error(std::string_view detail) -> std::runtime_error {
    return std::runtime_error(std::string("http/3: ") + std::string(detail));
}

inline void handle_cancel_push(conn_context& ctx, std::uint64_t push_id) {
    if (auto it = ctx.pushes.find(push_id); it != ctx.pushes.end())
        it->second->cancelled = true;
}

inline auto process_control_stream(conn_context& ctx, nghttp3_conn* conn, std::int64_t stream_id, stream_input_state& input) -> void {
    std::vector<std::byte> forward;
    while (true) {
        parsed_frame frame;
        if (!try_pop_frame(input.buffer, frame)) break;

        if (!input.settings_seen) {
            if (frame.type != settings_frame_type)
                throw make_frame_error("control stream is missing initial SETTINGS frame");
            input.settings_seen = true;
        } else if (frame.type == settings_frame_type) {
            throw make_frame_error("duplicate SETTINGS frame on control stream");
        }

        switch (frame.type) {
            case settings_frame_type:
                ctx.peer_settings_received = true;
                append_bytes(forward, frame.raw);
                break;
            case goaway_frame_type: {
                auto id = decode_exact_varint(span_bytes(frame.payload), "GOAWAY payload");
                if (!ctx.is_client) {
                    if (!ctx.peer_goaway_push_id || id < *ctx.peer_goaway_push_id)
                        ctx.peer_goaway_push_id = id;
                }
                append_bytes(forward, frame.raw);
                break;
            }
            case max_push_id_frame_type: {
                if (ctx.is_client)
                    throw make_frame_error("server sent MAX_PUSH_ID on control stream");
                auto id = decode_exact_varint(span_bytes(frame.payload), "MAX_PUSH_ID payload");
                if (ctx.peer_max_push_id && id < *ctx.peer_max_push_id)
                    throw make_frame_error("peer reduced MAX_PUSH_ID");
                ctx.peer_max_push_id = id;
                break;
            }
            case cancel_push_frame_type: {
                auto id = decode_exact_varint(span_bytes(frame.payload), "CANCEL_PUSH payload");
                handle_cancel_push(ctx, id);
                break;
            }
            default:
                append_bytes(forward, frame.raw);
                break;
        }
    }

    if (input.closed) {
        if (!input.buffer.empty())
            throw make_frame_error("truncated control stream frame");
        forward_stream_input(conn, stream_id, span_bytes(forward), true);
        throw make_frame_error("control stream was closed");
    }

    if (!forward.empty())
        forward_stream_input(conn, stream_id, span_bytes(forward), false);
}

inline auto process_request_stream(conn_context& ctx, nghttp3_conn* conn, std::int64_t stream_id, stream_input_state& input) -> void {
    std::vector<std::byte> forward;
    while (true) {
        parsed_frame frame;
        if (!try_pop_frame(input.buffer, frame)) break;

        if (!ctx.is_client) {
            if (frame.type == push_promise_frame_type)
                throw make_frame_error("client sent PUSH_PROMISE on request stream");
            append_bytes(forward, frame.raw);
            continue;
        }

        if (frame.type == push_promise_frame_type) {
            std::size_t push_id_len = 0;
            std::uint64_t push_id = 0;
            if (!try_decode_varint(span_bytes(frame.payload), push_id_len, push_id))
                throw make_frame_error("malformed PUSH_PROMISE payload");
            if (!ctx.advertised_max_push_id || push_id > *ctx.advertised_max_push_id)
                throw make_frame_error("received PUSH_PROMISE beyond advertised MAX_PUSH_ID");

            auto promised_request = decode_request_block(
                stream_id,
                span_bytes(frame.payload).subspan(push_id_len));
            auto& push = ctx.pushes[push_id];
            if (!push) {
                push = std::make_shared<push_state>();
                push->push_id = push_id;
                push->associated_stream_id = stream_id;
            } else if (push->promise_received && !request_blocks_equal(push->promised_request, promised_request)) {
                throw make_frame_error("received conflicting PUSH_PROMISE for existing push ID");
            }

            push->promise_received = true;
            push->promised_request = std::move(promised_request);
            maybe_queue_push(ctx, push);
            continue;
        }

        append_bytes(forward, frame.raw);
    }

    if (input.closed && !input.buffer.empty())
        throw make_frame_error("truncated request stream frame");

    if (!forward.empty() || input.closed)
        forward_stream_input(conn, stream_id, span_bytes(forward), input.closed);
}

inline auto process_push_stream(conn_context& ctx, std::int64_t stream_id, stream_input_state& input) -> void {
    if (!ctx.is_client)
        throw make_frame_error("client-initiated push stream is invalid");

    if (!input.push_id.has_value()) {
        std::size_t push_id_len = 0;
        std::uint64_t push_id = 0;
        if (!try_decode_varint(span_bytes(input.buffer), push_id_len, push_id)) {
            if (input.closed)
                throw make_frame_error("truncated push stream header");
            return;
        }

        if (!ctx.advertised_max_push_id || push_id > *ctx.advertised_max_push_id)
            throw make_frame_error("received push stream beyond advertised MAX_PUSH_ID");

        input.push_id = push_id;
        input.buffer.erase(input.buffer.begin(), input.buffer.begin() + static_cast<std::ptrdiff_t>(push_id_len));
        auto& push = ctx.pushes[push_id];
        if (!push) {
            push = std::make_shared<push_state>();
            push->push_id = push_id;
        }
        push->stream_id = stream_id;
    }

    auto push = ctx.pushes[*input.push_id];
    while (true) {
        parsed_frame frame;
        if (!try_pop_frame(input.buffer, frame)) break;

        switch (frame.type) {
            case headers_frame_type: {
                auto decoded = decode_response_block(stream_id, span_bytes(frame.payload));
                push->pushed_response.status = decoded.status;
                for (auto& field : decoded.fields)
                    push->pushed_response.fields.push_back(std::move(field));
                break;
            }
            case data_frame_type:
                append_bytes(push->pushed_response.body, span_bytes(frame.payload));
                break;
            case push_promise_frame_type:
            case settings_frame_type:
            case goaway_frame_type:
            case max_push_id_frame_type:
            case cancel_push_frame_type:
                throw make_frame_error("unexpected frame type on push stream");
            default:
                break;
        }
    }

    if (input.closed) {
        if (!input.buffer.empty())
            throw make_frame_error("truncated push stream frame");
        push->complete = true;
        maybe_queue_push(ctx, push);
    }
}

inline void process_input(conn_context& ctx, nghttp3_conn* conn, std::int64_t stream_id, std::span<const std::byte> data, bool fin) {
    auto& input = ctx.inputs[stream_id];
    append_bytes(input.buffer, data);
    input.closed = input.closed || fin;

    if (is_unidirectional_stream(stream_id) && !input.stream_type_known) {
        std::size_t type_len = 0;
        std::uint64_t stream_type = 0;
        if (!try_decode_varint(span_bytes(input.buffer), type_len, stream_type)) {
            if (input.closed)
                throw make_frame_error("truncated unidirectional stream type");
            return;
        }

        input.stream_type_known = true;
        input.stream_type = stream_type;

        switch (stream_type) {
            case control_stream_type:
                input.kind = stream_kind::control;
                if (ctx.remote_control_stream_id && *ctx.remote_control_stream_id != stream_id)
                    throw make_frame_error("received duplicate control stream");
                ctx.remote_control_stream_id = stream_id;
                break;
            case push_stream_type:
                input.kind = stream_kind::push;
                break;
            case qpack_encoder_stream_type:
            case qpack_decoder_stream_type:
                input.kind = stream_kind::qpack;
                break;
            default:
                input.kind = stream_kind::ignored;
                break;
        }

        if (input.kind == stream_kind::control || input.kind == stream_kind::qpack) {
            auto prefix = std::vector<std::byte>{input.buffer.begin(), input.buffer.begin() + static_cast<std::ptrdiff_t>(type_len)};
            forward_stream_input(conn, stream_id, span_bytes(prefix), false);
        }
        input.buffer.erase(input.buffer.begin(), input.buffer.begin() + static_cast<std::ptrdiff_t>(type_len));
    }

    if (!is_unidirectional_stream(stream_id))
        input.kind = stream_kind::request;

    switch (input.kind) {
        case stream_kind::request:
            process_request_stream(ctx, conn, stream_id, input);
            break;
        case stream_kind::control:
            process_control_stream(ctx, conn, stream_id, input);
            break;
        case stream_kind::push:
            process_push_stream(ctx, stream_id, input);
            break;
        case stream_kind::qpack:
            if (!input.buffer.empty() || input.closed) {
                auto buffered = std::move(input.buffer);
                input.buffer.clear();
                forward_stream_input(conn, stream_id, span_bytes(buffered), input.closed);
            }
            break;
        case stream_kind::ignored:
            if (input.closed)
                input.buffer.clear();
            break;
    }
}

inline auto make_callbacks() -> nghttp3_callbacks {
    nghttp3_callbacks cbs{};

    cbs.stream_close = [](nghttp3_conn*, std::int64_t stream_id,
                          std::uint64_t app_error_code,
                          void* ud, void*) -> int {
        auto* ctx = static_cast<conn_context*>(ud);
        if (auto it = ctx->streams.find(stream_id); it != ctx->streams.end()) {
            it->second->closed = true;
            it->second->close_error_code = app_error_code;
            it->second->aborted = !it->second->complete;
        }
        ctx->outbound_bodies.erase(stream_id);
        return 0;
    };

    cbs.recv_settings2 = [](nghttp3_conn*, const nghttp3_proto_settings*, void* ud) -> int {
        auto* ctx = static_cast<conn_context*>(ud);
        ctx->peer_settings_received = true;
        return 0;
    };

    cbs.shutdown = [](nghttp3_conn*, std::int64_t id, void* ud) -> int {
        auto* ctx = static_cast<conn_context*>(ud);
        ctx->goaway_received = true;
        if (ctx->goaway_id == -1 || id < ctx->goaway_id)
            ctx->goaway_id = id;
        return 0;
    };

    cbs.recv_header = [](nghttp3_conn*, std::int64_t stream_id,
                         std::int32_t, nghttp3_rcbuf* name,
                         nghttp3_rcbuf* value, std::uint8_t,
                         void* ud, void*) -> int {
        auto* ctx = static_cast<conn_context*>(ud);
        auto it = ctx->streams.find(stream_id);
        if (it == ctx->streams.end()) return 0;
        auto n = rcbuf_to_string(name);
        auto v = rcbuf_to_string(value);
        if (n == ":status")
            it->second->status_code = static_cast<http::status>(std::stoi(v));
        else if (n == ":method")
            it->second->method_str = v;
        else if (n == ":path")
            it->second->path = v;
        else if (n == ":scheme")
            it->second->scheme = v;
        else if (n == ":authority")
            it->second->authority = v;
        else if (!n.starts_with(":"))
            it->second->fields.push_back({std::move(n), std::move(v)});
        return 0;
    };

    cbs.end_headers = [](nghttp3_conn*, std::int64_t stream_id,
                         int, void* ud, void*) -> int {
        auto* ctx = static_cast<conn_context*>(ud);
        auto it = ctx->streams.find(stream_id);
        if (it != ctx->streams.end()) it->second->headers_done = true;
        return 0;
    };

    cbs.recv_data = [](nghttp3_conn*, std::int64_t stream_id,
                       const uint8_t* data, std::size_t len,
                       void* ud, void*) -> int {
        auto* ctx = static_cast<conn_context*>(ud);
        auto it = ctx->streams.find(stream_id);
        if (it != ctx->streams.end()) {
            auto bytes = std::as_bytes(std::span{data, len});
            it->second->body.insert(it->second->body.end(), bytes.begin(), bytes.end());
        }
        return 0;
    };

    cbs.end_stream = [](nghttp3_conn*, std::int64_t stream_id,
                        void* ud, void*) -> int {
        auto* ctx = static_cast<conn_context*>(ud);
        if (auto it = ctx->streams.find(stream_id); it != ctx->streams.end()) {
            it->second->complete = true;
            if (!it->second->method_str.empty()) {
                ctx->completed_server_streams.push_back(it->second);
                ctx->last_completed_stream_id = it->second->id;
            }
        }
        return 0;
    };

    cbs.begin_headers = [](nghttp3_conn*, std::int64_t stream_id,
                           void* ud, void*) -> int {
        auto* ctx = static_cast<conn_context*>(ud);
        if (!ctx->streams.contains(stream_id)) {
            auto sd = std::make_shared<stream_data>();
            sd->id = stream_id;
            ctx->streams[stream_id] = sd;
        }
        return 0;
    };

    return cbs;
}

inline auto read_outbound_body(
    nghttp3_conn*,
    std::int64_t,
    nghttp3_vec* vec,
    std::size_t veccnt,
    std::uint32_t* flags,
    void*,
    void* stream_user_data) -> nghttp3_ssize
{
    auto* state = static_cast<outbound_body_state*>(stream_user_data);
    if (state == nullptr || veccnt == 0) return NGHTTP3_ERR_CALLBACK_FAILURE;
    if (state->offset >= state->data.size()) {
        *flags |= NGHTTP3_DATA_FLAG_EOF;
        return 0;
    }

    auto* ptr = state->data.data() + state->offset;
    auto remaining = state->data.size() - state->offset;
    vec[0].base = reinterpret_cast<uint8_t*>(ptr);
    vec[0].len = remaining;
    state->offset = state->data.size();
    *flags |= NGHTTP3_DATA_FLAG_EOF;
    return 1;
}

inline auto drain_output(nghttp3_conn* conn) -> std::vector<pending_write> {
    std::vector<pending_write> out;
    std::int64_t sid = -1;
    int fin = 0;
    nghttp3_vec vec[8];
    for (;;) {
        auto n = nghttp3_conn_writev_stream(conn, &sid, &fin, vec, 8);
        if (n < 0) throw make_error("writev_stream", static_cast<int>(n));
        if (n == 0) break;

        auto count = static_cast<std::size_t>(n);
        pending_write write{.stream_id = sid, .fin = fin != 0};
        std::size_t total = 0;
        for (std::size_t i = 0; i < count; ++i) {
            auto bytes = std::as_bytes(std::span{
                reinterpret_cast<const char*>(vec[i].base), vec[i].len});
            write.data.insert(write.data.end(), bytes.begin(), bytes.end());
            total += vec[i].len;
        }
        out.push_back(std::move(write));
        nghttp3_conn_add_write_offset(conn, sid, total);
    }
    return out;
}

} // namespace h3

// ─── HTTP/3 client (RFC 9114) ────────────────────────────────

template <multiplexed S>
class client_v3 {
public:
    explicit client_v3(S& transport) : transport_(transport) {
        auto cbs = h3::make_callbacks();
        nghttp3_settings settings;
        nghttp3_settings_default(&settings);
        ctx_.is_client = true;
        h3::check(
            nghttp3_conn_client_new(&conn_, &cbs, &settings, nghttp3_mem_default(), &ctx_),
            "conn_client_new");
    }

    ~client_v3() { if (conn_) nghttp3_conn_del(conn_); }
    client_v3(const client_v3&) = delete;
    client_v3& operator=(const client_v3&) = delete;

    auto handshake(std::int64_t ctrl_id, std::int64_t qenc_id, std::int64_t qdec_id) -> task<void> {
        h3::check(nghttp3_conn_bind_control_stream(conn_, ctrl_id), "bind_control");
        h3::check(nghttp3_conn_bind_qpack_streams(conn_, qenc_id, qdec_id), "bind_qpack");
        ctx_.local_control_stream_id = ctrl_id;
        co_await flush_to(transport_);
    }

    auto allow_pushes(std::uint64_t max_push_id) -> task<void> {
        if (ctx_.advertised_max_push_id && max_push_id < *ctx_.advertised_max_push_id)
            throw std::runtime_error("http/3: MAX_PUSH_ID cannot be reduced");

        ctx_.advertised_max_push_id = max_push_id;
        auto payload = h3::encode_varint(max_push_id);
        h3::queue_control_frame(ctx_, h3::make_frame(h3::max_push_id_frame_type, payload));
        co_await flush_to(transport_);
    }

    auto request(http::request req, std::int64_t stream_id) -> task<http::response> {
        if (ctx_.goaway_received)
            throw std::runtime_error("http/3: goaway received");

        auto authority = request_authority(req);
        if (!authority)
            throw std::runtime_error("http/3: missing authority pseudo-header");

        auto path = request_path(req);
        auto scheme = request_scheme(req);
        if (req.method != method::CONNECT) {
            if (!path)
                throw std::runtime_error("http/3: missing path pseudo-header");
            if (!scheme)
                throw std::runtime_error("http/3: missing scheme pseudo-header");
        }

        auto nva = h3::nv_block{req.fields.size() + (req.method == method::CONNECT ? 2 : 4)};
        nva.push(":method", to_string(req.method));
        if (req.method != method::CONNECT) {
            nva.push(":scheme", *scheme);
            nva.push(":authority", *authority);
            nva.push(":path", *path);
        } else {
            nva.push(":authority", *authority);
        }
        for (auto& h : req.fields) {
            if (iequal(h.name, "host")) continue;
            nva.push(h.name, h.value);
        }

        auto sd = std::make_shared<h3::stream_data>();
        sd->id = stream_id;
        ctx_.streams[stream_id] = sd;

        auto outbound_body = std::make_shared<h3::outbound_body_state>();
        outbound_body->data = std::move(req.body);
        nghttp3_data_reader reader{.read_data = &h3::read_outbound_body};
        if (!outbound_body->data.empty())
            ctx_.outbound_bodies[stream_id] = outbound_body;

        h3::check(nghttp3_conn_submit_request(conn_, stream_id,
            nva.fields.data(), nva.fields.size(),
            outbound_body->data.empty() ? nullptr : &reader,
            outbound_body->data.empty() ? nullptr : outbound_body.get()), "submit_request");

        struct stream_scope {
            h3::conn_context& ctx;
            std::int64_t stream_id;

            ~stream_scope() {
                ctx.streams.erase(stream_id);
                ctx.outbound_bodies.erase(stream_id);
            }
        } cleanup{ctx_, stream_id};

        co_await flush_to(transport_);

        auto response_stream = co_await transport_.async_open(stream_id);
        std::array<std::byte, h3::io_buffer_size> buf;
        while (!sd->complete) {
            if (sd->aborted)
                throw std::runtime_error("http/3: stream closed before complete response");
            if (ctx_.goaway_received && ctx_.goaway_id != -1 && stream_id >= ctx_.goaway_id && !sd->headers_done)
                throw std::runtime_error("http/3: request rejected by GOAWAY");

            auto n = co_await response_stream.async_read(std::span{buf});
            if (n == 0) {
                static_cast<void>(feed(stream_id, {}, true));
                if (sd->complete) break;
                throw std::runtime_error("http/3: connection closed before complete response");
            }

            static_cast<void>(feed(
                stream_id,
                std::span<const std::byte>{buf.data(), static_cast<std::size_t>(n)},
                false));
            co_await flush_to(transport_);
        }

        if (sd->aborted)
            throw std::runtime_error("http/3: stream closed before complete response");

        co_return http::response{
            .status = sd->status_code,
            .reason = {},
            .fields = std::move(sd->fields),
            .body   = std::move(sd->body),
        };
    }

    auto feed(std::int64_t stream_id, std::span<const std::byte> data, bool fin) -> int {
        h3::process_input(ctx_, conn_, stream_id, data, fin);
        return static_cast<int>(data.size());
    }

    auto shutdown() -> task<void> {
        h3::check(nghttp3_conn_submit_shutdown_notice(conn_), "submit_shutdown_notice");
        h3::check(nghttp3_conn_shutdown(conn_), "shutdown");
        co_await flush_to(transport_);
    }

    auto take_push() -> std::optional<http::pushed_exchange> {
        if (ctx_.completed_pushes.empty()) return std::nullopt;
        auto push = std::move(ctx_.completed_pushes.front());
        ctx_.completed_pushes.pop_front();
        return push;
    }

    [[nodiscard]] auto goaway_received() const -> bool { return ctx_.goaway_received; }

private:
    auto flush_to(S& transport) -> task<void> {
        auto writes = h3::take_manual_writes(ctx_);
        auto nghttp3_writes = h3::drain_output(conn_);
        writes.insert(writes.end(),
            std::make_move_iterator(nghttp3_writes.begin()),
            std::make_move_iterator(nghttp3_writes.end()));
        for (auto& write : writes) {
            auto stream = co_await transport.async_open(write.stream_id);
            co_await async_write_to(
                stream,
                std::span<const std::byte>{write.data.data(), write.data.size()},
                write.fin);
        }
    }

    S& transport_;
    nghttp3_conn* conn_{nullptr};
    h3::conn_context ctx_{};
};

// ─── HTTP/3 server (RFC 9114) ────────────────────────────────

template <multiplexed S>
class server_v3 {
public:
    explicit server_v3(S& transport) : transport_(transport) {
        auto cbs = h3::make_callbacks();
        nghttp3_settings settings;
        nghttp3_settings_default(&settings);
        ctx_.is_client = false;
        h3::check(
            nghttp3_conn_server_new(&conn_, &cbs, &settings, nghttp3_mem_default(), &ctx_),
            "conn_server_new");
    }

    ~server_v3() { if (conn_) nghttp3_conn_del(conn_); }
    server_v3(const server_v3&) = delete;
    server_v3& operator=(const server_v3&) = delete;

    auto handshake(std::int64_t ctrl_id, std::int64_t qenc_id, std::int64_t qdec_id) -> task<void> {
        h3::check(nghttp3_conn_bind_control_stream(conn_, ctrl_id), "bind_control");
        h3::check(nghttp3_conn_bind_qpack_streams(conn_, qenc_id, qdec_id), "bind_qpack");
        ctx_.local_control_stream_id = ctrl_id;
        co_await flush_to(transport_);
    }

    auto feed(std::int64_t stream_id, std::span<const std::byte> data, bool fin) -> int {
        h3::process_input(ctx_, conn_, stream_id, data, fin);
        return static_cast<int>(data.size());
    }

    auto last_request() -> std::optional<http::request> {
        if (ctx_.completed_server_streams.empty()) return std::nullopt;
        auto sd = ctx_.completed_server_streams.front();
        ctx_.completed_server_streams.pop_front();
        return http::request{
            .method = from_string(sd->method_str),
            .target = std::move(sd->path),
            .scheme = std::move(sd->scheme),
            .authority = std::move(sd->authority),
            .fields = std::move(sd->fields),
            .body   = std::move(sd->body),
        };
    }

    auto respond(std::int64_t stream_id, http::response res) -> task<void> {
        auto nva = h3::nv_block{res.fields.size() + 1};
        nva.push(":status", std::to_string(res.status));
        for (auto& h : res.fields) nva.push(h.name, h.value);

        auto outbound_body = std::make_shared<h3::outbound_body_state>();
        outbound_body->data = std::move(res.body);
        nghttp3_data_reader reader{.read_data = &h3::read_outbound_body};
        h3::check(nghttp3_conn_submit_response(conn_, stream_id,
            nva.fields.data(), nva.fields.size(),
            outbound_body->data.empty() ? nullptr : &reader), "submit_response");
        if (!outbound_body->data.empty())
            ctx_.outbound_bodies[stream_id] = outbound_body;
        co_await flush_to(transport_);
    }

    auto push(std::int64_t associated_stream_id, std::int64_t push_stream_id,
              http::request req, http::response res) -> task<std::uint64_t> {
        if (req.method != method::GET && req.method != method::HEAD)
            throw std::runtime_error("http/3: pushed requests must be GET or HEAD");
        if (!req.body.empty())
            throw std::runtime_error("http/3: pushed requests must not include content");
        if (!ctx_.peer_max_push_id)
            throw std::runtime_error("http/3: peer has not advertised MAX_PUSH_ID");
        if (ctx_.peer_goaway_push_id && ctx_.next_push_id >= *ctx_.peer_goaway_push_id)
            throw std::runtime_error("http/3: peer GOAWAY rejects additional pushes");
        if (ctx_.next_push_id > *ctx_.peer_max_push_id)
            throw std::runtime_error("http/3: next push exceeds peer MAX_PUSH_ID");

        if (req.method == method::HEAD)
            res.body.clear();

        auto push_id = ctx_.next_push_id++;
        auto request_block = h3::make_request_block(req, associated_stream_id);
        auto push_id_payload = h3::encode_varint(push_id);
        push_id_payload.insert(push_id_payload.end(), request_block.begin(), request_block.end());
        h3::queue_write(
            ctx_,
            associated_stream_id,
            h3::make_frame(h3::push_promise_frame_type, push_id_payload),
            false);

        auto response_block = h3::make_response_block(res, push_stream_id);
        auto push_stream_header = h3::encode_varint(h3::push_stream_type);
        auto encoded_push_id = h3::encode_varint(push_id);
        push_stream_header.insert(push_stream_header.end(), encoded_push_id.begin(), encoded_push_id.end());
        auto headers_frame = h3::make_frame(h3::headers_frame_type, response_block);
        push_stream_header.insert(push_stream_header.end(), headers_frame.begin(), headers_frame.end());
        if (!res.body.empty()) {
            auto data_frame = h3::make_frame(h3::data_frame_type, std::span<const std::byte>{res.body.data(), res.body.size()});
            push_stream_header.insert(push_stream_header.end(), data_frame.begin(), data_frame.end());
        }
        h3::queue_write(ctx_, push_stream_id, std::move(push_stream_header), true);

        co_await flush_to(transport_);
        co_return push_id;
    }

    auto shutdown() -> task<void> {
        h3::check(nghttp3_conn_submit_shutdown_notice(conn_), "submit_shutdown_notice");
        h3::check(nghttp3_conn_shutdown(conn_), "shutdown");
        co_await flush_to(transport_);
    }

    auto last_stream_id() const -> std::int64_t {
        return ctx_.last_completed_stream_id;
    }

    [[nodiscard]] auto goaway_received() const -> bool { return ctx_.goaway_received; }

private:
    auto flush_to(S& transport) -> task<void> {
        auto writes = h3::take_manual_writes(ctx_);
        auto nghttp3_writes = h3::drain_output(conn_);
        writes.insert(writes.end(),
            std::make_move_iterator(nghttp3_writes.begin()),
            std::make_move_iterator(nghttp3_writes.end()));
        for (auto& write : writes) {
            auto stream = co_await transport.async_open(write.stream_id);
            co_await async_write_to(
                stream,
                std::span<const std::byte>{write.data.data(), write.data.size()},
                write.fin);
        }
    }

    S& transport_;
    nghttp3_conn* conn_{nullptr};
    h3::conn_context ctx_{};
};

} // namespace http
