module;

#include <nghttp2/nghttp2.h>

export module httpant:session;

import std;
import :trait;
import :message;

export namespace http {

namespace h2 {

inline constexpr std::size_t io_buffer_size = 16 * 1024;

inline auto make_error(std::string_view op, int rc) -> std::runtime_error {
    return std::runtime_error(
        std::string("http/2: ") + std::string(op) +
        " failed (" + std::to_string(rc) + ")");
}

inline void check(int rc, std::string_view op) {
    if (rc != 0) throw make_error(op, rc);
}

inline auto check_stream_id(int id, std::string_view op) -> int {
    if (id < 0) throw make_error(op, id);
    return id;
}

struct stream_data {
    std::int32_t id{0};
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
    std::uint32_t close_error_code{NGHTTP2_NO_ERROR};
    std::coroutine_handle<> waiter{};
};

struct outbound_body_state {
    std::vector<std::byte> data{};
    std::size_t offset{0};
};

struct push_data {
    std::int32_t promised_stream_id{0};
    std::int32_t associated_stream_id{0};
    bool complete{false};
    bool closed{false};
    bool aborted{false};
    std::string method_str{};
    std::string path{};
    std::string scheme{};
    std::string authority{};
    headers request_fields{};
    http::status status_code{0};
    headers response_fields{};
    std::vector<std::byte> body{};
    std::uint32_t close_error_code{NGHTTP2_NO_ERROR};
};

inline auto make_pushed_exchange(const push_data& push) -> http::pushed_exchange {
    return http::pushed_exchange{
        .push_id = 0,
        .associated_stream_id = push.associated_stream_id,
        .stream_id = push.promised_stream_id,
        .promised_request = http::request{
            .method = from_string(push.method_str),
            .target = push.path,
            .scheme = push.scheme,
            .authority = push.authority,
            .fields = push.request_fields,
            .body = {},
        },
        .pushed_response = http::response{
            .status = push.status_code,
            .reason = {},
            .fields = push.response_fields,
            .body = push.body,
        },
    };
}

struct session_context {
    std::unordered_map<std::int32_t, std::shared_ptr<stream_data>> streams{};
    std::unordered_map<std::int32_t, std::shared_ptr<push_data>> pushed_streams{};
    std::unordered_map<std::int32_t, std::shared_ptr<outbound_body_state>> outbound_bodies{};
    std::vector<std::byte> outbuf{};
    std::deque<std::shared_ptr<stream_data>> completed_server_streams{};
    std::deque<http::pushed_exchange> completed_pushes{};
    bool goaway_received{false};
    bool peer_settings_received{false};
    std::int32_t goaway_last_stream_id{0};
    std::int32_t last_completed_stream_id{0};
    std::uint32_t goaway_error_code{0};
};

inline auto read_outbound_body(
    nghttp2_session*,
    std::int32_t,
    uint8_t* buf,
    std::size_t length,
    uint32_t* flags,
    nghttp2_data_source* src,
    void*) -> nghttp2_ssize
{
    auto* state = static_cast<outbound_body_state*>(src->ptr);
    if (state == nullptr) return NGHTTP2_ERR_CALLBACK_FAILURE;
    if (state->offset >= state->data.size()) {
        *flags |= NGHTTP2_DATA_FLAG_EOF;
        return 0;
    }

    auto remaining = state->data.size() - state->offset;
    auto count = std::min(length, remaining);
    std::memcpy(buf, state->data.data() + state->offset, count);
    state->offset += count;
    if (state->offset >= state->data.size()) *flags |= NGHTTP2_DATA_FLAG_EOF;
    return static_cast<nghttp2_ssize>(count);
}

inline auto make_nv(std::string_view name, std::string_view value) -> nghttp2_nv {
    return {
        .name = reinterpret_cast<uint8_t*>(const_cast<char*>(name.data())),
        .value = reinterpret_cast<uint8_t*>(const_cast<char*>(value.data())),
        .namelen = name.size(),
        .valuelen = value.size(),
        .flags = NGHTTP2_NV_FLAG_NONE,
    };
}

inline auto create_callbacks() -> nghttp2_session_callbacks* {
    nghttp2_session_callbacks* cbs = nullptr;
    nghttp2_session_callbacks_new(&cbs);

    nghttp2_session_callbacks_set_on_header_callback(cbs,
        [](nghttp2_session*, const nghttp2_frame* frame,
           const uint8_t* name, std::size_t namelen,
           const uint8_t* value, std::size_t valuelen,
           uint8_t, void* ud) -> int {
            auto* ctx = static_cast<session_context*>(ud);
            if (frame->hd.type == NGHTTP2_PUSH_PROMISE) {
                auto promised_stream_id = frame->push_promise.promised_stream_id;
                auto& push = ctx->pushed_streams[promised_stream_id];
                if (!push) {
                    push = std::make_shared<push_data>();
                    push->promised_stream_id = promised_stream_id;
                    push->associated_stream_id = frame->hd.stream_id;
                }

                auto n = std::string(reinterpret_cast<const char*>(name), namelen);
                auto v = std::string(reinterpret_cast<const char*>(value), valuelen);
                if (n == ":method")
                    push->method_str = v;
                else if (n == ":path")
                    push->path = v;
                else if (n == ":scheme")
                    push->scheme = v;
                else if (n == ":authority")
                    push->authority = v;
                else if (!n.starts_with(":"))
                    push->request_fields.push_back({std::move(n), std::move(v)});
                return 0;
            }

            if (auto push_it = ctx->pushed_streams.find(frame->hd.stream_id);
                push_it != ctx->pushed_streams.end()) {
                auto n = std::string(reinterpret_cast<const char*>(name), namelen);
                auto v = std::string(reinterpret_cast<const char*>(value), valuelen);
                if (n == ":status")
                    push_it->second->status_code = static_cast<http::status>(std::stoi(v));
                else if (!n.starts_with(":"))
                    push_it->second->response_fields.push_back({std::move(n), std::move(v)});
                return 0;
            }

            auto it = ctx->streams.find(frame->hd.stream_id);
            if (it == ctx->streams.end()) return 0;
            auto n = std::string(reinterpret_cast<const char*>(name), namelen);
            auto v = std::string(reinterpret_cast<const char*>(value), valuelen);
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
        });

    nghttp2_session_callbacks_set_on_frame_recv_callback(cbs,
        [](nghttp2_session*, const nghttp2_frame* frame, void* ud) -> int {
            auto* ctx = static_cast<session_context*>(ud);
            if (frame->hd.type == NGHTTP2_HEADERS) {
                auto it = ctx->streams.find(frame->hd.stream_id);
                if (it != ctx->streams.end())
                    it->second->headers_done = true;
            }
            if (frame->hd.type == NGHTTP2_SETTINGS && frame->hd.stream_id == 0)
                ctx->peer_settings_received = true;
            if (frame->hd.type == NGHTTP2_GOAWAY) {
                ctx->goaway_received = true;
                ctx->goaway_last_stream_id = frame->goaway.last_stream_id;
                ctx->goaway_error_code = frame->goaway.error_code;
            }
            if (frame->hd.flags & NGHTTP2_FLAG_END_STREAM) {
                if (auto push_it = ctx->pushed_streams.find(frame->hd.stream_id);
                    push_it != ctx->pushed_streams.end()) {
                    push_it->second->complete = true;
                    ctx->completed_pushes.push_back(make_pushed_exchange(*push_it->second));
                    return 0;
                }

                auto it = ctx->streams.find(frame->hd.stream_id);
                if (it != ctx->streams.end()) {
                    it->second->complete = true;
                    if (!it->second->method_str.empty()) {
                        ctx->completed_server_streams.push_back(it->second);
                        ctx->last_completed_stream_id = it->second->id;
                    }
                    if (it->second->waiter)
                        it->second->waiter.resume();
                }
            }
            return 0;
        });

    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(cbs,
        [](nghttp2_session* session, uint8_t, std::int32_t stream_id,
           const uint8_t* data, std::size_t len, void* ud) -> int {
            auto* ctx = static_cast<session_context*>(ud);
            if (auto push_it = ctx->pushed_streams.find(stream_id);
                push_it != ctx->pushed_streams.end()) {
                auto bytes = std::as_bytes(std::span{data, len});
                push_it->second->body.insert(push_it->second->body.end(), bytes.begin(), bytes.end());
                nghttp2_session_consume(session, stream_id, len);
                return 0;
            }

            auto it = ctx->streams.find(stream_id);
            if (it != ctx->streams.end()) {
                auto bytes = std::as_bytes(std::span{data, len});
                it->second->body.insert(it->second->body.end(), bytes.begin(), bytes.end());
            }
            nghttp2_session_consume(session, stream_id, len);
            return 0;
        });

    nghttp2_session_callbacks_set_on_begin_headers_callback(cbs,
        [](nghttp2_session*, const nghttp2_frame* frame, void* ud) -> int {
            auto* ctx = static_cast<session_context*>(ud);
            if (frame->hd.type == NGHTTP2_PUSH_PROMISE) {
                auto promised_stream_id = frame->push_promise.promised_stream_id;
                auto& push = ctx->pushed_streams[promised_stream_id];
                if (!push) {
                    push = std::make_shared<push_data>();
                    push->promised_stream_id = promised_stream_id;
                    push->associated_stream_id = frame->hd.stream_id;
                }
                return 0;
            }

            if (frame->hd.type == NGHTTP2_HEADERS &&
                frame->headers.cat == NGHTTP2_HCAT_PUSH_RESPONSE) {
                auto& push = ctx->pushed_streams[frame->hd.stream_id];
                if (!push) {
                    push = std::make_shared<push_data>();
                    push->promised_stream_id = frame->hd.stream_id;
                }
                return 0;
            }

            if (frame->hd.type == NGHTTP2_HEADERS &&
                frame->headers.cat == NGHTTP2_HCAT_REQUEST) {
                auto sd = std::make_shared<stream_data>();
                sd->id = frame->hd.stream_id;
                ctx->streams[sd->id] = sd;
            }
            return 0;
        });

    nghttp2_session_callbacks_set_on_stream_close_callback(cbs,
        [](nghttp2_session*, std::int32_t stream_id, std::uint32_t error_code, void* ud) -> int {
            auto* ctx = static_cast<session_context*>(ud);
            if (auto push_it = ctx->pushed_streams.find(stream_id);
                push_it != ctx->pushed_streams.end()) {
                push_it->second->closed = true;
                push_it->second->close_error_code = error_code;
                push_it->second->aborted = !push_it->second->complete;
                ctx->pushed_streams.erase(push_it);
            }
            if (auto it = ctx->streams.find(stream_id); it != ctx->streams.end()) {
                it->second->closed = true;
                it->second->close_error_code = error_code;
                it->second->aborted = !it->second->complete;
                if (it->second->waiter) {
                    auto waiter = std::exchange(it->second->waiter, {});
                    waiter.resume();
                }
            }
            ctx->outbound_bodies.erase(stream_id);
            return 0;
        });

    return cbs;
}

inline void flush_output(nghttp2_session* session, session_context& ctx) {
    const uint8_t* data = nullptr;
    for (;;) {
        auto len = nghttp2_session_mem_send2(session, &data);
        if (len < 0) throw make_error("mem_send", static_cast<int>(len));
        if (len == 0) break;
        auto bytes = std::as_bytes(std::span{data, static_cast<std::size_t>(len)});
        ctx.outbuf.insert(ctx.outbuf.end(), bytes.begin(), bytes.end());
    }
}

inline auto write_and_clear(auto& transport, session_context& ctx) -> task<void> {
    if (!ctx.outbuf.empty()) {
        co_await async_write_to(
            transport,
            std::span<const std::byte>{ctx.outbuf.data(), ctx.outbuf.size()});
        ctx.outbuf.clear();
    }
}

inline auto pump_input(
    auto& transport,
    nghttp2_session* session,
    session_context& ctx,
    std::span<std::byte> buf,
    std::string_view eof_message) -> task<std::size_t>
{
    auto n = co_await transport.async_read(buf);
    if (n == 0)
        throw std::runtime_error(std::string(eof_message));

    auto rc = nghttp2_session_mem_recv2(
        session,
        reinterpret_cast<const uint8_t*>(buf.data()),
        n);
    if (rc < 0) throw make_error("mem_recv", static_cast<int>(rc));
    flush_output(session, ctx);
    co_await write_and_clear(transport, ctx);
    co_return n;
}

inline void require_peer_settings(const session_context& ctx, std::string_view message) {
    if (!ctx.peer_settings_received)
        throw std::runtime_error(std::string(message));
}

} // namespace h2

// ─── HTTP/2 client (RFC 9113) ─────────────────────────────────

template <duplex S>
class client_v2 {
public:
    explicit client_v2(S& transport) : transport_(transport) {
        auto* cbs = h2::create_callbacks();
        h2::check(nghttp2_session_client_new(&session_, cbs, &ctx_), "session_client_new");
        nghttp2_session_callbacks_del(cbs);

        h2::check(nghttp2_submit_settings(session_, NGHTTP2_FLAG_NONE, nullptr, 0), "submit_settings");
        h2::flush_output(session_, ctx_);
    }

    ~client_v2() { if (session_) nghttp2_session_del(session_); }
    client_v2(const client_v2&) = delete;
    client_v2& operator=(const client_v2&) = delete;
    client_v2(client_v2&& o) noexcept
        : transport_(o.transport_), session_(std::exchange(o.session_, nullptr)), ctx_(std::move(o.ctx_)) {}

    auto handshake() -> task<void> {
        co_await h2::write_and_clear(transport_, ctx_);
        std::array<std::byte, h2::io_buffer_size> buf;
        static_cast<void>(co_await h2::pump_input(
            transport_,
            session_,
            ctx_,
            std::span{buf},
            "http/2: connection closed before peer settings"));
        h2::require_peer_settings(ctx_, "http/2: peer SETTINGS not received during handshake");
    }

    auto request(http::request req) -> task<http::response> {
        if (ctx_.goaway_received)
            throw std::runtime_error("http/2: goaway received, no new streams");

        auto authority = request_authority(req);
        if (!authority)
            throw std::runtime_error("http/2: missing authority pseudo-header");

        auto path = request_path(req);
        auto scheme = request_scheme(req);
        if (req.method != method::CONNECT) {
            if (!path)
                throw std::runtime_error("http/2: missing path pseudo-header");
            if (!scheme)
                throw std::runtime_error("http/2: missing scheme pseudo-header");
        }

        std::vector<nghttp2_nv> nva;
        auto method_token = std::string(to_string(req.method));
        auto authority_token = std::string(*authority);
        std::optional<std::string> path_token;
        std::optional<std::string> scheme_token;
        nva.push_back(h2::make_nv(":method", method_token));
        if (req.method != method::CONNECT) {
            path_token.emplace(*path);
            scheme_token.emplace(*scheme);
            nva.push_back(h2::make_nv(":scheme", *scheme_token));
            nva.push_back(h2::make_nv(":authority", authority_token));
            nva.push_back(h2::make_nv(":path", *path_token));
        } else {
            nva.push_back(h2::make_nv(":authority", authority_token));
        }
        for (auto& h : req.fields) {
            if (iequal(h.name, "host")) continue;
            nva.push_back(h2::make_nv(h.name, h.value));
        }

        nghttp2_data_provider2 prd{};
        auto outbound_body = std::make_shared<h2::outbound_body_state>();
        outbound_body->data = std::move(req.body);
        if (!outbound_body->data.empty()) {
            prd.source.ptr = outbound_body.get();
            prd.read_callback = &h2::read_outbound_body;
        }

        auto sd = std::make_shared<h2::stream_data>();
        auto stream_id = h2::check_stream_id(
            nghttp2_submit_request2(session_, nullptr, nva.data(), nva.size(),
                outbound_body->data.empty() ? nullptr : &prd, nullptr), "submit_request");
        sd->id = stream_id;
        ctx_.streams[stream_id] = sd;
        if (!outbound_body->data.empty())
            ctx_.outbound_bodies[stream_id] = outbound_body;

        struct stream_scope {
            h2::session_context& ctx;
            std::int32_t stream_id;

            ~stream_scope() {
                ctx.streams.erase(stream_id);
                ctx.outbound_bodies.erase(stream_id);
            }
        } cleanup{ctx_, stream_id};

        h2::flush_output(session_, ctx_);
        co_await h2::write_and_clear(transport_, ctx_);

        std::array<std::byte, h2::io_buffer_size> buf;
        while (!sd->complete) {
            if (sd->aborted)
                throw std::runtime_error("http/2: stream closed before complete response");
            if (ctx_.goaway_received && stream_id > ctx_.goaway_last_stream_id && !sd->headers_done)
                throw std::runtime_error("http/2: request rejected by GOAWAY");

            static_cast<void>(co_await h2::pump_input(
                transport_,
                session_,
                ctx_,
                std::span{buf},
                "http/2: connection closed before complete response"));
        }

        if (sd->aborted)
            throw std::runtime_error("http/2: stream closed before complete response");

        co_return http::response{
            .status = sd->status_code,
            .reason = {},
            .fields = std::move(sd->fields),
            .body   = std::move(sd->body),
        };
    }

    auto shutdown() -> task<void> {
        nghttp2_submit_goaway(session_, NGHTTP2_FLAG_NONE, 0, NGHTTP2_NO_ERROR, nullptr, 0);
        h2::flush_output(session_, ctx_);
        co_await h2::write_and_clear(transport_, ctx_);
    }

    auto take_push() -> std::optional<http::pushed_exchange> {
        if (ctx_.completed_pushes.empty()) return std::nullopt;
        auto push = std::move(ctx_.completed_pushes.front());
        ctx_.completed_pushes.pop_front();
        return push;
    }

    [[nodiscard]] auto goaway_received() const -> bool { return ctx_.goaway_received; }
    [[nodiscard]] auto remote_window_size() const -> std::int32_t {
        return nghttp2_session_get_remote_window_size(session_);
    }
    [[nodiscard]] auto local_window_size() const -> std::int32_t {
        return nghttp2_session_get_local_window_size(session_);
    }

private:
    S& transport_;
    nghttp2_session* session_{nullptr};
    h2::session_context ctx_{};
};

// ─── HTTP/2 server (RFC 9113) ─────────────────────────────────

template <duplex S>
class server_v2 {
public:
    explicit server_v2(S& transport) : transport_(transport) {
        auto* cbs = h2::create_callbacks();
        h2::check(nghttp2_session_server_new(&session_, cbs, &ctx_), "session_server_new");
        nghttp2_session_callbacks_del(cbs);

        h2::check(nghttp2_submit_settings(session_, NGHTTP2_FLAG_NONE, nullptr, 0), "submit_settings");
        h2::flush_output(session_, ctx_);
    }

    ~server_v2() { if (session_) nghttp2_session_del(session_); }
    server_v2(const server_v2&) = delete;
    server_v2& operator=(const server_v2&) = delete;

    auto handshake() -> task<void> {
        co_await h2::write_and_clear(transport_, ctx_);
        std::array<std::byte, h2::io_buffer_size> buf;
        static_cast<void>(co_await h2::pump_input(
            transport_,
            session_,
            ctx_,
            std::span{buf},
            "http/2: connection closed before client preface"));
        h2::require_peer_settings(ctx_, "http/2: client SETTINGS not received during handshake");
    }

    auto receive() -> task<http::request> {
        std::array<std::byte, h2::io_buffer_size> buf;
        while (ctx_.completed_server_streams.empty()) {
            static_cast<void>(co_await h2::pump_input(
                transport_,
                session_,
                ctx_,
                std::span{buf},
                "http/2: connection closed before complete request"));
        }

        auto sd = ctx_.completed_server_streams.front();
        ctx_.completed_server_streams.pop_front();
        if (!sd || !sd->complete)
            throw std::runtime_error("http/2: request did not complete");

        co_return http::request{
            .method = from_string(sd->method_str),
            .target = std::move(sd->path),
            .scheme = std::move(sd->scheme),
            .authority = std::move(sd->authority),
            .fields = std::move(sd->fields),
            .body   = std::move(sd->body),
        };
    }

    auto respond(std::int32_t stream_id, http::response res) -> task<void> {
        std::vector<nghttp2_nv> nva;
        auto status_str = std::to_string(res.status);
        nva.push_back(h2::make_nv(":status", status_str));
        for (auto& h : res.fields)
            nva.push_back(h2::make_nv(h.name, h.value));

        nghttp2_data_provider2 prd{};
        auto outbound_body = std::make_shared<h2::outbound_body_state>();
        outbound_body->data = std::move(res.body);
        if (!outbound_body->data.empty()) {
            prd.source.ptr = outbound_body.get();
            prd.read_callback = &h2::read_outbound_body;
        }

        h2::check(nghttp2_submit_response2(session_, stream_id,
            nva.data(), nva.size(), outbound_body->data.empty() ? nullptr : &prd), "submit_response");
        if (!outbound_body->data.empty())
            ctx_.outbound_bodies[stream_id] = outbound_body;
        h2::flush_output(session_, ctx_);
        co_await h2::write_and_clear(transport_, ctx_);
    }

    auto push(std::int32_t associated_stream_id, http::request req, http::response res) -> task<std::int32_t> {
        if (req.method != method::GET && req.method != method::HEAD)
            throw std::runtime_error("http/2: pushed requests must be GET or HEAD");
        if (!req.body.empty())
            throw std::runtime_error("http/2: pushed requests must not include content");

        auto authority = request_authority(req);
        auto path = request_path(req);
        auto scheme = request_scheme(req);
        if (!authority || !path || !scheme)
            throw std::runtime_error("http/2: pushed requests require scheme, authority, and path");

        std::vector<nghttp2_nv> nva;
        auto method_token = std::string(to_string(req.method));
        auto scheme_token = std::string(*scheme);
        auto authority_token = std::string(*authority);
        auto path_token = std::string(*path);
        nva.push_back(h2::make_nv(":method", method_token));
        nva.push_back(h2::make_nv(":scheme", scheme_token));
        nva.push_back(h2::make_nv(":authority", authority_token));
        nva.push_back(h2::make_nv(":path", path_token));
        for (auto& h : req.fields) {
            if (iequal(h.name, "host")) continue;
            nva.push_back(h2::make_nv(h.name, h.value));
        }

        auto promised_stream_id = h2::check_stream_id(
            nghttp2_submit_push_promise(
                session_,
                NGHTTP2_FLAG_NONE,
                associated_stream_id,
                nva.data(),
                nva.size(),
                nullptr),
            "submit_push_promise");

        if (req.method == method::HEAD)
            res.body.clear();

        co_await respond(promised_stream_id, std::move(res));
        co_return promised_stream_id;
    }

    auto shutdown(std::int32_t last_stream_id = 0) -> task<void> {
        nghttp2_submit_goaway(session_, NGHTTP2_FLAG_NONE, last_stream_id, NGHTTP2_NO_ERROR, nullptr, 0);
        h2::flush_output(session_, ctx_);
        co_await h2::write_and_clear(transport_, ctx_);
    }

    auto last_stream_id() const -> std::int32_t {
        return ctx_.last_completed_stream_id;
    }

    [[nodiscard]] auto goaway_received() const -> bool { return ctx_.goaway_received; }
    [[nodiscard]] auto remote_window_size() const -> std::int32_t {
        return nghttp2_session_get_remote_window_size(session_);
    }
    [[nodiscard]] auto local_window_size() const -> std::int32_t {
        return nghttp2_session_get_local_window_size(session_);
    }

private:
    S& transport_;
    nghttp2_session* session_{nullptr};
    h2::session_context ctx_{};
};

} // namespace http
