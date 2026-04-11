#include "asio_support.hpp"
#include "quic_support.hpp"

#include <asio.hpp>
#include <asio/ssl.hpp>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <coroutine>
#include <exception>
#include <iostream>
#include <memory>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

import httpant;

const MsQuicApi* MsQuic = nullptr;

namespace {

using httpant::examples::async_accept;
using httpant::examples::async_connect;
using httpant::examples::async_resolve_first;
using httpant::examples::async_tls_handshake;
using httpant::examples::callback_queue;
using httpant::examples::endpoint_to_quic_address;
using httpant::examples::quic_client_credentials;
using httpant::examples::quic_configuration;
using httpant::examples::quic_connection_state;
using httpant::examples::quic_connection_transport;
using httpant::examples::quic_listener;
using httpant::examples::quic_runtime;
using httpant::examples::quic_server_credentials;
using httpant::examples::quic_stream;
using httpant::examples::tcp;
using httpant::examples::tcp_socket_stream;
using httpant::examples::tls_socket_stream;

enum class proxy_protocol {
    http1,
    http2,
    http3,
};

struct tls_certificate_files {
    std::string certificate_file;
    std::string private_key_file;
};

struct upstream_security_options {
    std::string server_name;
    std::optional<std::string> ca_certificate_file{};
    bool insecure_no_verify{false};
};

struct proxy_configuration {
    proxy_protocol listen_protocol{};
    std::string listen_host;
    std::string listen_port;
    std::uint16_t listen_port_number{0};
    proxy_protocol upstream_protocol{};
    std::string upstream_host;
    std::string upstream_port;
    std::uint16_t upstream_port_number{0};
    std::optional<tls_certificate_files> downstream_tls{};
    std::optional<upstream_security_options> upstream_tls{};
};

[[nodiscard]] auto usage_text() -> std::string {
    return "usage: httpant-reverse-proxy <listen-protocol> <listen-host> <listen-port> "
           "<upstream-protocol> <upstream-host> <upstream-port> "
           "[--listen-certificate-file <path> --listen-private-key-file <path>] "
           "[--upstream-server-name <name>] "
           "[--upstream-ca-certificate-file <path> | --upstream-insecure]";
}

[[nodiscard]] auto protocol_name(proxy_protocol protocol) -> std::string_view {
    switch (protocol) {
        case proxy_protocol::http1:
            return "http1";
        case proxy_protocol::http2:
            return "http2";
        case proxy_protocol::http3:
            return "http3";
    }
    throw std::runtime_error("unknown proxy protocol");
}

[[nodiscard]] auto scheme_for_protocol(proxy_protocol protocol) -> std::string_view {
    switch (protocol) {
        case proxy_protocol::http1:
            return "http";
        case proxy_protocol::http2:
        case proxy_protocol::http3:
            return "https";
    }
    throw std::runtime_error("unknown proxy protocol");
}

[[nodiscard]] auto parse_protocol(std::string_view text) -> proxy_protocol {
    if (text == "http1")
        return proxy_protocol::http1;
    if (text == "http2")
        return proxy_protocol::http2;
    if (text == "http3")
        return proxy_protocol::http3;
    throw std::runtime_error("unsupported protocol '" + std::string(text) + "'; expected one of http1/http2/http3");
}

[[nodiscard]] auto parse_port_number(std::string_view text, std::string_view name) -> std::uint16_t {
    if (text.empty())
        throw std::runtime_error(std::string(name) + " must not be empty");

    std::uint32_t value = 0;
    for (auto ch : text) {
        if (ch < '0' || ch > '9')
            throw std::runtime_error(std::string(name) + " must be a decimal port number");
        value = value * 10 + static_cast<std::uint32_t>(ch - '0');
        if (value > 65535)
            throw std::runtime_error(std::string(name) + " must be between 1 and 65535");
    }
    if (value == 0)
        throw std::runtime_error(std::string(name) + " must be between 1 and 65535");
    return static_cast<std::uint16_t>(value);
}

[[nodiscard]] auto take_flag_value(int argc, const char** argv, int& index, std::string_view flag) -> std::string {
    if (index + 1 >= argc)
        throw std::runtime_error("missing value for " + std::string(flag));
    ++index;
    return argv[index];
}

[[nodiscard]] auto parse_arguments(int argc, const char** argv) -> proxy_configuration {
    if (argc < 7)
        throw std::runtime_error(usage_text());

    proxy_configuration config{
        .listen_protocol = parse_protocol(argv[1]),
        .listen_host = argv[2],
        .listen_port = argv[3],
        .listen_port_number = parse_port_number(argv[3], "listen port"),
        .upstream_protocol = parse_protocol(argv[4]),
        .upstream_host = argv[5],
        .upstream_port = argv[6],
        .upstream_port_number = parse_port_number(argv[6], "upstream port"),
    };

    std::optional<std::string> listen_certificate_file;
    std::optional<std::string> listen_private_key_file;
    std::optional<std::string> upstream_server_name;
    std::optional<std::string> upstream_ca_certificate_file;
    bool upstream_insecure = false;

    for (auto index = 7; index < argc; ++index) {
        auto flag = std::string_view{argv[index]};
        if (flag == "--listen-certificate-file") {
            if (listen_certificate_file)
                throw std::runtime_error("--listen-certificate-file was specified more than once");
            listen_certificate_file = take_flag_value(argc, argv, index, flag);
            continue;
        }
        if (flag == "--listen-private-key-file") {
            if (listen_private_key_file)
                throw std::runtime_error("--listen-private-key-file was specified more than once");
            listen_private_key_file = take_flag_value(argc, argv, index, flag);
            continue;
        }
        if (flag == "--upstream-server-name") {
            if (upstream_server_name)
                throw std::runtime_error("--upstream-server-name was specified more than once");
            upstream_server_name = take_flag_value(argc, argv, index, flag);
            continue;
        }
        if (flag == "--upstream-ca-certificate-file") {
            if (upstream_ca_certificate_file)
                throw std::runtime_error("--upstream-ca-certificate-file was specified more than once");
            upstream_ca_certificate_file = take_flag_value(argc, argv, index, flag);
            continue;
        }
        if (flag == "--upstream-insecure") {
            if (upstream_insecure)
                throw std::runtime_error("--upstream-insecure was specified more than once");
            upstream_insecure = true;
            continue;
        }
        throw std::runtime_error("unknown argument '" + std::string(flag) + "'\n" + usage_text());
    }

    if (config.listen_protocol == proxy_protocol::http2 || config.listen_protocol == proxy_protocol::http3) {
        if (!listen_certificate_file || !listen_private_key_file)
            throw std::runtime_error("HTTP/2 and HTTP/3 listeners require --listen-certificate-file and --listen-private-key-file");
        config.downstream_tls = tls_certificate_files{
            .certificate_file = *listen_certificate_file,
            .private_key_file = *listen_private_key_file,
        };
    } else if (listen_certificate_file || listen_private_key_file) {
        throw std::runtime_error("listen certificate options are only valid with http2/http3 listeners");
    }

    if (config.upstream_protocol == proxy_protocol::http2 || config.upstream_protocol == proxy_protocol::http3) {
        if (!upstream_server_name)
            throw std::runtime_error("HTTP/2 and HTTP/3 upstreams require --upstream-server-name");
        if (upstream_ca_certificate_file.has_value() == upstream_insecure)
            throw std::runtime_error("choose exactly one of --upstream-ca-certificate-file or --upstream-insecure for HTTP/2 and HTTP/3 upstreams");
        config.upstream_tls = upstream_security_options{
            .server_name = *upstream_server_name,
            .ca_certificate_file = upstream_ca_certificate_file,
            .insecure_no_verify = upstream_insecure,
        };
    } else if (upstream_server_name || upstream_ca_certificate_file || upstream_insecure) {
        throw std::runtime_error("upstream TLS options are only valid with http2/http3 upstreams");
    }

    return config;
}

[[nodiscard]] auto make_alpn_wire(std::string_view protocol) -> std::vector<unsigned char> {
    if (protocol.empty() || protocol.size() > 255)
        throw std::runtime_error("ALPN identifier must contain between 1 and 255 bytes");

    std::vector<unsigned char> wire;
    wire.reserve(protocol.size() + 1);
    wire.push_back(static_cast<unsigned char>(protocol.size()));
    wire.insert(wire.end(), protocol.begin(), protocol.end());
    return wire;
}

[[nodiscard]] auto make_openssl_error(std::string_view what) -> std::runtime_error {
    auto code = ERR_get_error();
    if (code == 0)
        return std::runtime_error(std::string(what));

    std::array<char, 256> buffer{};
    ERR_error_string_n(code, buffer.data(), buffer.size());
    return std::runtime_error(std::string(what) + ": " + buffer.data());
}

inline void check_openssl(int rc, std::string_view what) {
    if (rc != 1)
        throw make_openssl_error(what);
}

inline auto select_h2_alpn(SSL*,
                           const unsigned char** out,
                           unsigned char* outlen,
                           const unsigned char* in,
                           unsigned int inlen,
                           void* arg) -> int {
    auto* alpn_wire = static_cast<const std::vector<unsigned char>*>(arg);
    if (SSL_select_next_proto(
            const_cast<unsigned char**>(out),
            outlen,
            alpn_wire->data(),
            static_cast<unsigned int>(alpn_wire->size()),
            in,
            inlen) != OPENSSL_NPN_NEGOTIATED)
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    return SSL_TLSEXT_ERR_OK;
}

inline void configure_tls_common(SSL_CTX* context) {
    check_openssl(SSL_CTX_set_min_proto_version(context, TLS1_2_VERSION), "set minimum TLS version");
    SSL_CTX_set_options(context, SSL_OP_NO_COMPRESSION);
}

inline void require_negotiated_alpn(SSL* ssl, std::string_view expected) {
    const unsigned char* selected = nullptr;
    unsigned int selected_size = 0;
    SSL_get0_alpn_selected(ssl, &selected, &selected_size);
    auto negotiated = std::string_view{reinterpret_cast<const char*>(selected), selected_size};
    if (negotiated != expected)
        throw std::runtime_error("TLS negotiated unexpected ALPN '" + std::string(negotiated) + "'");
}

struct h2_server_tls_context {
    explicit h2_server_tls_context(const tls_certificate_files& files)
        : context(asio::ssl::context::tls_server), alpn_wire(make_alpn_wire("h2")) {
        configure_tls_common(context.native_handle());
        context.use_certificate_chain_file(files.certificate_file);
        context.use_private_key_file(files.private_key_file, asio::ssl::context::pem);
        SSL_CTX_set_alpn_select_cb(context.native_handle(), &select_h2_alpn, &alpn_wire);
    }

    asio::ssl::context context;
    std::vector<unsigned char> alpn_wire;
};

struct h2_client_tls_context {
    explicit h2_client_tls_context(const upstream_security_options& options)
        : context(asio::ssl::context::tls_client), alpn_wire(make_alpn_wire("h2")) {
        configure_tls_common(context.native_handle());
        if (options.insecure_no_verify) {
            context.set_verify_mode(asio::ssl::verify_none);
        } else {
            context.set_verify_mode(asio::ssl::verify_peer);
            context.load_verify_file(*options.ca_certificate_file);
        }
        auto rc = SSL_CTX_set_alpn_protos(
            context.native_handle(),
            alpn_wire.data(),
            static_cast<unsigned int>(alpn_wire.size()));
        if (rc != 0)
            throw make_openssl_error("configure HTTP/2 ALPN");
    }

    asio::ssl::context context;
    std::vector<unsigned char> alpn_wire;
};

struct proxy_state {
    proxy_configuration config;
    asio::any_io_executor executor;
    tcp::endpoint listen_endpoint;
    std::optional<tcp::endpoint> upstream_endpoint{};
    std::shared_ptr<h2_server_tls_context> downstream_h2_tls{};
    std::shared_ptr<h2_client_tls_context> upstream_h2_tls{};
    std::shared_ptr<quic_configuration> downstream_h3_configuration{};
    std::shared_ptr<quic_configuration> upstream_h3_configuration{};
    http::cache_store cache;
    http::cookie_jar cookie_jar;
};

class detached_task {
public:
    struct promise_type {
        using handle_type = std::coroutine_handle<promise_type>;

        struct final_awaiter {
            bool await_ready() const noexcept {
                return false;
            }

            void await_suspend(handle_type handle) const noexcept {
                handle.destroy();
            }

            void await_resume() const noexcept {}
        };

        auto get_return_object() noexcept -> detached_task {
            return {};
        }

        auto initial_suspend() noexcept -> std::suspend_never {
            return {};
        }

        auto final_suspend() noexcept -> final_awaiter {
            return {};
        }

        void return_void() const noexcept {}

        void unhandled_exception() const {
            std::terminate();
        }
    };
};

struct http3_pending_request {
    std::int64_t stream_id{0};
    http::request request{};
};

class http3_server_session : public std::enable_shared_from_this<http3_server_session> {
public:
    http3_server_session(asio::any_io_executor executor, quic_connection_transport transport)
        : transport_(std::move(transport)), server_(transport_), request_queue_(executor, "http/3 request queue") {}

    auto start() -> http::task<void> {
        co_await transport_.async_connected();
        co_await server_.handshake(3, 7, 11);
        accept_loop_guarded(shared_from_this());
    }

    auto receive() -> http::task<http3_pending_request> {
        co_return co_await request_queue_.async_pop();
    }

    auto respond(std::int64_t stream_id, http::response response) -> http::task<void> {
        co_await server_.respond(stream_id, std::move(response));
    }

    void shutdown() {
        transport_.shutdown();
    }

    [[nodiscard]] auto remote_address() const -> std::string {
        return transport_.remote_address();
    }

private:
    static auto accept_loop_guarded(std::shared_ptr<http3_server_session> self) -> detached_task {
        try {
            co_await self->accept_loop();
        } catch (...) {
            self->request_queue_.close(std::current_exception());
            self->transport_.shutdown();
        }
    }

    static auto read_stream_guarded(std::shared_ptr<http3_server_session> self, quic_stream stream) -> detached_task {
        try {
            co_await self->read_stream(std::move(stream));
        } catch (...) {
            self->request_queue_.close(std::current_exception());
            self->transport_.shutdown();
        }
    }

    auto accept_loop() -> http::task<void> {
        for (;;) {
            auto stream = co_await transport_.async_accept();
            read_stream_guarded(shared_from_this(), std::move(stream));
        }
    }

    auto read_stream(quic_stream stream) -> http::task<void> {
        auto stream_id = stream.id();
        std::array<std::byte, 16 * 1024> buffer;
        for (;;) {
            auto size = co_await stream.async_read(std::span{buffer});
            if (size == 0) {
                static_cast<void>(server_.feed(stream_id, {}, true));
                queue_ready_requests();
                co_return;
            }
            static_cast<void>(server_.feed(
                stream_id,
                std::span<const std::byte>{buffer.data(), size},
                false));
            queue_ready_requests();
        }
    }

    void queue_ready_requests() {
        while (auto request = server_.last_request()) {
            request_queue_.push(http3_pending_request{
                .stream_id = server_.last_stream_id(),
                .request = std::move(*request),
            });
        }
    }

    quic_connection_transport transport_;
    http::stream<3>::server<quic_connection_transport> server_;
    callback_queue<http3_pending_request> request_queue_;
};

class http3_client_session : public std::enable_shared_from_this<http3_client_session> {
public:
    http3_client_session(quic_connection_transport transport)
        : transport_(std::move(transport)), client_(transport_) {}

    auto start() -> http::task<void> {
        co_await transport_.async_connected();
        co_await client_.handshake(2, 6, 10);
        accept_loop_guarded(shared_from_this());
    }

    auto request(http::request request) -> http::task<http::response> {
        co_return co_await client_.request(std::move(request), 0);
    }

    void shutdown() {
        transport_.shutdown();
    }

private:
    static auto accept_loop_guarded(std::shared_ptr<http3_client_session> self) -> detached_task {
        try {
            co_await self->accept_loop();
        } catch (...) {
            self->transport_.shutdown();
        }
    }

    static auto read_stream_guarded(std::shared_ptr<http3_client_session> self, quic_stream stream) -> detached_task {
        try {
            co_await self->read_stream(std::move(stream));
        } catch (...) {
            self->transport_.shutdown();
        }
    }

    auto accept_loop() -> http::task<void> {
        for (;;) {
            auto stream = co_await transport_.async_accept();
            read_stream_guarded(shared_from_this(), std::move(stream));
        }
    }

    auto read_stream(quic_stream stream) -> http::task<void> {
        auto stream_id = stream.id();
        std::array<std::byte, 16 * 1024> buffer;
        for (;;) {
            auto size = co_await stream.async_read(std::span{buffer});
            if (size == 0) {
                static_cast<void>(client_.feed(stream_id, {}, true));
                drain_pushes();
                co_return;
            }
            static_cast<void>(client_.feed(
                stream_id,
                std::span<const std::byte>{buffer.data(), size},
                false));
            drain_pushes();
        }
    }

    void drain_pushes() {
        while (client_.take_push().has_value()) {
        }
    }

    quic_connection_transport transport_;
    http::stream<3>::client<quic_connection_transport> client_;
};

[[nodiscard]] auto split_tokens(std::string_view value) -> std::vector<std::string> {
    std::vector<std::string> tokens;
    while (!value.empty()) {
        auto comma = value.find(',');
        auto token = comma == std::string_view::npos ? value : value.substr(0, comma);
        while (!token.empty() && token.front() == ' ')
            token.remove_prefix(1);
        while (!token.empty() && token.back() == ' ')
            token.remove_suffix(1);
        if (!token.empty())
            tokens.emplace_back(token);
        if (comma == std::string_view::npos)
            break;
        value.remove_prefix(comma + 1);
    }
    return tokens;
}

void replace_header(http::headers& headers, std::string_view name, std::string value) {
    std::erase_if(headers, [&](const http::header& header) {
        return http::iequal(header.name, name);
    });
    headers.push_back({std::string(name), std::move(value)});
}

void append_header_token(http::headers& headers, std::string_view name, std::string_view value) {
    for (auto& header : headers) {
        if (!http::iequal(header.name, name))
            continue;
        if (!header.value.empty())
            header.value += ", ";
        header.value += value;
        return;
    }
    headers.push_back({std::string(name), std::string(value)});
}

[[nodiscard]] auto wants_connection_close(const http::headers& headers) -> bool {
    auto connection = http::find_header(headers, "connection");
    if (!connection)
        return false;

    auto tokens = split_tokens(*connection);
    return std::any_of(tokens.begin(), tokens.end(), [](const std::string& token) {
        return http::iequal(token, "close");
    });
}

void strip_hop_by_hop_headers(http::headers& headers) {
    std::vector<std::string> transient_names{
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "proxy-connection",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    };

    if (auto connection = http::find_header(headers, "connection")) {
        auto tokens = split_tokens(*connection);
        transient_names.insert(transient_names.end(), tokens.begin(), tokens.end());
    }

    std::erase_if(headers, [&](const http::header& header) {
        return std::any_of(transient_names.begin(), transient_names.end(), [&](const std::string& transient_name) {
            return http::iequal(header.name, transient_name);
        });
    });
}

[[nodiscard]] auto upstream_authority(const proxy_configuration& config) -> std::string {
    return config.upstream_host + ":" + config.upstream_port;
}

[[nodiscard]] auto response_with_text(http::status status_code, std::string text) -> http::response {
    auto bytes = std::as_bytes(std::span{text.data(), text.size()});
    return http::response{
        .status = status_code,
        .reason = {},
        .fields = {{"content-type", "text/plain; charset=utf-8"}},
        .body = {bytes.begin(), bytes.end()},
    };
}

[[nodiscard]] auto lookup_request_cache_control(const http::request& request) -> std::optional<http::cache_control> {
    auto cache_control = http::find_header(request.fields, "cache-control");
    if (!cache_control)
        return std::nullopt;
    return http::parse_cache_control(*cache_control);
}

void store_response_cookies(const http::response& response,
                            const proxy_configuration& config,
                            http::cookie_jar& cookie_jar) {
    for (auto set_cookie : http::find_all_headers(response.fields, "set-cookie")) {
        auto parsed = http::parse_set_cookie(set_cookie);
        if (parsed)
            cookie_jar.store(*parsed, config.upstream_host);
    }
}

void apply_proxy_headers(http::request& upstream_request,
                         std::string_view upstream_authority_value,
                         std::string_view original_authority,
                         std::string_view remote_address,
                         std::string_view forwarded_proto) {
    replace_header(upstream_request.fields, "host", std::string(upstream_authority_value));
    append_header_token(upstream_request.fields, "x-forwarded-for", remote_address);
    replace_header(upstream_request.fields, "x-forwarded-proto", std::string(forwarded_proto));
    if (!original_authority.empty())
        replace_header(upstream_request.fields, "x-forwarded-host", std::string(original_authority));

    auto forwarded = std::string{"for="} + std::string(remote_address) + ";proto=" + std::string(forwarded_proto);
    if (!original_authority.empty())
        forwarded += ";host=" + std::string(original_authority);
    append_header_token(upstream_request.fields, "forwarded", forwarded);
    append_header_token(upstream_request.fields, "via", "1.1 httpant-reverse-proxy");
}

[[nodiscard]] auto canonicalize_request(const http::request& request,
                                        const proxy_configuration& config,
                                        http::cookie_jar& cookie_jar) -> http::request {
    if (request.method == http::method::CONNECT)
        throw std::runtime_error("CONNECT tunneling is not implemented by this example");

    auto path = http::request_path(request);
    if (!path)
        throw std::runtime_error("request path is required for reverse proxying");

    auto upstream_request = request;
    upstream_request.target = std::string(*path);
    upstream_request.scheme = std::string(scheme_for_protocol(config.upstream_protocol));
    upstream_request.authority = upstream_authority(config);
    strip_hop_by_hop_headers(upstream_request.fields);

    auto cookie_header = cookie_jar.match(config.upstream_host, *path);
    if (!cookie_header.empty())
        replace_header(upstream_request.fields, "cookie", std::move(cookie_header));

    return upstream_request;
}

template <typename Socket>
[[nodiscard]] auto remote_address_of(Socket& socket) -> std::string {
    std::error_code error;
    auto endpoint = socket.remote_endpoint(error);
    if (error)
        throw std::system_error(error, "remote endpoint query failed");
    return endpoint.address().to_string();
}

auto build_proxy_state(asio::io_context& io_context, proxy_configuration config) -> http::task<std::shared_ptr<proxy_state>> {
    auto listen_endpoint = co_await async_resolve_first(
        io_context.get_executor(),
        config.listen_host,
        config.listen_port,
        tcp::resolver::passive,
        "listen endpoint resolution failed");

    auto state = std::make_shared<proxy_state>(proxy_state{
        .config = std::move(config),
        .executor = io_context.get_executor(),
        .listen_endpoint = listen_endpoint,
        .upstream_endpoint = std::nullopt,
        .downstream_h2_tls = {},
        .upstream_h2_tls = {},
        .downstream_h3_configuration = {},
        .upstream_h3_configuration = {},
        .cache = {},
        .cookie_jar = {},
    });

    if (state->config.upstream_protocol == proxy_protocol::http1 ||
        state->config.upstream_protocol == proxy_protocol::http2) {
        state->upstream_endpoint = co_await async_resolve_first(
            io_context.get_executor(),
            state->config.upstream_host,
            state->config.upstream_port,
            tcp::resolver::flags{},
            "upstream endpoint resolution failed");
    }

    if (state->config.listen_protocol == proxy_protocol::http2)
        state->downstream_h2_tls = std::make_shared<h2_server_tls_context>(*state->config.downstream_tls);
    if (state->config.upstream_protocol == proxy_protocol::http2)
        state->upstream_h2_tls = std::make_shared<h2_client_tls_context>(*state->config.upstream_tls);

    if (state->config.listen_protocol == proxy_protocol::http3 ||
        state->config.upstream_protocol == proxy_protocol::http3) {
        auto runtime = std::make_shared<quic_runtime>();
        if (state->config.listen_protocol == proxy_protocol::http3) {
            state->downstream_h3_configuration = std::make_shared<quic_configuration>(
                runtime,
                quic_server_credentials{
                    .certificate_file = state->config.downstream_tls->certificate_file,
                    .private_key_file = state->config.downstream_tls->private_key_file,
                });
        }
        if (state->config.upstream_protocol == proxy_protocol::http3) {
            state->upstream_h3_configuration = std::make_shared<quic_configuration>(
                runtime,
                quic_client_credentials{
                    .server_name = state->config.upstream_tls->server_name,
                    .ca_certificate_file = state->config.upstream_tls->ca_certificate_file,
                    .insecure_no_verify = state->config.upstream_tls->insecure_no_verify,
                });
        }
    }

    co_return state;
}

auto fetch_upstream_http1_response(const std::shared_ptr<proxy_state>& state,
                                   http::request request) -> http::task<http::response> {
    tcp::socket upstream_socket{state->executor};
    co_await async_connect(upstream_socket, *state->upstream_endpoint, "upstream connect failed");

    tcp_socket_stream upstream_transport{std::move(upstream_socket)};
    using upstream_client = http::stream<1>::client<tcp_socket_stream>;
    upstream_client client{upstream_transport};
    co_return co_await client.request(std::move(request));
}

auto connect_upstream_h2_transport(const std::shared_ptr<proxy_state>& state) -> http::task<tls_socket_stream> {
    tcp::socket upstream_socket{state->executor};
    co_await async_connect(upstream_socket, *state->upstream_endpoint, "upstream TCP connect failed");

    asio::ssl::stream<tcp::socket> tls_socket{std::move(upstream_socket), state->upstream_h2_tls->context};
    check_openssl(
        SSL_set_tlsext_host_name(tls_socket.native_handle(), state->config.upstream_tls->server_name.c_str()),
        "set TLS server name indication");
    if (!state->config.upstream_tls->insecure_no_verify) {
        tls_socket.set_verify_mode(asio::ssl::verify_peer);
        tls_socket.set_verify_callback(asio::ssl::host_name_verification(state->config.upstream_tls->server_name));
    }

    co_await async_tls_handshake(tls_socket, asio::ssl::stream_base::client, "upstream TLS handshake failed");
    require_negotiated_alpn(tls_socket.native_handle(), "h2");
    co_return tls_socket_stream{std::move(tls_socket)};
}

auto fetch_upstream_http2_response(const std::shared_ptr<proxy_state>& state,
                                   http::request request) -> http::task<http::response> {
    auto upstream_transport = co_await connect_upstream_h2_transport(state);
    using upstream_client = http::stream<2>::client<tls_socket_stream>;
    upstream_client client{upstream_transport};
    co_await client.handshake();
    co_return co_await client.request(std::move(request));
}

auto fetch_upstream_http3_response(const std::shared_ptr<proxy_state>& state,
                                   http::request request) -> http::task<http::response> {
    auto transport = quic_connection_state::connect(
        state->executor,
        state->upstream_h3_configuration,
        state->config.upstream_tls->server_name,
        state->config.upstream_port_number);
    auto session = std::make_shared<http3_client_session>(std::move(transport));

    try {
        co_await session->start();
        auto response = co_await session->request(std::move(request));
        session->shutdown();
        co_return response;
    } catch (...) {
        session->shutdown();
        throw;
    }
}

auto fetch_upstream_response(const std::shared_ptr<proxy_state>& state,
                             http::request request) -> http::task<http::response> {
    switch (state->config.upstream_protocol) {
        case proxy_protocol::http1:
            co_return co_await fetch_upstream_http1_response(state, std::move(request));
        case proxy_protocol::http2:
            co_return co_await fetch_upstream_http2_response(state, std::move(request));
        case proxy_protocol::http3:
            co_return co_await fetch_upstream_http3_response(state, std::move(request));
    }

    throw std::runtime_error("unsupported upstream protocol");
}

auto proxy_request(const std::shared_ptr<proxy_state>& state,
                   const http::request& original_request,
                   std::string_view remote_address) -> http::task<http::response> {
    auto original_authority = http::request_authority(original_request).value_or(std::string_view{});
    auto cacheable_method = original_request.method == http::method::GET ||
                            original_request.method == http::method::HEAD;

    auto& config = state->config;
    auto& cache = state->cache;
    auto& cookie_jar = state->cookie_jar;

    auto cache_key_request = canonicalize_request(original_request, config, cookie_jar);
    auto request_cache_control = lookup_request_cache_control(original_request);
    auto cached_entry = cacheable_method ? cache.lookup(cache_key_request) : std::optional<http::cache_entry>{};
    if (cached_entry && http::is_fresh(*cached_entry))
        co_return cached_entry->stored;

    if (request_cache_control && request_cache_control->has(http::directive::only_if_cached)) {
        if (cached_entry && http::is_fresh(*cached_entry))
            co_return cached_entry->stored;
        co_return response_with_text(504, "cache entry required by only-if-cached is unavailable");
    }

    auto upstream_request = cached_entry ? http::make_conditional(cache_key_request, *cached_entry) : cache_key_request;
    auto forwarded_proto = original_request.scheme.empty()
        ? scheme_for_protocol(config.listen_protocol)
        : std::string_view{original_request.scheme};
    apply_proxy_headers(
        upstream_request,
        upstream_authority(config),
        original_authority,
        remote_address,
        forwarded_proto);

    auto upstream_response = co_await fetch_upstream_response(state, std::move(upstream_request));
    store_response_cookies(upstream_response, config, cookie_jar);

    if (cached_entry && upstream_response.status == 304) {
        auto refreshed = *cached_entry;
        refreshed.request_time = std::chrono::system_clock::now();
        refreshed.response_time = refreshed.request_time;
        cache.store(refreshed);
        co_return refreshed.stored;
    }

    strip_hop_by_hop_headers(upstream_response.fields);
    append_header_token(upstream_response.fields, "via", "1.1 httpant-reverse-proxy");

    if (cacheable_method && http::is_cacheable(upstream_response, cache_key_request)) {
        auto now = std::chrono::system_clock::now();
        cache.store(http::cache_entry{
            .key = cache_key_request,
            .stored = upstream_response,
            .request_time = now,
            .response_time = now,
        });
    }

    co_return upstream_response;
}

auto serve_http1_connection(tcp::socket socket,
                            std::shared_ptr<proxy_state> state) -> http::task<void> {
    auto remote_address = remote_address_of(socket);

    tcp_socket_stream downstream_transport{std::move(socket)};
    using downstream_server = http::stream<1>::server<tcp_socket_stream>;
    downstream_server server{downstream_transport};

    for (;;) {
        http::request request;
        try {
            request = co_await server.receive();
        } catch (const std::exception& error) {
            std::cerr << "downstream HTTP/1 connection closed: " << error.what() << '\n';
            co_return;
        }

        http::response response;
        auto close_after_response = wants_connection_close(request.fields);
        try {
            response = co_await proxy_request(state, request, remote_address);
            close_after_response = close_after_response || wants_connection_close(response.fields);
        } catch (const std::exception& error) {
            std::cerr << "proxy request failed: " << error.what() << '\n';
            response = response_with_text(502, std::string{"upstream failure: "} + error.what());
            close_after_response = true;
        }

        if (close_after_response)
            replace_header(response.fields, "connection", "close");

        co_await server.respond(std::move(response));
        if (close_after_response)
            co_return;
    }
}

auto serve_http1_connection_guarded(tcp::socket socket,
                                    std::shared_ptr<proxy_state> state) -> detached_task {
    try {
        co_await serve_http1_connection(std::move(socket), std::move(state));
    } catch (const std::exception& error) {
        std::cerr << "HTTP/1 connection task failed: " << error.what() << '\n';
    }
}

auto serve_http2_connection(tls_socket_stream transport,
                            std::shared_ptr<proxy_state> state) -> http::task<void> {
    auto remote_address = remote_address_of(transport.lowest_layer());

    using downstream_server = http::stream<2>::server<tls_socket_stream>;
    downstream_server server{transport};
    co_await server.handshake();

    for (;;) {
        http::request request;
        try {
            request = co_await server.receive();
        } catch (const std::exception& error) {
            std::cerr << "downstream HTTP/2 connection closed: " << error.what() << '\n';
            co_return;
        }

        auto stream_id = server.last_stream_id();
        http::response response;
        try {
            response = co_await proxy_request(state, request, remote_address);
        } catch (const std::exception& error) {
            std::cerr << "proxy request failed: " << error.what() << '\n';
            response = response_with_text(502, std::string{"upstream failure: "} + error.what());
        }
        co_await server.respond(stream_id, std::move(response));
    }
}

auto serve_http2_connection_from_socket(tcp::socket socket,
                                        std::shared_ptr<proxy_state> state) -> http::task<void> {
    asio::ssl::stream<tcp::socket> tls_socket{std::move(socket), state->downstream_h2_tls->context};
    co_await async_tls_handshake(tls_socket, asio::ssl::stream_base::server, "downstream TLS handshake failed");
    require_negotiated_alpn(tls_socket.native_handle(), "h2");
    co_await serve_http2_connection(tls_socket_stream{std::move(tls_socket)}, std::move(state));
}

auto serve_http2_connection_from_socket_guarded(tcp::socket socket,
                                                std::shared_ptr<proxy_state> state) -> detached_task {
    try {
        co_await serve_http2_connection_from_socket(std::move(socket), std::move(state));
    } catch (const std::exception& error) {
        std::cerr << "HTTP/2 connection task failed: " << error.what() << '\n';
    }
}

auto serve_http3_connection(quic_connection_transport transport,
                            std::shared_ptr<proxy_state> state) -> http::task<void> {
    auto session = std::make_shared<http3_server_session>(state->executor, std::move(transport));
    co_await session->start();
    auto remote_address = session->remote_address();

    for (;;) {
        http3_pending_request pending;
        try {
            pending = co_await session->receive();
        } catch (const std::exception& error) {
            std::cerr << "downstream HTTP/3 connection closed: " << error.what() << '\n';
            session->shutdown();
            co_return;
        }

        http::response response;
        try {
            response = co_await proxy_request(state, pending.request, remote_address);
        } catch (const std::exception& error) {
            std::cerr << "proxy request failed: " << error.what() << '\n';
            response = response_with_text(502, std::string{"upstream failure: "} + error.what());
        }
        co_await session->respond(pending.stream_id, std::move(response));
    }
}

auto serve_http3_connection_guarded(quic_connection_transport transport,
                                    std::shared_ptr<proxy_state> state) -> detached_task {
    try {
        co_await serve_http3_connection(std::move(transport), std::move(state));
    } catch (const std::exception& error) {
        std::cerr << "HTTP/3 connection task failed: " << error.what() << '\n';
    }
}

auto run_proxy(asio::io_context& io_context,
               proxy_configuration config,
               int& exit_code) -> http::task<void> {
    try {
        auto state = co_await build_proxy_state(io_context, std::move(config));

        std::cerr << "listening on " << protocol_name(state->config.listen_protocol) << "://"
                  << state->config.listen_host << ':' << state->config.listen_port
                  << ", proxying to " << protocol_name(state->config.upstream_protocol) << "://"
                  << state->config.upstream_host << ':' << state->config.upstream_port << '\n';

        switch (state->config.listen_protocol) {
            case proxy_protocol::http1:
            case proxy_protocol::http2: {
                tcp::acceptor acceptor{io_context};
                acceptor.open(state->listen_endpoint.protocol());
                acceptor.set_option(tcp::acceptor::reuse_address(true));
                acceptor.bind(state->listen_endpoint);
                acceptor.listen();

                for (;;) {
                    auto client_socket = co_await async_accept(acceptor, "downstream accept failed");
                    if (state->config.listen_protocol == proxy_protocol::http1)
                        serve_http1_connection_guarded(std::move(client_socket), state);
                    else
                        serve_http2_connection_from_socket_guarded(std::move(client_socket), state);
                }
            }
            case proxy_protocol::http3: {
                quic_listener listener{
                    io_context.get_executor(),
                    state->downstream_h3_configuration,
                    endpoint_to_quic_address(state->listen_endpoint),
                };

                for (;;) {
                    auto connection = co_await listener.async_accept();
                    serve_http3_connection_guarded(std::move(connection), state);
                }
            }
        }
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        exit_code = 1;
        io_context.stop();
    }

    co_return;
}

} // namespace

auto main(int argc, const char** argv) -> int {
    try {
        auto config = parse_arguments(argc, argv);
        asio::io_context io_context{1};
        auto exit_code = 0;
        auto proxy = run_proxy(io_context, std::move(config), exit_code);
        proxy.start();
        io_context.run();
        return exit_code;
    } catch (const std::exception& error) {
        const auto usage = usage_text();
        std::cerr << error.what() << '\n';
        if (std::string_view{error.what()}.find(usage) == std::string_view::npos)
            std::cerr << usage << '\n';
        return 1;
    }
}
