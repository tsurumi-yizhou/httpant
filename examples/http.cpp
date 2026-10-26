import std;
import httpant;
import httpant.io;
import httpant.examples.io;
import httpant.tls;
#ifdef HTTPANT_QUIC
import httpant.quic;
#endif

namespace {
namespace app = httpant::example;
namespace io = http::io::net;
using http::operator co_await;

struct options {
    std::string protocol = "h1";
    std::string mode = "roundtrip";
    std::string certificate, key, ca, server_name = "localhost";
    bool execution = false;
    bool tls = false;
    io::ip::tcp::endpoint address{app::loopback.address(), 8080};
    std::size_t requests = 10;
    std::size_t bytes = 1024;
    std::size_t warmup = 0;
    std::size_t samples = 1;
    std::chrono::seconds timeout{30};
};

void report(std::string_view role, const options& config, std::size_t sample, app::clock::time_point begin,
            std::span<const std::uint64_t> latency = {}) {
    auto seconds = std::chrono::duration<double>(app::clock::now() - begin).count();
    std::string p99 = "null";
    if (!latency.empty()) {
        std::vector<std::uint64_t> sorted(latency.begin(), latency.end());
        std::ranges::sort(sorted);
        p99 = std::to_string(sorted[(sorted.size() * 99 + 99) / 100 - 1]);
    }
    std::println(R"({{"backend":"{}","protocol":"{}","address":"{}","interface":"{}","role":"{}","sample":{},"warmup":{},"requests":{},"payload_bytes":{},"seconds":{:.9f},"requests_per_second":{:.3f},"payload_mib_per_second":{:.3f},"latency_p99_ns":{},"verified":true}})",
        io::io_context::mechanism(), config.protocol, app::host(config.address), config.execution ? "execution" : "coroutine",
        role, sample, config.warmup, config.requests, config.bytes, seconds, double(config.requests) / seconds,
        2.0 * config.requests * config.bytes / (1024 * 1024 * seconds), p99);
}

template<class Server>
auto receive(Server& endpoint, bool execution) -> http::task<typename Server::incoming_request> {
    if (execution)
        co_return co_await http::execution::receive(endpoint);
    co_return co_await http::coroutine::receive(endpoint);
}

template<class Server>
auto serve_endpoint(Server& endpoint, const options& config) -> http::task<void> {
    co_await http::coroutine::scoped(endpoint, [&config](auto& server) -> http::task<void> {
        const auto& stop = co_await http::current_stop_token();
        for (std::size_t sample = 0; sample <= config.samples; ++sample) {
            auto count = sample == 0 ? config.warmup : config.requests;
            auto begin = app::clock::now();
            for (std::size_t i = 0; i < count; ++i) {
                auto incoming = co_await receive(server, config.execution);
                app::require(incoming.head.method == http::method::POST && incoming.head.target == "/echo", "expected POST /echo");
                std::vector<std::byte> bytes;
                std::array<std::byte, 8192> buffer;
                while (auto count = co_await incoming.body.async_read(buffer, stop)) {
                    app::require(count <= config.bytes - bytes.size(), "request body exceeds --bytes");
                    bytes.insert(bytes.end(), buffer.begin(), buffer.begin() + count);
                }
                app::require(bytes.size() == config.bytes, "request body length differs from --bytes");
                http::buffer_body body{std::move(bytes)};
                http::response head{.status = 200, .fields = {
                    {"content-type", "application/octet-stream"},
                    {"content-length", std::to_string(config.bytes)}}};
                if (config.execution)
                    co_await http::execution::respond(server, std::move(incoming.token), std::move(head), body);
                else
                    co_await http::coroutine::respond(server, std::move(incoming.token), std::move(head), body);
            }
            if (sample) report("server", config, sample - 1, begin);
        }
    });
}

template<class Client>
auto fetch_endpoint(Client& endpoint, const options& config) -> http::task<void> {
    co_await http::coroutine::scoped(endpoint, [&config](auto& client) -> http::task<void> {
        std::string payload(config.bytes, 'x');
        for (std::size_t sample = 0; sample <= config.samples; ++sample) {
            auto count = sample == 0 ? config.warmup : config.requests;
            std::vector<std::uint64_t> latency;
            if (sample) latency.reserve(count);
            auto begin = app::clock::now();
            for (std::size_t i = 0; i < count; ++i) {
                payload.front() = static_cast<char>('a' + i % 26);
                http::request head{.method = http::method::POST, .target = "/echo", .scheme = config.tls || config.protocol == "h3" ? "https" : "http", .authority = "localhost"};
                http::fetched response;
                http::fetch_options limit{.body_limit = config.bytes};
                auto sent = app::clock::now();
                if (config.execution)
                    response = co_await http::execution::fetch(client, std::move(head), std::string_view{payload}, limit);
                else
                    response = co_await http::coroutine::fetch(client, std::move(head), std::string_view{payload}, limit);
                auto received = app::clock::now();
                if (sample) latency.push_back(std::chrono::duration_cast<std::chrono::nanoseconds>(received - sent).count());
                app::require(response.head.status == 200 && response.text() == payload, "HTTP echo changed the status or payload");
            }
            if (sample) report("client", config, sample - 1, begin, latency);
        }
    });
}

template<bool H2>
auto serve(io::ip::tcp::socket& socket, const options& config) -> http::task<void> {
    http::stream transport{socket};
    if (config.tls) {
        http::tls::context context{true};
        context.certificate(config.certificate, config.key);
        http::tls::stream secure{transport, context, H2 ? "h2" : "http/1.1"};
        
        co_await secure.handshake(true, H2 ? "h2" : "http/1.1");
        using endpoint_type = std::conditional_t<H2, http::v2::server<decltype(secure)>, http::v1::server<decltype(secure)>>;
        endpoint_type endpoint{secure};
        co_await serve_endpoint(endpoint, config);
        co_await secure.close();
    } else {
        using endpoint_type = std::conditional_t<H2, http::v2::server<decltype(transport)>, http::v1::server<decltype(transport)>>;
        endpoint_type endpoint{transport};
        co_await serve_endpoint(endpoint, config);
    }
}

template<bool H2>
auto fetch(io::ip::tcp::socket& socket, const options& config) -> http::task<void> {
    http::stream transport{socket};
    if (config.tls) {
        http::tls::context context{false};
        context.trust(config.ca);
        http::tls::stream secure{transport, context, H2 ? "h2" : "http/1.1"};
        secure.hostname(config.server_name);
        co_await secure.handshake(false, H2 ? "h2" : "http/1.1");
        using endpoint_type = std::conditional_t<H2, http::v2::client<decltype(secure)>, http::v1::client<decltype(secure)>>;
        endpoint_type endpoint{secure};
        co_await fetch_endpoint(endpoint, config);
        co_await secure.close();
    } else {
        using endpoint_type = std::conditional_t<H2, http::v2::client<decltype(transport)>, http::v1::client<decltype(transport)>>;
        endpoint_type endpoint{transport};
        co_await fetch_endpoint(endpoint, config);
    }
}

#ifdef HTTPANT_QUIC
auto quic_server(http::quic::connection<>& transport, const options& config) -> http::task<void> {
    co_await transport.run([&config](auto& connection) -> http::task<void> {
        http::v3::server endpoint{connection};
        co_await serve_endpoint(endpoint, config);
    });
}
auto quic_client(io::scheduler scheduler, io::ip::tcp::endpoint remote, const options& config) -> http::task<void> {
    http::quic::connection<> transport{scheduler, {remote.address(), 0},
        http::quic::credentials::client(config.ca), {remote.address(), remote.port()}, config.server_name};
    co_await transport.run([&config](auto& connection) -> http::task<void> {
        http::v3::client endpoint{connection};
        co_await fetch_endpoint(endpoint, config);
    });
}
auto quic_application(io::scheduler scheduler, const options& config) -> http::task<void> {
    if (config.mode == "client") {
        co_await quic_client(scheduler, config.address, config);
        co_return;
    }
    auto address = config.address;
    if (config.mode == "roundtrip") address.port(0);
    http::quic::connection<> server{scheduler, {address.address(), address.port()}, http::quic::credentials::server(config.certificate, config.key)};
    std::vector<http::task<void>> tasks;
    tasks.push_back(quic_server(server, config));
    if (config.mode == "roundtrip") {
        address.port(server.port());
        tasks.push_back(quic_client(scheduler, address, config));
    } else {
        std::println(std::cerr, "{} h3 server listening on port {} for {} requests", io::io_context::mechanism(), server.port(), config.requests);
    }
    co_await app::parallel(std::move(tasks));
}
#endif

template<bool H2>
auto accept(io::ip::tcp::acceptor& listener, io::ip::tcp::socket& peer, const options& config) -> http::task<void> {
    peer = co_await stdexec::then(io::async_accept(listener), [](auto socket, auto) { return std::move(socket); });
    co_await serve<H2>(peer, config);
}

template<bool H2>
auto connect(io::ip::tcp::socket& socket, io::ip::tcp::endpoint address, const options& config) -> http::task<void> {
#ifdef __linux__
    if (address.address().is_loopback())
        socket.bind({address.address(), 0});
#endif
    co_await io::async_connect(socket, address);
    co_await fetch<H2>(socket, config);
}

template<bool H2>
auto application(io::scheduler scheduler, const options& config) -> http::task<void> {
    io::ip::tcp::socket peer{scheduler}, client{scheduler};
    if (config.mode == "client") {
        client = io::ip::tcp::socket{scheduler, io::ip::tcp::v4()};
        co_await connect<H2>(client, config.address, config);
    } else {
        auto address = config.address;
        if (config.mode == "roundtrip")
            address.port(0);
        auto listener = io::ip::tcp::acceptor{scheduler, address};
        std::vector<http::task<void>> tasks;
        tasks.push_back(accept<H2>(listener, peer, config));
        if (config.mode == "roundtrip") {
            client = io::ip::tcp::socket{scheduler, io::ip::tcp::v4()};
            address.port(listener.local_endpoint().port());
            tasks.push_back(connect<H2>(client, address, config));
        } else {
            std::println(std::cerr, "{} {} server listening on port {} for {} requests",
                io::io_context::mechanism(), config.protocol, listener.local_endpoint().port(), config.requests);
        }
        co_await app::parallel(std::move(tasks));
    }
}
} // namespace

int main(int argc, char** argv) {
    try {
        options config;
        for (int i = 1; i < argc; ++i) {
            std::string_view option{argv[i]};
            if (option == "--tls") { config.tls = true; continue; }
            if (option == "--help") {
                std::println("Usage: http-example [--mode roundtrip|server|client] [--protocol h1|h2|h3] [--interface coroutine|execution] [--address IPv4:PORT] [--requests N] [--warmup N] [--samples N] [--bytes N] [--timeout-seconds N] [--tls] [--cert PEM --key PEM --ca PEM --server-name NAME]");
                return 0;
            }
            app::require(i + 1 < argc, "missing example argument value");
            std::string_view value{argv[++i]};
            if (option == "--cert") config.certificate = value;
            else if (option == "--key") config.key = value;
            else if (option == "--ca") config.ca = value;
            else if (option == "--server-name") config.server_name = value;
            else if (option == "--protocol") config.protocol = value;
            else if (option == "--mode") config.mode = value;
            else if (option == "--address") config.address = app::parse_endpoint(value);
            else if (option == "--requests") config.requests = app::number(value);
            else if (option == "--warmup") config.warmup = app::number(value, true);
            else if (option == "--samples") config.samples = app::number(value);
            else if (option == "--bytes") config.bytes = app::number(value);
            else if (option == "--timeout-seconds") config.timeout = std::chrono::seconds{app::number(value)};
            else if (option == "--interface") {
                app::require(value == "coroutine" || value == "execution", "unknown example interface");
                config.execution = value == "execution";
            } else throw std::invalid_argument(std::format("unknown example option: {}", option));
        }
        app::require(config.protocol == "h1" || config.protocol == "h2" || config.protocol == "h3", "unknown HTTP protocol");
        app::require(config.mode == "roundtrip" || config.mode == "server" || config.mode == "client", "unknown example mode");
        io::io_context context;
        if (config.protocol == "h3") {
#ifdef HTTPANT_QUIC
            if (config.mode != "client")
                app::require(!config.certificate.empty() && !config.key.empty(), "h3 server requires --cert and --key");
            app::run(context, quic_application(context.get_scheduler(), config), config.timeout);
#else
            throw std::invalid_argument("h3 requires HTTPANT_ENABLE_QUIC=ON");
#endif
        } else if (config.protocol == "h1")
            app::run(context, application<false>(context.get_scheduler(), config), config.timeout);
        else
            app::run(context, application<true>(context.get_scheduler(), config), config.timeout);
        return 0;
    } catch (const std::exception& error) {
        std::println(std::cerr, "native HTTP example: {}", error.what());
        return 1;
    }
}
