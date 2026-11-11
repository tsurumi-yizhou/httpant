import std;
import httpant;
import httpant.io;
import httpant.examples.io;

namespace {
namespace app = httpant::example;
namespace io = http::io::net;
using http::operator co_await;
using clock_type = std::chrono::steady_clock;

struct options {
    std::string scenario = "all";
    io::ip::tcp::endpoint address = app::loopback;
    std::filesystem::path directory;
    std::size_t iterations = 1000;
    std::size_t warmup = 100;
    std::size_t concurrency = 1;
    std::size_t bytes = 1024;
    std::size_t samples = 3;
    double seconds = 0;
    std::chrono::microseconds timer{1000};
    std::chrono::seconds timeout{30};
};

struct lane {
    io::ip::tcp::socket client, peer;
    explicit lane(io::scheduler s) : client(s), peer(s), udp_client(s), udp_peer(s) {}
    io::ip::udp::socket udp_client, udp_peer;
    std::optional<io::file> file;
    std::filesystem::path path;
    std::vector<std::byte> sent, received, echoed;
    std::vector<double> latency;
    std::vector<double> lateness;
    ~lane() {
        file.reset();
        if (!path.empty()) {
            std::error_code ignored;
            std::filesystem::remove(path, ignored);
        }
    }
};

auto setup(io::scheduler scheduler, lane& state, std::string_view scenario, io::ip::tcp::endpoint address) -> http::task<void> {
    if (scenario == "tcp") {
        auto listener = io::ip::tcp::acceptor{scheduler, address};
        state.client = io::ip::tcp::socket{scheduler, io::ip::tcp::v4()};
#ifdef __linux__
        state.client.bind({address.address(), 0});
#endif
        auto [peer, endpoint] = co_await stdexec::when_all(
            io::async_connect(state.client, {address.address(), listener.local_endpoint().port()}),
            io::async_accept(listener));
        state.peer = std::move(peer);
    } else if (scenario == "udp") {
        state.udp_client = io::ip::udp::socket{scheduler, io::ip::udp::endpoint{address.address(), address.port()}};
        state.udp_peer = io::ip::udp::socket{scheduler, io::ip::udp::endpoint{address.address(), address.port()}};
        state.udp_client.connect({address.address(), state.udp_peer.local_endpoint().port()});
        state.udp_peer.connect({address.address(), state.udp_client.local_endpoint().port()});
    } else if (scenario == "file") {
        state.file.emplace(scheduler.open_file(state.path, true));
    }
}

auto echo(lane& state, std::string_view scenario, std::size_t count) -> http::task<void> {
    for (std::size_t i = 0; i < count; ++i) {
        if (scenario == "tcp") {
            co_await io::async_read(state.peer, state.received);
            co_await io::async_write(state.peer, state.received);
        } else {
            auto received = co_await io::async_receive(state.udp_peer, io::buffer(state.received));
            app::require(received == state.received.size(), "UDP echo received an incomplete datagram");
            auto written = co_await io::async_send(state.udp_peer, io::buffer(state.received));
            app::require(written == received, "UDP echo sent an incomplete datagram");
        }
    }
}

auto file_roundtrip(lane& state) -> http::task<void> {
    std::size_t offset = 0;
    while (offset != state.sent.size()) {
        auto count = co_await io::async_write_at(*state.file, std::span{state.sent}.subspan(offset), offset);
        app::require(count && count <= state.sent.size() - offset, "file write made invalid progress");
        offset += count;
    }
    offset = 0;
    while (offset != state.echoed.size()) {
        auto count = co_await io::async_read_at(*state.file, std::span{state.echoed}.subspan(offset), offset);
        app::require(count && count <= state.echoed.size() - offset, "file read made invalid progress");
        offset += count;
    }
}

auto client(io::scheduler scheduler, lane& state, std::string_view scenario,
            std::size_t count, bool measured, std::chrono::microseconds timer) -> http::task<void> {
    for (std::size_t i = 0; i < count; ++i) {
        auto begin = clock_type::now();
        auto deadline = begin + timer;
        if (scenario == "post") {
            co_await scheduler.schedule();
        } else if (scenario == "timer") {
            co_await scheduler.schedule_at(deadline);
        } else if (scenario == "tcp") {
            co_await io::async_write(state.client, state.sent);
            co_await io::async_read(state.client, state.echoed);
        } else if (scenario == "udp") {
            auto sent = co_await io::async_send(state.udp_client, io::buffer(state.sent));
            auto received = co_await io::async_receive(state.udp_client, io::buffer(state.echoed));
            app::require(sent == state.sent.size() && received == state.echoed.size(), "UDP round trip lost datagram bytes");
        } else {
            co_await file_roundtrip(state);
        }
        auto end = clock_type::now();
        if (scenario != "post" && scenario != "timer")
            app::require(state.sent == state.echoed, "native round trip changed the payload");
        if (measured) {
            state.latency.push_back(std::chrono::duration<double, std::nano>(end - begin).count());
            if (scenario == "timer")
                state.lateness.push_back(std::chrono::duration<double, std::nano>(end - deadline).count());
        }
    }
}

auto workload(io::scheduler scheduler, std::vector<std::unique_ptr<lane>>& lanes,
              std::string_view scenario, std::size_t iterations, bool measured,
              std::chrono::microseconds timer, double& seconds) -> http::task<void> {
    std::vector<http::task<void>> tasks;
    for (auto& state : lanes) {
        if (scenario == "tcp" || scenario == "udp")
            tasks.push_back(echo(*state, scenario, iterations));
        tasks.push_back(client(scheduler, *state, scenario, iterations, measured, timer));
    }
    auto begin = clock_type::now();
    co_await app::parallel(std::move(tasks));
    seconds = std::chrono::duration<double>(clock_type::now() - begin).count();
}

auto percentile(const std::vector<double>& sorted, double fraction) -> double {
    if (sorted.empty())
        return 0;
    auto index = static_cast<std::size_t>(std::ceil(fraction * sorted.size()));
    return sorted[std::min(sorted.size(), std::max(std::size_t{1}, index)) - 1];
}

void benchmark(const options& config, std::string_view scenario) {
    app::require(scenario != "udp" || config.bytes <= 65507, "UDP payload exceeds the IPv4 datagram limit");
    io::io_context context;
    auto scheduler = context.get_scheduler();
    std::vector<std::unique_ptr<lane>> lanes;
    auto fixture = std::to_string(clock_type::now().time_since_epoch().count());
    std::vector<http::task<void>> setup_tasks;
    for (std::size_t i = 0; i < config.concurrency; ++i) {
        auto state = std::make_unique<lane>(scheduler);
        if (scenario != "post" && scenario != "timer") {
            state->sent.assign(config.bytes, std::byte{static_cast<unsigned char>(i % 251 + 1)});
            state->received.resize(config.bytes);
            state->echoed.resize(config.bytes);
        }
        state->latency.reserve(config.iterations);
        if (scenario == "timer")
            state->lateness.reserve(config.iterations);
        if (scenario == "file")
            state->path = config.directory / std::format("io-{}-{}.dat", fixture, i);
        setup_tasks.push_back(setup(scheduler, *state, scenario, config.address));
        lanes.push_back(std::move(state));
    }
    app::run(context, app::parallel(std::move(setup_tasks)), config.timeout);
    auto iterations = config.iterations;
    if (config.seconds > 0) {
        double elapsed = 0;
        app::run(context, workload(scheduler, lanes, scenario, iterations, false, config.timer, elapsed), config.timeout);
        auto estimate = std::ceil(double(iterations) * config.seconds * 1.1 / std::max(elapsed, 1e-9));
        app::require(estimate < double(std::numeric_limits<std::size_t>::max() / config.concurrency), "sample duration requires too many iterations");
        iterations = std::max(iterations, static_cast<std::size_t>(estimate));
        for (auto& state : lanes) {
            state->latency.reserve(iterations);
            if (scenario == "timer") state->lateness.reserve(iterations);
        }
    }
    for (std::size_t sample = 0; sample < config.samples; ++sample) {
        double ignored = 0, seconds = 0;
        if (config.warmup)
            app::run(context, workload(scheduler, lanes, scenario, config.warmup, false, config.timer, ignored), config.timeout);
        for (auto& state : lanes) {
            state->latency.clear();
            state->lateness.clear();
        }
        app::run(context, workload(scheduler, lanes, scenario, iterations, true, config.timer, seconds), config.timeout);
        std::vector<double> latencies, lateness;
        for (auto& state : lanes) {
            latencies.insert(latencies.end(), state->latency.begin(), state->latency.end());
            lateness.insert(lateness.end(), state->lateness.begin(), state->lateness.end());
        }
        std::ranges::sort(latencies);
        std::ranges::sort(lateness);
        auto operations = iterations * config.concurrency;
        app::require(latencies.size() == operations, "benchmark completion count mismatch");
        auto payload = scenario == "post" || scenario == "timer" ? 0 : config.bytes;
        auto mib = double(operations) * double(payload) * 2 / (1024 * 1024);
        std::println(R"({{"backend":"{}","scenario":"{}","address":"{}","build":"{}","compiler":"{}","sample":{},"iterations_per_lane":{},"warmup_per_lane":{},"concurrency":{},"payload_bytes":{},"directory":{:?},"timer_us":{},"operations":{},"seconds":{:.9f},"operations_per_second":{:.3f},"payload_mib_per_second":{:.3f},"latency_p50_ns":{:.1f},"latency_p95_ns":{:.1f},"latency_p99_ns":{:.1f},"latency_max_ns":{:.1f},"timer_lateness_p99_ns":{:.1f}}})",
            context.mechanism(), scenario, app::host(config.address), BENCH_BUILD, BENCH_COMPILER,
            sample, iterations, config.warmup, config.concurrency, payload, config.directory.string(),
            scenario == "timer" ? config.timer.count() : 0, operations, seconds,
            double(operations) / seconds, mib / seconds, percentile(latencies, .5),
            percentile(latencies, .95), percentile(latencies, .99), latencies.back(), percentile(lateness, .99));
    }
}
} // namespace

int main(int argc, char** argv) {
    try {
        options config;
        for (int i = 1; i < argc; ++i) {
            std::string_view option{argv[i]};
            if (option == "--help") {
                std::println("Usage: io-bench --directory EXISTING_DATA_DIR [--scenario all|post|timer|tcp|udp|file] [--address IPv4] [--iterations N] [--warmup N] [--concurrency N] [--bytes N] [--samples N] [--seconds N] [--timer-us N] [--timeout-seconds N]");
                return 0;
            }
            app::require(i + 1 < argc, "missing benchmark argument value");
            std::string_view value{argv[++i]};
            if (option == "--address") config.address = app::parse_endpoint(value, 0);
            else if (option == "--scenario") config.scenario = value;
            else if (option == "--directory") config.directory = std::filesystem::path{
                std::u8string_view{reinterpret_cast<const char8_t*>(value.data()), value.size()}};
            else if (option == "--iterations") config.iterations = app::number(value);
            else if (option == "--warmup") config.warmup = app::number(value, true);
            else if (option == "--concurrency") config.concurrency = app::number(value);
            else if (option == "--bytes") config.bytes = app::number(value);
            else if (option == "--seconds") {
                auto [end, error] = std::from_chars(value.data(), value.data() + value.size(), config.seconds);
                app::require(error == std::errc{} && end == value.data() + value.size() && std::isfinite(config.seconds) && config.seconds > 0, "invalid sample duration");
            }
            else if (option == "--samples") config.samples = app::number(value);
            else if (option == "--timer-us") config.timer = std::chrono::microseconds{app::number(value)};
            else if (option == "--timeout-seconds") config.timeout = std::chrono::seconds{app::number(value)};
            else throw std::invalid_argument(std::format("unknown benchmark option: {}", option));
        }
        app::require(config.concurrency <= std::numeric_limits<std::size_t>::max() / config.iterations, "operation count overflow");
#ifdef _WIN32
        app::require(config.directory.root_name().native().size() == 2 && config.directory.root_name().native()[1] == L':',
                     "Windows benchmark data must use a local drive path");
#endif
        app::require(std::filesystem::is_directory(config.directory), "--directory must name an existing data directory");
        bool found = false;
        for (std::string_view scenario : {"post", "timer", "tcp", "udp", "file"}) {
            if (config.scenario == "all" || config.scenario == scenario) {
                benchmark(config, scenario);
                found = true;
            }
        }
        app::require(found, "unknown benchmark scenario");
        return 0;
    } catch (const std::exception& error) {
        std::println(std::cerr, "native benchmark: {}", error.what());
        return 1;
    }
}
