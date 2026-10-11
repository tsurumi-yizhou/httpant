import std;
import httpant.dependencies.stdexec;
import httpant;

namespace {
std::atomic<std::size_t> calls{0}, requested_bytes{0}, live_bytes{0};
struct alignas(std::max_align_t) allocation_header { std::size_t size; };
}
void* operator new(std::size_t n) {
    auto* raw = static_cast<allocation_header*>(std::malloc(sizeof(allocation_header) + (n ? n : 1)));
    if (!raw) throw std::bad_alloc{};
    raw->size = n;
    ++calls;
    requested_bytes += n;
    live_bytes += n;
    return raw + 1;
}
void* operator new[](std::size_t n) { return ::operator new(n); }
void operator delete(void* p) noexcept {
    if (!p) return;
    auto* raw = static_cast<allocation_header*>(p) - 1;
    live_bytes -= raw->size;
    std::free(raw);
}
void operator delete(void* p, std::size_t) noexcept { ::operator delete(p); }
void operator delete[](void* p) noexcept { ::operator delete(p); }
void operator delete[](void* p, std::size_t) noexcept { ::operator delete(p); }

namespace {
using http::operator co_await;
std::size_t consumed = 0;
struct inline_sender {
    using sender_concept = stdexec::sender_tag;
    using completion_signatures = stdexec::completion_signatures<stdexec::set_value_t(int)>;
    template <typename R> struct operation {
        using operation_state_concept = stdexec::operation_state_tag;
        R receiver;
        void start() noexcept { stdexec::set_value(std::move(receiver), 42); }
    };
    template <typename R> auto connect(R r) && -> operation<R> { return {std::move(r)}; }
};
struct stop_sender {
    using sender_concept = stdexec::sender_tag;
    using completion_signatures = stdexec::completion_signatures<stdexec::set_value_t(), stdexec::set_stopped_t()>;
    template <typename R> struct operation {
        using operation_state_concept = stdexec::operation_state_tag;
        R receiver;
        void start() noexcept { stdexec::set_stopped(std::move(receiver)); }
    };
    template <typename R> auto connect(R r) && -> operation<R> { return {std::move(r)}; }
};
struct pending_sender {
    using sender_concept = stdexec::sender_tag;
    using completion_signatures = stdexec::completion_signatures<stdexec::set_value_t(int), stdexec::set_stopped_t()>;
    template <typename R> struct operation {
        using operation_state_concept = stdexec::operation_state_tag;
        struct cancel {
            operation* self;
            void operator()() const noexcept { stdexec::set_stopped(std::move(self->receiver)); }
        };
        R receiver;
        std::optional<std::stop_callback<cancel>> callback;
        void start() noexcept {
            callback.emplace(stdexec::get_stop_token(stdexec::get_env(receiver)), cancel{this});
        }
    };
    template <typename R> auto connect(R r) && -> operation<R> { return {std::move(r), {}}; }
};
auto pending() -> http::task<int> { co_return co_await pending_sender{}; }
auto normal() -> http::task<int> { co_return co_await inline_sender{}; }
auto level3() -> http::task<void> { co_await stop_sender{}; }
auto level2() -> http::task<void> { co_await level3(); }
auto level1() -> http::task<void> { co_await level2(); }
auto stop_chain() -> http::task<int> {
    try { co_await level1(); } catch (const http::stopped&) { co_return 1; }
    co_return 0;
}
template <typename Token> struct receiver {
    using receiver_concept = stdexec::receiver_t;
    Token token;
    auto get_env() const noexcept { return stdexec::prop{stdexec::get_stop_token, token}; }
    void set_value(int value) noexcept { consumed += value; }
    void set_value(http::fetched&& result) noexcept {
        if (result.head.status != 200 || result.text() != "hello") std::abort();
        consumed += result.text().size();
    }
    void set_error(std::exception_ptr) noexcept { std::abort(); }
    void set_stopped() noexcept { ++consumed; }
};
template <typename Token, typename Factory> void invoke(Token token, Factory factory) {
    auto operation = stdexec::connect(http::defer(factory), receiver<Token>{token});
    stdexec::start(operation);
}
struct memory_stream {
    std::string_view input{"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"};
    struct read {
        memory_stream* stream;
        std::span<std::byte> buffer;
        bool await_ready() const noexcept { return true; }
        void await_suspend(std::coroutine_handle<>) const noexcept {}
        auto await_resume() -> std::size_t {
            auto n = std::min(buffer.size(), stream->input.size());
            if (n) std::memcpy(buffer.data(), stream->input.data(), n);
            stream->input.remove_prefix(n);
            return n;
        }
    };
    struct write {
        std::size_t size;
        bool await_ready() const noexcept { return true; }
        void await_suspend(std::coroutine_handle<>) const noexcept {}
        auto await_resume() const noexcept -> std::size_t { return size; }
    };
    auto async_read(std::span<std::byte> bytes, std::stop_token) -> read { return {this, bytes}; }
    auto async_write(std::span<const std::byte> bytes, std::stop_token) -> write { return {bytes.size()}; }
};
void http1() {
    memory_stream stream;
    auto operation = stdexec::connect(http::execution::fetch<http::protocol_version::http1>(
        stream, http::request{.target = "/", .scheme = "http", .authority = "localhost"}),
        receiver<std::stop_token>{});
    stdexec::start(operation);
}
template <typename F> void measure(std::string_view mode, std::size_t n, F operation) {
    auto cold_calls = calls.load(), cold_bytes = requested_bytes.load(), cold_live = live_bytes.load();
    auto begin = std::chrono::steady_clock::now();
    operation();
    auto end = std::chrono::steady_clock::now();
    auto cc = calls.load() - cold_calls, cb = requested_bytes.load() - cold_bytes;
    auto retained = live_bytes.load() - cold_live;
    auto cold_ns = std::chrono::duration<double, std::nano>(end - begin).count();
    for (int i = 0; i < 1000; ++i) operation();
    auto warm_calls = calls.load(), warm_bytes = requested_bytes.load(), warm_live = live_bytes.load();
    begin = std::chrono::steady_clock::now();
    for (std::size_t i = 0; i < n; ++i) operation();
    end = std::chrono::steady_clock::now();
    auto wc = calls.load() - warm_calls, wb = requested_bytes.load() - warm_bytes;
    auto delta = live_bytes.load() - warm_live;
    auto warm_ns = std::chrono::duration<double, std::nano>(end - begin).count() / n;
    std::println("{},cold_ns={:.1f},cold_new={},cold_bytes={},cold_retained={},warm_ns={:.1f},warm_new={:.6f},warm_bytes={:.3f},warm_live_delta={},consumed={}",
        mode, cold_ns, cc, cb, retained, warm_ns, double(wc)/n, double(wb)/n, delta, consumed);
}
}
int main(int argc, char** argv) {
    std::string_view mode = argc > 1 ? argv[1] : "await";
    std::size_t n = argc > 2 ? std::stoul(argv[2]) : 100000;
    if (mode == "http1") measure(mode, n, [] { http1(); });
    else if (mode == "await") measure(mode, n, [] { invoke(std::stop_token{}, normal); });
    else if (mode == "std") {
        std::stop_source source;
        measure(mode, n, [&] { invoke(source.get_token(), normal); });
    } else if (mode == "inplace") {
        stdexec::inplace_stop_source source;
        measure(mode, n, [&] { invoke(source.get_token(), normal); });
    } else if (mode == "prestop") {
        stdexec::inplace_stop_source source;
        source.request_stop();
        measure(mode, n, [&] { invoke(source.get_token(), normal); });
    } else if (mode == "stop") measure(mode, n, [] { invoke(std::stop_token{}, stop_chain); });
    else if (mode == "cancel") measure(mode, n, [] {
        stdexec::inplace_stop_source source;
        auto operation = stdexec::connect(http::defer(pending),
            receiver<stdexec::inplace_stop_token>{source.get_token()});
        stdexec::start(operation);
        source.request_stop();
    });
    else return 1;
}
