import std;
import httpant.io;

// This executable links only httpant::io. No HTTP protocol module or coroutine
// stack participates in these sender-based networking and lifetime checks.
namespace {
using namespace std::chrono_literals;
namespace io = http::io::net;

void require(bool condition, std::string_view message) {
    if (!condition)
        throw std::runtime_error(std::string{message});
}

template <class... T> using values = std::tuple<std::decay_t<T>...>;
template <class T> using one_signature = T;

template <class Sender> struct outcome {
    using tuple = stdexec::value_types_of_t<Sender, decltype(stdexec::prop{stdexec::get_stop_token, std::stop_token{}}), values, one_signature>;
    std::optional<tuple> value;
    std::error_code error;
    std::exception_ptr exception;
    bool stopped = false;
    int completions = 0;
};

template <class Sender> struct receiver {
    using receiver_concept = stdexec::receiver_t;
    io::io_context* context;
    outcome<Sender>* result;
    std::stop_token stop;
    auto get_env() const noexcept { return stdexec::prop{stdexec::get_stop_token, stop}; }
    template <class... T> void set_value(T&&... value) noexcept {
        try {
            result->value.emplace(std::forward<T>(value)...);
        } catch (...) {
            result->exception = std::current_exception();
        }
        ++result->completions;
        context->stop();
    }
    void set_error(std::error_code error) noexcept {
        result->error = error;
        ++result->completions;
        context->stop();
    }
    void set_error(std::exception_ptr error) noexcept {
        result->exception = std::move(error);
        ++result->completions;
        context->stop();
    }
    void set_error(const io::closed& error) noexcept { set_error(error.code()); }
    void set_stopped() noexcept {
        result->stopped = true;
        ++result->completions;
        context->stop();
    }
};

template <class Sender>
auto run(io::io_context& context, Sender sender, std::stop_token stop = {}) -> outcome<Sender> {
    outcome<Sender> result;
    auto state = stdexec::connect(std::move(sender), receiver<Sender>{&context, &result, stop});
    stdexec::start(state);
    context.run();
    require(result.completions == 1, "native sender must complete exactly once");
    return result;
}

template <class Sender> void success(const outcome<Sender>& result) {
    if (result.exception)
        std::rethrow_exception(result.exception);
    if (result.error)
        throw std::system_error(result.error);
    require(result.value.has_value() && !result.stopped, "expected value completion");
}

template <class Sender> using errors = stdexec::error_types_of_t<Sender, stdexec::env<>, std::tuple>;
template <class Sender> constexpr bool network_errors = std::same_as<errors<Sender>, std::tuple<std::error_code>>;
using stream_type = io::ip::tcp::socket;
using datagram_type = io::ip::udp::socket;
using acceptor_type = io::ip::tcp::acceptor;
static_assert(stdexec::scheduler<io::io_context::scheduler_type>);
static_assert(std::same_as<io::ip::tcp::endpoint, io::ip::basic_endpoint<io::ip::tcp>>);
static_assert(std::same_as<io::ip::udp::endpoint, io::ip::basic_endpoint<io::ip::udp>>);
static_assert(network_errors<decltype(io::async_accept(std::declval<acceptor_type&>()))>);
static_assert(network_errors<decltype(io::async_connect(stdexec::just(io::ip::tcp::endpoint{}), std::declval<stream_type&>()))>);
static_assert(network_errors<decltype(stdexec::just() | io::async_accept(std::declval<acceptor_type&>()))>);
static_assert(network_errors<decltype(stdexec::just(io::mutable_buffer{}) | io::async_read_some(std::declval<stream_type&>()))>);
static_assert(network_errors<decltype(stdexec::just(io::const_buffer{}) | io::async_write_some(std::declval<stream_type&>()))>);
static_assert(network_errors<decltype(io::async_receive(stdexec::just(0, io::mutable_buffer{}), std::declval<datagram_type&>()))>);
static_assert(network_errors<decltype(io::async_send(stdexec::just(0, io::const_buffer{}), std::declval<datagram_type&>()))>);
static_assert(network_errors<decltype(io::async_receive_from(stdexec::just(0, io::mutable_buffer{}, io::ip::udp::endpoint{}), std::declval<datagram_type&>()))>);
static_assert(network_errors<decltype(io::async_send_to(stdexec::just(0, io::const_buffer{}, io::ip::udp::endpoint{}), std::declval<datagram_type&>()))>);
static_assert(network_errors<decltype(stdexec::just(io::socket_base::wait_write) | io::async_wait(std::declval<stream_type&>()))>);

void address_types() {
    auto v4 = io::ip::make_address("127.2.3.4");
    require(v4.is_v4() && v4.to_v4().to_uint() == 0x7f020304, "IPv4 address bytes");
    require(v4.to_string() == "127.2.3.4", "IPv4 formatting");
    auto v6 = io::ip::make_address("::1");
    require(v6.is_v6() && v6.is_loopback(), "IPv6 loopback");
    require(io::ip::make_address(v6.to_string()) == v6, "IPv6 address round trip");
    auto scoped = io::ip::make_address_v6("fe80::1%7");
    require(scoped.scope_id() == 7 && io::ip::make_address_v6(scoped.to_string()) == scoped, "IPv6 scope round trip");
    std::error_code error = std::make_error_code(std::errc::io_error);
    require(io::ip::make_address("::1", error) == v6 && !error, "address parsing clears an error");
    static_cast<void>(io::ip::make_address_v4("::1", error));
    require(error == std::errc::invalid_argument, "IPv4 parsing reports invalid text");
    static_cast<void>(io::ip::make_address_v6("fe80::1%bad", error));
    require(error == std::errc::invalid_argument, "IPv6 parsing reports invalid scope");
    static_cast<void>(io::ip::make_address("", error));
    require(error == std::errc::invalid_argument, "address parsing reports empty text");
    bool threw = false;
    try { static_cast<void>(io::ip::make_address("invalid")); }
    catch (const std::system_error& e) { threw = e.code() == std::errc::invalid_argument; }
    require(threw, "address parsing throws system_error");
    io::ip::tcp::endpoint ep{v6, 1234};
    require(ep.address() == v6 && ep.port() == 1234 && ep.protocol() == io::ip::tcp::v6(), "IPv6 endpoint");
    ep.port(4321); ep.address(v4);
    require(ep.address() == v4 && ep.port() == 4321 && ep.protocol() == io::ip::tcp::v4(), "endpoint setters");
    std::array<int, 4> storage{};
    auto bytes = io::buffer(storage);
    io::const_buffer immutable = bytes;
    require(bytes.size() == sizeof storage && immutable.data() == storage.data(), "TS buffers use byte sizes");
    require((bytes + 5).size() == sizeof storage - 5 && (immutable + 100).size() == 0, "TS buffer offset");
    require(io::buffer_sequence_end(bytes) - io::buffer_sequence_begin(bytes) == 1, "single-buffer sequence");
}

struct failed_input {
    using sender_concept = stdexec::sender_t;
    using completion_signatures = stdexec::completion_signatures<stdexec::set_value_t(io::mutable_buffer), stdexec::set_error_t(std::error_code), stdexec::set_stopped_t()>;
    bool stopped;
    template <class R> struct operation {
        using operation_state_concept = stdexec::operation_state_t;
        R receiver;
        bool stopped;
        void start() & noexcept {
            if (stopped) stdexec::set_stopped(std::move(receiver));
            else stdexec::set_error(std::move(receiver), std::make_error_code(std::errc::permission_denied));
        }
    };
    template <class R> auto connect(R receiver) const noexcept -> operation<R> { return {std::move(receiver), stopped}; }
};

template <class T> struct full {
    auto push(T) noexcept -> bool { return false; }
    auto try_pop(T&) noexcept -> bool { return false; }
};

void scheduler_and_input(io::io_context& context) {
    io::basic_io_context<http::queues::local> other;
    io::ip::udp::socket socket{context, io::ip::udp::endpoint{io::ip::address_v4::loopback(), 0}};
    std::array<std::byte, 1> bytes;
    auto mismatch = run(context, stdexec::write_env(io::async_receive(socket, io::buffer(bytes)),
        stdexec::prop{stdexec::get_start_scheduler, other.get_scheduler()}));
    require(mismatch.error == std::errc::invalid_argument, "a different I/O scheduler must report invalid_argument");
    auto adapted = run(context, stdexec::write_env(stdexec::just(io::buffer(bytes)) | io::async_receive(socket),
        stdexec::prop{stdexec::get_start_scheduler, other.get_scheduler()}));
    require(adapted.error == std::errc::invalid_argument, "adapted operations must check the receiver scheduler");
    auto denied = run(context, failed_input{false} | io::async_receive(socket));
    require(denied.error == std::errc::permission_denied, "upstream errors must be forwarded");
    auto stopped = run(context, failed_input{true} | io::async_receive(socket));
    require(stopped.stopped, "upstream stopped must be forwarded");
    std::stop_source stop; stop.request_stop();
    auto cancelled = run(context, io::async_receive(socket, io::buffer(bytes)), stop.get_token());
    require(cancelled.stopped, "a pre-stopped network operation must complete as stopped");
    io::basic_io_context<full> saturated;
    auto refused = run(context, saturated.get_scheduler().schedule());
    require(refused.error == std::errc::no_buffer_space, "full queue must report an error");
    auto refused_stop = run(context, saturated.get_scheduler().schedule(), stop.get_token());
    require(refused_stop.error == std::errc::no_buffer_space && !refused_stop.stopped,
            "a rejected submission must report its error on the submitting thread");
}

void ipv6(io::io_context& context) {
    io::ip::tcp::acceptor acceptor{context};
    acceptor.open(io::ip::tcp::v6());
    acceptor.set_option(io::socket_base::reuse_address{true});
    acceptor.bind({io::ip::address_v6::loopback(), 0}); acceptor.listen();
    io::ip::tcp::socket client{context, io::ip::tcp::v6()};
    client.set_option(io::ip::tcp::no_delay{true});
    auto connected = run(context, stdexec::when_all(
        io::async_connect(client, acceptor.local_endpoint()), stdexec::just() | io::async_accept(acceptor)));
    success(connected);
    auto [peer, remote] = std::move(*connected.value);
    require(remote.address().is_v6() && remote == client.local_endpoint(), "IPv6 accept returns the peer endpoint");
    require(peer.remote_endpoint() == client.local_endpoint() && client.remote_endpoint() == acceptor.local_endpoint(), "IPv6 TCP endpoints");
    auto writable = run(context, stdexec::just(io::socket_base::wait_write) | io::async_wait(client));
    success(writable);
    require(std::get<0>(*writable.value) == io::socket_base::wait_write, "socket wait must report write readiness");
    std::array<std::byte, 4> sent{std::byte{1}, std::byte{2}, std::byte{3}, std::byte{4}}, received{};
    success(run(context, io::async_write(client, sent)));
    auto readable = run(context, io::async_wait(peer, io::socket_base::wait_read));
    success(readable);
    require(std::get<0>(*readable.value) == io::socket_base::wait_read, "socket wait must report read readiness");
    auto waits = run(context, stdexec::when_all(io::async_wait(peer, io::socket_base::wait_read), io::async_wait(peer, io::socket_base::wait_write)));
    success(waits);
    require(std::get<0>(*waits.value) == io::socket_base::wait_read && std::get<1>(*waits.value) == io::socket_base::wait_write,
            "concurrent waits must use their own requested bits");
    auto both = io::socket_base::wait_read | io::socket_base::wait_write;
    auto combined = run(context, io::async_wait(peer, both));
    success(combined);
    require(std::get<0>(*combined.value) == both, "a combined wait must report all ready requested bits");
    for (auto events : {io::socket_base::wait_error, static_cast<io::socket_base::wait_type>(0)}) {
        std::stop_source stop;
        auto cancel = stdexec::then(context.get_scheduler().schedule_after(2ms), [&] { stop.request_stop(); });
        auto waiting = run(context, stdexec::when_all(io::async_wait(peer, events), std::move(cancel)), stop.get_token());
        require(waiting.stopped, "an error-only wait must ignore queued input and stop on cancellation");
    }
    auto peeked = run(context, io::async_receive(peer, io::socket_base::message_peek, io::buffer(received)));
    success(peeked);
    success(run(context, io::async_read(peer, received)));
    require(sent == received, "IPv6 stream peek must retain input");

    io::ip::udp::socket first{context, io::ip::udp::endpoint{io::ip::address_v6::loopback(), 0}};
    io::ip::udp::socket second{context, io::ip::udp::endpoint{io::ip::address_v6::loopback(), 0}};
    io::ip::udp::endpoint hint;
    auto transfer = run(context, stdexec::when_all(
        stdexec::just(0, io::buffer(received), hint) | io::async_receive_from(second),
        stdexec::just(0, io::const_buffer{io::buffer(sent)}, second.local_endpoint()) | io::async_send_to(first)));
    success(transfer);
    auto [count, source, written] = *transfer.value;
    require(count == sent.size() && written == sent.size() && source == first.local_endpoint() && received == sent, "IPv6 datagram send and receive");
    peer.close(); require(!peer.is_open() && peer.native_handle() == native_io::invalid_handle, "close clears the socket handle");
}

void completion_races(io::io_context& context) {
    auto scheduler = context.get_scheduler();
    auto socket = io::ip::tcp::socket{scheduler, io::ip::tcp::v4()};
    std::array<std::byte, 1> buffer;
    auto source = io::async_read_some(socket, io::buffer(buffer));
    outcome<decltype(source)> result;
    auto state = stdexec::connect(source, receiver<decltype(source)>{&context, &result, {}});
    // Reproduce a successful kernel completion queued before a stop request.
    state.cancelled.store(true, std::memory_order_release);
    state.complete(state, 1, {});
    success(result);
    require(std::get<0>(*result.value) == 1 && result.completions == 1,
            "a late stop request must preserve successfully transferred bytes");
    context.run();

    auto relative = scheduler.schedule_after(15ms);
    auto begin = scheduler.now();
    auto delayed = run(context, stdexec::let_value(scheduler.schedule_after(20ms),
        [&] { return relative; }));
    success(delayed);
    require(scheduler.now() - begin >= 35ms, "relative timer must measure its delay from start");
}

// Cancellation during submission and after dispatch must both finish the receive.
void cancel_from_completion(io::io_context& context) {
    for (auto kind : {native_io::operation::post, native_io::operation::timer}) {
        auto scheduler = context.get_scheduler();
        auto socket = io::ip::udp::socket{scheduler, io::ip::udp::endpoint{}};
        std::array<std::byte, 1> buffer;
        struct pending_receive : native_io::request {
            io::io_context* context;
            bool stopped = false;
        } receive;
        receive.context = &context;
        receive.kind = native_io::operation::receive_from;
        receive.file = socket.native_handle();
        receive.buffer = buffer.data();
        receive.size = buffer.size();
        receive.complete = [](native_io::request& request, std::int64_t size, std::error_code error) noexcept {
            auto& self = static_cast<pending_receive&>(request);
            self.stopped = self.cancelled.load() && (error || size < 0);
            self.context->stop();
        };
        struct trigger : native_io::request {
            native_io::engine<>* engine;
            native_io::request* target;
        } timer;
        timer.engine = scheduler.engine();
        timer.target = &receive;
        timer.kind = kind;
        timer.deadline = scheduler.now() + 2ms;
        timer.complete = [](native_io::request& request, std::int64_t, std::error_code) noexcept {
            auto& self = static_cast<trigger&>(request);
            self.engine->cancel(*self.target);
        };
        if (kind == native_io::operation::post) {
            scheduler.engine()->start(receive);
            scheduler.engine()->start(timer);
        } else {
            scheduler.engine()->start(timer);
            scheduler.engine()->start(receive);
        }
        context.run();
        require(receive.stopped, "completion-driven UDP cancellation must complete before the event loop blocks");
    }
}

struct post_chain {
    io::io_context& context;
    io::scheduler scheduler;
    std::size_t remaining;
    bool live = false;
    bool failed = false;
    const bool* finished = nullptr;
    struct receiver {
        using receiver_concept = stdexec::receiver_t;
        post_chain* owner;
        void set_value() noexcept { owner->next(); }
        void set_stopped() noexcept { owner->failed = true; owner->context.stop(); }
        void set_error(std::error_code) noexcept { set_stopped(); }
        void set_error(std::exception_ptr) noexcept { set_stopped(); }
    };
    using state_type = stdexec::connect_result_t<decltype(stdexec::schedule(scheduler)), receiver>;
    alignas(state_type) std::byte storage[sizeof(state_type)];
    auto state() noexcept -> state_type& { return *std::launder(reinterpret_cast<state_type*>(storage)); }
    ~post_chain() { if (live) std::destroy_at(&state()); }
    void start() noexcept {
        ::new (static_cast<void*>(storage)) state_type(stdexec::connect(stdexec::schedule(scheduler), receiver{this}));
        live = true;
        stdexec::start(state());
    }
    void next() noexcept {
        if ((finished && *finished) || --remaining == 0) {
            context.stop();
            return;
        }
        std::destroy_at(&state());
        live = false;
        start();
    }
};

void queued_posts(io::io_context& context) {
    post_chain chain{context, context.get_scheduler(), 32768};
    chain.start();
    context.run();
    require(!chain.failed && chain.remaining == 0, "in-thread posts must progress without wakeup writes");

    struct receiver {
        using receiver_concept = stdexec::receiver_t;
        io::io_context* context;
        std::atomic<int>* completions;
        std::atomic<bool>* failed;
        void set_value() noexcept {
            if (completions->fetch_add(1, std::memory_order_acq_rel) + 1 == 512)
                context->stop();
        }
        void set_stopped() noexcept { failed->store(true); set_value(); }
        void set_error(std::error_code) noexcept { set_stopped(); }
        void set_error(std::exception_ptr) noexcept { set_stopped(); }
    };
    auto scheduler = context.get_scheduler();
    using state_type = stdexec::connect_result_t<decltype(stdexec::schedule(scheduler)), receiver>;
    std::atomic<int> completions{0};
    std::atomic<bool> failed{false};
    std::vector<std::unique_ptr<state_type>> states;
    for (int i = 0; i != 512; ++i)
        states.emplace_back(new state_type(stdexec::connect(stdexec::schedule(scheduler), receiver{&context, &completions, &failed})));
    std::vector<std::jthread> producers;
    for (int lane = 0; lane != 4; ++lane)
        producers.emplace_back([&, lane] {
            for (int i = lane; i < 512; i += 4) stdexec::start(*states[i]);
        });
    context.run();
    require(!failed.load() && completions.load() == 512, "coalesced cross-thread posts must not lose wakeups");
}

void post_fairness(io::io_context& context) {
    bool fired = false;
    bool failed = false;
    struct receiver {
        using receiver_concept = stdexec::receiver_t;
        bool* fired;
        bool* failed;
        void set_value() noexcept { *fired = true; }
        void set_stopped() noexcept { *failed = true; *fired = true; }
        void set_error(std::error_code) noexcept { set_stopped(); }
        void set_error(std::exception_ptr) noexcept { set_stopped(); }
    };
    post_chain posts{context, context.get_scheduler(), 1000000};
    posts.finished = &fired;
    auto alarm = stdexec::connect(context.get_scheduler().schedule_after(1ms), receiver{&fired, &failed});
    posts.start();
    stdexec::start(alarm);
    context.run();
    require(fired && !failed && posts.remaining != 0, "continuous local posts must dispatch ready timers");
}

void timers(io::io_context& context) {
    auto scheduler = context.get_scheduler();
    std::vector<int> order;
    auto begin = scheduler.now();
    auto record = [&](int value, std::chrono::milliseconds delay) {
        return stdexec::then(scheduler.schedule_after(delay), [&, value, delay] {
            require(scheduler.now() - begin >= delay, "timers must not complete early");
            order.push_back(value);
        });
    };
    success(run(context, stdexec::when_all(record(3, 30ms), record(1, 10ms), record(2, 20ms))));
    std::ranges::sort(order);
    require(order == std::vector<int>{1, 2, 3}, "all timer deadlines must complete exactly once");
    require(scheduler.now() - begin >= 30ms, "timers must not complete early");
    success(run(context, scheduler.schedule_after(1ms)));
    std::stop_source stop;
    auto cancel = stdexec::then(scheduler.schedule_after(1ms), [&] { stop.request_stop(); });
    auto cancelled = run(context, stdexec::when_all(scheduler.schedule_after(1s), std::move(cancel)), stop.get_token());
    require(cancelled.stopped, "cancelling the nearest timer must drain its operation");
    success(run(context, scheduler.schedule_after(1ms)));
}

void tcp(io::io_context& context) {
    auto scheduler = context.get_scheduler();
    auto acceptor = io::ip::tcp::acceptor{scheduler, {io::ip::address_v4::loopback(), 0}};
    auto client = io::ip::tcp::socket{scheduler, io::ip::tcp::v4()};
    auto connected = run(context, stdexec::when_all(
        io::async_connect(client, {io::ip::address_v4{{127, 0, 0, 1}}, acceptor.local_endpoint().port()}), io::async_accept(acceptor)));
    success(connected);
    auto peer = std::move(std::get<0>(*connected.value));
    std::array<std::byte, 64> sent{}, received{};
    sent[17] = std::byte{91};
    auto transferred = run(context, stdexec::when_all(
        stdexec::just(io::buffer(std::span<std::byte>{received})) | io::async_read(peer),
        stdexec::just(io::buffer(std::span<const std::byte>{sent})) | io::async_write(client)));
    success(transferred);
    require(sent == received, "TCP composed senders must transfer the entire buffer");

    std::array<io::mutable_buffer, 20> into{};
    std::array<io::const_buffer, 20> from{};
    for (std::size_t i = 0; i < from.size(); ++i) {
        sent[i] = static_cast<std::byte>(i + 1);
        received[i] = std::byte{};
        into[i] = {received.data() + i, 1};
        from[i] = {sent.data() + i, 1};
    }
    success(run(context, stdexec::when_all(io::async_read(peer, into), io::async_write(client, from))));
    require(sent == received, "composed transfers must advance across native buffer batches");
    std::array<io::mutable_buffer, 3> scatter{{{received.data(), 17}, {}, {received.data() + 17, received.size() - 17}}};
    std::array<io::const_buffer, 2> gather{{{sent.data(), 29}, {sent.data() + 29, sent.size() - 29}}};
    received.fill(std::byte{});
    auto chunks = run(context, stdexec::when_all(io::async_read_some(peer, scatter), io::async_write_some(client, gather)));
    success(chunks);
    require(std::get<0>(*chunks.value) == sent.size() && std::get<1>(*chunks.value) == sent.size() && received == sent,
            "stream operations must gather and scatter buffers");

    std::stop_source stop;
    auto cancel = stdexec::then(scheduler.schedule_after(2ms), [&] { stop.request_stop(); });
    auto cancelled = run(context, stdexec::when_all(io::async_read_some(peer, io::buffer(received)), std::move(cancel)), stop.get_token());
    require(cancelled.stopped && !cancelled.error, "pending TCP read must stop");
    auto next = run(context, stdexec::when_all(io::async_read(peer, received), io::async_write(client, sent)));
    success(next);
    require(sent == received, "TCP connection must remain usable after cancelling a read");

    client.shutdown(io::socket_base::shutdown_send);
    auto eof = run(context, io::async_read_some(peer, io::buffer(received)));
    success(eof);
    require(std::get<0>(*eof.value) == 0, "TCP shutdown must report EOF");
}

void udp(io::io_context& context) {
    auto scheduler = context.get_scheduler();
    io::ip::udp::endpoint source_hint;
    auto first = io::ip::udp::socket{scheduler, io::ip::udp::endpoint{}};
    auto second = io::ip::udp::socket{scheduler, io::ip::udp::endpoint{}};
    io::ip::udp::endpoint destination{io::ip::address_v4{{127, 0, 0, 1}}, second.local_endpoint().port()};
    std::array<std::byte, 32> sent{}, received{};
    sent[19] = std::byte{73};
    std::array<io::mutable_buffer, 2> scatter{{{received.data(), 11}, {received.data() + 11, received.size() - 11}}};
    std::array<io::const_buffer, 3> gather{{{sent.data(), 7}, {}, {sent.data() + 7, sent.size() - 7}}};
    auto transfer = run(context, stdexec::when_all(
        stdexec::just(scatter, source_hint) | io::async_receive_from(second),
        stdexec::just(gather, destination) | io::async_send_to(first)));
    success(transfer);
    auto& [count, source, written] = *transfer.value;
    require(count == sent.size() && written == sent.size() && sent == received, "UDP must preserve the datagram");
    require(source == io::ip::udp::endpoint{io::ip::address_v4{{127, 0, 0, 1}}, first.local_endpoint().port()}, "UDP must report the source endpoint");

    std::array<std::byte, 0> empty;
    auto zero = run(context, stdexec::when_all(io::async_receive_from(second, io::buffer(empty), source_hint), io::async_send_to(first, io::buffer(empty), destination)));
    success(zero);
    require(std::get<0>(*zero.value) == 0 && std::get<2>(*zero.value) == 0, "zero-length UDP datagrams must succeed");

    std::array<std::byte, 1> short_buffer;
    auto truncated = run(context, stdexec::when_all(io::async_receive_from(second, io::buffer(short_buffer), source_hint), io::async_send_to(first, io::buffer(sent), destination)));
    success(truncated);
    require(std::get<0>(*truncated.value) == short_buffer.size(), "UDP truncation returns the copied byte count");

    std::stop_source stop;
    auto cancel = stdexec::then(scheduler.schedule_after(2ms), [&] { stop.request_stop(); });
    auto cancelled = run(context, stdexec::when_all(io::async_receive_from(second, io::buffer(received), source_hint), std::move(cancel)), stop.get_token());
    require(cancelled.stopped && !cancelled.error, "pending UDP receive must stop");
    auto next = run(context, stdexec::when_all(io::async_receive_from(second, io::buffer(received), source_hint), io::async_send_to(first, io::buffer(sent), destination)));
    success(next);
    require(received == sent, "UDP must receive another complete datagram after truncation and cancellation");

    first.connect(destination);
    second.connect({io::ip::address_v4{{127, 0, 0, 1}}, first.local_endpoint().port()});
    auto connected = run(context, stdexec::when_all(io::async_receive(second, scatter), io::async_send(first, gather)));
    success(connected);
    require(std::get<0>(*connected.value) == sent.size() && received == sent, "connected UDP senders must transfer a datagram");
}

void foreign_stop(io::io_context& context) {
    io::ip::udp::socket socket{context, io::ip::udp::endpoint{io::ip::address_v4::loopback(), 0}};
    std::array<std::byte, 1> buffer;
    std::stop_source stop;
    std::binary_semaphore pending{0};
    std::jthread producer{[&] {
        pending.acquire();
        stop.request_stop();
    }};
    auto ready = stdexec::then(context.get_scheduler().schedule_after(2ms), [&] { pending.release(); });
    auto cancelled = run(context, stdexec::when_all(io::async_receive(socket, io::buffer(buffer)), std::move(ready)), stop.get_token());
    require(cancelled.stopped && cancelled.completions == 1, "a foreign stop must drain a suspended receive once");
}

void close_wait(io::io_context& context) {
    io::ip::udp::socket socket{context, io::ip::udp::endpoint{io::ip::address_v4::loopback(), 0}};
    std::array<std::byte, 1> buffer;
    auto close = stdexec::then(context.get_scheduler().schedule_after(2ms), [&] { socket.close(); });
    auto closed = run(context, stdexec::when_all(io::async_receive(socket, io::buffer(buffer)), std::move(close)));
    require(closed.error == std::errc::operation_canceled && closed.completions == 1,
            "closing a socket must drain its pending receive before releasing the handle");
}

void files(io::io_context& context, const std::filesystem::path& directory) {
    auto scheduler = context.get_scheduler();
    auto path = directory / "native-execution.dat";
    auto file = scheduler.open_file(path, true);
    std::array<std::byte, 4> sent{std::byte{4}, std::byte{3}, std::byte{2}, std::byte{1}}, received{};
    auto written = run(context, io::async_write_at(file, sent, 7));
    success(written);
    auto read = run(context, io::async_read_at(file, received, 7));
    success(read);
    require(std::get<0>(*written.value) == sent.size() && std::get<0>(*read.value) == sent.size() && sent == received, "file senders must preserve offsets");
    file.close();
    std::filesystem::remove(path);
}

struct short_stream {
    int calls = 0;
    std::size_t progress = 1;
    auto read_some(std::span<std::byte> buffer) {
        ++calls;
        return stdexec::just(std::min(progress, buffer.size()));
    }
    auto write_some(std::span<const std::byte> buffer) {
        ++calls;
        return stdexec::just(std::min(progress, buffer.size()));
    }
};

struct threaded_stream {
    std::mutex mutex;
    std::vector<std::thread> workers;
    ~threaded_stream() {
        for (auto& worker : workers)
            worker.join();
    }
    struct sender {
        using sender_concept = stdexec::sender_t;
        using completion_signatures = stdexec::completion_signatures<stdexec::set_value_t(std::size_t)>;
        threaded_stream* stream;
        template <class Receiver> struct operation {
            using operation_state_concept = stdexec::operation_state_t;
            threaded_stream* stream;
            Receiver receiver;
            void start() & noexcept {
                std::lock_guard lock{stream->mutex};
                stream->workers.emplace_back([target = std::move(receiver)]() mutable {
                    stdexec::set_value(std::move(target), std::size_t{1});
                });
            }
        };
        template <class Receiver> auto connect(Receiver receiver) const -> operation<Receiver> {
            return {stream, std::move(receiver)};
        }
    };
    auto read_some(std::span<std::byte>) { return sender{this}; }
    auto write_some(std::span<const std::byte>) { return sender{this}; }
};

struct destroying_receiver {
    using receiver_concept = stdexec::receiver_t;
    std::function<void()> destroy;
    bool* failed;
    void set_value() noexcept { destroy(); }
    void set_error(std::error_code) noexcept { *failed = true; destroy(); }
    void set_error(std::exception_ptr) noexcept { *failed = true; destroy(); }
    void set_error(const io::closed&) noexcept { *failed = true; destroy(); }
    void set_stopped() noexcept { *failed = true; destroy(); }
};

template <class Sender> void destroy_on_completion(io::io_context& context, Sender sender) {
    bool failed = false;
    using operation = stdexec::connect_result_t<Sender, destroying_receiver>;
    std::unique_ptr<operation> state;
    state.reset(new operation(stdexec::connect(std::move(sender), destroying_receiver{
        [&] { state.reset(); context.stop(); }, &failed})));
    stdexec::start(*state);
    context.run();
    require(!state && !failed, "completion must allow immediate operation destruction");
}

void composed_transfers() {
    short_stream stream;
    std::array<std::byte, 32768> buffer{};
    require(stdexec::sync_wait(io::async_read(stream, buffer)).has_value(), "synchronous read chunks must compose");
    require(stream.calls == static_cast<int>(buffer.size()), "read must continue after partial completion");
    stream.calls = 0;
    require(stdexec::sync_wait(io::async_write(stream, buffer)).has_value(), "synchronous write chunks must compose");
    require(stream.calls == static_cast<int>(buffer.size()), "write must continue after partial completion");
    stream.calls = 0;
    require(stdexec::sync_wait(io::async_read(stream, io::mutable_buffer{})).has_value() && stream.calls == 0, "an empty transfer must not initiate I/O");
    stream.progress = 0;
    bool failed = false;
    try {
        static_cast<void>(stdexec::sync_wait(io::async_write(stream, buffer)));
    } catch (const io::closed&) {
        failed = true;
    }
    require(failed, "zero progress must fail, not loop forever");
    threaded_stream threaded;
    std::array<std::byte, 64> cross_thread;
    require(stdexec::sync_wait(io::async_read(threaded, cross_thread)).has_value(), "cross-thread partial completions must compose");
}
} // namespace

int main(int argc, char** argv) {
    try {
        require(argc == 2, "pass the existing build directory");
        address_types();
        composed_transfers();
        io::io_context context;
        auto scheduler = context.get_scheduler();
        auto scheduled = run(context, stdexec::schedule(scheduler));
        success(scheduled);
        destroy_on_completion(context, scheduler.schedule());
        short_stream stream;
        std::array<std::byte, 4> bytes;
        destroy_on_completion(context, io::async_read(stream, bytes));
        std::stop_source stop;
        stop.request_stop();
        auto stopped = run(context, scheduler.schedule_after(1s), stop.get_token());
        require(stopped.stopped, "a pre-stopped native operation must complete as stopped");
        queued_posts(context);
        post_fairness(context);
        completion_races(context);
        cancel_from_completion(context);
        timers(context);
        scheduler_and_input(context);
        ipv6(context);
        tcp(context);
        udp(context);
        foreign_stop(context);
        close_wait(context);
        files(context, argv[1]);
        std::println("native execution: TCP, UDP, files, cancellation, and composed transfers passed");
        return 0;
    } catch (const std::exception& error) {
        std::println(std::cerr, "native execution: {}", error.what());
        return 1;
    }
}
