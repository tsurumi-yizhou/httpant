export module httpant.quic;

import std;
import httpant;
import httpant.io;
import httpant.dependencies.msquic;

export namespace http::quic {
using http::operator co_await;

namespace detail {
inline void check(QUIC_STATUS status, std::string_view action) {
    if (httpant::dependencies::quic_failed(status))
        throw std::runtime_error(std::format("quic: {}: {}", action, status));
}
struct runtime {
    MsQuicApi api;
    HQUIC registration = nullptr;
    runtime() {
        check(api.GetInitStatus(), "open API");
        check(api.RegistrationOpen(nullptr, &registration), "open registration");
    }
    ~runtime() { api.RegistrationClose(registration); }
};
inline auto library() -> runtime& { static runtime value; return value; }

// A notification claims a post once. Receiver completion always runs in the engine.
template <template <class> class Queue, template <class> class Local>
class signal {
    struct ticket {
        native_io::engine<Queue>* engine;
        native_io::request* request;
        std::atomic<unsigned> phase{0};
        void notify() noexcept {
            if (phase.exchange(2, std::memory_order_acq_rel) == 1) engine->start(*request);
        }
        void arm() noexcept {
            unsigned expected = 0;
            if (!phase.compare_exchange_strong(expected, 1, std::memory_order_acq_rel)) engine->start(*request);
        }
    };
    native_io::engine<Queue>* engine_;
    http::queues::buffer<std::weak_ptr<ticket>, Local> waiters_;
public:
    explicit signal(io::net::basic_scheduler<Queue> scheduler) : engine_(scheduler.engine()) {}
    void notify() {
        while (!waiters_.empty()) {
            auto item = waiters_.front().lock();
            waiters_.pop_front();
            if (item) item->notify();
        }
    }
    struct sender {
        using sender_concept = stdexec::sender_t;
        using completion_signatures = stdexec::completion_signatures<stdexec::set_value_t(), stdexec::set_error_t(std::error_code), stdexec::set_stopped_t()>;
        signal* owner;
        std::stop_token stop;
        auto get_env() const noexcept -> io::net::detail::environment<Queue> { return {{owner->engine_}}; }
        template <class Receiver> struct operation : native_io::request {
            using operation_state_concept = stdexec::operation_state_t;
            signal* owner;
            std::stop_token stop;
            Receiver receiver;
            std::shared_ptr<ticket> item;
            struct cancel {
                ticket* item;
                void operator()() const noexcept { item->notify(); }
            };
            std::optional<std::stop_callback<cancel>> watch;
            operation(signal* owner, std::stop_token stop, Receiver receiver)
                : owner(owner), stop(stop), receiver(std::move(receiver)), item(std::make_shared<ticket>()) {
                item->engine = owner->engine_;
                item->request = this;
                this->complete = [](native_io::request& base, std::int64_t, std::error_code error) noexcept {
                    auto& self = static_cast<operation&>(base);
                    if (self.rejected) std::terminate();
                    self.watch.reset();
                    if (self.stop.stop_requested()) stdexec::set_stopped(std::move(self.receiver));
                    else if (error) stdexec::set_error(std::move(self.receiver), error);
                    else stdexec::set_value(std::move(self.receiver));
                };
            }
            operation(operation&&) = delete;
            void start() & noexcept {
                try {
                    owner->waiters_.push_back(item);
                    watch.emplace(stop, cancel{item.get()});
                    item->arm();
                } catch (...) {
                    stdexec::set_error(std::move(receiver), std::make_error_code(std::errc::not_enough_memory));
                }
            }
        };
        template <stdexec::receiver Receiver>
        auto connect(Receiver receiver) const -> operation<Receiver> { return {owner, stop, std::move(receiver)}; }
    };
    auto wait(std::stop_token stop) -> sender { return {this, stop}; }
};
template <template <class> class Queue, template <class> class Local> struct state;
} // namespace detail

class credentials {
    bool server_;
    std::string certificate_, key_, ca_;
    explicit credentials(bool server) : server_(server) {}
public:
    static auto server(const std::string& certificate, const std::string& key) -> credentials {
        credentials result{true};
        result.certificate_ = certificate;
        result.key_ = key;
        return result;
    }
    static auto client(const std::string& ca = {}) -> credentials {
        credentials result{false};
        result.ca_ = ca;
        return result;
    }
    auto is_server() const noexcept -> bool { return server_; }
private:
    template <template <class> class Queue, template <class> class Local> friend struct detail::state;
    void load(HQUIC configuration) const {
        QUIC_CREDENTIAL_CONFIG config{};
        QUIC_CERTIFICATE_FILE file{key_.c_str(), certificate_.c_str()};
        config.Type = server_ ? QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE : QUIC_CREDENTIAL_TYPE_NONE;
        config.Flags = server_ ? QUIC_CREDENTIAL_FLAG_NONE : QUIC_CREDENTIAL_FLAG_CLIENT;
        if (server_) config.CertificateFile = &file;
        if (!ca_.empty()) {
            config.Flags = static_cast<QUIC_CREDENTIAL_FLAGS>(config.Flags | QUIC_CREDENTIAL_FLAG_SET_CA_CERTIFICATE_FILE);
            config.CaCertificateFile = ca_.c_str();
        }
        detail::check(detail::library().api.ConfigurationLoadCredential(configuration, &config), "load credentials");
    }
};

namespace detail {
struct transmission {
    std::vector<std::byte> bytes;
    QUIC_BUFFER buffer{};
    bool done = false, canceled = false, fin = false;
};
template <template <class> class Queue, template <class> class Local>
struct stream_state : std::enable_shared_from_this<stream_state<Queue, Local>> {
    state<Queue, Local>* owner;
    HQUIC handle = nullptr;
    std::uint64_t id = 0;
    http::stream_access access = http::stream_access::bidirectional;
    http::queues::buffer<std::vector<std::byte>, Local> input;
    http::queues::buffer<std::shared_ptr<transmission>, Local> output;
    std::size_t input_offset = 0;
    std::uint64_t received = 0, consumed = 0, pending_receive = 0;
    std::optional<std::uint64_t> read_error, write_error;
    QUIC_STATUS start_status = QUIC_STATUS_SUCCESS;
    bool started = false, eof = false, fin_queued = false, fin_acked = false, send_closed = false;
    explicit stream_state(state<Queue, Local>* owner) : owner(owner) {}
};

template <template <class> class Queue, template <class> class Local>
struct state : std::enable_shared_from_this<state<Queue, Local>> {
    using stream_type = stream_state<Queue, Local>;
    enum class kind { connected, connection, peer_close, transport_close, closed, incoming, started, receive, sent, eof, read_reset, write_reset, fin, stream_closed };
    struct record {
        kind type{};
        std::shared_ptr<stream_type> stream;
        HQUIC handle = nullptr;
        std::vector<std::byte> bytes;
        transmission* tx = nullptr;
        std::uint64_t value = 0;
        QUIC_STATUS status = QUIC_STATUS_SUCCESS;
        bool flag = false;
    };
    io::net::basic_scheduler<Queue> scheduler;
    const MsQuicApi& api = library().api;
    credentials tls;
    HQUIC configuration = nullptr, listener = nullptr, conn = nullptr;
    std::uint16_t port = 0;
    Queue<record> records;
    signal<Queue, Local> changed;
    std::map<stream_type*, std::shared_ptr<stream_type>> streams;
    http::queues::buffer<std::shared_ptr<stream_type>, Local> accepted;
    std::exception_ptr failure;
    std::atomic<bool> admitted{false};
    // Set from any thread when an event could not be queued for the engine; consumed
    // on the engine thread by drain(), which surfaces it as a typed connection error.
    std::atomic<bool> delivery_failed{false};
    bool handshake = false, running = false, closed = false, peer_closed = false, closing = false;
    struct delivery : native_io::request {
        std::shared_ptr<state> owner;
        explicit delivery(std::shared_ptr<state> owner) : owner(std::move(owner)) {
            this->complete = [](native_io::request& base, std::int64_t, std::error_code error) noexcept {
                if (base.rejected) std::terminate();
                std::unique_ptr<delivery> self{static_cast<delivery*>(&base)};
                auto& owner = *self->owner;
                try {
                    if (error) throw std::system_error(error);
                    owner.drain();
                } catch (...) { if (!owner.failure) owner.failure = std::current_exception(); }
                owner.changed.notify();
            };
        }
    };
    state(io::net::basic_scheduler<Queue> scheduler, credentials tls)
        : scheduler(scheduler), tls(std::move(tls)), changed(scheduler) {}
    ~state() {
        if (listener) api.ListenerClose(listener);
        if (conn) api.ConnectionClose(conn);
        for (auto& [key, stream] : streams) if (stream->handle) api.StreamClose(stream->handle);
        if (configuration) api.ConfigurationClose(configuration);
    }
    void publish(record item) noexcept {
        auto owner = this->weak_from_this().lock();
        if (!owner) return;
        bool queued = false;
        try { queued = records.push(std::move(item)); }
        catch (...) {}
        if (!queued) delivery_failed.store(true, std::memory_order_release);
        // The post owns the callback context until the engine has consumed its records.
        // A failed post must not take the process down: drain() turns delivery_failed
        // into a typed connection error, closing at most this connection.
        auto* next = new (std::nothrow) delivery{std::move(owner)};
        if (!next) {
            delivery_failed.store(true, std::memory_order_release);
            return;
        }
        scheduler.engine()->start(*next);
    }
    static auto listener_event(HQUIC, void* context, QUIC_LISTENER_EVENT* event) noexcept -> QUIC_STATUS {
        auto& self = *static_cast<state*>(context);
        if (event->Type != QUIC_LISTENER_EVENT_NEW_CONNECTION) return QUIC_STATUS_SUCCESS;
        if (self.admitted.exchange(true, std::memory_order_acq_rel)) return QUIC_STATUS_CONNECTION_REFUSED;
        // A dying state must not become the accepted connection's callback context.
        auto owner = self.weak_from_this().lock();
        if (!owner) return QUIC_STATUS_CONNECTION_REFUSED;
        auto handle = event->NEW_CONNECTION.Connection;
        self.api.SetCallbackHandler(handle, reinterpret_cast<void*>(connection_event), &self);
        self.publish({.type = kind::connection, .handle = handle});
        return QUIC_STATUS_SUCCESS;
    }
    static auto connection_event(HQUIC, void* context, QUIC_CONNECTION_EVENT* event) noexcept -> QUIC_STATUS {
        auto& self = *static_cast<state*>(context);
        record item;
        switch (event->Type) {
        case QUIC_CONNECTION_EVENT_CONNECTED: item.type = kind::connected; break;
        case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:
            item.type = kind::transport_close; item.status = event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status; break;
        case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER:
            item.type = kind::peer_close; item.value = event->SHUTDOWN_INITIATED_BY_PEER.ErrorCode; break;
        case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE: item.type = kind::closed; break;
        case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED: {
            try {
                item.type = kind::incoming;
                item.stream = std::make_shared<stream_type>(&self);
                item.stream->handle = event->PEER_STREAM_STARTED.Stream;
                if (event->PEER_STREAM_STARTED.Flags & QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL)
                    item.stream->access = http::stream_access::receive_only;
            } catch (...) {
                self.publish({.type = kind::transport_close, .status = QUIC_STATUS_OUT_OF_MEMORY});
                return QUIC_STATUS_OUT_OF_MEMORY;
            }
            break;
        }
        default: return QUIC_STATUS_SUCCESS;
        }
        auto incoming = item.stream;
        self.publish(std::move(item));
        if (incoming) self.api.SetCallbackHandler(incoming->handle, reinterpret_cast<void*>(stream_event), incoming.get());
        return QUIC_STATUS_SUCCESS;
    }
    static auto stream_event(HQUIC, void* context, QUIC_STREAM_EVENT* event) noexcept -> QUIC_STATUS {
        auto& stream = *static_cast<stream_type*>(context);
        record item{.stream = stream.shared_from_this()};
        switch (event->Type) {
        case QUIC_STREAM_EVENT_START_COMPLETE:
            item.type = kind::started; item.status = event->START_COMPLETE.Status; item.value = event->START_COMPLETE.ID; break;
        case QUIC_STREAM_EVENT_RECEIVE:
            item.type = kind::receive;
            try {
                item.bytes.resize(event->RECEIVE.TotalBufferLength);
                auto* out = item.bytes.data();
                for (std::uint32_t i = 0; i < event->RECEIVE.BufferCount; ++i) {
                    auto& buffer = event->RECEIVE.Buffers[i];
                    std::memcpy(out, buffer.Buffer, buffer.Length);
                    out += buffer.Length;
                }
                item.flag = (event->RECEIVE.Flags & QUIC_RECEIVE_FLAG_FIN) != 0;
            } catch (...) {
                stream.owner->publish({.type = kind::transport_close, .status = QUIC_STATUS_OUT_OF_MEMORY});
                return QUIC_STATUS_OUT_OF_MEMORY;
            }
            break;
        case QUIC_STREAM_EVENT_SEND_COMPLETE:
            item.type = kind::sent; item.tx = static_cast<transmission*>(event->SEND_COMPLETE.ClientContext); item.flag = event->SEND_COMPLETE.Canceled; break;
        case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN: item.type = kind::eof; break;
        case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:
            item.type = kind::read_reset; item.value = event->PEER_SEND_ABORTED.ErrorCode; break;
        case QUIC_STREAM_EVENT_PEER_RECEIVE_ABORTED:
            item.type = kind::write_reset; item.value = event->PEER_RECEIVE_ABORTED.ErrorCode; break;
        case QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE:
            item.type = kind::fin; item.flag = event->SEND_SHUTDOWN_COMPLETE.Graceful; break;
        case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE: item.type = kind::stream_closed; break;
        default: return QUIC_STATUS_SUCCESS;
        }
        auto pending = item.type == kind::receive && !item.bytes.empty();
        stream.owner->publish(std::move(item));
        return pending ? QUIC_STATUS_PENDING : QUIC_STATUS_SUCCESS;
    }
    void initialize(io::net::ip::udp::endpoint local, io::net::ip::udp::endpoint remote, const std::string& name) {
        MsQuicSettings settings;
        settings.SetPeerBidiStreamCount(128).SetPeerUnidiStreamCount(16).SetSendBufferingEnabled(false).SetIdleTimeoutMs(10000);
        QUIC_BUFFER alpn{2, reinterpret_cast<std::uint8_t*>(const_cast<char*>("h3"))};
        check(api.ConfigurationOpen(library().registration, &alpn, 1, &settings, sizeof(settings), nullptr, &configuration), "open configuration");
        tls.load(configuration);
        QUIC_ADDR address{};
        std::memcpy(&address, local.data(), local.size());
        if (tls.is_server()) {
            check(api.ListenerOpen(library().registration, listener_event, this, &listener), "open listener");
            check(api.ListenerStart(listener, &alpn, 1, &address), "start listener");
            std::uint32_t size = sizeof(address);
            check(api.GetParam(listener, httpant::dependencies::listener_address, &size, &address), "get listener address");
        } else {
            if (!remote.port()) throw http::usage_error("quic: client requires a remote port");
            check(api.ConnectionOpen(library().registration, connection_event, this, &conn), "open connection");
            check(api.SetParam(conn, httpant::dependencies::connection_local_address, sizeof(address), &address), "set local address");
            QUIC_ADDR destination{};
            std::memcpy(&destination, remote.data(), remote.size());
            check(api.SetParam(conn, httpant::dependencies::connection_remote_address, sizeof(destination), &destination), "set remote address");
            check(api.ConnectionStart(conn, configuration, local.address().is_v6() ? QUIC_ADDRESS_FAMILY_INET6 : QUIC_ADDRESS_FAMILY_INET, name.c_str(), remote.port()), "start connection");
            std::uint32_t size = sizeof(address);
            check(api.GetParam(conn, httpant::dependencies::connection_local_address, &size, &address), "get local address");
        }
        port = httpant::dependencies::quic_port(address);
    }
    void drain() {
        record item;
        if (delivery_failed.exchange(false, std::memory_order_acq_rel) && !failure)
            failure = std::make_exception_ptr(std::system_error(std::make_error_code(std::errc::not_enough_memory)));
        while (records.try_pop(item)) {
            auto* stream = item.stream.get();
            try {
                switch (item.type) {
                case kind::connection:
                    if (conn || !listener) { api.ConnectionClose(item.handle); break; }
                    conn = item.handle;
                    api.ListenerStop(listener);
                    check(api.ConnectionSetConfiguration(conn, configuration), "set configuration");
                    break;
                case kind::connected: handshake = true; break;
                case kind::transport_close:
                    if (!closing) failure = std::make_exception_ptr(std::runtime_error(std::format("quic: transport shutdown: {}", item.status)));
                    peer_closed = true; break;
                case kind::peer_close: peer_closed = true; break;
                case kind::closed: closed = true; break;
                case kind::incoming: {
                    auto next = item.stream;
                    streams.emplace(next.get(), next);
                    std::uint32_t size = sizeof(next->id);
                    check(api.GetParam(next->handle, httpant::dependencies::stream_id, &size, &next->id), "get stream ID");
                    next->started = true;
                    accepted.push_back(std::move(next));
                    break;
                }
                case kind::started:
                    stream->start_status = item.status;
                    stream->id = item.value;
                    stream->started = true;
                    break;
                case kind::receive:
                    stream->received += item.bytes.size();
                    stream->pending_receive = item.bytes.size();
                    if (!item.bytes.empty()) stream->input.push_back(std::move(item.bytes));
                    if (item.flag) stream->eof = true;
                    break;
                case kind::sent:
                    item.tx->done = true; item.tx->canceled = item.flag;
                    while (!stream->output.empty() && stream->output.front()->done) stream->output.pop_front();
                    break;
                case kind::eof: stream->eof = true; break;
                case kind::read_reset: stream->read_error = item.value; break;
                case kind::write_reset: stream->write_error = item.value; break;
                case kind::fin: stream->send_closed = true; stream->fin_acked = item.flag; break;
                case kind::stream_closed:
                    release_receive(*stream);
                    if (stream->handle) api.StreamClose(stream->handle);
                    stream->handle = nullptr;
                    stream->send_closed = true;
                    streams.erase(stream);
                    break;
                }
            } catch (const std::bad_alloc&) { std::terminate(); }
            catch (...) { if (!failure) failure = std::current_exception(); }
        }
    }
    void release_receive(stream_type& stream) {
        if (auto count = std::exchange(stream.pending_receive, 0); count && stream.handle)
            api.StreamReceiveComplete(stream.handle, count);
    }
    void check_open() const {
        if (failure) std::rethrow_exception(failure);
        if (!running || closed || peer_closed) throw std::runtime_error("quic: connection is closed");
    }
    void shutdown(std::uint64_t error) {
        if (conn && !closed && !closing) {
            closing = true;
            for (auto& [key, stream] : streams) release_receive(*stream);
            api.ConnectionShutdown(conn, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, error);
        }
    }
    auto finish() -> http::task<void> {
        if (listener) { api.ListenerClose(listener); listener = nullptr; }
        drain();
        shutdown(0);
        while (conn && !closed) co_await changed.wait({});
        for (auto& [key, stream] : streams) {
            release_receive(*stream);
            if (stream->handle) { api.StreamClose(stream->handle); stream->handle = nullptr; }
        }
        if (conn) { api.ConnectionClose(conn); conn = nullptr; }
    }
};
} // namespace detail

template <template <class> class Queue = http::queues::locked, template <class> class Local = http::queues::local>
class connection;

template <template <class> class Queue = http::queues::locked, template <class> class Local = http::queues::local>
class stream {
    std::shared_ptr<detail::state<Queue, Local>> owner_;
    std::shared_ptr<detail::stream_state<Queue, Local>> state_;
    friend class connection<Queue, Local>;
    stream(std::shared_ptr<detail::state<Queue, Local>> owner, std::shared_ptr<detail::stream_state<Queue, Local>> state)
        : owner_(std::move(owner)), state_(std::move(state)) {}
    static auto released() -> http::task<void> { co_return; }
    static auto acknowledged(std::shared_ptr<detail::state<Queue, Local>> owner,
                             std::shared_ptr<detail::stream_state<Queue, Local>> state,
                             std::shared_ptr<detail::transmission> tx, std::stop_token stop) -> http::task<std::size_t> {
        while (!tx->done || (tx->fin && !state->send_closed)) {
            if (stop.stop_requested()) throw http::stopped{};
            if (state->write_error) throw http::stream_reset{http::application_error{*state->write_error}};
            if (tx->canceled) throw std::runtime_error("quic: send canceled");
            owner->check_open();
            co_await owner->changed.wait(stop);
        }
        if (tx->canceled) throw std::runtime_error("quic: send canceled");
        if (tx->fin && !state->fin_acked) throw std::runtime_error("quic: send shutdown was aborted");
        co_return tx->bytes.size();
    }
public:
    auto identifier() const -> http::stream_identifier { return {state_->id}; }
    auto access() const -> http::stream_access { return state_->access; }
    auto async_read(std::span<std::byte> bytes, std::stop_token stop) -> http::task<std::size_t> {
        if (access() == http::stream_access::send_only) throw http::usage_error("quic: read on send-only stream");
        if (bytes.empty()) co_return 0;
        for (;;) {
            if (stop.stop_requested()) throw http::stopped{};
            if (state_->read_error) throw http::stream_reset{http::application_error{*state_->read_error}};
            if (!state_->input.empty()) {
                auto& input = state_->input.front();
                auto size = std::min(bytes.size(), input.size() - state_->input_offset);
                std::ranges::copy(std::span{input}.subspan(state_->input_offset, size), bytes.begin());
                state_->input_offset += size;
                if (state_->input_offset == input.size()) {
                    state_->input.pop_front();
                    state_->input_offset = 0;
                    owner_->release_receive(*state_);
                }
                co_return size;
            }
            if (state_->eof) co_return 0;
            owner_->check_open();
            if (!state_->handle) throw std::runtime_error("quic: stream is closed");
            co_await owner_->changed.wait(stop);
        }
    }
    auto async_write(std::span<const std::byte> bytes, bool fin, std::stop_token stop)
        -> http::task<http::stream_write_result<http::task<void>, http::task<std::size_t>>> {
        if (stop.stop_requested()) throw http::stopped{};
        if (access() == http::stream_access::receive_only || state_->fin_queued)
            throw http::usage_error("quic: write on closed send side");
        if (state_->write_error) throw http::stream_reset{http::application_error{*state_->write_error}};
        owner_->check_open();
        if (!state_->handle) throw http::usage_error("quic: write on closed stream");
        if (bytes.size() > std::numeric_limits<std::uint32_t>::max()) throw http::usage_error("quic: send too large");
        auto tx = std::make_shared<detail::transmission>();
        tx->bytes.assign(bytes.begin(), bytes.end());
        tx->fin = fin;
        tx->buffer = {static_cast<std::uint32_t>(bytes.size()), reinterpret_cast<std::uint8_t*>(tx->bytes.data())};
        if (bytes.empty() && !fin) tx->done = true;
        else {
            state_->output.push_back(tx);
            auto status = owner_->api.StreamSend(state_->handle, &tx->buffer, 1, fin ? QUIC_SEND_FLAG_FIN : QUIC_SEND_FLAG_NONE, tx.get());
            if (httpant::dependencies::quic_failed(status)) {
                tx->done = tx->canceled = true;
                while (!state_->output.empty() && state_->output.front()->done) state_->output.pop_front();
                detail::check(status, "send stream");
            }
        }
        state_->fin_queued = fin;
        co_return {bytes.size(), released(), acknowledged(owner_, state_, std::move(tx), stop)};
    }
    void consume(std::size_t size) {
        if (size > state_->received - state_->consumed) throw http::usage_error("quic: consumed bytes exceed input");
        state_->consumed += size;
    }
    void shutdown(http::stream_side side, http::application_error error) {
        if (!state_->handle || owner_->closed || owner_->peer_closed) return;
        unsigned flags = 0;
        if (side != http::stream_side::receiving && access() != http::stream_access::receive_only) {
            flags |= QUIC_STREAM_SHUTDOWN_FLAG_ABORT_SEND; state_->write_error = error.value;
        }
        if (side != http::stream_side::sending && access() != http::stream_access::send_only) {
            owner_->release_receive(*state_);
            flags |= QUIC_STREAM_SHUTDOWN_FLAG_ABORT_RECEIVE; state_->read_error = error.value;
        }
        detail::check(owner_->api.StreamShutdown(state_->handle, static_cast<QUIC_STREAM_SHUTDOWN_FLAGS>(flags), error.value), "shutdown stream");
        owner_->changed.notify();
    }
};

template <template <class> class Queue, template <class> class Local>
class connection {
    std::shared_ptr<detail::state<Queue, Local>> state_;
    auto open(bool unidirectional, std::stop_token stop) -> http::task<stream<Queue, Local>> {
        if (stop.stop_requested()) throw http::stopped{};
        state_->check_open();
        auto next = std::make_shared<detail::stream_state<Queue, Local>>(state_.get());
        if (unidirectional) next->access = http::stream_access::send_only;
        // Registered first: an open handle's callback context must stay owned.
        state_->streams.emplace(next.get(), next);
        auto opened = state_->api.StreamOpen(state_->conn, unidirectional ? QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL : QUIC_STREAM_OPEN_FLAG_NONE,
            detail::state<Queue, Local>::stream_event, next.get(), &next->handle);
        if (httpant::dependencies::quic_failed(opened)) {
            state_->streams.erase(next.get());
            detail::check(opened, "open stream");
        }
        auto status = state_->api.StreamStart(next->handle, QUIC_STREAM_START_FLAG_IMMEDIATE);
        if (httpant::dependencies::quic_failed(status)) {
            state_->api.StreamClose(next->handle);
            next->handle = nullptr;
            state_->streams.erase(next.get());
            detail::check(status, "start stream");
        }
        try {
            while (!next->started) {
                state_->check_open();
                co_await state_->changed.wait(stop);
            }
            if (stop.stop_requested()) throw http::stopped{};
            detail::check(next->start_status, "start stream");
        } catch (...) {
            if (next->handle) {
                if (httpant::dependencies::quic_failed(next->start_status)) {
                    state_->api.StreamClose(next->handle);
                    next->handle = nullptr;
                    state_->streams.erase(next.get());
                } else {
                    state_->api.StreamShutdown(next->handle, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 0);
                }
            }
            throw;
        }
        co_return stream<Queue, Local>{state_, std::move(next)};
    }
public:
    using stream_type = stream<Queue, Local>;
    static constexpr auto completion_order = http::stream_completion_order::serialized;
    connection(io::net::basic_scheduler<Queue> scheduler, io::net::ip::udp::endpoint local, credentials tls,
               io::net::ip::udp::endpoint remote = {}, std::string server_name = "localhost")
        : state_(std::make_shared<detail::state<Queue, Local>>(scheduler, std::move(tls))) {
        try { state_->initialize(local, remote, server_name); }
        catch (...) {
            if (state_->listener) { state_->api.ListenerClose(state_->listener); state_->listener = nullptr; }
            if (state_->conn) { state_->api.ConnectionClose(state_->conn); state_->conn = nullptr; }
            throw;
        }
    }
    connection(const connection&) = delete;
    auto operator=(const connection&) -> connection& = delete;
    auto port() const -> std::uint16_t { return state_->port; }
    auto async_open_bidirectional(std::stop_token stop) -> http::task<stream<Queue, Local>> { return open(false, stop); }
    auto async_open_unidirectional(std::stop_token stop) -> http::task<stream<Queue, Local>> { return open(true, stop); }
    auto async_accept(std::stop_token stop) -> http::task<stream<Queue, Local>> {
        for (;;) {
            if (stop.stop_requested()) throw http::stopped{};
            if (!state_->accepted.empty()) {
                auto next = std::move(state_->accepted.front()); state_->accepted.pop_front();
                co_return stream<Queue, Local>{state_, std::move(next)};
            }
            state_->check_open();
            co_await state_->changed.wait(stop);
        }
    }
    auto async_close(http::application_error error) -> http::task<void> {
        state_->shutdown(error.value);
        const auto& stop = co_await http::current_stop_token();
        while (state_->conn && !state_->closed) {
            if (state_->failure) std::rethrow_exception(state_->failure);
            co_await state_->changed.wait(stop);
        }
    }
    template <class Body> auto run(Body body) -> http::task<void> {
        if (state_->running || state_->closed) throw http::usage_error("quic: connection run is one-shot");
        state_->running = true;
        const auto& stop = co_await http::current_stop_token();
        std::exception_ptr failure;
        try {
            while (!state_->handshake) {
                state_->check_open();
                co_await state_->changed.wait(stop);
            }
            co_await body(*this);
            co_await async_close(http::application_error{0});
        } catch (...) { failure = std::current_exception(); }
        co_await http::with_stop(std::stop_token{}, state_->finish());
        state_->running = false;
        state_->closed = true;
        if (state_->failure) std::rethrow_exception(state_->failure);
        if (failure) std::rethrow_exception(failure);
    }
};
static_assert(http::stream_factory<connection<>>);
} // namespace http::quic
