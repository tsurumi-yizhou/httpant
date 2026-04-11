#pragma once

#include <asio.hpp>
#include <msquic.hpp>

#include <array>
#include <coroutine>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <deque>
#include <exception>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <unordered_map>
#include <utility>
#include <variant>
#include <vector>

namespace httpant::examples {

[[nodiscard]] inline auto quic_address_to_string(const QUIC_ADDR& address) -> std::string;

[[nodiscard]] inline auto quic_error_message(std::string_view what, QUIC_STATUS status) -> std::string {
    return std::string(what) + " failed (" + std::to_string(static_cast<long>(status)) + ')';
}

inline void check_quic_status(QUIC_STATUS status, std::string_view what) {
    if (QUIC_FAILED(status))
        throw std::runtime_error(quic_error_message(what, status));
}

template <typename T>
class callback_queue {
public:
    callback_queue(asio::any_io_executor executor, std::string name)
        : executor_(executor), name_(std::move(name)) {}

    callback_queue(const callback_queue&) = delete;
    auto operator=(const callback_queue&) -> callback_queue& = delete;

    struct pop_operation {
        callback_queue* queue;

        bool await_ready() noexcept {
            return queue->ready();
        }

        auto await_suspend(std::coroutine_handle<> continuation) -> bool {
            return queue->arm_waiter(continuation);
        }

        auto await_resume() -> T {
            return queue->pop();
        }
    };

    auto async_pop() -> pop_operation {
        return {this};
    }

    void push(T value) {
        std::optional<std::coroutine_handle<>> waiter;
        {
            std::lock_guard lock(mutex_);
            if (closed_)
                return;
            values_.push_back(std::move(value));
            if (waiter_)
                waiter = std::exchange(waiter_, {});
        }

        if (waiter)
            asio::post(executor_, [continuation = *waiter]() mutable {
                continuation.resume();
            });
    }

    void close(std::exception_ptr error = {}) {
        std::optional<std::coroutine_handle<>> waiter;
        {
            std::lock_guard lock(mutex_);
            if (closed_)
                return;
            closed_ = true;
            if (error && !error_)
                error_ = std::move(error);
            if (waiter_)
                waiter = std::exchange(waiter_, {});
        }

        if (waiter)
            asio::post(executor_, [continuation = *waiter]() mutable {
                continuation.resume();
            });
    }

private:
    auto ready() -> bool {
        std::lock_guard lock(mutex_);
        return !values_.empty() || closed_;
    }

    auto arm_waiter(std::coroutine_handle<> continuation) -> bool {
        std::lock_guard lock(mutex_);
        if (!values_.empty() || closed_)
            return false;
        if (waiter_)
            throw std::runtime_error(name_ + ": concurrent waiters are not supported");
        waiter_ = continuation;
        return true;
    }

    auto pop() -> T {
        std::lock_guard lock(mutex_);
        if (!values_.empty()) {
            auto value = std::move(values_.front());
            values_.pop_front();
            return value;
        }
        if (error_)
            std::rethrow_exception(error_);
        throw std::runtime_error(name_ + ": queue closed");
    }

    asio::any_io_executor executor_;
    std::string name_;
    std::mutex mutex_;
    std::deque<T> values_{};
    std::coroutine_handle<> waiter_{};
    std::exception_ptr error_{};
    bool closed_{false};
};

class quic_runtime {
public:
    quic_runtime()
        : api_(std::make_unique<MsQuicApi>()),
          registration_(nullptr)
    {
        if (!api_ || !api_->IsValid())
            throw std::runtime_error("msquic api initialization failed");
        if (::MsQuic && ::MsQuic != api_.get())
            throw std::runtime_error("msquic global api is already initialized");
        ::MsQuic = api_.get();

        registration_ = std::make_unique<MsQuicRegistration>("httpant-reverse-proxy");
        if (!registration_ || !registration_->IsValid())
            throw std::runtime_error(quic_error_message("msquic registration open", registration_->GetInitStatus()));
    }

    quic_runtime(const quic_runtime&) = delete;
    auto operator=(const quic_runtime&) -> quic_runtime& = delete;

    [[nodiscard]] auto registration() const -> const MsQuicRegistration& {
        return *registration_;
    }

private:
    std::unique_ptr<MsQuicApi> api_;
    std::unique_ptr<MsQuicRegistration> registration_;
};

struct quic_server_credentials {
    std::string certificate_file;
    std::string private_key_file;
};

struct quic_client_credentials {
    std::string server_name;
    std::optional<std::string> ca_certificate_file;
    bool insecure_no_verify{false};
};

class quic_configuration {
public:
    quic_configuration(std::shared_ptr<quic_runtime> runtime,
                       quic_server_credentials credentials)
        : runtime_(std::move(runtime)),
          alpn_("h3"),
          server_credentials_(std::move(credentials))
    {
        if (!runtime_)
            throw std::runtime_error("msquic runtime is required");
        settings_.SetPeerBidiStreamCount(1);
        settings_.SetPeerUnidiStreamCount(3);

        certificate_file_.CertificateFile = server_credentials_.certificate_file.c_str();
        certificate_file_.PrivateKeyFile = server_credentials_.private_key_file.c_str();

        credentials_ = MsQuicCredentialConfig{QUIC_CREDENTIAL_FLAG_NONE};
        credentials_.Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE;
        credentials_.CertificateFile = &certificate_file_;

        configuration_ = std::make_unique<MsQuicConfiguration>(
            runtime_->registration(),
            alpn_,
            settings_,
            credentials_);
        if (!configuration_ || !configuration_->IsValid())
            throw std::runtime_error(quic_error_message("msquic server configuration open", configuration_->GetInitStatus()));
    }

    quic_configuration(std::shared_ptr<quic_runtime> runtime,
                       quic_client_credentials credentials)
        : runtime_(std::move(runtime)),
          alpn_("h3"),
          client_credentials_(std::move(credentials))
    {
        if (!runtime_)
            throw std::runtime_error("msquic runtime is required");
        settings_.SetPeerBidiStreamCount(1);
        settings_.SetPeerUnidiStreamCount(3);

        auto flags = QUIC_CREDENTIAL_FLAG_CLIENT;
        if (client_credentials_.insecure_no_verify)
            flags = static_cast<QUIC_CREDENTIAL_FLAGS>(flags | QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION);
        if (client_credentials_.ca_certificate_file.has_value()) {
            flags = static_cast<QUIC_CREDENTIAL_FLAGS>(flags | QUIC_CREDENTIAL_FLAG_SET_CA_CERTIFICATE_FILE);
            ca_certificate_file_ = *client_credentials_.ca_certificate_file;
        }

        credentials_ = MsQuicCredentialConfig{flags};
        credentials_.Type = QUIC_CREDENTIAL_TYPE_NONE;
        if (!ca_certificate_file_.empty())
            credentials_.CaCertificateFile = ca_certificate_file_.c_str();

        configuration_ = std::make_unique<MsQuicConfiguration>(
            runtime_->registration(),
            alpn_,
            settings_,
            credentials_);
        if (!configuration_ || !configuration_->IsValid())
            throw std::runtime_error(quic_error_message("msquic client configuration open", configuration_->GetInitStatus()));
    }

    quic_configuration(const quic_configuration&) = delete;
    auto operator=(const quic_configuration&) -> quic_configuration& = delete;

    [[nodiscard]] auto runtime() const -> const std::shared_ptr<quic_runtime>& {
        return runtime_;
    }

    [[nodiscard]] auto native() const -> const MsQuicConfiguration& {
        return *configuration_;
    }

private:
    std::shared_ptr<quic_runtime> runtime_;
    MsQuicAlpn alpn_;
    MsQuicSettings settings_{};
    MsQuicCredentialConfig credentials_{};
    QUIC_CERTIFICATE_FILE certificate_file_{};
    std::string ca_certificate_file_{};
    quic_server_credentials server_credentials_{};
    quic_client_credentials client_credentials_{};
    std::unique_ptr<MsQuicConfiguration> configuration_;
};

struct quic_stream_state;
struct quic_connection_state;

class quic_stream {
public:
    quic_stream() = default;
    explicit quic_stream(std::shared_ptr<quic_stream_state> state) : state_(std::move(state)) {}

    struct read_operation;
    struct write_operation;

    auto async_read(std::span<std::byte> buffer) -> read_operation;
    auto async_write(std::span<const std::byte> buffer) -> write_operation;
    auto async_write(std::span<const std::byte> buffer, bool fin) -> write_operation;

    [[nodiscard]] auto id() const -> std::int64_t;

private:
    std::shared_ptr<quic_stream_state> state_{};
};

struct quic_stream_state : std::enable_shared_from_this<quic_stream_state> {
    explicit quic_stream_state(asio::any_io_executor executor, std::int64_t stream_id)
        : executor(std::move(executor)), stream_id(stream_id) {}

    [[nodiscard]] auto can_read() -> bool {
        std::lock_guard lock(mutex);
        return !receive_buffer.empty() || peer_fin || shutdown_complete || error != nullptr;
    }

    auto arm_read(std::coroutine_handle<> continuation) -> bool {
        std::lock_guard lock(mutex);
        if (!receive_buffer.empty() || peer_fin || shutdown_complete || error != nullptr)
            return false;
        if (read_waiter)
            throw std::runtime_error("quic stream does not support concurrent reads");
        read_waiter = continuation;
        return true;
    }

    auto consume(std::span<std::byte> buffer) -> std::size_t {
        std::lock_guard lock(mutex);
        if (error)
            std::rethrow_exception(error);

        auto count = std::min(buffer.size(), receive_buffer.size());
        for (std::size_t index = 0; index < count; ++index) {
            buffer[index] = receive_buffer.front();
            receive_buffer.pop_front();
        }

        if (count != 0)
            return count;
        if (peer_fin || shutdown_complete)
            return 0;
        throw std::runtime_error("quic stream resumed without available data");
    }

    void complete_send(quic_stream::write_operation* operation, bool canceled);

    void fail(std::exception_ptr failure) {
        std::optional<std::coroutine_handle<>> waiter;
        {
            std::lock_guard lock(mutex);
            if (!error)
                error = std::move(failure);
            if (read_waiter)
                waiter = std::exchange(read_waiter, {});
        }
        if (waiter)
            asio::post(executor, [continuation = *waiter]() mutable {
                continuation.resume();
            });
    }

    void note_peer_fin() {
        std::optional<std::coroutine_handle<>> waiter;
        {
            std::lock_guard lock(mutex);
            peer_fin = true;
            if (read_waiter)
                waiter = std::exchange(read_waiter, {});
        }
        if (waiter)
            asio::post(executor, [continuation = *waiter]() mutable {
                continuation.resume();
            });
    }

    void append_received(const QUIC_STREAM_EVENT& event) {
        std::optional<std::coroutine_handle<>> waiter;
        {
            std::lock_guard lock(mutex);
            for (std::uint32_t index = 0; index < event.RECEIVE.BufferCount; ++index) {
                auto bytes = std::as_bytes(std::span{
                    event.RECEIVE.Buffers[index].Buffer,
                    event.RECEIVE.Buffers[index].Length});
                receive_buffer.insert(receive_buffer.end(), bytes.begin(), bytes.end());
            }
            if ((event.RECEIVE.Flags & QUIC_RECEIVE_FLAG_FIN) != 0)
                peer_fin = true;
            if (read_waiter)
                waiter = std::exchange(read_waiter, {});
        }
        if (waiter)
            asio::post(executor, [continuation = *waiter]() mutable {
                continuation.resume();
            });
    }

    static auto callback(MsQuicStream*, void* context, QUIC_STREAM_EVENT* event) noexcept -> QUIC_STATUS {
        auto* state = static_cast<quic_stream_state*>(context);
        try {
            switch (event->Type) {
                case QUIC_STREAM_EVENT_START_COMPLETE:
                    if (QUIC_FAILED(event->START_COMPLETE.Status)) {
                        state->fail(std::make_exception_ptr(
                            std::runtime_error(quic_error_message("quic stream start", event->START_COMPLETE.Status))));
                    }
                    return QUIC_STATUS_SUCCESS;
                case QUIC_STREAM_EVENT_RECEIVE:
                    state->append_received(*event);
                    return QUIC_STATUS_SUCCESS;
                case QUIC_STREAM_EVENT_SEND_COMPLETE:
                    state->complete_send(
                        static_cast<quic_stream::write_operation*>(event->SEND_COMPLETE.ClientContext),
                        event->SEND_COMPLETE.Canceled != FALSE);
                    return QUIC_STATUS_SUCCESS;
                case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
                    state->note_peer_fin();
                    return QUIC_STATUS_SUCCESS;
                case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:
                    state->fail(std::make_exception_ptr(
                        std::runtime_error("quic peer aborted the receive side of the stream")));
                    return QUIC_STATUS_SUCCESS;
                case QUIC_STREAM_EVENT_PEER_RECEIVE_ABORTED:
                    state->fail(std::make_exception_ptr(
                        std::runtime_error("quic peer aborted the send side of the stream")));
                    return QUIC_STATUS_SUCCESS;
                case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE: {
                    std::optional<std::coroutine_handle<>> waiter;
                    {
                        std::lock_guard lock(state->mutex);
                        state->shutdown_complete = true;
                        if (state->read_waiter)
                            waiter = std::exchange(state->read_waiter, {});
                    }
                    if (waiter) {
                        asio::post(state->executor, [continuation = *waiter]() mutable {
                            continuation.resume();
                        });
                    }
                    return QUIC_STATUS_SUCCESS;
                }
                default:
                    return QUIC_STATUS_SUCCESS;
            }
        } catch (...) {
            state->fail(std::current_exception());
            return QUIC_STATUS_INTERNAL_ERROR;
        }
    }

    asio::any_io_executor executor;
    std::int64_t stream_id{0};
    std::unique_ptr<MsQuicStream> stream{};
    std::mutex mutex{};
    std::deque<std::byte> receive_buffer{};
    std::coroutine_handle<> read_waiter{};
    std::exception_ptr error{};
    bool peer_fin{false};
    bool shutdown_complete{false};
};

class quic_connection_transport {
public:
    quic_connection_transport() = default;
    explicit quic_connection_transport(std::shared_ptr<quic_connection_state> state) : state_(std::move(state)) {}

    struct connection_io_operation {
        std::string message;

        bool await_ready() const noexcept {
            return true;
        }

        void await_suspend(std::coroutine_handle<>) const noexcept {}

        auto await_resume() -> std::size_t {
            throw std::runtime_error(message);
        }
    };

    struct open_operation {
        std::shared_ptr<quic_connection_state> state;
        std::int64_t stream_id{0};
        std::optional<quic_stream> result{};
        std::exception_ptr error{};

        bool await_ready() {
            try {
                result = open();
            } catch (...) {
                error = std::current_exception();
            }
            return true;
        }

        void await_suspend(std::coroutine_handle<>) const noexcept {}

        auto await_resume() -> quic_stream {
            if (error)
                std::rethrow_exception(error);
            return std::move(*result);
        }

    private:
        auto open() -> quic_stream;
    };

    auto async_read(std::span<std::byte>) -> connection_io_operation {
        return {"quic connections do not support connection-level reads"};
    }

    auto async_write(std::span<const std::byte>) -> connection_io_operation {
        return {"quic connections do not support connection-level writes"};
    }

    auto async_write(std::span<const std::byte>, bool) -> connection_io_operation {
        return {"quic connections do not support connection-level writes"};
    }

    auto async_accept() const -> decltype(auto);
    auto async_open(std::int64_t stream_id) const -> open_operation {
        return {state_, stream_id};
    }
    auto async_connected() const -> decltype(auto);

    void shutdown(std::uint64_t error_code = 0) const;

    [[nodiscard]] auto remote_address() const -> std::string;
    [[nodiscard]] auto valid() const -> bool {
        return static_cast<bool>(state_);
    }

private:
    std::shared_ptr<quic_connection_state> state_{};
};

struct quic_connection_state : std::enable_shared_from_this<quic_connection_state> {
    quic_connection_state(asio::any_io_executor executor,
                          bool client_role,
                                                    std::shared_ptr<quic_configuration> configuration)
        : executor(std::move(executor)),
          configuration(std::move(configuration)),
          accepted_streams(this->executor, "quic stream accept"),
          connected_events(this->executor, "quic connection ready"),
          client_role(client_role),
          next_local_bidirectional_id(client_role ? 0 : 1),
          next_local_unidirectional_id(client_role ? 2 : 3) {}

    static auto connect(asio::any_io_executor executor,
                        std::shared_ptr<quic_configuration> configuration,
                        std::string server_name,
                        std::uint16_t port) -> quic_connection_transport
    {
        auto state = std::make_shared<quic_connection_state>(std::move(executor), true, std::move(configuration));
        state->server_name = std::move(server_name);
        state->port = port;
        state->connection = std::make_unique<MsQuicConnection>(
            state->configuration->runtime()->registration(),
            CleanUpManual,
            &quic_connection_state::callback,
            state.get());
        if (!state->connection || !state->connection->IsValid())
            throw std::runtime_error(quic_error_message("msquic connection open", state->connection->GetInitStatus()));

        auto status = state->connection->Start(state->configuration->native(), state->server_name.c_str(), state->port);
        if (QUIC_FAILED(status))
            throw std::runtime_error(quic_error_message("msquic connection start", status));

        return quic_connection_transport{std::move(state)};
    }

    static auto accept(asio::any_io_executor executor,
                       std::shared_ptr<quic_configuration> configuration,
                       HQUIC handle) -> std::shared_ptr<quic_connection_state>
    {
        auto state = std::make_shared<quic_connection_state>(
            std::move(executor),
            false,
            std::move(configuration));
        state->connection = std::make_unique<MsQuicConnection>(handle, CleanUpManual, &quic_connection_state::callback, state.get());
        if (!state->connection || !state->connection->IsValid())
            throw std::runtime_error(quic_error_message("msquic accepted connection", state->connection->GetInitStatus()));
        auto status = state->connection->SetConfiguration(state->configuration->native());
        if (QUIC_FAILED(status))
            throw std::runtime_error(quic_error_message("msquic connection configuration", status));
        return state;
    }

    auto async_accept() -> decltype(auto) {
        return accepted_streams.async_pop();
    }

    auto async_connected() -> decltype(auto) {
        return connected_events.async_pop();
    }

    auto open_stream(std::int64_t stream_id) -> quic_stream {
        std::shared_ptr<quic_stream_state> existing;
        {
            std::lock_guard lock(mutex);
            if (auto it = streams.find(stream_id); it != streams.end())
                existing = it->second;
        }
        if (existing)
            return quic_stream{std::move(existing)};

        if ((stream_id & 0x1) != (client_role ? 0 : 1))
            throw std::runtime_error("quic stream open requested a peer-initiated stream that is not known locally");

        auto is_unidirectional = (stream_id & 0x2) != 0;
        {
            std::lock_guard lock(mutex);
            auto& next = is_unidirectional ? next_local_unidirectional_id : next_local_bidirectional_id;
            if (stream_id != next)
                throw std::runtime_error("quic local stream id sequence is inconsistent with HTTP/3 expectations");
        }

        auto stream_state = std::make_shared<quic_stream_state>(executor, stream_id);
        auto open_flags = is_unidirectional ? QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL : QUIC_STREAM_OPEN_FLAG_NONE;
        auto stream = std::make_unique<MsQuicStream>(*connection, open_flags, CleanUpManual, &quic_stream_state::callback, stream_state.get());
        if (!stream || !stream->IsValid())
            throw std::runtime_error(quic_error_message("msquic stream open", stream->GetInitStatus()));
        stream_state->stream = std::move(stream);

        auto status = stream_state->stream->Start(QUIC_STREAM_START_FLAG_IMMEDIATE);
        if (QUIC_FAILED(status))
            throw std::runtime_error(quic_error_message("msquic stream start", status));

        {
            std::lock_guard lock(mutex);
            auto& next = is_unidirectional ? next_local_unidirectional_id : next_local_bidirectional_id;
            next += 4;
            streams.emplace(stream_id, stream_state);
        }
        return quic_stream{std::move(stream_state)};
    }

    void shutdown(std::uint64_t error_code) {
        if (connection)
            connection->Shutdown(error_code, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE);
    }

    [[nodiscard]] auto remote_address() const -> std::string {
        std::lock_guard lock(mutex);
        return remote_address_text;
    }

    void fail(std::exception_ptr failure) {
        std::vector<std::shared_ptr<quic_stream_state>> active_streams;
        {
            std::lock_guard lock(mutex);
            if (!terminal_error)
                terminal_error = failure;
            for (auto& [_, stream] : streams)
                active_streams.push_back(stream);
        }

        connected_events.close(terminal_error);
        accepted_streams.close(terminal_error);
        for (auto& stream : active_streams)
            stream->fail(terminal_error);
    }

    void note_connected(MsQuicConnection& connection_handle) {
        QuicAddr address;
        if (QUIC_SUCCEEDED(connection_handle.GetRemoteAddr(address))) {
            std::lock_guard lock(mutex);
            remote_address_text = quic_address_to_string(address.SockAddr);
        }
        connected_events.push(std::monostate{});
    }

    void note_remote_stream(HQUIC handle) {
        auto stream_state = std::make_shared<quic_stream_state>(executor, -1);
        auto stream = std::make_unique<MsQuicStream>(handle, CleanUpManual, &quic_stream_state::callback, stream_state.get());
        if (!stream || !stream->IsValid()) {
            fail(std::make_exception_ptr(std::runtime_error(quic_error_message(
                "msquic accepted stream",
                stream ? stream->GetInitStatus() : QUIC_STATUS_OUT_OF_MEMORY))));
            return;
        }

        stream_state->stream_id = static_cast<std::int64_t>(stream->ID());
        stream_state->stream = std::move(stream);

        {
            std::lock_guard lock(mutex);
            streams.emplace(stream_state->stream_id, stream_state);
        }

        accepted_streams.push(quic_stream{std::move(stream_state)});
    }

    static auto callback(MsQuicConnection* connection, void* context, QUIC_CONNECTION_EVENT* event) noexcept -> QUIC_STATUS {
        auto* state = static_cast<quic_connection_state*>(context);
        try {
            switch (event->Type) {
                case QUIC_CONNECTION_EVENT_CONNECTED:
                    state->note_connected(*connection);
                    return QUIC_STATUS_SUCCESS;
                case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED:
                    state->note_remote_stream(event->PEER_STREAM_STARTED.Stream);
                    return QUIC_STATUS_SUCCESS;
                case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:
                    state->fail(std::make_exception_ptr(std::runtime_error(quic_error_message(
                        "quic transport shutdown",
                        event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status))));
                    return QUIC_STATUS_SUCCESS;
                case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER:
                    state->fail(std::make_exception_ptr(
                        std::runtime_error("quic peer initiated shutdown")));
                    return QUIC_STATUS_SUCCESS;
                case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
                    state->fail(std::make_exception_ptr(
                        std::runtime_error("quic connection shutdown complete")));
                    return QUIC_STATUS_SUCCESS;
                default:
                    return QUIC_STATUS_SUCCESS;
            }
        } catch (...) {
            state->fail(std::current_exception());
            return QUIC_STATUS_INTERNAL_ERROR;
        }
    }

    asio::any_io_executor executor;
    std::shared_ptr<quic_configuration> configuration;
    callback_queue<quic_stream> accepted_streams;
    callback_queue<std::monostate> connected_events;
    std::unique_ptr<MsQuicConnection> connection{};
    mutable std::mutex mutex{};
    std::unordered_map<std::int64_t, std::shared_ptr<quic_stream_state>> streams{};
    std::exception_ptr terminal_error{};
    std::string server_name{};
    std::string remote_address_text{};
    std::uint16_t port{0};
    bool client_role{false};
    std::int64_t next_local_bidirectional_id{0};
    std::int64_t next_local_unidirectional_id{0};
};

class quic_listener {
public:
    quic_listener() = default;

    quic_listener(asio::any_io_executor executor,
                  std::shared_ptr<quic_configuration> configuration,
                  QuicAddr address)
        : state_(std::make_shared<state>(std::move(executor), std::move(configuration), address))
    {}

    auto async_accept() const -> decltype(auto) {
        return state_->accepted_connections->async_pop();
    }

private:
    struct state {
        state(asio::any_io_executor executor,
              std::shared_ptr<quic_configuration> configuration,
              QuicAddr address)
            : executor(std::move(executor)),
              configuration(std::move(configuration)),
              accepted_connections(std::make_shared<callback_queue<quic_connection_transport>>(this->executor, "quic connection accept"))
        {
            if (!this->configuration)
                throw std::runtime_error("msquic listener configuration is required");
            listener = std::make_unique<MsQuicListener>(
                this->configuration->runtime()->registration(),
                CleanUpManual,
                &state::callback,
                this);
            if (!listener || !listener->IsValid())
                throw std::runtime_error(quic_error_message("msquic listener open", listener->GetInitStatus()));

            auto status = listener->Start(MsQuicAlpn{"h3"}, address);
            if (QUIC_FAILED(status))
                throw std::runtime_error(quic_error_message("msquic listener start", status));
        }

        static auto callback(MsQuicListener*, void* context, QUIC_LISTENER_EVENT* event) noexcept -> QUIC_STATUS {
            auto* self = static_cast<state*>(context);
            try {
                switch (event->Type) {
                    case QUIC_LISTENER_EVENT_NEW_CONNECTION:
                        self->accepted_connections->push(quic_connection_transport{quic_connection_state::accept(
                            self->executor,
                            self->configuration,
                            event->NEW_CONNECTION.Connection)});
                        return QUIC_STATUS_SUCCESS;
                    case QUIC_LISTENER_EVENT_STOP_COMPLETE:
                        self->accepted_connections->close();
                        return QUIC_STATUS_SUCCESS;
                    default:
                        return QUIC_STATUS_SUCCESS;
                }
            } catch (...) {
                self->accepted_connections->close(std::current_exception());
                return QUIC_STATUS_INTERNAL_ERROR;
            }
        }

        asio::any_io_executor executor;
        std::shared_ptr<quic_configuration> configuration;
        std::shared_ptr<callback_queue<quic_connection_transport>> accepted_connections;
        std::unique_ptr<MsQuicListener> listener{};
    };

    std::shared_ptr<state> state_{};
};

struct quic_stream::read_operation {
    std::shared_ptr<quic_stream_state> state;
    std::span<std::byte> buffer;

    bool await_ready() {
        return state->can_read();
    }

    auto await_suspend(std::coroutine_handle<> continuation) -> bool {
        return state->arm_read(continuation);
    }

    auto await_resume() -> std::size_t {
        return state->consume(buffer);
    }
};

struct quic_stream::write_operation {
    std::shared_ptr<quic_stream_state> state;
    std::span<const std::byte> source;
    bool fin{false};
    std::vector<std::byte> payload{};
    QUIC_BUFFER buffer{};
    std::coroutine_handle<> continuation{};
    std::size_t result{0};
    std::exception_ptr error{};

    bool await_ready() const noexcept {
        return false;
    }

    auto await_suspend(std::coroutine_handle<> continuation_handle) -> bool {
        continuation = continuation_handle;
        payload.assign(source.begin(), source.end());
        buffer.Buffer = reinterpret_cast<std::uint8_t*>(payload.data());
        buffer.Length = static_cast<std::uint32_t>(payload.size());

        auto flags = fin ? QUIC_SEND_FLAG_FIN : QUIC_SEND_FLAG_NONE;
        auto status = state->stream->Send(&buffer, 1, flags, this);
        if (QUIC_FAILED(status)) {
            error = std::make_exception_ptr(std::runtime_error(quic_error_message("quic stream send", status)));
            return false;
        }
        return true;
    }

    auto await_resume() -> std::size_t {
        if (error)
            std::rethrow_exception(error);
        return result;
    }
};

inline void quic_stream_state::complete_send(quic_stream::write_operation* operation, bool canceled) {
    asio::post(executor, [operation, canceled]() mutable {
        if (canceled) {
            operation->error = std::make_exception_ptr(
                std::runtime_error("quic stream send was canceled"));
        } else {
            operation->result = operation->payload.size();
        }
        operation->continuation.resume();
    });
}

inline auto quic_stream::async_read(std::span<std::byte> buffer) -> read_operation {
    return {state_, buffer};
}

inline auto quic_stream::async_write(std::span<const std::byte> buffer) -> write_operation {
    return {state_, buffer, false};
}

inline auto quic_stream::async_write(std::span<const std::byte> buffer, bool fin) -> write_operation {
    return {state_, buffer, fin};
}

inline auto quic_stream::id() const -> std::int64_t {
    return state_ ? state_->stream_id : -1;
}

inline auto quic_connection_transport::open_operation::open() -> quic_stream {
    if (!state)
        throw std::runtime_error("quic connection is not initialized");
    return state->open_stream(stream_id);
}

inline auto quic_connection_transport::async_accept() const -> decltype(auto) {
    return state_->async_accept();
}

inline auto quic_connection_transport::async_connected() const -> decltype(auto) {
    return state_->async_connected();
}

inline void quic_connection_transport::shutdown(std::uint64_t error_code) const {
    if (state_)
        state_->shutdown(error_code);
}

inline auto quic_connection_transport::remote_address() const -> std::string {
    return state_ ? state_->remote_address() : std::string{};
}

[[nodiscard]] inline auto endpoint_to_quic_address(const asio::ip::tcp::endpoint& endpoint) -> QuicAddr {
    auto family = endpoint.address().is_v4() ? QUIC_ADDRESS_FAMILY_INET : QUIC_ADDRESS_FAMILY_INET6;
    QuicAddr address{static_cast<QUIC_ADDRESS_FAMILY>(family)};
    address.SetPort(endpoint.port());

    if (endpoint.address().is_v4()) {
        auto bytes = endpoint.address().to_v4().to_bytes();
        auto* ipv4 = reinterpret_cast<sockaddr_in*>(&address.SockAddr);
        std::memcpy(&ipv4->sin_addr, bytes.data(), bytes.size());
    } else {
        auto bytes = endpoint.address().to_v6().to_bytes();
        auto* ipv6 = reinterpret_cast<sockaddr_in6*>(&address.SockAddr);
        std::memcpy(&ipv6->sin6_addr, bytes.data(), bytes.size());
        ipv6->sin6_scope_id = endpoint.address().to_v6().scope_id();
    }

    return address;
}

[[nodiscard]] inline auto quic_address_to_string(const QUIC_ADDR& address) -> std::string {
    if (QuicAddrGetFamily(&address) == QUIC_ADDRESS_FAMILY_INET) {
        const auto* ipv4 = reinterpret_cast<const sockaddr_in*>(&address);
        std::array<unsigned char, 4> bytes{};
        std::memcpy(bytes.data(), &ipv4->sin_addr, bytes.size());
        return asio::ip::address_v4{bytes}.to_string();
    }

    const auto* ipv6 = reinterpret_cast<const sockaddr_in6*>(&address);
    std::array<unsigned char, 16> bytes{};
    std::memcpy(bytes.data(), &ipv6->sin6_addr, bytes.size());
    return asio::ip::address_v6{bytes, ipv6->sin6_scope_id}.to_string();
}

} // namespace httpant::examples