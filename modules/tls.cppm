export module httpant.tls;

import std;
import httpant;
import httpant.dependencies.wolfssl;

export namespace http::tls {
using http::operator co_await;
inline void check_tls(int result, std::string_view action) {
    if (result != WOLFSSL_SUCCESS)
        throw std::runtime_error(std::format("{}: wolfSSL error {}", action, result));
}

namespace detail {
struct buffers {
    std::vector<std::byte> input, output;
    std::size_t consumed = 0;
    std::exception_ptr failure;
    static int read(WOLFSSL*, char* bytes, int size, void* context) noexcept {
        auto& self = *static_cast<buffers*>(context);
        auto count = std::min<std::size_t>(size, self.input.size() - self.consumed);
        if (!count) return WOLFSSL_CBIO_ERR_WANT_READ;
        std::memcpy(bytes, self.input.data() + self.consumed, count);
        self.consumed += count;
        return static_cast<int>(count);
    }
    static int write(WOLFSSL*, char* bytes, int size, void* context) noexcept {
        auto& self = *static_cast<buffers*>(context);
        if (size < 0 || static_cast<std::size_t>(size) > (128u << 10) - self.output.size())
            return WOLFSSL_CBIO_ERR_WANT_WRITE;
        try {
            auto data = std::as_bytes(std::span{bytes, static_cast<std::size_t>(size)});
            self.output.insert(self.output.end(), data.begin(), data.end());
            return size;
        } catch (...) {
            self.failure = std::current_exception();
            return WOLFSSL_CBIO_ERR_GENERAL;
        }
    }
};

// All operations share the caller's serialized executor. Dispatch starts only
// after the releasing coroutine suspends; nested releases join the same queue.
inline thread_local std::deque<std::coroutine_handle<>> ready;
inline thread_local bool dispatching = false;
inline void dispatch() {
    if (std::exchange(dispatching, true)) return;
    while (!ready.empty()) {
        auto next = ready.front();
        ready.pop_front();
        next.resume();
    }
    dispatching = false;
}

class mutex {
    struct waiter {
        http::detail::waiter_slot<> slot;
        bool acquired = false;
    };
    bool held_ = false;
    std::deque<waiter*> waiting_;
    struct release {
        mutex& owner;
        bool await_ready() noexcept {
            if (!owner.waiting_.empty()) return false;
            owner.held_ = false;
            return true;
        }
        void await_suspend(std::coroutine_handle<> current) {
            if (owner.waiting_.empty()) owner.held_ = false;
            else {
                auto* next = owner.waiting_.front();
                owner.waiting_.pop_front();
                next->acquired = true;
                if (auto handle = next->slot.take()) ready.push_back(handle);
            }
            ready.push_back(current);
            dispatch();
        }
        void await_resume() const noexcept {}
    };
public:
    template<class T>
    auto run(http::task<T> work, std::stop_token stop) -> http::task<T> {
        waiter next;
        std::exception_ptr failure;
        if (std::exchange(held_, true)) {
            waiting_.push_back(&next);
            try {
                co_await http::detail::park_until{next.slot, [&] { return next.acquired; }, stop};
            } catch (...) {
                std::erase(waiting_, &next);
                if (!next.acquired) throw;
                failure = std::current_exception();
            }
        }
        if constexpr (std::is_void_v<T>) {
            try { if (!failure) co_await std::move(work); } catch (...) { failure = std::current_exception(); }
            co_await release{*this};
            if (failure) std::rethrow_exception(failure);
        } else {
            std::optional<T> result;
            try { if (!failure) result.emplace(co_await std::move(work)); } catch (...) { failure = std::current_exception(); }
            co_await release{*this};
            if (failure) std::rethrow_exception(failure);
            co_return std::move(*result);
        }
    }
};
}

struct verification_failure : std::runtime_error { using std::runtime_error::runtime_error; };

class context {
    struct release { void operator()(WOLFSSL_CTX* p) const { wolfSSL_CTX_free(p); } };
    std::unique_ptr<WOLFSSL_CTX, release> context_;
public:
    explicit context(bool server) {
        static const int initialized = wolfSSL_Init();
        check_tls(initialized, "initialize TLS");
        context_.reset(wolfSSL_CTX_new(server ? wolfTLS_server_method() : wolfTLS_client_method()));
        if (!context_) throw std::runtime_error("cannot create TLS context");
        check_tls(wolfSSL_CTX_SetMinVersion(context_.get(), WOLFSSL_TLSV1_2), "set minimum TLS version");
        wolfSSL_CTX_SetIORecv(context_.get(), detail::buffers::read);
        wolfSSL_CTX_SetIOSend(context_.get(), detail::buffers::write);
    }
    auto native_handle() const -> WOLFSSL_CTX* { return context_.get(); }
    void certificate(const std::string& cert, const std::string& key) {
        check_tls(wolfSSL_CTX_use_certificate_chain_file(context_.get(), cert.c_str()), "load certificate");
        check_tls(wolfSSL_CTX_use_PrivateKey_file(context_.get(), key.c_str(), WOLFSSL_FILETYPE_PEM), "load key");
    }
    void trust(const std::string& ca, bool verify = true) {
        wolfSSL_CTX_set_verify(context_.get(), verify ? WOLFSSL_VERIFY_PEER : WOLFSSL_VERIFY_NONE, nullptr);
        if (verify && (ca.empty() ? wolfSSL_CTX_load_system_CA_certs(context_.get()) :
                wolfSSL_CTX_load_verify_locations(context_.get(), ca.c_str(), nullptr)) != WOLFSSL_SUCCESS)
            throw verification_failure("cannot load TLS trust roots");
    }
};

template<http::byte_stream Transport>
class stream {
    struct release { void operator()(WOLFSSL* p) const { wolfSSL_free(p); } };
    struct state : detail::buffers {
        Transport transport;
        std::unique_ptr<WOLFSSL, release> session;
        std::size_t generation = 0;
        detail::mutex reader, writer, receiving, sending;
        explicit state(Transport transport) : transport(std::move(transport)) {}
        auto flush(std::stop_token stop) -> http::task<void> {
            co_await sending.run(flush_output(stop), stop);
        }
        auto flush_output(std::stop_token stop) -> http::task<void> {
            while (!output.empty()) {
                auto bytes = std::exchange(output, {});
                std::span<const std::byte> remaining{bytes};
                try {
                    while (!remaining.empty()) {
                        auto count = co_await transport.async_write(remaining, stop);
                        if (!count) throw std::runtime_error("TLS transport write made no progress");
                        remaining = remaining.subspan(count);
                    }
                } catch (...) {
                    // A partly written record stays first in line for the next flush.
                    output.insert(output.begin(), remaining.begin(), remaining.end());
                    throw;
                }
            }
        }
        auto advance(int error, std::size_t before, std::stop_token stop) -> http::task<void> {
            if (failure) std::rethrow_exception(failure);
            if (error != WOLFSSL_ERROR_WANT_READ && error != WOLFSSL_ERROR_WANT_WRITE) {
                if (wolfSSL_get_verify_result(session.get()) != 0 || error == DOMAIN_NAME_MISMATCH ||
                    error == VERIFY_CERT_ERROR || error == ASN_BEFORE_DATE_E || error == ASN_AFTER_DATE_E ||
                    error == ASN_SIG_CONFIRM_E || error == ASN_NO_SIGNER_E || error == ASN_SELF_SIGNED_E)
                    throw verification_failure("TLS certificate verification failed");
                throw std::runtime_error(std::format("TLS failed: wolfSSL error {}", error));
            }
            co_await flush(stop);
            if (error == WOLFSSL_ERROR_WANT_READ)
                co_await receiving.run(receive(before, stop), stop);
        }
        auto receive(std::size_t before, std::stop_token stop) -> http::task<void> {
            if (before != generation || consumed < input.size()) co_return;
            std::array<std::byte, 16384> bytes;
            auto count = co_await transport.async_read(bytes, stop);
            if (!count) throw std::runtime_error("TLS transport closed without close_notify");
            input.assign(bytes.begin(), bytes.begin() + count);
            consumed = 0;
            ++generation;
        }
    };
    std::shared_ptr<state> state_;
public:
    stream(Transport transport, context& context, std::string protocol = {})
        : state_(std::make_shared<state>(std::move(transport))) {
        auto& s = *state_;
        s.session.reset(wolfSSL_new(context.native_handle()));
        if (!s.session) throw std::runtime_error("cannot create TLS session");
        wolfSSL_SetIOReadCtx(s.session.get(), static_cast<detail::buffers*>(&s));
        wolfSSL_SetIOWriteCtx(s.session.get(), static_cast<detail::buffers*>(&s));
        if (!protocol.empty()) check_tls(wolfSSL_UseALPN(s.session.get(), protocol.data(), protocol.size(), WOLFSSL_ALPN_FAILED_ON_MISMATCH), "set ALPN");
    }
    void hostname(const std::string& host, bool verify = true) {
        if (host.size() > 65535) throw std::invalid_argument("TLS hostname too long");
        if (verify) check_tls(wolfSSL_check_domain_name(native_handle(), host.c_str()), "set verification hostname");
        check_tls(wolfSSL_UseSNI(native_handle(), WOLFSSL_SNI_HOST_NAME, host.data(), host.size()), "set SNI");
    }
    auto native_handle() const -> WOLFSSL* { return state_->session.get(); }
    auto transport() -> Transport& { return state_->transport; }
    auto handshake(bool server = false, std::string_view protocol = {}) -> http::task<void> {
        auto s = state_;
        const auto& stop = co_await http::current_stop_token();
        for (;;) {
            auto before = s->generation;
            auto result = server ? wolfSSL_accept(native_handle()) : wolfSSL_connect(native_handle());
            if (result == WOLFSSL_SUCCESS) break;
            co_await s->advance(wolfSSL_get_error(native_handle(), result), before, stop);
        }
        co_await s->flush(stop);
        if (protocol.empty()) co_return;
        char* selected = nullptr;
        unsigned short size = 0;
        check_tls(wolfSSL_ALPN_GetProtocol(native_handle(), &selected, &size), "read negotiated ALPN");
        if (std::string_view{selected, size} != protocol) throw std::runtime_error("unexpected TLS ALPN");
    }
    auto async_read(std::span<std::byte> bytes, std::stop_token stop = {}) -> http::task<std::size_t> {
        if (bytes.empty()) co_return 0;
        auto s = state_;
        co_return co_await s->reader.run(read(bytes, stop), stop);
    }
private:
    auto read(std::span<std::byte> bytes, std::stop_token stop) -> http::task<std::size_t> {
        auto s = state_;
        for (;;) {
            if (stop.stop_requested()) throw http::stopped{};
            auto before = s->generation;
            auto result = wolfSSL_read(native_handle(), bytes.data(), std::min<std::size_t>(bytes.size(), 16384));
            auto error = wolfSSL_get_error(native_handle(), result);
            if (result > 0) co_return result;
            if (error == WOLFSSL_ERROR_ZERO_RETURN) co_return 0;
            co_await s->advance(error, before, stop);
        }
    }
public:
    // Sends close_notify without waiting for the peer's; the transport
    // closes with the last copy of the stream. A peer that has already
    // closed its socket cannot receive it, and that loses nothing.
    auto close(std::stop_token stop = {}) -> http::task<void> {
        auto s = state_;
        co_await s->writer.run(shutdown(stop), stop);
    }
private:
    auto shutdown(std::stop_token stop) -> http::task<void> {
        auto s = state_;
        auto result = wolfSSL_shutdown(native_handle());
        if (s->failure) std::rethrow_exception(s->failure);
        if (result != WOLFSSL_SUCCESS && result != WOLFSSL_SHUTDOWN_NOT_DONE)
            throw std::runtime_error(std::format("TLS close failed: wolfSSL error {}", wolfSSL_get_error(native_handle(), result)));
        try {
            co_await s->flush(stop);
        } catch (const std::system_error&) {}
    }
public:
    auto async_write(std::span<const std::byte> bytes, std::stop_token stop = {}) -> http::task<std::size_t> {
        if (bytes.empty()) co_return 0;
        auto s = state_;
        co_return co_await s->writer.run(write(bytes, stop), stop);
    }
private:
    auto write(std::span<const std::byte> bytes, std::stop_token stop) -> http::task<std::size_t> {
        auto s = state_;
        for (;;) {
            if (stop.stop_requested()) throw http::stopped{};
            auto before = s->generation;
            auto result = wolfSSL_write(native_handle(), bytes.data(), std::min<std::size_t>(bytes.size(), 16384));
            auto error = wolfSSL_get_error(native_handle(), result);
            if (result > 0) { co_await s->flush(stop); co_return result; }
            co_await s->advance(error, before, stop);
        }
    }
};
}
