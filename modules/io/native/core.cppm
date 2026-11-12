export module httpant.io:native;
import std;
export import httpant.queue;

export namespace native_io {
    using handle = std::intptr_t;
    inline constexpr handle invalid_handle = -1;
    struct socket_address {
        alignas(std::uint64_t) std::array<std::byte, 32> bytes{};
        unsigned length = 0;
        auto data() noexcept -> void* { return bytes.data(); }
        auto data() const noexcept -> const void* { return bytes.data(); }
        auto size() const noexcept -> unsigned { return length; }
        auto operator==(const socket_address&) const -> bool = default;
    };
    auto family(bool v6) noexcept -> int;
    auto make_address(bool v6, const unsigned char*, std::uint16_t, unsigned long = 0) -> socket_address;
    void address_bytes(const socket_address&, unsigned char*) noexcept;
    auto address_port(const socket_address&) noexcept -> std::uint16_t;
    auto address_scope(const socket_address&) noexcept -> unsigned long;
    auto is_v6(const socket_address&) noexcept -> bool;
    auto parse_address(std::string_view, bool, std::error_code&) noexcept -> socket_address;
    auto address_string(const socket_address&) -> std::string;
    enum class operation { post, read, write, read_at, write_at, connect, accept, readable, timer, receive, receive_from, send, send_to };

    inline constexpr std::size_t max_buffers = 16;
    struct buffer {
        void* data = nullptr;
        std::size_t size = 0;
    };

    struct alignas(std::max_align_t) request {
        operation kind = operation::post;
        handle file = invalid_handle;
        void* buffer = nullptr;
        std::size_t size = 0;
        std::array<native_io::buffer, max_buffers> buffers{};
        unsigned buffer_count = 0;
        int flags = 0;
        int events = 1;
        std::uint64_t offset = 0;
        socket_address address;
        std::chrono::steady_clock::time_point deadline{};
        void (*complete)(request&, std::int64_t, std::error_code) noexcept = nullptr;
        std::atomic<bool> cancelled{false};
        std::atomic<bool> closed{false};
        const std::atomic<bool>* lifetime_closed = nullptr;
        std::shared_ptr<void> lifetime;
        auto is_closed() const noexcept -> bool {
            return closed.load(std::memory_order_acquire) || (lifetime_closed && lifetime_closed->load(std::memory_order_acquire));
        }

        request* next = nullptr;
        request* registered_next = nullptr;
        request** registered_previous = nullptr;
        request* active_next = nullptr;
        request** active_previous = nullptr;
        bool rejected = false;
        bool cancel_sent = false;
        bool cancel_acknowledged = false;
        bool result_ready = false;
        std::int64_t result = 0;
        std::error_code error;
        // Each mechanism constructs its typed state before accessing it.
        alignas(std::max_align_t) std::array<std::byte, 512> native;
    };

    template <template <class> class Queue = http::queues::locked> class engine {
    public:
        engine();
        ~engine();
        engine(const engine&) = delete;
        auto operator=(const engine&) -> engine& = delete;
        void start(request&) noexcept;
        void cancel(request&) noexcept;
        void cancel_file(handle) noexcept;
        void run();
        void stop() noexcept;
        static auto name() noexcept -> const char*;

    private:
        struct impl;
        std::unique_ptr<impl> impl_;
    };

    auto open_socket(bool datagram, bool v6) -> handle;
    void listen(handle, int);
    auto socket_endpoint(handle, bool remote = false) -> socket_address;
    void bind(handle, socket_address);
    void connect_datagram(handle, socket_address);
    void set_option(handle, int, bool);
    void configure_stream(handle) noexcept;
    void shutdown(handle, int) noexcept;
    void close_socket(handle) noexcept;
    auto open_file(const char* path, bool write) -> handle;
    void close_file(handle) noexcept;
} // namespace native_io

export namespace http::io::net {
    template <class Protocol, template <class> class Queue = http::queues::locked> class basic_socket;
    template <class Protocol, template <class> class Queue = http::queues::locked> class basic_stream_socket;
    template <class Protocol, template <class> class Queue = http::queues::locked> class basic_datagram_socket;
    template <class Protocol, template <class> class Queue = http::queues::locked> class basic_socket_acceptor;
    template <template <class> class Queue = http::queues::locked> class basic_io_context;
    using io_context = basic_io_context<>;
    namespace ip {
        class address_v4 {
        public:
            using bytes_type = std::array<unsigned char, 4>;
            using uint_type = std::uint_least32_t;
            constexpr address_v4() noexcept = default;
            constexpr explicit address_v4(bytes_type bytes) noexcept : bytes_(bytes) {}
            constexpr explicit address_v4(uint_type value) noexcept
                : bytes_{static_cast<unsigned char>(value >> 24), static_cast<unsigned char>(value >> 16), static_cast<unsigned char>(value >> 8),
                         static_cast<unsigned char>(value)} {}
            constexpr auto to_bytes() const noexcept -> bytes_type { return bytes_; }
            constexpr auto to_uint() const noexcept -> uint_type {
                return (uint_type{bytes_[0]} << 24) | (uint_type{bytes_[1]} << 16) | (uint_type{bytes_[2]} << 8) | bytes_[3];
            }
            auto to_string() const -> std::string { return native_io::address_string(native_io::make_address(false, bytes_.data(), 0)); }
            constexpr auto is_loopback() const noexcept -> bool { return bytes_[0] == 127; }
            constexpr auto is_unspecified() const noexcept -> bool { return to_uint() == 0; }
            constexpr auto is_multicast() const noexcept -> bool { return bytes_[0] >= 224 && bytes_[0] <= 239; }
            static constexpr auto any() noexcept -> address_v4 { return address_v4{}; }
            static constexpr auto loopback() noexcept -> address_v4 { return address_v4{0x7f000001}; }
            static constexpr auto broadcast() noexcept -> address_v4 { return address_v4{0xffffffff}; }
            auto operator==(const address_v4&) const -> bool = default;
            auto operator<=>(const address_v4&) const = default;

        private:
            bytes_type bytes_{};
        };
        class address_v6 {
        public:
            using bytes_type = std::array<unsigned char, 16>;
            constexpr address_v6() noexcept = default;
            constexpr explicit address_v6(bytes_type bytes, unsigned long scope = 0) noexcept : bytes_(bytes), scope_(scope) {}
            constexpr auto to_bytes() const noexcept -> bytes_type { return bytes_; }
            constexpr auto scope_id() const noexcept -> unsigned long { return scope_; }
            constexpr void scope_id(unsigned long value) noexcept { scope_ = value; }
            auto to_string() const -> std::string { return native_io::address_string(native_io::make_address(true, bytes_.data(), 0, scope_)); }
            constexpr auto is_unspecified() const noexcept -> bool { return bytes_ == bytes_type{}; }
            constexpr auto is_loopback() const noexcept -> bool { return *this == loopback(); }
            constexpr auto is_multicast() const noexcept -> bool { return bytes_[0] == 255; }
            static constexpr auto any() noexcept -> address_v6 { return {}; }
            static constexpr auto loopback() noexcept -> address_v6 {
                bytes_type bytes{};
                bytes[15] = 1;
                return address_v6{bytes};
            }
            auto operator==(const address_v6&) const -> bool = default;
            auto operator<=>(const address_v6&) const = default;

        private:
            bytes_type bytes_{};
            unsigned long scope_ = 0;
        };
        class address {
        public:
            constexpr address() noexcept = default;
            constexpr address(address_v4 value) noexcept : value_(value) {}
            constexpr address(address_v6 value) noexcept : value_(value) {}
            constexpr auto is_v4() const noexcept -> bool { return value_.index() == 0; }
            constexpr auto is_v6() const noexcept -> bool { return value_.index() == 1; }
            auto to_v4() const -> address_v4 { return std::get<address_v4>(value_); }
            auto to_v6() const -> address_v6 { return std::get<address_v6>(value_); }
            auto to_string() const -> std::string {
                return std::visit([](auto a) { return a.to_string(); }, value_);
            }
            auto is_loopback() const noexcept -> bool {
                return std::visit([](auto a) { return a.is_loopback(); }, value_);
            }
            auto is_unspecified() const noexcept -> bool {
                return std::visit([](auto a) { return a.is_unspecified(); }, value_);
            }
            auto is_multicast() const noexcept -> bool {
                return std::visit([](auto a) { return a.is_multicast(); }, value_);
            }
            auto operator==(const address&) const -> bool = default;
            auto operator<=>(const address&) const = default;

        private:
            std::variant<address_v4, address_v6> value_;
        };
        inline auto make_address_v4(std::string_view text, std::error_code& error) noexcept -> address_v4 {
            auto a = native_io::parse_address(text, false, error);
            address_v4::bytes_type bytes{};
            if (error)
                return {};
            native_io::address_bytes(a, bytes.data());
            return address_v4{bytes};
        }
        inline auto make_address_v6(std::string_view text, std::error_code& error) noexcept -> address_v6 {
            auto a = native_io::parse_address(text, true, error);
            address_v6::bytes_type bytes{};
            if (error)
                return {};
            native_io::address_bytes(a, bytes.data());
            return address_v6{bytes, native_io::address_scope(a)};
        }
        inline auto make_address(std::string_view text, std::error_code& error) noexcept -> address {
            if (text.find(':') != text.npos)
                return make_address_v6(text, error);
            return make_address_v4(text, error);
        }
        inline auto make_address_v4(std::string_view text) -> address_v4 {
            std::error_code error;
            auto a = make_address_v4(text, error);
            if (error)
                throw std::system_error(error);
            return a;
        }
        inline auto make_address_v6(std::string_view text) -> address_v6 {
            std::error_code error;
            auto a = make_address_v6(text, error);
            if (error)
                throw std::system_error(error);
            return a;
        }
        inline auto make_address(std::string_view text) -> address {
            std::error_code error;
            auto a = make_address(text, error);
            if (error)
                throw std::system_error(error);
            return a;
        }
        template <class Protocol, template <class> class Queue = http::queues::locked> class basic_endpoint {
        public:
            using protocol_type = Protocol;
            using data_type = void;
            basic_endpoint() : basic_endpoint(Protocol::v4(), 0) {}
            basic_endpoint(Protocol protocol, std::uint16_t port)
                : basic_endpoint(protocol.family() == native_io::family(true) ? ip::address{address_v6{}} : ip::address{address_v4{}}, port) {}
            basic_endpoint(const ip::address& a, std::uint16_t port) {
                if (a.is_v6()) {
                    auto v = a.to_v6();
                    auto bytes = v.to_bytes();
                    value_ = native_io::make_address(true, bytes.data(), port, v.scope_id());
                } else {
                    auto bytes = a.to_v4().to_bytes();
                    value_ = native_io::make_address(false, bytes.data(), port);
                }
            }
            auto protocol() const noexcept -> Protocol { return native_io::is_v6(value_) ? Protocol::v6() : Protocol::v4(); }
            auto address() const -> ip::address {
                if (native_io::is_v6(value_)) {
                    address_v6::bytes_type bytes{};
                    native_io::address_bytes(value_, bytes.data());
                    return address_v6{bytes, native_io::address_scope(value_)};
                }
                address_v4::bytes_type bytes{};
                native_io::address_bytes(value_, bytes.data());
                return address_v4{bytes};
            }
            void address(const ip::address& a) { *this = basic_endpoint{a, port()}; }
            auto port() const noexcept -> std::uint16_t { return native_io::address_port(value_); }
            void port(std::uint16_t p) { *this = basic_endpoint{address(), p}; }
            auto data() noexcept -> data_type* { return value_.data(); }
            auto data() const noexcept -> const data_type* { return value_.data(); }
            auto size() const noexcept -> std::size_t { return value_.size(); }
            auto capacity() const noexcept -> std::size_t { return value_.bytes.size(); }
            void resize(std::size_t n) {
                if (n > capacity())
                    throw std::length_error("endpoint size");
                value_.length = static_cast<unsigned>(n);
            }
            auto operator==(const basic_endpoint& other) const -> bool { return address() == other.address() && port() == other.port(); }

        private:
            native_io::socket_address value_;
        };
        class tcp {
        public:
            using endpoint = basic_endpoint<tcp>;
            using socket = basic_stream_socket<tcp>;
            using acceptor = basic_socket_acceptor<tcp>;
            class no_delay {
            public:
                explicit no_delay(bool value = false) : value_(value) {}
                auto value() const noexcept -> bool { return value_; }
                static constexpr int key = 2;

            private:
                bool value_;
            };
            static auto v4() noexcept -> tcp { return tcp{false}; }
            static auto v6() noexcept -> tcp { return tcp{true}; }
            auto family() const noexcept -> int { return native_io::family(v6_); }
            auto type() const noexcept -> int { return 1; }
            auto protocol() const noexcept -> int { return 6; }
            auto operator==(const tcp&) const -> bool = default;

        private:
            explicit tcp(bool value) : v6_(value) {}
            bool v6_;
        };
        class udp {
        public:
            using endpoint = basic_endpoint<udp>;
            using socket = basic_datagram_socket<udp>;
            static auto v4() noexcept -> udp { return udp{false}; }
            static auto v6() noexcept -> udp { return udp{true}; }
            auto family() const noexcept -> int { return native_io::family(v6_); }
            auto type() const noexcept -> int { return 2; }
            auto protocol() const noexcept -> int { return 17; }
            auto operator==(const udp&) const -> bool = default;

        private:
            explicit udp(bool value) : v6_(value) {}
            bool v6_;
        };
    } // namespace ip
    class mutable_buffer {
    public:
        constexpr mutable_buffer() noexcept = default;
        constexpr mutable_buffer(void* p, std::size_t n) noexcept : data_(p), size_(n) {}
        constexpr auto data() const noexcept -> void* { return data_; }
        constexpr auto size() const noexcept -> std::size_t { return size_; }
        auto operator+=(std::size_t n) noexcept -> mutable_buffer& {
            n = std::min(n, size_);
            data_ = static_cast<std::byte*>(data_) + n;
            size_ -= n;
            return *this;
        }

    private:
        void* data_ = nullptr;
        std::size_t size_ = 0;
    };
    class const_buffer {
    public:
        constexpr const_buffer() noexcept = default;
        constexpr const_buffer(const void* p, std::size_t n) noexcept : data_(p), size_(n) {}
        constexpr const_buffer(mutable_buffer b) noexcept : data_(b.data()), size_(b.size()) {}
        constexpr auto data() const noexcept -> const void* { return data_; }
        constexpr auto size() const noexcept -> std::size_t { return size_; }
        auto operator+=(std::size_t n) noexcept -> const_buffer& {
            n = std::min(n, size_);
            data_ = static_cast<const std::byte*>(data_) + n;
            size_ -= n;
            return *this;
        }

    private:
        const void* data_ = nullptr;
        std::size_t size_ = 0;
    };
    inline auto buffer(void* p, std::size_t n) noexcept -> mutable_buffer { return {p, n}; }
    inline auto buffer(const void* p, std::size_t n) noexcept -> const_buffer { return {p, n}; }
    inline auto buffer(mutable_buffer b) noexcept -> mutable_buffer { return b; }
    inline auto buffer(const_buffer b) noexcept -> const_buffer { return b; }
    template <class T, std::size_t N> auto buffer(std::span<T, N> bytes) noexcept { return buffer(bytes.data(), bytes.size_bytes()); }
    template <class T, std::size_t N> auto buffer(T (&a)[N]) noexcept { return buffer(a, N * sizeof(T)); }
    template <class T> auto buffer(T& value) noexcept { return buffer(std::data(value), std::size(value) * sizeof(*std::data(value))); }
    inline auto operator+(mutable_buffer b, std::size_t n) noexcept -> mutable_buffer { return b += n; }
    inline auto operator+(const_buffer b, std::size_t n) noexcept -> const_buffer { return b += n; }
    inline auto buffer_sequence_begin(const mutable_buffer& b) noexcept { return &b; }
    inline auto buffer_sequence_end(const mutable_buffer& b) noexcept { return &b + 1; }
    inline auto buffer_sequence_begin(const const_buffer& b) noexcept { return &b; }
    inline auto buffer_sequence_end(const const_buffer& b) noexcept { return &b + 1; }
    template <class C> auto buffer_sequence_begin(C& c) noexcept(noexcept(c.begin())) -> decltype(c.begin()) { return c.begin(); }
    template <class C> auto buffer_sequence_end(C& c) noexcept(noexcept(c.end())) -> decltype(c.end()) { return c.end(); }
    template <class T, std::size_t N> auto buffer_sequence_begin(T (&a)[N]) noexcept { return a; }
    template <class T, std::size_t N> auto buffer_sequence_end(T (&a)[N]) noexcept { return a + N; }
    class socket_base {
    public:
        using message_flags = int;
        static constexpr message_flags message_out_of_band = 1;
        static constexpr message_flags message_peek = 2;
        static constexpr message_flags message_do_not_route = 4;
        enum wait_type { wait_read = 1, wait_write = 2, wait_error = 4 };
        enum shutdown_type { shutdown_receive, shutdown_send, shutdown_both };
        static constexpr int max_listen_connections = 1024;
        template <int Key> class boolean_option {
        public:
            explicit boolean_option(bool value = false) noexcept : value_(value) {}
            auto value() const noexcept -> bool { return value_; }
            static constexpr int key = Key;

        private:
            bool value_;
        };
        using reuse_address = boolean_option<0>;
        using keep_alive = boolean_option<1>;
    };
    constexpr auto operator|(socket_base::wait_type a, socket_base::wait_type b) noexcept -> socket_base::wait_type {
        return static_cast<socket_base::wait_type>(static_cast<int>(a) | static_cast<int>(b));
    }
    constexpr auto operator&(socket_base::wait_type a, socket_base::wait_type b) noexcept -> socket_base::wait_type {
        return static_cast<socket_base::wait_type>(static_cast<int>(a) & static_cast<int>(b));
    }

} // namespace http::io::net
