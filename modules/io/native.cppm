export module httpant.io;
import std;

export namespace native_io {
    using handle = std::intptr_t;
    inline constexpr handle invalid_handle = -1;
    struct endpoint {
        std::array<std::uint8_t, 4> ip{127, 0, 0, 1};
        std::uint16_t port = 0;
    };
    enum class operation { post, read, write, read_at, write_at, connect, accept, readable, timer };

    struct alignas(std::max_align_t) request {
        operation kind = operation::post;
        handle file = invalid_handle;
        void* buffer = nullptr;
        std::size_t size = 0;
        std::uint64_t offset = 0;
        endpoint address;
        std::chrono::steady_clock::time_point deadline{};
        void (*complete)(request&, std::int64_t, std::error_code) noexcept = nullptr;
        std::atomic<bool> cancelled{false};
        std::atomic<bool> closed{false};
        const std::atomic<bool>* lifetime_closed = nullptr;
        auto is_closed() const noexcept -> bool {
            return closed.load(std::memory_order_acquire) || (lifetime_closed && lifetime_closed->load(std::memory_order_acquire));
        }

        request* next = nullptr;
        request* active_next = nullptr;
        bool cancel_sent = false;
        bool cancel_acknowledged = false;
        bool result_ready = false;
        std::int64_t result = 0;
        std::error_code error;
        alignas(std::max_align_t) std::array<std::byte, 128> native{};
    };

    class engine {
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

    auto open_socket(bool datagram = false) -> handle;
    auto listen(endpoint, int backlog = 1024) -> handle;
    auto local_port(handle) -> std::uint16_t;
    void bind(handle, endpoint);
    void connect_datagram(handle, endpoint);
    void configure_stream(handle) noexcept;
    void shutdown(handle) noexcept;
    void close_socket(handle) noexcept;
    auto open_file(const char* path, bool write) -> handle;
    void close_file(handle) noexcept;
} // namespace native_io
