export module httpant.io:execution;
import std;
import httpant.dependencies.stdexec;
import :native;
import :mechanism;

export namespace http::io::net {
    template <template <class> class Queue = http::queues::locked> class basic_scheduler;
    using scheduler = basic_scheduler<>;
    namespace detail {
        template <template <class> class Queue> struct resource {
            native_io::engine<Queue>* context;
            auto get_scheduler() const noexcept -> http::io::net::basic_scheduler<Queue>;
            friend bool operator==(resource, resource) = default;
        };
        template <template <class> class Queue> struct environment {
            resource<Queue> source;
            auto query(stdexec::get_completion_scheduler_t<stdexec::set_value_t>) const noexcept -> basic_scheduler<Queue>;
            auto query(stdexec::get_completion_scheduler_t<stdexec::set_stopped_t>) const noexcept -> basic_scheduler<Queue>;
        };
        template <class... Values> struct result { std::tuple<Values...> values; };
        template <class Value> struct value_sig {
            using type = stdexec::set_value_t(Value);
        };
        template <class... Values> struct value_sig<result<Values...>> {
            using type = stdexec::set_value_t(Values...);
        };
        template <> struct value_sig<void> {
            using type = stdexec::set_value_t();
        };
        template <class Value>
        using signatures = stdexec::completion_signatures<typename value_sig<Value>::type, stdexec::set_error_t(std::error_code),
                                                            stdexec::set_error_t(std::exception_ptr), stdexec::set_stopped_t()>;
        struct handle_state {
            native_io::handle value;
            bool file;
            std::atomic<bool> closed{false};
            handle_state(native_io::handle value, bool file) : value(value), file(file) {}
            ~handle_state() {
                if (file)
                    native_io::close_file(value);
                else
                    native_io::close_socket(value);
            }
        };
        template <template <class> class Queue> struct specification {
            native_io::operation kind;
            detail::resource<Queue> resource;
            native_io::handle file = native_io::invalid_handle;
            void* buffer = nullptr;
            std::size_t size = 0;
            std::array<native_io::buffer, native_io::max_buffers> buffers{};
            unsigned buffer_count = 0;
            // A datagram cannot be split, so one that needs more descriptors fails.
            bool oversized = false;
            int flags = 0;
            int events = 1;
            std::uint64_t offset = 0;
            native_io::socket_address address;
            std::chrono::steady_clock::time_point deadline{};
            std::shared_ptr<handle_state> keepalive;
        };
        template <class Sequence, class Buffer> concept buffer_sequence = requires(const Sequence& sequence) {
            { *net::buffer_sequence_begin(sequence) } -> std::convertible_to<Buffer>;
            net::buffer_sequence_end(sequence);
        };
        template <class Buffer, class Sequence, template <class> class Queue> auto set_buffers(specification<Queue>& spec, const Sequence& sequence) noexcept -> bool {
            auto end = net::buffer_sequence_end(sequence);
            auto it = net::buffer_sequence_begin(sequence);
            for (; it != end && spec.buffer_count < native_io::max_buffers; ++it) {
                Buffer b{*it};
                if (b.size()) spec.buffers[spec.buffer_count++] = {const_cast<void*>(static_cast<const void*>(b.data())), b.size()};
            }
            return it == end;
        }
        template <class Protocol> inline constexpr bool datagram = std::same_as<typename Protocol::socket, basic_datagram_socket<Protocol>>;
        struct count_result {
            auto operator()(native_io::request&, std::int64_t n) const noexcept -> std::size_t { return static_cast<std::size_t>(n); }
        };
        struct done_result {
            void operator()(native_io::request&, std::int64_t) const noexcept {}
        };
        struct relative_timer_result {
            std::chrono::nanoseconds delay;
            void operator()(native_io::request&, std::int64_t) const noexcept {}
        };

        template <template <class> class Queue, class Value, class Finish, bool Network = false> struct sender {
            using sender_concept = stdexec::sender_t;
            using completion_signatures = std::conditional_t<Network, stdexec::completion_signatures<typename value_sig<Value>::type, stdexec::set_error_t(std::error_code), stdexec::set_stopped_t()>, signatures<Value>>;
            specification<Queue> spec;
            [[no_unique_address]] Finish finish;
            auto get_env() const noexcept -> environment<Queue> { return {spec.resource}; }
            template <class R> struct op : native_io::request {
                using operation_state_concept = stdexec::operation_state_t;
                R receiver;
                detail::resource<Queue> resource;
                [[no_unique_address]] Finish finish;
                std::shared_ptr<handle_state> keepalive;
                bool oversized;
                struct on_stop {
                    op* self;
                    void operator()() const noexcept { self->resource.context->cancel(*self); }
                };
                using token = stdexec::stop_token_of_t<stdexec::env_of_t<R>>;
                std::optional<stdexec::stop_callback_for_t<token, on_stop>> watch;
                op(R r, sender source) noexcept(std::is_nothrow_move_constructible_v<R>)
                    : receiver(std::move(r)), resource(source.spec.resource), finish(std::move(source.finish)), keepalive(std::move(source.spec.keepalive)), oversized(source.spec.oversized) {
                    this->kind = source.spec.kind;
                    this->file = source.spec.file;
                    this->buffer = source.spec.buffer;
                    this->size = source.spec.size;
                    this->buffers = source.spec.buffers;
                    this->buffer_count = source.spec.buffer_count;
                    this->flags = source.spec.flags;
                    this->events = source.spec.events;
                    this->offset = source.spec.offset;
                    this->address = source.spec.address;
                    this->deadline = source.spec.deadline;
                    this->lifetime_closed = keepalive ? &keepalive->closed : nullptr;
                    this->complete = [](native_io::request& request, std::int64_t value, std::error_code error) noexcept {
                        auto& self = static_cast<op&>(request);
                        self.watch.reset();
                        auto receiver = std::move(self.receiver);
                        if (!self.rejected && self.cancelled.load(std::memory_order_acquire) && (error || value < 0)) {
                            stdexec::set_stopped(std::move(receiver));
                            return;
                        }
                        if (error) {
                            stdexec::set_error(std::move(receiver), error);
                            return;
                        }
                        try {
                            if constexpr (std::is_void_v<Value>) {
                                std::invoke(self.finish, self, value);
                                stdexec::set_value(std::move(receiver));
                            } else {
                                auto result = std::invoke(self.finish, self, value);
                                if constexpr (requires { result.values; })
                                    std::apply([&](auto&&... values) { stdexec::set_value(std::move(receiver), std::move(values)...); }, std::move(result.values));
                                else
                                    stdexec::set_value(std::move(receiver), std::move(result));
                            }
                        } catch (const std::system_error& error) {
                            if constexpr (Network) stdexec::set_error(std::move(receiver), error.code());
                            else stdexec::set_error(std::move(receiver), std::current_exception());
                        } catch (const std::bad_alloc&) {
                            if constexpr (Network) stdexec::set_error(std::move(receiver), std::make_error_code(std::errc::not_enough_memory));
                            else stdexec::set_error(std::move(receiver), std::current_exception());
                        } catch (...) {
                            if constexpr (Network) stdexec::set_error(std::move(receiver), std::make_error_code(std::errc::io_error));
                            else stdexec::set_error(std::move(receiver), std::current_exception());
                        }
                    };
                }
                op(op&&) = delete;
                void start() & noexcept {
                    if constexpr (Network) {
                        auto env = stdexec::get_env(receiver);
                        if constexpr (requires { stdexec::get_start_scheduler(env); }) {
                            auto scheduler = stdexec::get_start_scheduler(env);
                            if constexpr (requires { scheduler.engine(); }) {
                                if (static_cast<const void*>(scheduler.engine()) != static_cast<const void*>(resource.context)) {
                                    stdexec::set_error(std::move(receiver), std::make_error_code(std::errc::invalid_argument));
                                    return;
                                }
                            } else {
                                stdexec::set_error(std::move(receiver), std::make_error_code(std::errc::invalid_argument));
                                return;
                            }
                        }
                        if (oversized) {
                            stdexec::set_error(std::move(receiver), std::make_error_code(std::errc::message_size));
                            return;
                        }
                    }
                    if constexpr (std::same_as<Finish, relative_timer_result>)
                        this->deadline = std::chrono::steady_clock::now() + finish.delay;
                    try {
                        watch.emplace(stdexec::get_stop_token(stdexec::get_env(receiver)), on_stop{this});
                    } catch (...) {
                        auto failure = std::current_exception();
                        auto target = std::move(receiver);
                        if constexpr (Network) stdexec::set_error(std::move(target), std::make_error_code(std::errc::not_enough_memory));
                        else stdexec::set_error(std::move(target), std::move(failure));
                        return;
                    }
                    resource.context->start(*this);
                }
            };
            template <stdexec::receiver R> auto connect(R receiver) const & noexcept(std::is_nothrow_move_constructible_v<R>) -> op<R> { return {std::move(receiver), *this}; }
            template <stdexec::receiver R> auto connect(R receiver) && noexcept(std::is_nothrow_move_constructible_v<R>) -> op<R> { return {std::move(receiver), std::move(*this)}; }
        };
    } // namespace detail

    template <template <class> class Queue = http::queues::locked> class basic_file;
    using file = basic_file<>;
    template <template <class> class Queue> class basic_scheduler {
    public:
        using scheduler_concept = stdexec::scheduler_t;
        using socket_type = basic_stream_socket<ip::tcp, Queue>;
        using acceptor_type = basic_socket_acceptor<ip::tcp, Queue>;
        explicit basic_scheduler(detail::resource<Queue> resource) noexcept : resource_(resource) {}
        friend bool operator==(const basic_scheduler&, const basic_scheduler&) = default;
        auto query(stdexec::get_forward_progress_guarantee_t) const noexcept -> stdexec::forward_progress_guarantee {
            return stdexec::forward_progress_guarantee::parallel;
        }
        auto schedule() const noexcept { return detail::sender<Queue, void, detail::done_result>{{.kind = native_io::operation::post, .resource = resource_}, {}}; }
        auto open_file(const std::filesystem::path& path, bool write = false) const -> basic_file<Queue>;
        auto engine() const noexcept -> native_io::engine<Queue>* { return resource_.context; }
        auto now() const noexcept { return std::chrono::steady_clock::now(); }
        auto schedule_at(std::chrono::steady_clock::time_point at) const {
            return detail::sender<Queue, void, detail::done_result>{{.kind = native_io::operation::timer, .resource = resource_, .deadline = at}, {}};
        }
        auto schedule_after(std::chrono::nanoseconds duration) const {
            return detail::sender<Queue, void, detail::relative_timer_result>{{.kind = native_io::operation::timer, .resource = resource_}, {duration}};
        }

    private:
        detail::resource<Queue> resource_;
    };

    namespace detail { struct access; }
    template <class Protocol, template <class> class Queue> class basic_socket : public socket_base {
    public:
        using protocol_type = Protocol;
        using endpoint_type = typename Protocol::endpoint;
        using native_handle_type = native_io::handle;
        explicit basic_socket(basic_io_context<Queue>& context);
        explicit basic_socket(basic_scheduler<Queue> scheduler);
        basic_socket(basic_io_context<Queue>& context, Protocol protocol) : basic_socket(context) { open(protocol); }
        basic_socket(basic_scheduler<Queue> scheduler, Protocol protocol) : basic_socket(scheduler) { open(protocol); }
        basic_socket(basic_scheduler<Queue> scheduler, Protocol, native_handle_type handle) : basic_socket(scheduler) { assign(handle); }
        basic_socket(basic_io_context<Queue>& context, Protocol, native_handle_type handle) : basic_socket(context) { assign(handle); }
        basic_socket(basic_socket&&) noexcept = default;
        auto operator=(basic_socket&& other) noexcept -> basic_socket& {
            if (this != &other) { close(); state_ = std::move(other.state_); resource_ = other.resource_; }
            return *this;
        }
        ~basic_socket() { close(); }
        auto get_scheduler() const noexcept -> basic_scheduler<Queue>;
        void open(Protocol protocol = Protocol::v4()) {
            if (is_open()) throw std::system_error(std::make_error_code(std::errc::device_or_resource_busy));
            assign(native_io::open_socket(std::same_as<Protocol, ip::udp>, protocol.family() == native_io::family(true)));
        }
        void bind(const endpoint_type& ep) { native_io::bind(native_handle(), detail_address(ep)); }
        void connect(const endpoint_type& ep) { native_io::connect_datagram(native_handle(), detail_address(ep)); }
        void shutdown(shutdown_type direction) noexcept { native_io::shutdown(native_handle(), direction); }
        void close() noexcept {
            if (!state_) return;
            state_->closed.store(true, std::memory_order_release);
            resource_.context->cancel_file(state_->value); state_.reset();
        }
        auto native_handle() const noexcept -> native_handle_type { return state_ ? state_->value : native_io::invalid_handle; }
        auto is_open() const noexcept -> bool { return state_ != nullptr; }
        auto local_endpoint() const -> endpoint_type { return from_address(native_io::socket_endpoint(native_handle())); }
        auto remote_endpoint() const -> endpoint_type { return from_address(native_io::socket_endpoint(native_handle(), true)); }
        template <class Option> void set_option(const Option& option) { native_io::set_option(native_handle(), Option::key, option.value()); }
    protected:
        std::shared_ptr<detail::handle_state> state_;
        detail::resource<Queue> resource_{};
    private:
        friend struct detail::access;
        void assign(native_handle_type handle) {
            try { state_ = std::make_shared<detail::handle_state>(handle, false); }
            catch (...) { native_io::close_socket(handle); throw; }
        }
        static auto detail_address(const endpoint_type& ep) noexcept -> native_io::socket_address {
            native_io::socket_address a; std::memcpy(a.data(), ep.data(), ep.size()); a.length = ep.size(); return a;
        }
        static auto from_address(const native_io::socket_address& a) -> endpoint_type {
            endpoint_type ep; std::memcpy(ep.data(), a.data(), a.size()); ep.resize(a.size()); return ep;
        }
    };
    template <class Protocol, template <class> class Queue> class basic_stream_socket : public basic_socket<Protocol, Queue> {
    public:
        using basic_socket<Protocol, Queue>::basic_socket;
        friend auto read_some(basic_stream_socket& socket, std::span<std::byte> bytes) noexcept { return read_chunk(socket, bytes); }
        friend auto write_some(basic_stream_socket& socket, std::span<const std::byte> bytes) noexcept { return write_chunk(socket, bytes); }
    };
    template <class Protocol, template <class> class Queue> class basic_datagram_socket : public basic_socket<Protocol, Queue> {
    public:
        using basic_socket<Protocol, Queue>::basic_socket;
        basic_datagram_socket(basic_scheduler<Queue> scheduler, const typename Protocol::endpoint& ep) : basic_socket<Protocol, Queue>(scheduler, ep.protocol()) { this->bind(ep); }
        basic_datagram_socket(basic_io_context<Queue>& context, const typename Protocol::endpoint& ep) : basic_socket<Protocol, Queue>(context, ep.protocol()) { this->bind(ep); }
    };
    template <class Protocol, template <class> class Queue> class basic_socket_acceptor : public basic_socket<Protocol, Queue> {
    public:
        using basic_socket<Protocol, Queue>::basic_socket;
        using socket_type = basic_stream_socket<Protocol, Queue>;
        basic_socket_acceptor(basic_scheduler<Queue> scheduler, const typename Protocol::endpoint& ep, bool reuse = true)
            : basic_socket<Protocol, Queue>(scheduler, ep.protocol()) {
            this->set_option(socket_base::reuse_address{reuse}); this->bind(ep); listen();
        }
        basic_socket_acceptor(basic_io_context<Queue>& context, const typename Protocol::endpoint& ep, bool reuse = true);
        void listen(int backlog = socket_base::max_listen_connections) { native_io::listen(this->native_handle(), backlog); }
    };

    template <template <class> class Queue> class basic_file {
    public:
        basic_file(native_io::handle handle, detail::resource<Queue> resource) : resource_(resource) {
            try {
                state_ = std::make_shared<detail::handle_state>(handle, true);
            } catch (...) {
                native_io::close_file(handle);
                throw;
            }
        }
        basic_file(basic_file&&) noexcept = default;
        auto operator=(basic_file&& other) noexcept -> basic_file<Queue>& {
            if (this != &other) {
                close();
                state_ = std::move(other.state_);
                resource_ = other.resource_;
            }
            return *this;
        }
        ~basic_file() { close(); }
        auto read_at(std::span<std::byte> into, std::uint64_t offset) {
            return detail::sender<Queue, std::size_t, detail::count_result>{{.kind = native_io::operation::read_at,
                                                                      .resource = resource_,
                                                                      .file = state_ ? state_->value : native_io::invalid_handle,
                                                                      .buffer = into.data(),
                                                                      .size = into.size(),
                                                                      .offset = offset,
                                                                      .keepalive = state_},
                                                                     {}};
        }
        auto write_at(std::span<const std::byte> from, std::uint64_t offset) {
            return detail::sender<Queue, std::size_t, detail::count_result>{{.kind = native_io::operation::write_at,
                                                                      .resource = resource_,
                                                                      .file = state_ ? state_->value : native_io::invalid_handle,
                                                                      .buffer = const_cast<std::byte*>(from.data()),
                                                                      .size = from.size(),
                                                                      .offset = offset,
                                                                      .keepalive = state_},
                                                                     {}};
        }
        void close() noexcept {
            if (!state_)
                return;
            state_->closed.store(true, std::memory_order_release);
            resource_.context->cancel_file(state_->value);
            state_.reset();
        }

    private:
        std::shared_ptr<detail::handle_state> state_;
        detail::resource<Queue> resource_;
    };

    template <template <class> class Queue>
    inline auto basic_scheduler<Queue>::open_file(const std::filesystem::path& path, bool write) const -> basic_file<Queue> {
        auto utf8 = path.u8string();
        return {native_io::open_file(reinterpret_cast<const char*>(utf8.c_str()), write), resource_};
    }

    template <template <class> class Queue> class basic_io_context {
    public:
        using scheduler_type = http::io::net::basic_scheduler<Queue>;
        using count_type = std::uint32_t;
        basic_io_context() = default;
        basic_io_context(const basic_io_context&) = delete;
        auto get_scheduler() noexcept -> scheduler_type { return basic_scheduler<Queue>{{&engine_}}; }
        void run() { engine_.run(); }
        void stop() noexcept { engine_.stop(); }
        static auto mechanism() noexcept -> std::string_view { return native_io::engine<Queue>::name(); }

    private:
        native_io::engine<Queue> engine_;
    };

    template <template <class> class Queue>
    inline auto detail::resource<Queue>::get_scheduler() const noexcept -> http::io::net::basic_scheduler<Queue> { return http::io::net::basic_scheduler<Queue>{*this}; }
    template <class Protocol, template <class> class Queue> basic_socket<Protocol, Queue>::basic_socket(basic_scheduler<Queue> s) : resource_{s.engine()} {}
    template <class Protocol, template <class> class Queue> basic_socket<Protocol, Queue>::basic_socket(basic_io_context<Queue>& c) : basic_socket(c.get_scheduler()) {}
    template <class Protocol, template <class> class Queue> auto basic_socket<Protocol, Queue>::get_scheduler() const noexcept -> basic_scheduler<Queue> { return resource_.get_scheduler(); }
    template <class Protocol, template <class> class Queue> basic_socket_acceptor<Protocol, Queue>::basic_socket_acceptor(basic_io_context<Queue>& c, const typename Protocol::endpoint& ep, bool reuse)
        : basic_socket_acceptor(c.get_scheduler(), ep, reuse) {}
    template <template <class> class Queue>
    auto detail::environment<Queue>::query(stdexec::get_completion_scheduler_t<stdexec::set_value_t>) const noexcept -> basic_scheduler<Queue> { return source.get_scheduler(); }
    template <template <class> class Queue>
    auto detail::environment<Queue>::query(stdexec::get_completion_scheduler_t<stdexec::set_stopped_t>) const noexcept -> basic_scheduler<Queue> { return source.get_scheduler(); }
    namespace detail {
        template <class Operation, class Resource> struct operation_factory {
            Resource* resource;
            template <class... Args> auto operator()(Args&... args) const noexcept(noexcept(Operation{}(*resource, args...))) { return Operation{}(*resource, args...); }
        };

        template <class Operation, class Resource> struct operation_adaptor : stdexec::sender_adaptor_closure<operation_adaptor<Operation, Resource>> {
            Resource* resource;
            explicit operation_adaptor(Resource& r) noexcept : resource(&r) {}
            template <stdexec::sender Sender> auto operator()(Sender&& sender) const { return Operation{}(std::forward<Sender>(sender), *resource); }
        };
    } // namespace detail

    namespace detail {
        struct access {
            template <class Protocol, template <class> class Queue> static auto spec(basic_socket<Protocol, Queue>& socket, native_io::operation kind) noexcept -> specification<Queue> {
                return {.kind = kind, .resource = socket.resource_, .file = socket.native_handle(), .keepalive = socket.state_};
            }
            template <class Protocol> static auto address(const ip::basic_endpoint<Protocol>& ep) noexcept -> native_io::socket_address {
                native_io::socket_address a; std::memcpy(a.data(), ep.data(), ep.size()); a.length = ep.size(); return a;
            }
            template <class Protocol> static auto endpoint(const native_io::socket_address& a) -> ip::basic_endpoint<Protocol> {
                ip::basic_endpoint<Protocol> ep; std::memcpy(ep.data(), a.data(), a.size()); ep.resize(a.size()); return ep;
            }
        };
        template <class Protocol, template <class> class Queue> struct accepted {
            detail::resource<Queue> resource;
            auto operator()(native_io::request&, std::int64_t h) const -> result<basic_stream_socket<Protocol, Queue>, ip::basic_endpoint<Protocol>> {
                basic_stream_socket<Protocol, Queue> socket{resource.get_scheduler(), Protocol::v4(), h};
                native_io::configure_stream(h);
                auto ep = socket.remote_endpoint();
                return {{std::move(socket), ep}};
            }
        };
        template <class Protocol> struct datagram_result {
            auto operator()(native_io::request& r, std::int64_t n) const -> result<std::size_t, ip::basic_endpoint<Protocol>> {
                return {{static_cast<std::size_t>(n), access::endpoint<Protocol>(r.address)}};
            }
        };
        struct wait_result {
            auto operator()(native_io::request&, std::int64_t n) const noexcept -> socket_base::wait_type { return static_cast<socket_base::wait_type>(n); }
        };
    }
    struct async_connect_t {
        template <class Protocol, template <class> class Queue> auto operator()(basic_stream_socket<Protocol, Queue>& socket, const typename Protocol::endpoint& ep) const noexcept {
            auto spec = detail::access::spec(socket, native_io::operation::connect); spec.address = detail::access::address(ep);
            return detail::sender<Queue, void, detail::done_result, true>{std::move(spec), {}};
        }
        template <class Protocol, template <class> class Queue> auto operator()(basic_stream_socket<Protocol, Queue>& socket) const { return detail::operation_adaptor<async_connect_t, basic_stream_socket<Protocol, Queue>>{socket}; }
        template <stdexec::sender Sender, class Protocol, template <class> class Queue> auto operator()(Sender&& sender, basic_stream_socket<Protocol, Queue>& socket) const {
            return stdexec::let_value(std::forward<Sender>(sender), detail::operation_factory<async_connect_t, basic_stream_socket<Protocol, Queue>>{&socket});
        }
    };
    inline constexpr async_connect_t async_connect{};
    struct async_accept_t;
    namespace detail {
        template <class Protocol, template <class> class Queue> struct accept_sender : stdexec::sender_adaptor_closure<accept_sender<Protocol, Queue>> {
            using sender_concept = stdexec::sender_t;
            using source_type = sender<Queue, result<basic_stream_socket<Protocol, Queue>, typename Protocol::endpoint>, accepted<Protocol, Queue>, true>;
            using completion_signatures = typename source_type::completion_signatures;
            source_type source;
            basic_socket_acceptor<Protocol, Queue>* acceptor;
            accept_sender(source_type s, basic_socket_acceptor<Protocol, Queue>& a) noexcept : source(std::move(s)), acceptor(&a) {}
            auto get_env() const noexcept { return source.get_env(); }
            template <class R> auto connect(R receiver) const noexcept(std::is_nothrow_move_constructible_v<R>) { return source.connect(std::move(receiver)); }
            template <stdexec::sender Sender> auto operator()(Sender&& upstream) const {
                return stdexec::let_value(std::forward<Sender>(upstream), operation_factory<async_accept_t, basic_socket_acceptor<Protocol, Queue>>{acceptor});
            }
        };
    }
    struct async_accept_t {
        template <class Protocol, template <class> class Queue> auto operator()(basic_socket_acceptor<Protocol, Queue>& acceptor) const noexcept {
            auto spec = detail::access::spec(acceptor, native_io::operation::accept);
            return detail::accept_sender<Protocol, Queue>{{std::move(spec), {{acceptor.get_scheduler().engine()}}}, acceptor};
        }
        template <stdexec::sender Sender, class Protocol, template <class> class Queue> auto operator()(Sender&& sender, basic_socket_acceptor<Protocol, Queue>& acceptor) const {
            return stdexec::let_value(std::forward<Sender>(sender), detail::operation_factory<async_accept_t, basic_socket_acceptor<Protocol, Queue>>{&acceptor});
        }
    };
    inline constexpr async_accept_t async_accept{};
    struct open_file_t {
        template <stdexec::scheduler Scheduler>
        auto operator()(const Scheduler& sch, const std::filesystem::path& path, bool write = false) const -> decltype(sch.open_file(path, write)) {
            return sch.open_file(path, write);
        }
    };
    inline constexpr open_file_t open_file{};
    struct async_read_at_t {
        template <class File> auto operator()(File& file, std::span<std::byte> into, std::uint64_t offset) const -> decltype(file.read_at(into, offset)) {
            return file.read_at(into, offset);
        }
    };
    inline constexpr async_read_at_t async_read_at{};
    struct async_write_at_t {
        template <class File>
        auto operator()(File& file, std::span<const std::byte> from, std::uint64_t offset) const -> decltype(file.write_at(from, offset)) {
            return file.write_at(from, offset);
        }
    };
    inline constexpr async_write_at_t async_write_at{};


    struct async_receive_t {
        template <class Protocol, template <class> class Queue, detail::buffer_sequence<mutable_buffer> Buffers> auto operator()(basic_socket<Protocol, Queue>& socket, const Buffers& buffers) const noexcept { return (*this)(socket, 0, buffers); }
        template <class Protocol, template <class> class Queue, detail::buffer_sequence<mutable_buffer> Buffers> auto operator()(basic_socket<Protocol, Queue>& socket, socket_base::message_flags flags, const Buffers& buffers) const noexcept {
            auto spec = detail::access::spec(socket, native_io::operation::receive);
            spec.oversized = !detail::set_buffers<mutable_buffer>(spec, buffers) && detail::datagram<Protocol>; spec.flags = flags;
            return detail::sender<Queue, std::size_t, detail::count_result, true>{std::move(spec), {}};
        }
        template <class Protocol, template <class> class Queue> auto operator()(basic_socket<Protocol, Queue>& socket) const { return detail::operation_adaptor<async_receive_t, basic_socket<Protocol, Queue>>{socket}; }
        template <stdexec::sender Sender, class Protocol, template <class> class Queue> auto operator()(Sender&& sender, basic_socket<Protocol, Queue>& socket) const {
            return stdexec::let_value(std::forward<Sender>(sender), detail::operation_factory<async_receive_t, basic_socket<Protocol, Queue>>{&socket});
        }
    };
    inline constexpr async_receive_t async_receive{};
    struct async_send_t {
        template <class Protocol, template <class> class Queue, detail::buffer_sequence<const_buffer> Buffers> auto operator()(basic_socket<Protocol, Queue>& socket, const Buffers& buffers) const noexcept { return (*this)(socket, 0, buffers); }
        template <class Protocol, template <class> class Queue, detail::buffer_sequence<const_buffer> Buffers> auto operator()(basic_socket<Protocol, Queue>& socket, socket_base::message_flags flags, const Buffers& buffers) const noexcept {
            auto spec = detail::access::spec(socket, native_io::operation::send);
            spec.oversized = !detail::set_buffers<const_buffer>(spec, buffers) && detail::datagram<Protocol>; spec.flags = flags;
            return detail::sender<Queue, std::size_t, detail::count_result, true>{std::move(spec), {}};
        }
        template <class Protocol, template <class> class Queue> auto operator()(basic_socket<Protocol, Queue>& socket) const { return detail::operation_adaptor<async_send_t, basic_socket<Protocol, Queue>>{socket}; }
        template <stdexec::sender Sender, class Protocol, template <class> class Queue> auto operator()(Sender&& sender, basic_socket<Protocol, Queue>& socket) const {
            return stdexec::let_value(std::forward<Sender>(sender), detail::operation_factory<async_send_t, basic_socket<Protocol, Queue>>{&socket});
        }
    };
    inline constexpr async_send_t async_send{};
    struct async_receive_from_t {
        template <class Protocol, template <class> class Queue, detail::buffer_sequence<mutable_buffer> Buffers> auto operator()(basic_datagram_socket<Protocol, Queue>& socket, const Buffers& buffers, typename Protocol::endpoint& ep) const noexcept { return (*this)(socket, 0, buffers, ep); }
        template <class Protocol, template <class> class Queue, detail::buffer_sequence<mutable_buffer> Buffers> auto operator()(basic_datagram_socket<Protocol, Queue>& socket, socket_base::message_flags flags, const Buffers& buffers, typename Protocol::endpoint& ep) const noexcept {
            auto spec = detail::access::spec(socket, native_io::operation::receive_from);
            spec.oversized = !detail::set_buffers<mutable_buffer>(spec, buffers); spec.flags = flags;
            return detail::sender<Queue, detail::result<std::size_t, typename Protocol::endpoint>, detail::datagram_result<Protocol>, true>{std::move(spec), {}};
        }
        template <class Protocol, template <class> class Queue> auto operator()(basic_datagram_socket<Protocol, Queue>& socket) const { return detail::operation_adaptor<async_receive_from_t, basic_datagram_socket<Protocol, Queue>>{socket}; }
        template <stdexec::sender Sender, class Protocol, template <class> class Queue> auto operator()(Sender&& sender, basic_datagram_socket<Protocol, Queue>& socket) const {
            return stdexec::let_value(std::forward<Sender>(sender), detail::operation_factory<async_receive_from_t, basic_datagram_socket<Protocol, Queue>>{&socket});
        }
    };
    inline constexpr async_receive_from_t async_receive_from{};
    struct async_send_to_t {
        template <class Protocol, template <class> class Queue, detail::buffer_sequence<const_buffer> Buffers> auto operator()(basic_datagram_socket<Protocol, Queue>& socket, const Buffers& buffers, const typename Protocol::endpoint& ep) const noexcept { return (*this)(socket, 0, buffers, ep); }
        template <class Protocol, template <class> class Queue, detail::buffer_sequence<const_buffer> Buffers> auto operator()(basic_datagram_socket<Protocol, Queue>& socket, socket_base::message_flags flags, const Buffers& buffers, const typename Protocol::endpoint& ep) const noexcept {
            auto spec = detail::access::spec(socket, native_io::operation::send_to);
            spec.oversized = !detail::set_buffers<const_buffer>(spec, buffers); spec.flags = flags;
            spec.address = detail::access::address(ep);
            return detail::sender<Queue, std::size_t, detail::count_result, true>{std::move(spec), {}};
        }
        template <class Protocol, template <class> class Queue> auto operator()(basic_datagram_socket<Protocol, Queue>& socket) const { return detail::operation_adaptor<async_send_to_t, basic_datagram_socket<Protocol, Queue>>{socket}; }
        template <stdexec::sender Sender, class Protocol, template <class> class Queue> auto operator()(Sender&& sender, basic_datagram_socket<Protocol, Queue>& socket) const {
            return stdexec::let_value(std::forward<Sender>(sender), detail::operation_factory<async_send_to_t, basic_datagram_socket<Protocol, Queue>>{&socket});
        }
    };
    inline constexpr async_send_to_t async_send_to{};
    struct async_read_some_t {
        template <class Stream, detail::buffer_sequence<mutable_buffer> Buffers>
        auto operator()(Stream& stream, const Buffers& buffers) const -> decltype(stream.read_some(std::span<std::byte>{})) {
            mutable_buffer first;
            for (auto it = net::buffer_sequence_begin(buffers); it != net::buffer_sequence_end(buffers); ++it) {
                first = mutable_buffer{*it};
                if (first.size()) break;
            }
            return stream.read_some(std::span<std::byte>{static_cast<std::byte*>(first.data()), first.size()});
        }
        template <class Protocol, template <class> class Queue, detail::buffer_sequence<mutable_buffer> Buffers> auto operator()(basic_stream_socket<Protocol, Queue>& socket, const Buffers& buffers) const noexcept { return async_receive(socket, buffers); }
        template <class Stream> auto operator()(Stream& stream, std::span<std::byte> bytes) const -> decltype(stream.read_some(bytes)) { return stream.read_some(bytes); }
        template <class Stream> auto operator()(Stream& stream) const { return detail::operation_adaptor<async_read_some_t, Stream>{stream}; }
        template <stdexec::sender Sender, class Stream> auto operator()(Sender&& sender, Stream& stream) const {
            return stdexec::let_value(std::forward<Sender>(sender), detail::operation_factory<async_read_some_t, Stream>{&stream});
        }
    };
    inline constexpr async_read_some_t async_read_some{};
    struct async_write_some_t {
        template <class Stream, detail::buffer_sequence<const_buffer> Buffers>
        auto operator()(Stream& stream, const Buffers& buffers) const -> decltype(stream.write_some(std::span<const std::byte>{})) {
            const_buffer first;
            for (auto it = net::buffer_sequence_begin(buffers); it != net::buffer_sequence_end(buffers); ++it) {
                first = const_buffer{*it};
                if (first.size()) break;
            }
            return stream.write_some(std::span<const std::byte>{static_cast<const std::byte*>(first.data()), first.size()});
        }
        template <class Protocol, template <class> class Queue, detail::buffer_sequence<const_buffer> Buffers> auto operator()(basic_stream_socket<Protocol, Queue>& socket, const Buffers& buffers) const noexcept { return async_send(socket, buffers); }
        template <class Stream> auto operator()(Stream& stream, std::span<const std::byte> bytes) const -> decltype(stream.write_some(bytes)) { return stream.write_some(bytes); }
        template <class Stream> auto operator()(Stream& stream) const { return detail::operation_adaptor<async_write_some_t, Stream>{stream}; }
        template <stdexec::sender Sender, class Stream> auto operator()(Sender&& sender, Stream& stream) const {
            return stdexec::let_value(std::forward<Sender>(sender), detail::operation_factory<async_write_some_t, Stream>{&stream});
        }
    };
    inline constexpr async_write_some_t async_write_some{};
    struct async_wait_t {
        template <class Protocol, template <class> class Queue> auto operator()(basic_socket<Protocol, Queue>& socket, socket_base::wait_type events) const noexcept {
            auto spec = detail::access::spec(socket, native_io::operation::readable); spec.events = events;
            return detail::sender<Queue, socket_base::wait_type, detail::wait_result, true>{std::move(spec), {}};
        }
        template <class Protocol, template <class> class Queue> auto operator()(basic_socket<Protocol, Queue>& socket) const { return detail::operation_adaptor<async_wait_t, basic_socket<Protocol, Queue>>{socket}; }
        template <stdexec::sender Sender, class Protocol, template <class> class Queue> auto operator()(Sender&& sender, basic_socket<Protocol, Queue>& socket) const {
            return stdexec::let_value(std::forward<Sender>(sender), detail::operation_factory<async_wait_t, basic_socket<Protocol, Queue>>{&socket});
        }
    };
    inline constexpr async_wait_t async_wait{};

    template <class Protocol, template <class> class Queue> auto read_chunk(basic_stream_socket<Protocol, Queue>& socket, std::span<std::byte> bytes) noexcept { return async_read_some(socket, buffer(bytes)); }
    template <class Protocol, template <class> class Queue> auto write_chunk(basic_stream_socket<Protocol, Queue>& socket, std::span<const std::byte> bytes) noexcept { return async_write_some(socket, buffer(bytes)); }

    struct closed : std::system_error {
        closed() : std::system_error(std::make_error_code(std::errc::connection_reset), "peer closed") {}
    };

    namespace detail {
        template <class Sequence, bool Writing> struct buffer_cursor {
            using buffer_type = std::conditional_t<Writing, const_buffer, mutable_buffer>;
            Sequence sequence;
            std::size_t offset = 0;
            auto size() const noexcept -> std::size_t {
                std::size_t n = 0;
                for (auto it = net::buffer_sequence_begin(sequence); it != net::buffer_sequence_end(sequence); ++it)
                    n += buffer_type{*it}.size();
                return n - offset;
            }
            auto empty() const noexcept -> bool { return size() == 0; }
            void consume(std::size_t n) noexcept { offset += n; }
            auto batch() const noexcept -> std::array<buffer_type, native_io::max_buffers> {
                std::array<buffer_type, native_io::max_buffers> buffers{};
                auto skip = offset;
                unsigned n = 0;
                for (auto it = net::buffer_sequence_begin(sequence); it != net::buffer_sequence_end(sequence) && n < buffers.size(); ++it) {
                    buffer_type b{*it};
                    if (skip >= b.size()) { skip -= b.size(); continue; }
                    b += skip; skip = 0;
                    buffers[n++] = b;
                }
                return buffers;
            }
        };
        template <class Stream, bool Writing, class Sequence> struct transfer_sender {
            using sender_concept = stdexec::sender_t;
            using completion_signatures = signatures<void>;
            using buffer_type = buffer_cursor<Sequence, Writing>;
            struct specification {
                Stream* stream;
                buffer_type remaining;
            };
            specification data;

            static auto next(Stream& stream, const buffer_type& bytes) {
                if constexpr (Writing)
                    return async_write_some(stream, bytes.batch());
                else
                    return async_read_some(stream, bytes.batch());
            }

            template <class Receiver> class operation {
                enum class phase { starting, waiting, completed };
                enum class result { value, error, exception, stopped };
                specification data_;
                Receiver receiver_;
                struct child_receiver {
                    using receiver_concept = stdexec::receiver_t;
                    operation* owner;
                    auto get_env() const noexcept -> stdexec::env_of_t<Receiver> { return stdexec::get_env(owner->receiver_); }
                    void set_value(std::size_t count) noexcept {
                        owner->count_ = count;
                        owner->result_ = result::value;
                        owner->completed();
                    }
                    void set_error(std::error_code error) noexcept {
                        owner->error_ = error;
                        owner->result_ = result::error;
                        owner->completed();
                    }
                    void set_error(std::exception_ptr error) noexcept {
                        owner->exception_ = std::move(error);
                        owner->result_ = result::exception;
                        owner->completed();
                    }
                    void set_stopped() noexcept {
                        owner->result_ = result::stopped;
                        owner->completed();
                    }
                };
                using child_type = stdexec::connect_result_t<decltype(next(std::declval<Stream&>(), buffer_type{})), child_receiver>;

            public:
                using operation_state_concept = stdexec::operation_state_t;
                operation(specification data, Receiver target) : data_(data), receiver_(std::move(target)) {}
                operation(operation&&) = delete;
                ~operation() { destroy_child(); }
                void start() & noexcept { advance(); }

            private:
                auto child() noexcept -> child_type& {
                    return *std::launder(reinterpret_cast<child_type*>(storage_));
                }
                void destroy_child() noexcept {
                    if (std::exchange(live_, false))
                        std::destroy_at(&child());
                }
                void completed() noexcept {
                    if (phase_.exchange(phase::completed, std::memory_order_acq_rel) == phase::waiting)
                        advance();
                }
                void advance() noexcept {
                    try {
                        for (;;) {
                            if (live_) {
                                destroy_child();
                                if (result_ == result::error) {
                                    auto error = error_;
                                    auto target = std::move(receiver_);
                                    stdexec::set_error(std::move(target), error);
                                    return;
                                }
                                if (result_ == result::exception) {
                                    auto error = std::move(exception_);
                                    auto target = std::move(receiver_);
                                    stdexec::set_error(std::move(target), std::move(error));
                                    return;
                                }
                                if (result_ == result::stopped) {
                                    auto target = std::move(receiver_);
                                    stdexec::set_stopped(std::move(target));
                                    return;
                                }
                                if (count_ == 0)
                                    throw closed{};
                                if (count_ > data_.remaining.size())
                                    throw std::logic_error("stream: transfer exceeded the supplied buffer");
                                data_.remaining.consume(count_);
                            }
                            if (stdexec::get_stop_token(stdexec::get_env(receiver_)).stop_requested()) {
                                auto target = std::move(receiver_);
                                stdexec::set_stopped(std::move(target));
                                return;
                            }
                            if (data_.remaining.empty()) {
                                auto target = std::move(receiver_);
                                stdexec::set_value(std::move(target));
                                return;
                            }
                            phase_.store(phase::starting, std::memory_order_relaxed);
                            ::new (static_cast<void*>(storage_)) child_type(stdexec::connect(
                                next(*data_.stream, data_.remaining), child_receiver{this}));
                            live_ = true;
                            stdexec::start(child());
                            // A synchronous completion is consumed by this loop;
                            // a later completion continues it after start returned.
                            if (phase_.exchange(phase::waiting, std::memory_order_acq_rel) != phase::completed)
                                return;
                        }
                    } catch (...) {
                        auto failure = std::current_exception();
                        destroy_child();
                        auto target = std::move(receiver_);
                        stdexec::set_error(std::move(target), std::move(failure));
                    }
                }
                std::size_t count_ = 0;
                std::error_code error_;
                std::exception_ptr exception_;
                result result_ = result::value;
                std::atomic<phase> phase_{phase::starting};
                bool live_ = false;
                alignas(child_type) std::byte storage_[sizeof(child_type)];
            };
            template <stdexec::receiver Receiver>
            auto connect(Receiver receiver) const -> operation<Receiver> { return {data, std::move(receiver)}; }
        };
    }

    struct async_read_t {
        template <class Stream, class Buffer, std::size_t N> requires detail::buffer_sequence<Buffer[N], mutable_buffer>
        auto operator()(Stream& stream, const Buffer (&buffers)[N]) const { return (*this)(stream, std::to_array(buffers)); }
        template <class Stream, detail::buffer_sequence<mutable_buffer> Buffers> auto operator()(Stream& stream, const Buffers& buffers) const {
            return detail::transfer_sender<Stream, false, Buffers>{{&stream, {buffers}}};
        }
        template <class Stream> auto operator()(Stream& stream, std::span<std::byte> bytes) const {
            return (*this)(stream, net::buffer(bytes));
        }
        template <class Stream> auto operator()(Stream& stream) const { return detail::operation_adaptor<async_read_t, Stream>{stream}; }
        template <stdexec::sender Sender, class Stream>
        auto operator()(Sender&& sender, Stream& stream) const {
            return stdexec::let_value(std::forward<Sender>(sender), detail::operation_factory<async_read_t, Stream>{&stream});
        }
    };
    inline constexpr async_read_t async_read{};

    struct async_write_t {
        template <class Stream, class Buffer, std::size_t N> requires detail::buffer_sequence<Buffer[N], const_buffer>
        auto operator()(Stream& stream, const Buffer (&buffers)[N]) const { return (*this)(stream, std::to_array(buffers)); }
        template <class Stream, detail::buffer_sequence<const_buffer> Buffers> auto operator()(Stream& stream, const Buffers& buffers) const {
            return detail::transfer_sender<Stream, true, Buffers>{{&stream, {buffers}}};
        }
        template <class Stream> auto operator()(Stream& stream, std::span<const std::byte> bytes) const {
            return (*this)(stream, net::buffer(bytes));
        }
        template <class Stream> auto operator()(Stream& stream) const { return detail::operation_adaptor<async_write_t, Stream>{stream}; }
        template <stdexec::sender Sender, class Stream>
        auto operator()(Sender&& sender, Stream& stream) const {
            return stdexec::let_value(std::forward<Sender>(sender), detail::operation_factory<async_write_t, Stream>{&stream});
        }
    };
    inline constexpr async_write_t async_write{};

    static_assert(stdexec::scheduler<scheduler>);
} // namespace http::io::net
