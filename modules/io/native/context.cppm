module;
#include <asio/detail/config.hpp>
#ifdef _WIN32
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#else
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <unistd.h>
#include <errno.h>
#endif

module httpant.io;
import std;
import :mechanism;
import httpant.dependencies.asio;

namespace native_io {
    namespace detail {
        struct asio_operation {
            asio::cancellation_signal signal;
            bool started = false;
        };
        struct asio_resource {
            using stream = asio::generic::stream_protocol;
            using acceptor = asio::basic_socket_acceptor<stream>;
            using udp = asio::ip::udp;
#ifdef _WIN32
            using descriptor = asio::windows::stream_handle;
#else
            using descriptor = asio::posix::stream_descriptor;
#endif
            std::variant<stream::socket, udp::socket, acceptor, descriptor> value;
            asio_resource(asio::io_context& context, request& r) : value(std::in_place_type<stream::socket>, context) {
                int type = 0;
                int listening = 0;
#ifdef _WIN32
                int size = sizeof type;
                if (::getsockopt(r.file, SOL_SOCKET, SO_TYPE, reinterpret_cast<char*>(&type), &size)) {
                    auto error = ::WSAGetLastError();
                    if (::GetFileType(reinterpret_cast<HANDLE>(r.file)) != FILE_TYPE_PIPE)
                        throw std::system_error(error, std::system_category());
                    value.emplace<descriptor>(context, reinterpret_cast<HANDLE>(r.file));
                    return;
                }
                auto option = [&](int key, int& value) {
                    int size = sizeof value;
                    if (::getsockopt(r.file, SOL_SOCKET, key, reinterpret_cast<char*>(&value), &size))
                        throw std::system_error(::WSAGetLastError(), std::system_category());
                };
#else
                struct stat info;
                if (::fstat(r.file, &info) < 0) throw std::system_error(errno, std::generic_category());
                if (!S_ISSOCK(info.st_mode)) {
                    value.emplace<descriptor>(context, r.file);
                    return;
                }
                auto option = [&](int key, int& value) {
                    socklen_t size = sizeof value;
                    if (::getsockopt(r.file, SOL_SOCKET, key, &value, &size))
                        throw std::system_error(errno, std::generic_category());
                };
                option(SO_TYPE, type);
#endif
                sockaddr_storage address{};
#ifdef _WIN32
                int length = sizeof address;
                if (::getsockname(r.file, reinterpret_cast<sockaddr*>(&address), &length))
                    throw std::system_error(::WSAGetLastError(), std::system_category());
#else
                socklen_t length = sizeof address;
                if (::getsockname(r.file, reinterpret_cast<sockaddr*>(&address), &length))
                    throw std::system_error(errno, std::generic_category());
#endif
                if (type == SOCK_DGRAM) {
                    auto& socket = value.emplace<udp::socket>(context);
                    socket.assign(address.ss_family == AF_INET6 ? udp::v6() : udp::v4(), r.file);
                } else {
                    auto protocol = address.ss_family;
                    option(SO_ACCEPTCONN, listening);
                    if (listening) {
                        auto& socket = value.emplace<acceptor>(context);
                        socket.assign(stream{protocol, 0}, r.file);
                    } else
                        std::get<stream::socket>(value).assign(stream{protocol, 0}, r.file);
                }
            }
            ~asio_resource() { release(); }
            void release() noexcept {
                std::visit([](auto& socket) {
                    std::error_code ignored;
                    if (socket.is_open()) {
#ifndef _WIN32
                        if constexpr (std::same_as<std::decay_t<decltype(socket)>, descriptor>) socket.release();
                        else
#endif
                        socket.release(ignored);
                    }
                }, value);
            }
        };
#ifdef ASIO_HAS_FILE
        struct asio_file {
            asio::random_access_file value;
            asio_file(asio::io_context& context, handle file) : value(context) {
#ifdef _WIN32
                value.assign(reinterpret_cast<asio::random_access_file::native_handle_type>(file));
#else
                value.assign(static_cast<asio::random_access_file::native_handle_type>(file));
#endif
            }
            ~asio_file() { release(); }
            void release() noexcept {
                std::error_code ignored;
                if (value.is_open()) value.release(ignored);
            }
        };
#endif
        template <class Endpoint> auto asio_endpoint(const socket_address& address) -> Endpoint {
            Endpoint result;
            std::memcpy(result.data(), address.data(), address.size());
            result.resize(address.size());
            return result;
        }
        auto poll_events(request& r) -> int {
#ifdef _WIN32
            WSAPOLLFD descriptor{static_cast<SOCKET>(r.file), static_cast<short>((r.events & 1 ? POLLRDNORM : 0) | (r.events & 2 ? POLLWRNORM : 0)), 0};
            if (::WSAPoll(&descriptor, 1, 0) < 0)
                throw std::system_error(::WSAGetLastError(), std::system_category());
#else
            pollfd descriptor{static_cast<int>(r.file), static_cast<short>((r.events & 1 ? POLLIN : 0) | (r.events & 2 ? POLLOUT : 0)), 0};
            if (::poll(&descriptor, 1, 0) < 0)
                throw std::system_error(errno, std::generic_category());
#endif
            return (descriptor.revents & (POLLIN | POLLHUP) && r.events & 1 ? 1 : 0)
                 | (descriptor.revents & POLLOUT && r.events & 2 ? 2 : 0)
                 | (descriptor.revents & (POLLERR | POLLNVAL) ? 4 : 0);
        }
        template <class Socket> auto asio_wait(Socket& socket, int events) -> asio::awaitable<void> {
            using namespace asio::experimental::awaitable_operators;
            auto wait = [&](int event) -> asio::awaitable<void> {
                co_await socket.async_wait(event == 1 ? Socket::wait_read : event == 2 ? Socket::wait_write : Socket::wait_error, asio::use_awaitable);
            };
            switch (events & 7) {
            case 0: co_await wait(4); break;
            case 1: co_await wait(1); break;
            case 2: co_await wait(2); break;
            case 3: co_await (wait(1) || wait(2)); break;
            case 4: co_await wait(4); break;
            case 5: co_await (wait(1) || wait(4)); break;
            case 6: co_await (wait(2) || wait(4)); break;
            case 7: co_await (wait(1) || wait(2) || wait(4)); break;
            default: throw std::system_error(std::make_error_code(std::errc::invalid_argument));
            }
        }
    }

    struct detail::asio_loop::impl {
        asio::io_context context{1};
        decltype(asio::make_work_guard(context)) guard = asio::make_work_guard(context);
        std::map<handle, std::shared_ptr<detail::asio_resource>> sockets;
#ifdef ASIO_HAS_FILE
        std::map<handle, std::shared_ptr<detail::asio_file>> files;
#endif
        auto socket(request& r) -> std::shared_ptr<detail::asio_resource> {
            auto entry = sockets.find(r.file);
            if (entry != sockets.end()) return entry->second;
            auto current = std::make_shared<detail::asio_resource>(context, r);
            sockets.emplace(r.file, current);
            return current;
        }
        auto perform(request& r) -> asio::awaitable<void> {
            co_await asio::this_coro::reset_cancellation_state(asio::enable_total_cancellation());
            std::int64_t result = 0;
            std::error_code error;
            try {
                if (r.kind == operation::timer) {
                    asio::steady_timer timer{context, r.deadline};
                    co_await timer.async_wait(asio::use_awaitable);
                } else if (r.kind == operation::read_at || r.kind == operation::write_at) {
#ifdef ASIO_HAS_FILE
                    auto entry = files.find(r.file);
                    auto resource = entry != files.end() ? entry->second : std::make_shared<detail::asio_file>(context, r.file);
                    if (entry == files.end()) files.emplace(r.file, resource);
                    if (r.kind == operation::read_at)
                        result = co_await resource->value.async_read_some_at(r.offset, asio::buffer(r.buffer, r.size), asio::use_awaitable);
                    else
                        result = co_await resource->value.async_write_some_at(r.offset, asio::buffer(r.buffer, r.size), asio::use_awaitable);
#endif
                } else {
                    auto resource = socket(r);
                    std::array<asio::mutable_buffer, max_buffers> buffers;
                    auto count = r.buffer_count;
                    for (unsigned i = 0; i < count; ++i) buffers[i] = asio::buffer(r.buffers[i].data, r.buffers[i].size);
                    if (!count) { buffers[0] = asio::buffer(r.buffer, r.size); count = 1; }
                    auto sequence = std::span{buffers.data(), count};
                    if (auto* descriptor = std::get_if<detail::asio_resource::descriptor>(&resource->value)) {
                        if (r.kind == operation::read)
                            result = co_await descriptor->async_read_some(sequence, asio::use_awaitable);
                        else if (r.kind == operation::write)
                            result = co_await descriptor->async_write_some(sequence, asio::use_awaitable);
#ifndef _WIN32
                        else if (r.kind == operation::readable) {
                            co_await detail::asio_wait(*descriptor, r.events);
                            result = detail::poll_events(r);
                        }
#endif
                        else throw std::system_error(std::make_error_code(std::errc::invalid_argument));
                    } else if (r.kind == operation::accept) {
                        auto peer = co_await std::get<detail::asio_resource::acceptor>(resource->value).async_accept(asio::use_awaitable);
                        result = peer.release();
                        configure_stream(result);
                    } else if (r.kind == operation::readable) {
                        if (auto* stream = std::get_if<detail::asio_resource::stream::socket>(&resource->value))
                            co_await detail::asio_wait(*stream, r.events);
                        else if (auto* datagram = std::get_if<asio::ip::udp::socket>(&resource->value))
                            co_await detail::asio_wait(*datagram, r.events);
                        else co_await detail::asio_wait(std::get<detail::asio_resource::acceptor>(resource->value), r.events);
                        result = detail::poll_events(r);
                    } else if (auto* stream = std::get_if<detail::asio_resource::stream::socket>(&resource->value)) {
                        switch (r.kind) {
                        case operation::connect:
                            co_await stream->async_connect(detail::asio_endpoint<detail::asio_resource::stream::endpoint>(r.address), asio::use_awaitable); break;
                        case operation::read: result = co_await stream->async_read_some(sequence, asio::use_awaitable); break;
                        case operation::write: result = co_await stream->async_write_some(sequence, asio::use_awaitable); break;
                        case operation::receive: result = co_await stream->async_receive(sequence, r.flags, asio::use_awaitable); break;
                        case operation::send: result = co_await stream->async_send(sequence, r.flags, asio::use_awaitable); break;
                        default: throw std::system_error(std::make_error_code(std::errc::invalid_argument));
                        }
                    } else {
                        auto& datagram = std::get<asio::ip::udp::socket>(resource->value);
                        asio::ip::udp::endpoint endpoint;
                        auto receive = asio::redirect_error(asio::use_awaitable, error);
                        switch (r.kind) {
                        case operation::read:
                        case operation::receive: result = co_await datagram.async_receive(sequence, r.flags, receive); break;
                        case operation::write:
                        case operation::send: result = co_await datagram.async_send(sequence, r.flags, asio::use_awaitable); break;
                        case operation::receive_from:
                            result = co_await datagram.async_receive_from(sequence, endpoint, r.flags, receive);
                            std::memcpy(r.address.data(), endpoint.data(), endpoint.size());
                            r.address.length = endpoint.size(); break;
                        case operation::send_to:
                            result = co_await datagram.async_send_to(sequence, detail::asio_endpoint<asio::ip::udp::endpoint>(r.address), r.flags, asio::use_awaitable); break;
                        default: throw std::system_error(std::make_error_code(std::errc::invalid_argument));
                        }
                        if (error == asio::error::message_size) error.clear();
                        if (error) throw std::system_error(error);
                    }
                }
            } catch (const std::system_error& failure) {
                error = failure.code();
                if (error == asio::error::eof) { error.clear(); result = 0; }
                else {
                    result = -1;
                    if (error == asio::error::operation_aborted) error = std::make_error_code(std::errc::operation_canceled);
                }
            } catch (...) {
                result = -1;
                error = std::make_error_code(std::errc::not_enough_memory);
            }
            r.result = result;
            r.error = error;
        }
        auto execute(request& r) -> asio::awaitable<void> {
            detail::asio_data(r).pending->started = true;
            try {
                if (r.cancelled.load(std::memory_order_acquire) || r.is_closed()) r.result = -1;
                else co_await perform(r);
            } catch (const std::system_error& error) {
                r.result = -1; r.error = error.code();
            } catch (...) {
                r.result = -1; r.error = std::make_error_code(std::errc::not_enough_memory);
            }
            // Complete after the operation and its cancellation slot are gone.
            r.result_ready = true;
        }
    };
    detail::asio_loop::asio_loop() : impl_(new impl) {}
    detail::asio_loop::~asio_loop() { delete impl_; }
    void detail::asio_loop::signal() noexcept { impl_->context.stop(); }
    void detail::asio_loop::restart() { impl_->context.restart(); }
    void detail::asio_loop::run_one(bool pending) {
        if (!pending) impl_->context.run_one();
        impl_->context.poll();
    }
    void detail::asio_loop::close(handle file) noexcept {
        if (auto entry = impl_->sockets.find(file); entry != impl_->sockets.end()) {
            entry->second->release();
            impl_->sockets.erase(entry);
        }
#ifdef ASIO_HAS_FILE
        if (auto entry = impl_->files.find(file); entry != impl_->files.end()) {
            entry->second->release();
            impl_->files.erase(entry);
        }
#endif
    }
    void detail::asio_loop::start(request& r) {
        auto pending = std::make_shared<asio_operation>();
        asio_data(r).pending = pending.get();
        r.result_ready = false;
        asio::co_spawn(impl_->context, impl_->execute(r),
            asio::bind_cancellation_slot(pending->signal.slot(), asio::consign(asio::detached, pending)));
    }
    void detail::asio_loop::cancel(request& r) noexcept {
        auto& pending = *asio_data(r).pending;
        if (pending.started && !r.cancel_sent) {
            r.cancel_sent = true;
            pending.signal.emit(asio::cancellation_type::all);
        }
    }
}
