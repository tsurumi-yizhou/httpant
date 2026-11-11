module;

#include <asio.hpp>
#include <asio/experimental/awaitable_operators.hpp>

export module httpant.dependencies.asio;

export namespace asio {
using ::asio::any_io_executor;
using ::asio::basic_socket_acceptor;
using ::asio::awaitable;
using ::asio::bind_cancellation_slot;
using ::asio::cancellation_signal;
using ::asio::cancellation_type;
using ::asio::co_spawn;
using ::asio::consign;
using ::asio::detached;
using ::asio::enable_total_cancellation;
using ::asio::mutable_buffer;
using ::asio::socket_base;
using ::asio::steady_timer;
using ::asio::use_awaitable;
using ::asio::redirect_error;
#ifdef ASIO_HAS_FILE
using ::asio::random_access_file;
#endif
using ::asio::async_write;
using ::asio::buffer;
using ::asio::io_context;
using ::asio::make_work_guard;
using ::asio::post;
}

export namespace asio::ip {
using ::asio::ip::tcp;
using ::asio::ip::udp;
using ::asio::ip::address_v4;
using ::asio::ip::address_v6;
}

export namespace asio::error {
using ::asio::error::make_error_code;
using ::asio::error::get_system_category;
using ::asio::error::broken_pipe;
using ::asio::error::eof;
using ::asio::error::message_size;
using ::asio::error::operation_aborted;
}


export namespace asio::this_coro {
using ::asio::this_coro::reset_cancellation_state;
using ::asio::this_coro::throw_if_cancelled;
}
export namespace asio::experimental::awaitable_operators {
using ::asio::experimental::awaitable_operators::operator||;
}

#ifdef ASIO_HAS_POSIX_STREAM_DESCRIPTOR
export namespace asio::posix {
using ::asio::posix::stream_descriptor;
}
#endif
#ifdef ASIO_HAS_WINDOWS_STREAM_HANDLE
export namespace asio::windows {
using ::asio::windows::stream_handle;
}
#endif
export namespace asio::generic {
using ::asio::generic::stream_protocol;
}

export namespace std {
template <class T, class Executor, class... Args>
struct coroutine_traits<::asio::awaitable<T, Executor>, Args...>;
}

template struct asio::execution::detail::outstanding_work_t<0>;
