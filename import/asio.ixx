module;

#include <asio.hpp>
#include <asio/ssl.hpp>

export module httpant.dependencies.asio;

export namespace asio {
using ::asio::any_io_executor;
using ::asio::async_write;
using ::asio::buffer;
using ::asio::io_context;
using ::asio::post;
}

export namespace asio::ip {
using ::asio::ip::tcp;
using ::asio::ip::address_v4;
using ::asio::ip::address_v6;
}

export namespace asio::ssl {
using ::asio::ssl::stream;
using ::asio::ssl::stream_base;
using ::asio::ssl::context;
using ::asio::ssl::host_name_verification;
}

export namespace asio::error {
using ::asio::error::eof;
using ::asio::error::operation_aborted;
}

export namespace httpant::dependencies {
inline constexpr int asio_verify_none = SSL_VERIFY_NONE;
inline constexpr int asio_verify_peer = SSL_VERIFY_PEER;
}
