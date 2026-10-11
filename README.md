# Httpant

A modern C++ library with no I/O and pure protocols.

## Build

Requires CMake 4.0+, Ninja, C++23, and the
[xclang toolchain](https://github.com/clice-io/xclang), whose `xclang::std`
target provides the standard library module. With dependencies installed in a
prefix:

```sh
cmake -S . -B build -G Ninja \
  --toolchain "$XCLANG_ROOT/lib/cmake/xclang/toolchain.cmake" \
  -DCMAKE_PREFIX_PATH=/path/to/dependencies \
  -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build --output-on-failure
```

Only Linux is validated so far (Clang 23 + libc++; GCC is unsupported).
Build dependencies with the same toolchain as Httpant.

Options: `BUILD_TESTING` (default `ON`), `ENABLE_EXAMPLES` (default `ON`).
Core dependencies: llhttp, nghttp2, nghttp3, stdexec; tests and examples add
Asio, OpenSSL, MsQuic, and Boost.UT. Dependencies can come from vcpkg,
FetchContent, or the parent project; existing CMake targets are reused
before `find_package` is called:

| Dependency | Accepted targets (in preference order) |
| --- | --- |
| llhttp | `llhttp::llhttp`, `llhttp::llhttp_static`, `llhttp_static`, `llhttp_shared` |
| nghttp2 | `nghttp2::nghttp2`, `nghttp2::nghttp2_static`, `nghttp2`, `nghttp2_static` |
| nghttp3 | `nghttp3::nghttp3`, `nghttp3::nghttp3_static`, `nghttp3`, `nghttp3_static` |
| stdexec | `STDEXEC::stdexec`, `stdexec` |
| Asio | `asio::asio`, `asio` |
| OpenSSL | `OpenSSL::SSL` and `OpenSSL::Crypto` |
| MsQuic | `msquic` |
| Boost.UT | `Boost::ut` |

To embed Httpant, create the dependency targets in the parent first:

```cmake
# Set these before creating dependency and application targets.
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_SCAN_FOR_MODULES ON)
# find_package(...) or FetchContent_MakeAvailable(...) for the dependencies
set(BUILD_TESTING OFF CACHE BOOL "Build tests")
set(ENABLE_EXAMPLES OFF CACHE BOOL "Build examples")
add_subdirectory(httpant)
target_link_libraries(my_app PRIVATE httpant)
```

## How to use

Wrap your own backend (asio, OpenSSL, wolfSSL, MsQuic, ...) with Httpant's
transport concepts: HTTP/1.1 and HTTP/2 use a stop-aware `byte_stream`;
HTTP/3 uses a `stream_factory` that opens and accepts QUIC
streams. Httpant keeps only protocol state; sockets, TLS, QUIC, caching,
cookies, and connection management stay in your application.

## Two interfaces

Two async stacks, both from `import httpant;`:

- **Coroutine stack** (`http::coroutine`): operations return `http::task<T>`,
  a lazy, single-consumer, move-only coroutine. Awaiting a task passes the
  stop token down the chain; a root task gets its token from
  `task.start(token)`. `co_await sender` awaits a P2300 sender with one
  distinct value signature (outside namespace `http`, write
  `using http::operator co_await;`).
- **Execution stack** (`http::execution`): operations return lazy P2300
  senders with the stop token from the receiver's environment. Composes with
  `stdexec::sync_wait`, `then`, `when_all`, etc.

`start`, `close`, `request`, `receive`, `respond`, `fetch` exist on both
stacks; `scoped`, `with_scope`, `upgrade`, and `body.async_read` are
coroutine-only.

Cancellation is `http::stopped`: thrown through coroutine chains (not a
`std::exception`, so `catch (const std::exception&)` won't swallow it) and
delivered as `set_stopped` on the execution stack.

### Execution boundary

- The coroutine bridge forwards the stop token only; allocators, schedulers,
  and other environment queries do not propagate. Bridging failures complete
  with `set_error(std::exception_ptr)`.
- An awaited sender may complete inline or on another thread; the bridge
  resumes exactly once. Normalize senders with alternative value signatures
  before awaiting.
- Each connection has one serialized execution context: run its endpoint
  operations, transport resumptions, and stop requests there. Httpant
  creates no executor — use a strand or your own event loop, and give the
  Asio and QUIC adapters serialized executors.
- An operation must stay alive until it completes; request stop and wait
  before releasing its buffers or transport.

Initialization failure is terminal for an HTTP/2 or HTTP/3 endpoint: close,
join, and recreate it with a new transport — Httpant never retries.

Benchmark: `cmake -S bench -B build-bench -G Ninja` with the same toolchain
and dependencies as the main build, then
`build-bench/boundary-cost <mode>` (`await`, `std`, `inplace`, `prestop`,
`stop`, `cancel`, `http1`).

### Structured lifetimes

HTTP/2 and HTTP/3 endpoints run drivers beside the application (the HTTP/2
reader, the HTTP/3 accept loop and stream readers) in an endpoint-owned
scope: `start` spawns them, `close` stops and joins them (pending exchanges
finish with `http::stopped`), and a started endpoint must be closed before
destruction. `http::coroutine::scoped(endpoint, body)` does all three for
you:

```cpp
http::v2::client<TlsStream> client{tls};
auto response = co_await http::coroutine::scoped(client, [&](auto& c) -> http::task<std::string> {
    auto received = co_await http::coroutine::request(c, request);
    co_return co_await read_all(received.body);
});
```

HTTP/1.1 runs no drivers, so its `start`/`close` complete immediately.
`http::task_scope` is public; `http::coroutine::with_scope(body)` gives
applications the same structure — running children spawned with
`scope.spawn(task)` are stopped and joined before it completes.

Protocol versions are namespaces, not name suffixes:

```cpp
http::v1::client<TcpStream> http1{tcp};
http::v2::client<TlsStream> http2{tls};
http::v3::client<QuicFactory> http3{quic};
```

HTTP/3 uses one nghttp3-owned QPACK state; `http::v3::configuration`
controls its capacities and `compression_state()` exposes the peer SETTINGS
snapshot. H3 push is unavailable until the backend can submit it through
that same QPACK owner.

## Transport and lifecycle contracts

Every transport operation takes a `std::stop_token`; a stopped token
completes the pending operation by throwing `http::stopped` unless it
already finished. HTTP/3 factories additionally declare serialized
completion ordering
(`completion_order = http::stream_completion_order::serialized`): all
resumptions for one connection must be marshalled onto one serialized
context so nghttp3/QPACK have a sole mutator.

Exchange correlation is move-only and opaque: servers receive an exchange
token next to each request and move it into `respond` — no stream IDs, no
`last_*` accessors. H2 GOAWAY boundaries derive from the exchanges
delivered; H3 shutdown flushes GOAWAY before closing the factory with
`H3_NO_ERROR`.

Failures come in three kinds:

- **`http::protocol_error`** — a wire or protocol-engine failure.
  `error_info` gives the typed condition, scope, retryability, and optional
  exchange identity; `protocol_action` records what remains for the
  application (stream reset, connection close, or `no_action`).
- **`http::usage_error`** (a `std::logic_error`) — a call outside the
  contract: request on a closed connection, an exchange token from another
  server, an unframable message, a contract-breaking transport.
- **`http::stopped`** — cancellation, described above.

## Methods

`http::method` is a 32-byte literal type that is always a valid RFC 9110
token. Literals like `.method = "PROPFIND"` are checked at compile time,
`http::method::parse(text)` at runtime. Extension methods keep their token
on every version, so a proxy forwards them unchanged.

## One-shot requests

`fetch` creates a client on a connection you already have, runs the exchange
inside `scoped`, reads the whole response, and closes the client. The
connection stays yours.

```cpp
http::request request{.method = http::method::POST, .target = "/orders",
                      .scheme = "https", .authority = "api.example.com"};

using enum http::protocol_version;
auto r1 = co_await http::coroutine::fetch<http1>(tls, request, "a=b"sv);   // byte stream: HTTP/1.1
auto r2 = co_await http::coroutine::fetch<http2>(tls, request);            // byte stream: HTTP/2
auto r3 = co_await http::coroutine::fetch<http3>(quic, request);           // stream factory: HTTP/3

// The execution stack: a lazy sender.
auto [r4] = *stdexec::sync_wait(http::execution::fetch<http1>(tls, request));

r1.head.status;   // http::response
r1.text();        // the body, read to its end
```

Give the request a scheme and authority (or a `Host` field) and `fetch` adds
what the version needs. A body is a span/string of bytes (copied at the
call) or any `body_stream` you frame yourself. `fetch` buffers the whole
response up to a template bound: `fetch<Version, Limit>` (default
`http::default_fetch_limit`, 64 MiB) fails with a `resource_limit`
`protocol_error` beyond it.

Around it: `http::client_for<Connection, Version>` names the client type,
`http::alpn(version)` is the ALPN identifier, `http::request_origin(request)`
gives the host and port, and `http::coroutine::upgrade(stream, request)`
performs an HTTP/1.1 protocol switch (e.g. WebSocket), handing you the
connection plus any bytes already sent after the `101`.

## Streaming bodies

`http::request`/`http::response` carry only metadata — never a buffered
body. Reads return `http::received<head, body>` (stream with `async_read`
until it returns 0); writes take a `http::buffer_body` or your own
`body_stream` next to the head.

```cpp
import httpant;

http::buffer_body request_body; // or fill it
auto received = co_await http::coroutine::request(
    client,
    http::request{.method = http::method::GET, .target = "/", .fields = {{"host", "example.com"}}},
    request_body);

// received.head is the response metadata; received.body streams the payload.
std::array<std::byte, 8192> buf;
auto& stop = co_await http::current_stop_token();
while (auto n = co_await received.body.async_read(buf, stop)) { /* use n bytes */ }
```

## State boundary

The library owns only protocol state (connection persistence, GOAWAY, stream
state machines, HPACK/QPACK, 100-continue). `caching.cppm` exposes typed RFC
9111 storage/use decisions; `cookie.cppm` separates Set-Cookie parsing,
PSL-aware acceptance, and request-context selection. Your application owns
the containers, eviction, PSL data, and SameSite policy.
