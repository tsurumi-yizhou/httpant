# Httpant

A modern C++ library with no I/O and pure protocols.

## Build

Httpant requires CMake 4.0+, Ninja, C++23, and the
[xclang toolchain](https://github.com/clice-io/xclang). Its `xclang::std`
target builds the standard library module; Httpant links it transitively.
With dependencies installed in a prefix:

```sh
cmake -S . -B build -G Ninja \
  --toolchain "$XCLANG_ROOT/lib/cmake/xclang/toolchain.cmake" \
  -DCMAKE_PREFIX_PATH=/path/to/dependencies \
  -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build --output-on-failure
```

Use xclang's toolchain file as the common build entry on all platforms.
`XCLANG_TARGET` selects the target, for example
`-DXCLANG_TARGET=x86_64-pc-windows-msvc` for Windows with the MSVC ABI.
That target uses Clang with Microsoft's STL and Windows SDK, including
Microsoft's `std` module; it does not invoke `cl.exe`. The SDK must be
available to xclang. See the
[xclang CMake guide](https://github.com/clice-io/xclang/blob/main/docs/en/integrations/cmake.md)
for supported targets and SDK setup. Build dependencies with the same
toolchain and target. Httpant's Windows and macOS builds have not yet been
validated.

`BUILD_TESTING` is the standard CTest option (default `ON`);
`ENABLE_EXAMPLES` controls examples (default `ON`). Both can be disabled for
a library-only build. Core dependencies are llhttp, nghttp2, nghttp3, and
stdexec. Tests and examples additionally need Asio, OpenSSL, and MsQuic;
only tests need Boost.UT.

Dependencies can come from vcpkg, FetchContent, or the parent project.
Httpant reuses existing CMake targets before calling `find_package`:

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

For example, create dependency targets in the parent before adding Httpant:

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

A dependency without a CMake build can be supplied as an interface/imported
target with one of the names above and the appropriate include directories,
compile definitions, and link libraries. nghttp2 also supports a fallback
search for installed headers and libraries.

When using vcpkg, select its toolchain with `CMAKE_TOOLCHAIN_FILE` and
chain-load xclang with `VCPKG_CHAINLOAD_TOOLCHAIN_FILE`. Omit the vcpkg
toolchain to build without vcpkg; `VCPKG_MANIFEST_INSTALL=OFF` disables its
automatic installation while retaining the toolchain. Only standalone
builds add features to Httpant's vcpkg manifest; an `add_subdirectory` build
leaves dependency acquisition to the parent project. Use a custom vcpkg
triplet that also chain-loads xclang, so the dependencies use the same
compiler, ABI, and sysroot as Httpant. All module targets must agree on the
C++ language standard and extension settings (`CMAKE_CXX_EXTENSIONS=OFF`).

Httpant owns the `.ixx` wrappers in `import/`. They expose the
API needed by Httpant under `httpant.dependencies.*` module names and do not
replace upstream dependency targets. Applications can continue using those
targets and upstream headers themselves; the wrappers are not a complete
module API for each upstream library. Textual includes are confined to these
wrappers. Constant/function macros used by Httpant are exposed as typed C++
entities, and protocol invariants formerly guarded by `assert` now throw
`std::logic_error` in all build configurations.

Compiler checks on Linux passed with xclang 23.1.2.8 and Ubuntu Clang
23.1.3 with libc++. GCC is not currently supported by these dependency
modules: GCC 15.2 rejects declarations exposing translation-unit-local
entities in stdexec, Asio, and MsQuic; GCC 16 (20260322 snapshot) crashes
while compiling stdexec's `forwarding_query`. The GCC 16 failure also
occurs with a minimal module containing only the stdexec header, without
Httpant code. Neither GCC build reached test execution.

## How to use

Wrap your own backend such as `asio`, OpenSSL, wolfSSL, or MsQuic with Httpant's transport concepts. HTTP/1.1 and HTTP/2 use a stop-aware `byte_stream`; HTTP/3 uses a `stream_factory` that explicitly opens and accepts QUIC streams. Copying a handle never means “open another stream”. Httpant keeps only the state the HTTP protocols require; sockets, TLS, QUIC, caching, cookie storage, and connection management stay in your application.

## Two interfaces

Httpant exposes the same protocol operations through two symmetrical, first-class async surfaces, both reachable from `import httpant;`:

- **Coroutine** — `http::coroutine::start/request/receive/respond` return `http::task<T>`, a lazy, single-consumer, move-only coroutine you drive with `co_await` or `.start()`.
- **P2300 (std::execution)** — `http::execution::start/request/receive/respond` return real P2300 senders that compose with `stdexec::sync_wait`, `then`, `when_all` and the rest of stdexec.

`http::task<T>` itself is a P2300 sender; both surfaces invoke the same private endpoint operation, and `http::execution` returns that sender directly. No public conversion layer is needed or exposed.

Protocol versions are namespaces, not name suffixes:

```cpp
http::v1::client<TcpStream> http1{tcp};
http::v2::client<TlsStream> http2{tls};
http::v3::client<QuicFactory> http3{quic};
```

Version-local types follow the same boundary, such as `http::v2::configuration`,
`http::v2::error_code`, and `http::v3::error_code`. There are no `*_v1`/`*_v2`/`*_v3`
aliases or numeric `stream<N>` facade.

HTTP/3 uses one nghttp3-owned QPACK state for ordinary requests and responses.
`http::v3::configuration` controls decoder capacity, blocked streams, encoder capacity,
and maximum field-section size; `compression_state()` exposes the peer SETTINGS snapshot.
H3 push is intentionally unavailable until the backend can submit it through that same
QPACK owner—there is no literal-only compatibility codec.

## Transport and lifecycle contracts

Every transport operation accepts a `std::stop_token`, and every result or failure is
delivered through its awaitable completion channel. HTTP/3 factories additionally declare
serialized completion ordering: all resumptions for one connection must be marshalled onto
one serialized execution context so nghttp3 and QPACK have a sole mutator.

H1/H2/H3 exchange correlation is move-only and opaque. Servers receive an exchange token
next to each request and must move that token into `respond`; applications never pass stream
IDs or poll a `last_*` accessor. H2 GOAWAY boundaries are derived from exchanges actually
delivered to the application. H3 shutdown flushes GOAWAY before closing the factory with
`H3_NO_ERROR`.

Protocol failures use `http::protocol_error`. Its `error_info` describes the typed condition,
scope, retryability, and optional exchange identity; its `protocol_action` separately records
the RFC-required response, stream reset, connection close, or `no_action`. Backend diagnostic
codes are never treated as HTTP wire codes.

## One-shot requests

For a single request on a connection you already have, `fetch` creates the client, runs the exchange, reads the whole response, and destroys the client. The connection stays yours.

```cpp
http::request request{.method = http::method::POST, .target = "/orders",
                      .scheme = "https", .authority = "api.example.com"};

// The connection kind and the namespace name the version; no template argument.
auto response = co_await http::v1::fetch(tls, request, "a=b"sv);   // byte stream: HTTP/1.1
auto response = co_await http::v2::fetch(tls, request);             // byte stream: HTTP/2
auto response = co_await http::v3::fetch(quic, request);            // stream factory: HTTP/3

// or pick the version generically:
auto response = co_await http::coroutine::fetch<http::protocol_version::http2>(tls, request);

response.head.status;   // http::response
response.text();        // the body, read to its end
```

The request is the same for every version. Give it a scheme and an authority (or a `Host` field); `fetch` adds what the version needs, such as the `Host` field for HTTP/1.1 and a `Content-Length` for a body of known size. A body can be a span or string of bytes (copied when you call `fetch`, so your buffer need not outlive it) or any `body_stream`, which you frame yourself with `Content-Length` or `Transfer-Encoding`. `http::execution::fetch<Version>(...)` returns the same operation as a P2300 sender, and every form takes an optional `std::stop_token` that cancels the response reads.

Around it: `http::client_for<Connection, Version>` names the client type for a connection kind and version, `http::alpn(version)` is the ALPN identifier to offer (`"h2"`, `"h3"`, none for HTTP/1.1), `http::request_origin(request)` gives the host and port to connect to, and `http::coroutine::upgrade(stream, request)` performs an HTTP/1.1 protocol switch (for example to WebSocket) and hands you the connection with the bytes the server already sent after its `101`.

## Streaming bodies

`http::request`/`http::response` carry only metadata (method, target, status, fields, ...) — never a buffered body. Message bodies are asynchronous byte streams:

- Read side: protocol reads return `http::received<head, body>`; the head surfaces once the header section parses, then you stream the body with `async_read` until it returns 0.
- Write side: pass a `http::buffer_body` (in-memory) or any of your own `body_stream` next to the head.

```cpp
import httpant;

http::buffer_body request_body; // or fill it
auto received = co_await http::coroutine::request(
    client,
    http::request{.method = http::method::GET, .target = "/", .fields = {{"host", "example.com"}}},
    request_body);

// received.head is the response metadata; received.body streams the payload.
std::array<std::byte, 8192> buf;
while (auto n = co_await received.body.async_read(buf)) { /* use n bytes */ }
```

## State boundary

The library owns only protocol state (connection persistence, GOAWAY, stream state machines, HPACK/QPACK, 100-continue). Application coordination lives outside it: `caching.cppm` exposes typed RFC 9111 storage/use decisions with explicit clocks, while `cookie.cppm` separates Set-Cookie parsing, PSL-aware acceptance, and request-context selection. Your application owns the cache/cookie containers, eviction, PSL data, and SameSite browsing policy.
