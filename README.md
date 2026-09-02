# Httpant

A modern C++ library with no I/O and pure protocols.

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
