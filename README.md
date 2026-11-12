# Httpant

HTTP/1.1, HTTP/2, and HTTP/3 over caller-owned transports, with independent
coroutine and execution interfaces.

## WebSocket protocol

`http::websocket` supplies sans-I/O RFC 6455 opening-handshake validation and
binary framing. `key` takes 16 caller-generated random bytes; `opening_response`
and `check_response` validate the chosen subprotocol. `encode` takes an optional
four-byte client mask. The caller supplies cryptographic randomness, transport,
control-frame responses, scheduling, and deadlines.

The incremental `decoder` enforces masking direction, continuation order,
canonical lengths, control-frame rules, and close status/reason validity. Its
default limits are 64 KiB per frame, 8 MiB per fragmented message, and 80 KiB of
input buffering. Text frames and extension negotiation are refused. `next`
returns fragments and control frames individually; `available` bounds the next
transport read. HTTP upgrade callers retain and feed bytes already read beyond
the opening headers.

## Native I/O engine (`httpant.io`) — opt-in

`httpant.io` exports networking under `http::io::net`. Its `io_context`
owns the event loop and returns a stdexec scheduler through `get_scheduler()`.
`ip::tcp` and `ip::udp` provide `socket` and `endpoint` types; TCP also provides
`acceptor`. The socket templates expose `open`, `bind`, `close`, `shutdown`,
`local_endpoint`, `remote_endpoint`, `native_handle`, `is_open`, and `set_option`;
acceptors also expose `listen`. `ip::address`, `ip::address_v4`,
`ip::address_v6`, and `ip::basic_endpoint<Protocol>` represent IPv4 and IPv6.

`basic_io_context<Queue>`, `basic_scheduler<Queue>`, `basic_file<Queue>`, and
`native_io::engine<Queue>` select a queue template. Socket templates take it
after `Protocol`. The default is `http::queues::locked<T>`, guarded by
`std::mutex`; `io_context`, `scheduler`, and `file` name the default
instantiations. `httpant.queue`, also exported by both public modules, defines
`http::queues::queue<Q, T>`: `push(T) -> bool` accepts an item, and
`try_pop(T&) -> bool` removes an available item. A failed push leaves the queue
unchanged. Native submissions and blocking file work report `no_buffer_space`
when a queue refuses an item. The engine assembles bounded batches itself;
active-request registration and resource-close scanning remain separate.

HTTP/2 and HTTP/3 `client<S, Queue>` / `server<S, Queue>` use
`http::queues::local<T>` by default. This unsynchronized queue also supplies
their session state, receive queues, body chunks, deferred wakes, and flush
waiters. A QUIC transport is just another `http::stream_factory`. The reference MsQuic
adapter under `adapters/msquic` supplies `http::quic::connection<Queue, Local>`
and `stream<Queue, Local>`; the core `httpant` package neither links nor
depends on MsQuic.

P2762R2 operations provide direct, upstream-sender, and pipe forms:
`async_connect`, `async_accept`, `async_read_some`, `async_write_some`,
`async_receive`, `async_receive_from`, `async_send`, `async_send_to`, and
`async_wait`. Buffers are sequences of `mutable_buffer` or `const_buffer` values produced by
`buffer(...)`; a single buffer is also a sequence. Native operations gather or
scatter up to 16 nonempty buffers per transfer without allocating descriptor
storage. Composed stream transfers advance through the full sequence. Message flags precede
the buffer argument. `async_receive_from` takes an endpoint argument after the
buffer; `async_send_to` takes the destination there.

Successful completion values are `(socket, endpoint)` for accept, no values for
connect, `(size_t)` for reads and writes, `(size_t, endpoint)` for receive-from,
and `(socket_base::wait_type)` for readiness. Network failures use
`set_error(error_code)`; cancellation uses the receiver's stop token and can
complete with `set_stopped()`. Upstream error and stopped signals pass through.
A receiver scheduler from another context reports `invalid_argument`.
The paper's message-operation signature lists omit the values shown in its
operation semantics; this implementation uses those byte counts and endpoints.

`async_read` and `async_write` compose partial stream transfers to fill or drain
a buffer sequence. Positioned file operations, `file`, posting, and the scheduler's
`schedule_at` / `schedule_after` timers also live in `http::io::net`.

Select the mechanism at configure time with `HTTPANT_IO_BACKEND`:

| Platform | Default | Other choices |
| --- | --- | --- |
| Linux | `asio` | `uring`, `epoll` |
| Windows | `asio` | `ioring`, `iocp` |
| macOS and the BSDs | `asio` | `kqueue` |

`asio` drives a standalone Asio `io_context` on the thread calling `run()`.
Submissions enter the selected `Queue`; cross-thread cancellation and queue
notifications wake that loop. Each pending operation has its own cancellation
slot. Positioned files use Asio random-access files when built with IOCP or
io_uring support; other platforms use the same two-worker file queue as `epoll`.
The default Linux Asio build uses that worker queue and does not need liburing.

`epoll` creates nonblocking sockets once, coalesces cross-thread eventfd
wakeups, completes local posts without a wakeup, and uses timerfd deadlines.
Two lazily started workers handle positioned file I/O. `uring` requires Linux
6.1: its ring is created disabled with a single issuer and deferred task work,
and the first thread to call `run()` enables it and must remain its only runner.
The Windows mechanisms
share completion-port socket operations, AcceptEx/ConnectEx, handle association,
and a high-resolution waitable timer. `iocp` submits files through overlapped
I/O; `ioring` submits positioned files through its ring. Ring completion events
feed the completion port. Data transfers and socket readiness use completion-port
events. Socket notification registrations remain alive until removal is acknowledged. Pending operations retain their request state until their
kernel completion and any cancellation acknowledgment have been consumed.
Datagram receives report the number of bytes placed in the supplied buffer.

For example, configure Linux with
`cmake --preset debug -DHTTPANT_IO_BACKEND=epoll`, or add
`-DHTTPANT_ENABLE_IO=ON -DHTTPANT_IO_BACKEND=iocp` to a Windows configure command.
An installed package keeps the backend it was built with. A consumer that
adds httpant as a subproject selects its own with `HTTPANT_IO_BACKEND`, set
before httpant's `CMakeLists.txt` runs; the same platform choices apply.
Asio and liburing (on Linux) are plain dependencies in `vcpkg.json`.

`http::io::net::io_context::mechanism()` reports the selection. `async_receive_from` completes with a byte count and
source endpoint; an empty UDP datagram is a successful message.

Start connected operation states and drive `io_context::run()` until their
completion receivers stop the loop. Resources and buffers remain alive until
completion. [The native HTTP example](examples/http.cpp) runs HTTP/1.1
and HTTP/2 over these sockets with both coroutine and execution interfaces.
[The standalone execution test](testing/io/execution.cpp) covers TCP, UDP,
cancellation, and positioned files.

It is **off by default**. httpant's default identity is the sans-I/O protocol
library: it parses bytes and produces bytes, and opens nothing. Turn the engine
on when you want it:

```sh
cmake --preset debug
cmake --build --preset debug
ctest --preset debug -R '^(io|execution)$'
```

```cpp
import httpant;     // protocol
import httpant.io;  // engine
```

```cmake
find_package(httpant CONFIG REQUIRED)
target_link_libraries(your-target PRIVATE httpant::httpant httpant::io)
```

A source checkout works the same through `FetchContent`, with the options set
as normal variables first:

```cmake
set(HTTPANT_ENABLE_IO ON)
FetchContent_Declare(httpant GIT_REPOSITORY https://github.com/tsurumi-yizhou/httpant.git
  GIT_TAG <commit> EXCLUDE_FROM_ALL)
FetchContent_MakeAvailable(httpant)
```

Published targets:

| Target | Module | What it is |
| --- | --- | --- |
| `httpant` | `httpant` | the protocol library |
| `httpant::io` | `httpant.io` | the engine, `HTTPANT_ENABLE_IO=ON` only |
| `httpant::imports` | C library wrappers | linked by the protocol target |
| `httpant::tls` | `httpant.tls` | TLS over a caller transport, `HTTPANT_ENABLE_TLS=ON` only |

`HTTPANT_ENABLE_TLS=ON` builds `httpant-tls`, aliased as `httpant::tls`, over
wolfSSL. It is on by default at top level, where examples and tests need it, and
off in a subproject.
`import httpant.tls;` exports `http::tls::context`, `http::tls::stream<Transport>`,
and `http::tls::verification_failure`. The transport supplies
`async_read(span, stop)` and `async_write(span, stop)`; the TLS stream also
satisfies `http::byte_stream`. Socket I/O stays in the supplied transport.

A context selects client or server mode with its boolean constructor.
`certificate(cert, key)` loads PEM files; `trust(ca)` loads a CA file, and
`trust("")` loads system roots. `trust("", false)` disables peer verification.
Configure the context before creating sessions. A stream accepts the transport,
context, and optional ALPN string; `hostname(host, verify)` sets SNI and optional
hostname verification. `handshake(server, required_protocol)` checks the selected
ALPN when `required_protocol` is nonempty. TLS 1.2 is the minimum version.

All operations on a stream share one serialized executor. Copies share session
state; synchronous wolfSSL memory I/O uses a 128 KiB pending-output limit.
Certificate and hostname failures throw `verification_failure`. A successful
read returns its plaintext before further output work. Only `close_notify`
produces EOF; a raw transport EOF throws. `close(stop)` checks shutdown, sends
`close_notify` without waiting for the peer, ignores a final transport
`std::system_error`, and propagates `http::stopped`.

The wrappers are a separate target because CMake rejects a public module source
that imports a module provided by a private source of the same target — folding
them into `httpant` fails at generate time.

The engine links stdexec, the standard library, and the selected mechanism's dependencies. Its link
graph contains the shared execution module independently of the HTTP protocol
target. Only `uring` links liburing, imported from its vcpkg archive; Windows
adds `ws2_32` and `kernel32`.

`import httpant;` and `import httpant.io;` expose the same execution definitions.
The internal `httpant-stdexec` target owns stdexec and its extensions in one
named module. stdexec comes from the builtin vcpkg registry; the extension
names that upstream does not export are exposed by `import/stdexec.ixx` as
`httpant::stdexec_ext`.

### Native examples and backend measurements

With native I/O enabled, `HTTPANT_BUILD_EXAMPLES=ON` builds `http-example` beside the
Asio examples. `HTTPANT_BUILD_BENCHMARKS=ON` also builds `io-bench` when native I/O is
enabled. Both use the selected `HTTPANT_IO_BACKEND`; their application sources
contain no backend branches.

```sh
cmake --preset release -DHTTPANT_IO_BACKEND=epoll -DHTTPANT_BUILD_EXAMPLES=ON -DHTTPANT_BUILD_TESTS=ON
cmake --build --preset release --target http-example io-bench httpant-certificate
build/debug/httpant-certificate build/debug
build/debug/http-example --protocol h2 --interface execution --requests 100 --bytes 131072
build/debug/io-bench --directory build/debug --address 127.0.0.2 --scenario tcp --iterations 10000 --warmup 1000 --concurrency 8 --bytes 4096 --samples 5
```

Linux measurements default to `127.0.0.2`, with both endpoints
bound to that address. The runner verifies that TCP and UDP routes use `lo`
and stops if either route uses another interface. `--address` selects the
benchmark address; JSON records include it, and the Linux runner records
`device: "lo"`. Windows and the other platforms default to `127.0.0.1`.

The HTTP example defaults to a finite loopback round trip on an ephemeral port.
It verifies every echoed request body and prints JSON records for both roles.
`h2` uses cleartext prior knowledge by default. For HTTP/1.1 or HTTP/2 TLS,
add `--tls`, server `--cert`/`--key`, and client `--ca`/`--server-name` arguments.
The example uses `httpant.tls` and requires `http/1.1` or `h2` ALPN.
Both endpoints send `close_notify` at the end of a session.
To run separate processes, use matching
protocol, request-count, and body-size arguments:

```sh
build/debug/http-example --mode server --address 127.0.0.2:8080 --protocol h1 --requests 100 --bytes 1024
build/debug/http-example --mode client --address 127.0.0.2:8080 --protocol h1 --requests 100 --bytes 1024
```

[The backend runner](bench/run.py) selects `asio`/`uring`/`epoll` on Linux,
`asio`/`ioring`/`iocp` on Windows, and `asio`/`kqueue` on macOS/BSD. It requires an existing
configured build tree, builds in Release by default, and validates each backend
before collecting samples. `--interop` additionally checks every built
server/client backend pair in separate processes, for all selected protocols
and both interfaces. The server selects its port and reports it to the controller.

```sh
python3 bench/run.py --build-dir build/debug --backends uring epoll --address 127.0.0.2 --concurrency 1 4 16 --bytes 64 1024 --iterations 1000 --warmup 100 --samples 5 --seconds 0.2 --http-requests 2000 --http-warmup 200 --http-samples 5 --interop
python3 bench/run.py --build-dir build/debug --backends uring epoll --check-only --interop
```

On Windows, run the script with Python against an existing Windows build tree
and select `--backends ioring iocp`. `--data-dir` selects an existing directory
for temporary I/O files independently of the build directory; it also sets
`HTTPANT_DATA_DIR` for the native checks. Windows data must use a local drive
path. UNC and WSL shares are rejected by the benchmark. Retained executables are named
`http-example-BACKEND[.exe]` and `io-bench-BACKEND[.exe]` in the
build directory. Validation results are reused when the executable bytes,
effective test definitions, host, and evidence logs match. The JSONL output
defaults to `BUILD_DIR/native-results.jsonl`; `--output` selects another file.
Individual workload failures are recorded, remaining workloads continue, and
any failure produces a nonzero exit status.

| Scenario | One measured operation |
| --- | --- |
| `post` | One completion scheduled on the context |
| `timer` | One deadline wait; also reports p99 deadline lateness |
| `tcp` | One full-buffer request/echo on an established connection |
| `udp` | One connected datagram request/echo |
| `file` | One positioned write/read through the file cache |

`--seconds` calibrates the per-lane iteration count toward a sample duration,
keeping `--iterations` as the minimum count. Actual durations and the data
directory are included in each JSON record. `--http-warmup` excludes initial
requests from HTTP timing; `--http-samples` repeats measurements on the same
connection and reports each client/server sample separately.

`--iterations` and `--warmup` apply per lane; `--concurrency` sets the lane count
on one event-loop thread. TCP/UDP measurements run both loopback endpoints on
that context.
Each sample excludes resource setup and its warmup, checks payload contents, and
reports operations/s, payload MiB/s, and p50/p95/p99/max completion latency.
TCP, UDP, and file throughput counts two payload transfers per round trip.
Latency quantiles pool all lanes within a sample; the runner summarizes medians
across samples. File measurements exclude durability flushes. Compare identical
arguments on the same host, OS, and filesystem without concurrent builds.
### QUIC adapters

`httpant` defines `http::stream_factory` and the HTTP/3 protocol over it, but
does not own a QUIC transport and does not link MsQuic. A consumer links its
QUIC implementation, wraps it as a `stream_factory`, and passes it to
`http::v3::client` or `http::v3::server`.

The reference adapter lives in
[`adapters/msquic`](adapters/msquic/README.md). It builds MsQuic 2.6.4 from
source, links it, and exports the `httpant::msquic` target; the core package has
no MsQuic dependency. The adapter owns the MsQuic event loop, credentials, and
stream handles. The consumer deploys `msquic.dll`, `libmsquic.so.2`, or
`libmsquic.2.dylib` with the application.

Because the adapter is a separate target, the protocol test suite uses the
in-tree `mock_stream_factory` and needs no MsQuic at all.

### HTTP throughput and p99

[The HTTP measurement runner](bench/http.py) accepts existing Release binaries
and records five verified samples per protocol/interface condition. It
calibrates request count toward two seconds per sample, with a 1,000-request
minimum. Successful samples are reused only when the binary, arguments,
environment metadata, certificate, and evidence hashes match.

```sh
python3 bench/http.py --build-dir build/debug --binaries epoll=build/debug/http-example-epoll uring=build/debug/http-example-uring --compiler 'Clang 23.1.2 (xclang 23.1.2.10)'
```

For Windows binaries, pass `iocp=PATH` and `ioring=PATH` instead. A WSL controller
can launch native `.exe` files; the runner converts credential paths and takes
`--windows-version` as execution-environment metadata. It performs no builds.

Measured October 26, 2026 (Asia/Taipei), on a Ryzen 7 9800X3D with 16 logical
CPUs: Linux/WSL2 kernel `6.18.33.2-microsoft-standard-WSL2` for epoll/io_uring,
and native Windows `10.0.26300.9711` for IOCP/IORing. Application code used
Clang 23.1.2, `-O3 -DNDEBUG`, including Windows foundation modules. HTTP/2
used the Release nghttp2 archive. The HTTP/3 measurements below predate the
current msquic transport.
Each condition used one persistent connection, one in-flight POST, a 1 KiB
request and echoed response, 200 warmup requests, and five measured samples.
Both endpoints ran on one native context in the same process. The table shows
median request throughput and median per-sample p99; each p99 uses nearest rank
from client fetch start through the complete response body. Handshake and
warmup are excluded. Payload MiB/s counts both body directions in the raw data.

| Backend | Interface | H1 req/s | H1 p99 µs | H2 req/s | H2 p99 µs | H3 req/s | H3 p99 µs |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| epoll | coroutine | 28,296 | 84.7 | 17,957 | 122.6 | 6,640 | 304.1 |
| epoll | execution | 28,186 | 84.6 | 18,117 | 119.9 | 6,775 | 260.0 |
| io_uring | coroutine | 30,529 | 69.1 | 20,687 | 103.2 | 7,124 | 272.0 |
| io_uring | execution | 29,895 | 79.6 | 20,482 | 103.9 | 6,763 | 333.0 |
| IOCP | coroutine | 27,329 | 50.1 | 17,665 | 86.1 | 7,806 | 207.7 |
| IOCP | execution | 29,145 | 47.3 | 17,539 | 81.6 | 7,610 | 220.3 |
| IORing | coroutine | 27,055 | 52.6 | 16,887 | 88.2 | 7,696 | 209.2 |
| IORing | execution | 26,717 | 51.1 | 17,824 | 78.2 | 7,565 | 214.8 |

HTTP/1.1 and HTTP/2 used cleartext TCP; HTTP/3 used TLS 1.3. These measurements
describe the single-flight workload above. Capacity at higher concurrency
requires a separate workload.
Windows IORing uses the shared IOCP socket path for TCP and UDP. kqueue remains
unmeasured because no macOS/BSD runtime host was available.

[The evidence record](bench/http-results.jsonl) contains all 120 client samples,
source hashes, validation results, repairs, and execution metadata. Unchanged
epoll HTTP/1 samples were reused; HTTP/2 samples were replaced after correcting
the Release dependency selection. HTTP/3 samples were collected after the
pacing and completed-stream lifetime fixes. Windows samples and checks use
uniform Release optimization for all application and foundation modules.

## Build

Requires CMake 4.0+, Ninja, C++23, and the
[xclang toolchain](https://github.com/clice-io/xclang), whose `xclang::std`
target provides the standard library module. `cmake/toolchain.cmake` reads two
environment variables: `XCLANG_ROOT` names the xclang tree and `VCPKG_ROOT` the
vcpkg checkout. `XCLANG_TARGET` selects the target, the host's by default.
`CMakePresets.json` has the `debug` and `release` configurations; machine paths
belong in a Git-ignored `CMakeUserPresets.json` that inherits them:

```sh
cmake --preset debug
cmake --build --preset debug
ctest --preset debug
```

`debug` tests the protocol, the native engine and the examples; `release`
builds them optimized, with the benchmarks and without tests. Add
`-DHTTPANT_ENABLE_IO=OFF` for the protocol alone. Each preset builds in
`build/<preset>`. The MsQuic adapter is a separate project under
`adapters/msquic`.

The protocol suite, including completed HTTP/3 stream-handle release, is
locally validated on Linux x64 with Clang 23 and libc++;
GCC is unsupported. Seven native checks pass for each of Linux x64 `uring` and
`epoll` and Windows x64 `ioring` and `iocp`: the two native I/O suites, four HTTP
protocol/interface round trips with 128 KiB bodies, and benchmark smoke tests.
Sixteen HTTP/1 and HTTP/2 separate-process server/client combinations pass on
each OS. QUIC adds four HTTP/3 checks per backend (128 KiB bodies and 2,048
sequential streams, both interfaces), a native transport suite, and eight
HTTP/3 process pairs per OS. The
Windows executables were cross-compiled with xclang and run on build 26300.
The post-fix run collected 630 I/O samples and 320 HTTP endpoint measurements,
with concurrency 1/4/16 and five samples per condition. The subsequent Linux
`lo` run replaces its mirrored-path TCP, UDP, and HTTP measurements with 180
network samples and 160 HTTP endpoint records. Its 4 KiB UDP cases pass on both
Linux backends at all three concurrency levels. Windows file data used
local NTFS storage; the earlier WSL-share file measurements are excluded from
performance-change comparisons. This host routes 127.0.0.1 TCP/UDP through
WSL mirrored networking's 1500-MTU loopback0 interface. Direct UDP controls
receive 1472-byte payloads but time out at 1473/4096 bytes; only first IP
fragments return. A 4096-byte control succeeds on 127.0.0.2, which routes through
Linux lo. Earlier 127.0.0.1 network results include the mirrored path and are
excluded from the current Linux network results. The failed controls and
earlier backend timeouts remain recorded. macOS/BSD
runtime measurements have not been collected. The CI matrix also builds the
protocol on macOS and Windows and the io engine on Linux and macOS. Build
dependencies with the same toolchain as Httpant.

Options: `HTTPANT_BUILD_TESTS` and `HTTPANT_ENABLE_TLS` (default `ON` at top
level), `HTTPANT_BUILD_EXAMPLES`, `HTTPANT_BUILD_BENCHMARKS` and
`HTTPANT_ENABLE_IO` (default `OFF`). Every dependency
comes from vcpkg at the microsoft/vcpkg baseline in `vcpkg-configuration.json`
through `cmake/toolchain.cmake`, which writes the `*-xclang` triplet for the
target into the build directory. The protocol needs llhttp, nghttp2, nghttp3 and
stdexec; the engine adds liburing on Linux, and TLS, tests and examples add
Asio, wolfSSL and Boost.UT. `cmake/dependencies.cmake` finds them for this build
and for the installed package alike; nghttp2 and liburing install no CMake
package, so `cmake/FindNghttp2.cmake` and `cmake/FindLiburing.cmake` import
them.

## How to use

Wrap your own backend (asio, wolfSSL, MsQuic, ...) with Httpant's
transport concepts: HTTP/1.1 and HTTP/2 use a stop-aware `byte_stream`;
HTTP/3 uses a `stream_factory` that opens and accepts QUIC
streams. The application selects the transport and owns connection lifetimes,
caching, and cookies. The optional native QUIC factory is described above.

A sender-based byte stream can be passed through the borrowed
`http::stream` transport. Its read and write operations remain senders with the
protocol stop token in their receiver environment:

```cpp
http::stream transport{socket};
http::v1::client client{transport};
auto reply = co_await http::coroutine::fetch(client, head);
```

## Two interfaces

Both interfaces use concrete, typed client and server objects. Their shared
protocol operations are named members (`start`, `close`, `request`, `receive`,
`respond`); each interface owns and completes its operations independently.

- **Coroutine interface** (`http::coroutine`): lazy, move-only `http::task<T>`
  values with stop propagation. Promise-aware `as_awaitable` supports direct
  awaiting from application coroutine types that expose an execution
  environment and a stopped continuation.
- **Execution interface** (`http::execution`): lazy P2300 senders. The operation
  CPOs accept direct arguments or an upstream sender. Operations with input
  values also provide a bound pipeable form, such as
  `stdexec::just(head) | http::execution::request(client)`.

`start`, `close`, `request`, `receive`, `respond`, `read`, `fetch`, and `upgrade`
exist on both interfaces. `scoped` and `with_scope` manage coroutine lifetimes.
The shared protocol algorithms use internal C++ coroutine frames. The execution
interface owns those frames as sender operation states; the coroutine interface
returns its distinct public task type. The task wrappers share one typed promise,
so a coroutine factory can adopt an existing frame. For `request` and `respond`,
the adapter binds the exact value-taking member when available; reference-taking
members run with message arguments owned by the adapter's task.

Cancellation throws `http::stopped` through HTTP coroutine chains and completes
execution operations with `set_stopped`. A direct application coroutine boundary
forwards the stop token and transfers a stopped result to the parent's stopped
continuation.

### Execution boundary

- Coroutine boundaries forward the stop token. HTTP and application tasks share
  the bounded thread-local pool in `httpant.memory`; ASan builds use direct
  allocation. Scheduling remains the caller's responsibility. Sender failures use
  `set_error(std::exception_ptr)` at the protocol operation boundary.
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

Build the boundary benchmark in the existing project build directory:

```sh
cmake --preset release
cmake --build --preset release --target httpant-boundary-cost
build/debug/httpant-boundary-cost request-facade 50000
```

`request-member` is the concrete-call control; `http1-forwarded` is an explicit
forwarding-coroutine control for `http1-coroutine`. Other modes cover sender
awaiting, stop-token variants, cancellation, and buffered HTTP/1 fetches. Counts
cover plain global `new`/`new[]`; timings are single samples. The measured
inputs, review decisions and limits are recorded with the benchmark source.

Measured on Linux x64 with xclang 23.1.2.10 and libc++, Release
(`-O3 -DNDEBUG`), 50,000 iterations per mode after warm-up:

| Operation | ns/op | `new` calls/op | Requested bytes/op |
| --- | ---: | ---: | ---: |
| Await an inline sender | 18.7 | 0 | 0 |
| Complete with a pre-stopped token | 5.1 | 0 | 0 |
| HTTP/1 request: direct member | 393.3 | 5 | 931 |
| HTTP/1 request: coroutine facade | 416.0 | 5 | 931 |
| HTTP/1 buffered fetch: execution | 646.2 | 7 | 941 |
| HTTP/1 buffered fetch: coroutine | 600.1 | 7 | 941 |

HTTP cases use an in-memory transport. Allocation counts include the operation's
owned request and response data; frame pools are warm. Before the changes,
pre-stopped completion allocated once (24 bytes), and execution fetch allocated
eight times (946 bytes). Timings are single-run averages, without a statistical
speedup claim; aligned allocation and C-library `malloc` are outside the counter.

### Structured lifetimes

HTTP/2 and HTTP/3 endpoints run drivers beside the application (the HTTP/2
reader, the HTTP/3 accept loop and stream readers) in an endpoint-owned
scope: `start` spawns them, `close` stops and joins them (pending exchanges
finish with `http::stopped`), and a started endpoint must be closed before
destruction. `http::coroutine::scoped(endpoint, body)` does all three for
you:

```cpp
http::v2::client<TlsStream> client{tls};
auto run_session = [&](auto& c) -> http::task<std::string> {
    auto received = co_await http::coroutine::request(c, request);
    co_return co_await read_all(received.body);
};
auto response = co_await http::coroutine::scoped(client, std::move(run_session));
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
  `error_info` gives the typed condition, the scope the action implies, and an
  optional exchange identity; `protocol_action` records what remains for the
  application (stream reset, connection close, or `no_action`), and
  `http::retryable(info)` derives the retry answer from the condition. Error
  codes are one 62-bit space (RFC 9114 §8.1): an engine writes the bits its own
  frame format has, and there is no per-version code type.
- **`http::usage_error`** (a `std::logic_error`) — a call outside the
  contract: request on a closed connection, an exchange token from another
  server, an unframable message, a contract-breaking transport.
- **`http::stopped`** — cancellation, described above.

## Methods

`http::method` is a 32-byte literal type that is always a valid RFC 9110
token, and `http::status` is a 16-bit type that is always within 100-599
(RFC 9110 §15). Literals like `.method = "PROPFIND"` or `.status = 404` are
checked at compile time; `http::method::parse(text)` and `http::status::parse(text)`
are the runtime doors. Extension methods keep their token on every version, so
a proxy forwards them unchanged.

## Buffered requests

`fetch` sends one request through a caller-owned client and reads the response
body into `http::fetched`. The concrete client type selects the protocol and
retains its configuration. The caller owns endpoint startup, shutdown, and
recovery after a failed exchange.

```cpp
http::v1::client client{transport};
http::request head{.method = http::method::POST, .target = "/orders",
                   .scheme = "https", .authority = "api.example.com"};

auto reply = co_await http::coroutine::fetch(client, head, "a=b"sv);
reply.head.status.code();
reply.text();

// Three execution forms; each remains lazy until started.
auto direct = http::execution::fetch(client, head);
auto adapted = http::execution::fetch(stdexec::just(head), client);
auto piped = stdexec::just(head) | http::execution::fetch(client);
```

HTTP/2 and HTTP/3 clients run drivers for the endpoint lifetime. A coroutine
caller can place multiple fetches inside `http::coroutine::scoped(client, body)`;
an execution caller uses the `start` and `close` senders around its exchanges.
Successful fetches leave the endpoint available for another request. Close the
endpoint to recover from an interrupted exchange. In HTTP/2, an incomplete
outbound body remains deferred until the peer or endpoint closes its stream.

A direct span or string body is copied before the lazy operation is returned.
A body stream is borrowed until the operation completes. `fetch` derives a Host
field and known body length when needed. `http::fetch_options{.body_limit = n}`
sets the response buffer bound (default 64 MiB); exceeding it raises a
`resource_limit` protocol error.

`http::request_origin(head)` derives the host and port. The HTTP/1 client also
supports `upgrade(client, head)` on both interfaces: the result reports whether
the protocol switched and returns bytes already received after the response
head. A refused upgrade returns its buffered response in `result.body`, using
the optional `fetch_options` body bound, and consumes it so the client can issue
another request. The transport remains owned by the caller.

## Streaming bodies

`http::request`/`http::response` carry only metadata — never a buffered
body. Reads return `http::received<head, body>` (stream with `async_read`
until it returns 0); writes take a `http::buffer_body` or your own
`body_stream` next to the head. `http::span_body` borrows contiguous bytes whose
owner outlives the operation. HTTP/2 data providers consume contiguous bodies
without a separate staging allocation; streamed sources retain their staging
buffer. A cancelled producer is detached, while a completed producer retains
its EOF until the final frame can be emitted.

```cpp
import httpant;

http::buffer_body request_body; // or fill it
auto received = co_await http::coroutine::request(
    client,
    http::request{.method = http::method::GET, .target = "/", .fields = {{"host", "example.com"}}},
    request_body);

// received.head is the response metadata; received.body streams the payload.
std::array<std::byte, 8192> buf;
while (auto n = co_await http::coroutine::read(received.body, buf)) { /* use n bytes */ }
```

## State boundary

The library owns only protocol state (connection persistence, GOAWAY, stream
state machines, HPACK/QPACK, 100-continue). `caching.cppm` exposes typed RFC
9111 storage/use decisions; `cookie.cppm` separates Set-Cookie parsing,
PSL-aware acceptance, and request-context selection. Your application owns
the containers, eviction, PSL data, and SameSite policy.

## References and validation

WG21 papers are cited by number in the source comments; P2762R2 is the
networking design basis. The execution and coroutine evidence is recorded with
the benchmark source and in repository history.
