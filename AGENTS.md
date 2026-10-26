# AGENTS.md — httpant

HTTP/1.1, HTTP/2 and HTTP/3 without I/O, plus the native I/O engine that a
service plugs underneath. Read `README.md` first.

## Layout

| Path | Contents |
| --- | --- |
| `modules/` | The `httpant` module and its partitions: `error`, `message`, `role`, `trait`, `parse/*`, `serialize/*`, `client/*`, `server/*`, `session/*`, `endpoint/*`, `execution`, `coroutine`, `fetch`, `caching`, `cookie` |
| `modules/io/` | The optional `httpant.io` module: `native.cppm` exports `native/core.cppm` (resource and engine types) and `execution.cppm` (senders and networking CPOs); `native/queue.cppm` and mechanism partitions provide execution; `native/context.cppm` contains the private Asio runtime |
| `modules/tls.cppm` | The optional `httpant.tls` module over caller-supplied byte streams |
| `modules/quic.cppm` | The optional `httpant.quic` stream factory with msquic worker events posted to the native engine |
| `import/` | Foundation modules: C library wrappers, shared stdexec definitions, `httpant.memory`, `httpant.queue`, the production `asio` wrapper, and `wolfssl`/`msquic`/`boost.ut` wrappers |
| `testing/` | Protocol tests are globbed into one executable; `testing/io/` contains standalone engine and sender suites that need a scratch directory |
| `examples/`, `bench/` | Optional examples and benchmarks; build commands are in `README.md` |

## Rules

- Keep file, test, target, and variable names concise. Do not repeat context
  already expressed by a directory, module, or enclosing scope.

- **The protocol layer does no I/O, and that is the default build.** `httpant`
  parses bytes and produces bytes; a caller moves them. Platform socket, file,
  and timer mechanisms belong in `httpant.io`, which is
  off unless `HTTPANT_ENABLE_IO` is set. `HTTPANT_ENABLE_QUIC` separately adds
  the QUIC transport and requires native I/O. Do not make the engine a default: a
  protocol library keeps application I/O optional. Asio is the default mechanism
  on every platform. Linux also offers `uring` and `epoll`, Windows offers
  `ioring` and `iocp`, and macOS/BSD offers `kqueue`. Only `uring` needs liburing,
  installed through the `uring` vcpkg feature.
- **`httpant.io` is its own module, not a partition of `httpant`**, and its own
  target `httpant-io`: partitions cannot be imported from outside the module,
  and linking liburing into every protocol consumer would be wrong.
- **Published target names:** `httpant`,
  `httpant-io`, `httpant-imports` — aliased `httpant::httpant`, `httpant::io`
  (and `httpant::default-io`), `httpant::imports`. The optional `httpant-quic`
  target is aliased `httpant::quic`; `httpant-quic-imports` owns its C wrappers.
  `httpant-tls` is aliased `httpant::tls`; `httpant-tls-imports` owns the wolfSSL wrapper.
  A target whose name contains "::" can only be an alias or an imported target
  in CMake, so the real names
  stay plain and the aliases carry the namespace.
- **One template partition per mechanism.** A new platform adds
  `modules/io/native/<mechanism>.cppm` (`export module httpant.io:mechanism;`), a branch in
  `cmake/modules.cmake`, and any private runtime unit it needs. Portable socket setup shared by the
  mechanisms stays in `posix.cppm`; Windows socket resources, completion-port
  dispatch, and high-resolution deadlines are shared in `windows.cppm`.
- **Keep `httpant-io` independent of the protocol target and both HTTP
  interfaces.** It uses the shared stdexec module, the standard library, and
  platform APIs. `httpant-stdexec` is the internal target that owns execution
  definitions for the package.
- Execution operations are CPOs with factory, upstream-sender, and pipeable
  forms. Coroutine operations return promise-aware HTTP tasks. Both call named
  endpoint members directly. `fetch` accepts an existing concrete client and
  buffers one exchange; endpoint lifetime belongs to the caller.
- Native networking follows P2762. The reviewed stdexec source and module-export
  patch are pinned in `../vcpkg-registry/ports/stdexec`; WG21 proposals are cited by number
  in the source.
- The `import/*.ixx` wrappers exist so the rest of the tree never includes a C
  header. Keep it that way.
- TLS consumers import `httpant.tls` and link `httpant::tls`. The `tls` feature
  selects wolfSSL independently of native I/O. Keep the stream transport-generic,
  context I/O registration in the context constructor, and wolfSSL memory I/O
  synchronous. Lock release must suspend before dispatching waiters; a read
  that produced plaintext must return it. Keep session-end `close()` calls.
  The test credential fixture uses the `httpant-certificate` executable.

## Verify

```sh
cmake --preset debug
cmake --build --preset debug
ctest --preset debug
```
