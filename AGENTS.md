# AGENTS.md — httpant

HTTP/1.1, HTTP/2 and HTTP/3 without I/O, plus the native I/O engine that a
service plugs underneath. Read `README.md` first.

## Layout

| Path | Contents |
| --- | --- |
| `modules/` | The `httpant` module and its partitions: `error`, `message`, `role`, `trait`, `parse/*`, `serialize/*`, `client/*`, `server/*`, `session/*`, `endpoint/*`, `execution`, `coroutine`, `fetch`, `caching`, `cookie` |
| `modules/io/` | The `httpant.io` module, built only with `HTTPANT_ENABLE_IO=ON`: `native.cppm` (interface), `native/queue.cppm` (partition), and one implementation unit per mechanism (`uring`, `ioring`, `kqueue`, `posix`) |
| `import/` | Module wrappers over C libraries (`llhttp`, `nghttp2`, `nghttp3`, `stdexec`, and the test-only `asio`/`openssl`/`msquic`/`boost.ut`) |
| `testing/` | `httpant-test` (one executable, `testing/*.cpp` globbed) and `httpant-io-test` (its own executable: it needs a scratch directory) |
| `examples/`, `bench/` | Off by default: `ENABLE_EXAMPLES`, `BUILD_TESTING` |

## Rules

- **The protocol layer does no I/O, and that is the default build.** `httpant`
  parses bytes and produces bytes; a caller moves them. Anything that opens a
  socket, file or timer belongs in `httpant.io`, which is off unless
  `HTTPANT_ENABLE_IO` is set. Do not make the engine a default: a protocol
  library that pulls liburing into every consumer is a different product.
- **`httpant.io` is its own module, not a partition of `httpant`**, and its own
  target `httpant-io`: partitions cannot be imported from outside the module,
  and linking liburing into every protocol consumer would be wrong.
- **Three target names, and they are the published interface:** `httpant`,
  `httpant-io`, `httpant-imports` — aliased `httpant::httpant`, `httpant::io`
  (and `httpant::default-io`), `httpant::imports`. A target whose name contains
  "::" can only be an alias or an imported target in CMake, so the real names
  stay plain and the aliases carry the namespace.
- **One implementation unit per mechanism.** A new platform adds
  `modules/io/native/<mechanism>.cppm` (`module httpant.io;`), a branch in
  `CMakeLists.txt`, and nothing else. Portable socket setup shared by the
  mechanisms stays in `posix.cppm`.
- **Do not add a dependency to `httpant-io`.** It builds against the standard
  library and the platform API only; that is what lets it be consumed by a
  project that never wanted the protocol code.
- The `import/*.ixx` wrappers exist so the rest of the tree never includes a C
  header. Keep it that way.

## Verify

```sh
cmake -B build -DBUILD_TESTING=ON
cmake --build build
ctest --test-dir build
```
