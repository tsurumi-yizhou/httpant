# httpant-msquic

The MsQuic adapter for httpant. This is a consumer-side package: httpant core
does not link or depend on msquic.

`http::stream_factory` in `httpant` is the interface. A transport implements it
and is passed to the protocol:

```cpp
import httpant;
import httpant.quic;          // this adapter

http::quic::connection<> transport{scheduler, local, credentials};
http::v3::client client{transport};
```

The adapter links `msquic` itself and exports the `httpant-msquic` target:

```cmake
add_subdirectory(path/to/httpant/adapters/msquic)
target_link_libraries(your_app PRIVATE httpant-msquic)
```

The adapter builds msquic 2.6.4 from source with `FetchContent` as a shared
library. TLS uses schannel on Windows and the manifest's OpenSSL (3.5 or newer)
elsewhere. The consumer deploys `msquic.dll`, `libmsquic.so.2`, or
`libmsquic.2.dylib` with the application.
