# Httpant

A modern C++ library with no I/O and pure protocols.

## How to use

You should wrap your own backend like `asio`/`openssl`/`wolfssl`/`msquic` as async-byte-stream and pass it to the library. Httpant works on this abstract bytes layer.