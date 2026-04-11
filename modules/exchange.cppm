export module httpant:exchange;

import std;
import :trait;
import :message;
import :codec;
import :session;
import :channel;

export namespace http {

// Unified HTTP version interface: http::stream\<1/2/3\>::client/server

template <int Version>
struct stream;

template <>
struct stream<1> {
    template <duplex S>
    using client = client_v1<S>;
    template <duplex S>
    using server = server_v1<S>;
};

template <>
struct stream<2> {
    template <duplex S>
    using client = client_v2<S>;
    template <duplex S>
    using server = server_v2<S>;
};

template <>
struct stream<3> {
    template <multiplexed S>
    using client = client_v3<S>;
    template <multiplexed S>
    using server = server_v3<S>;
};

} // namespace http
