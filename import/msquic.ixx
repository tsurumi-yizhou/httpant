module;

#include <msquic.hpp>

export module httpant.dependencies.msquic;

namespace httpant::dependencies::detail {
inline constexpr auto module_QUIC_ADDRESS_FAMILY_INET = QUIC_ADDRESS_FAMILY_INET;
inline constexpr auto module_QUIC_ADDRESS_FAMILY_INET6 = QUIC_ADDRESS_FAMILY_INET6;
inline constexpr auto module_QUIC_STATUS_INTERNAL_ERROR = QUIC_STATUS_INTERNAL_ERROR;
inline constexpr auto module_QUIC_STATUS_OUT_OF_MEMORY = QUIC_STATUS_OUT_OF_MEMORY;
inline constexpr auto module_QUIC_STATUS_SUCCESS = QUIC_STATUS_SUCCESS;
using module_QUIC_STATUS = QUIC_STATUS;
}

#undef QUIC_ADDRESS_FAMILY_INET
export inline constexpr auto QUIC_ADDRESS_FAMILY_INET = httpant::dependencies::detail::module_QUIC_ADDRESS_FAMILY_INET;
#undef QUIC_ADDRESS_FAMILY_INET6
export inline constexpr auto QUIC_ADDRESS_FAMILY_INET6 = httpant::dependencies::detail::module_QUIC_ADDRESS_FAMILY_INET6;
#undef QUIC_STATUS_INTERNAL_ERROR
export inline constexpr auto QUIC_STATUS_INTERNAL_ERROR = httpant::dependencies::detail::module_QUIC_STATUS_INTERNAL_ERROR;
#undef QUIC_STATUS_OUT_OF_MEMORY
export inline constexpr auto QUIC_STATUS_OUT_OF_MEMORY = httpant::dependencies::detail::module_QUIC_STATUS_OUT_OF_MEMORY;
#undef QUIC_STATUS_SUCCESS
export inline constexpr auto QUIC_STATUS_SUCCESS = httpant::dependencies::detail::module_QUIC_STATUS_SUCCESS;
#undef QUIC_STATUS
export using QUIC_STATUS = httpant::dependencies::detail::module_QUIC_STATUS;
export using ::HQUIC;
export using ::MsQuic;
export using ::MsQuicAlpn;
export using ::MsQuicApi;
export using ::MsQuicConfiguration;
export using ::MsQuicConnection;
export using ::MsQuicCredentialConfig;
export using ::MsQuicListener;
export using ::MsQuicRegistration;
export using ::MsQuicSettings;
export using ::MsQuicStream;
export using ::QUIC_ADDR;
export using ::QUIC_ADDRESS_FAMILY;
export using ::QUIC_API_TABLE;
export using ::QUIC_BUFFER;
export using ::QUIC_CERTIFICATE_FILE;
export using ::QUIC_CONNECTION_EVENT;
export using ::QUIC_CONNECTION_EVENT_CONNECTED;
export using ::QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED;
export using ::QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE;
export using ::QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER;
export using ::QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT;
export using ::QUIC_CONNECTION_SHUTDOWN_FLAG_NONE;
export using ::QUIC_CREDENTIAL_FLAGS;
export using ::QUIC_CREDENTIAL_FLAG_CLIENT;
export using ::QUIC_CREDENTIAL_FLAG_NONE;
export using ::QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION;
export using ::QUIC_CREDENTIAL_FLAG_SET_CA_CERTIFICATE_FILE;
export using ::QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE;
export using ::QUIC_CREDENTIAL_TYPE_NONE;
export using ::QUIC_LISTENER_EVENT;
export using ::QUIC_LISTENER_EVENT_NEW_CONNECTION;
export using ::QUIC_LISTENER_EVENT_STOP_COMPLETE;
export using ::QUIC_RECEIVE_FLAG_FIN;
export using ::QUIC_SEND_FLAG_FIN;
export using ::QUIC_SEND_FLAG_NONE;
export using ::QUIC_STREAM_EVENT;
export using ::QUIC_STREAM_EVENT_PEER_RECEIVE_ABORTED;
export using ::QUIC_STREAM_EVENT_PEER_SEND_ABORTED;
export using ::QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN;
export using ::QUIC_STREAM_EVENT_RECEIVE;
export using ::QUIC_STREAM_EVENT_SEND_COMPLETE;
export using ::QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE;
export using ::QUIC_STREAM_EVENT_START_COMPLETE;
export using ::QUIC_STREAM_OPEN_FLAG_NONE;
export using ::QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL;
export using ::QUIC_STREAM_SHUTDOWN_FLAGS;
export using ::QUIC_STREAM_SHUTDOWN_FLAG_ABORT_RECEIVE;
export using ::QUIC_STREAM_SHUTDOWN_FLAG_ABORT_SEND;
export using ::QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL;
export using ::QUIC_STREAM_SHUTDOWN_FLAG_NONE;
export using ::QUIC_STREAM_START_FLAG_IMMEDIATE;
export using ::QuicAddr;
export using ::QuicAddrGetFamily;

export namespace httpant::dependencies {
inline bool quic_failed(QUIC_STATUS status) noexcept { return QUIC_FAILED(status); }
inline bool quic_succeeded(QUIC_STATUS status) noexcept { return QUIC_SUCCEEDED(status); }
}

export using ::CleanUpManual;
export using ::sockaddr_in;
export using ::sockaddr_in6;

// Keep the platform byte-order helper inside this module's object file.
export namespace httpant::dependencies {
void set_quic_address_port(QuicAddr& address, uint16_t port) {
    address.SetPort(port);
}
}
