module;

#include <openssl/ssl.h>
#include <openssl/err.h>

export module httpant.dependencies.openssl;

namespace httpant::dependencies::detail {
inline constexpr auto module_OPENSSL_NPN_NEGOTIATED = OPENSSL_NPN_NEGOTIATED;
inline constexpr auto module_SSL_OP_NO_COMPRESSION = SSL_OP_NO_COMPRESSION;
inline constexpr auto module_SSL_TLSEXT_ERR_ALERT_FATAL = SSL_TLSEXT_ERR_ALERT_FATAL;
inline constexpr auto module_SSL_TLSEXT_ERR_OK = SSL_TLSEXT_ERR_OK;
inline constexpr auto module_TLS1_2_VERSION = TLS1_2_VERSION;
}

#undef OPENSSL_NPN_NEGOTIATED
export inline constexpr auto OPENSSL_NPN_NEGOTIATED = httpant::dependencies::detail::module_OPENSSL_NPN_NEGOTIATED;
#undef SSL_OP_NO_COMPRESSION
export inline constexpr auto SSL_OP_NO_COMPRESSION = httpant::dependencies::detail::module_SSL_OP_NO_COMPRESSION;
#undef SSL_TLSEXT_ERR_ALERT_FATAL
export inline constexpr auto SSL_TLSEXT_ERR_ALERT_FATAL = httpant::dependencies::detail::module_SSL_TLSEXT_ERR_ALERT_FATAL;
#undef SSL_TLSEXT_ERR_OK
export inline constexpr auto SSL_TLSEXT_ERR_OK = httpant::dependencies::detail::module_SSL_TLSEXT_ERR_OK;
#undef TLS1_2_VERSION
export inline constexpr auto TLS1_2_VERSION = httpant::dependencies::detail::module_TLS1_2_VERSION;
export using ::ERR_error_string_n;
export using ::ERR_get_error;
export using ::SSL_CTX;
export using ::SSL_CTX_set_alpn_protos;
export using ::SSL_CTX_set_alpn_select_cb;
export using ::SSL_CTX_set_options;
export using ::SSL_get0_alpn_selected;
export using ::SSL_select_next_proto;

export namespace httpant::dependencies {
inline long ssl_ctx_set_min_proto_version(SSL_CTX* context, int version) {
    return SSL_CTX_set_min_proto_version(context, version);
}
inline long ssl_set_tlsext_host_name(SSL* ssl, const char* name) {
    return SSL_set_tlsext_host_name(ssl, name);
}
}
export using ::SSL;
