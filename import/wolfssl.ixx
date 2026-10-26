module;

#pragma push_macro("_GNU_SOURCE")
#include <wolfssl/options.h>
#pragma pop_macro("_GNU_SOURCE")

// Certificate features enabled by the wolfssl port build.
#define WOLFSSL_CUSTOM_OID
#define HAVE_OID_ENCODING
#define WOLFSSL_ASN_TEMPLATE
#include <wolfssl/ssl.h>
#include <wolfssl/error-ssl.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/random.h>

export module httpant.dependencies.wolfssl;

export using ::WOLFSSL;
export using ::WOLFSSL_CTX;
export using ::wolfSSL_Init;
export using ::wolfSSL_CTX_new;
export using ::wolfSSL_CTX_free;
export using ::wolfTLS_client_method;
export using ::wolfTLS_server_method;
export using ::wolfSSL_CTX_SetMinVersion;
export using ::wolfSSL_CTX_load_system_CA_certs;
export using ::wolfSSL_CTX_load_verify_locations;
export using ::wolfSSL_CTX_set_verify;
export using ::wolfSSL_CTX_use_certificate_chain_file;
export using ::wolfSSL_CTX_use_PrivateKey_file;
export using ::wolfSSL_CTX_SetIORecv;
export using ::wolfSSL_CTX_SetIOSend;
export using ::wolfSSL_new;
export using ::wolfSSL_free;
export using ::wolfSSL_SetIOReadCtx;
export using ::wolfSSL_SetIOWriteCtx;
export using ::wolfSSL_check_domain_name;
export using ::wolfSSL_UseSNI;
export using ::wolfSSL_UseALPN;
export using ::wolfSSL_ALPN_GetProtocol;
export using ::wolfSSL_connect;
export using ::wolfSSL_accept;
export using ::wolfSSL_read;
export using ::wolfSSL_write;
export using ::wolfSSL_shutdown;
export using ::wolfSSL_get_error;
export using ::WOLFSSL_SUCCESS;
export using ::WOLFSSL_SHUTDOWN_NOT_DONE;
export using ::WOLFSSL_TLSV1_2;
export using ::WOLFSSL_VERIFY_PEER;
export using ::WOLFSSL_VERIFY_NONE;
export using ::WOLFSSL_FILETYPE_PEM;
export using ::WOLFSSL_SNI_HOST_NAME;
export using ::WOLFSSL_ALPN_FAILED_ON_MISMATCH;
export using ::WOLFSSL_ERROR_WANT_READ;
export using ::WOLFSSL_ERROR_WANT_WRITE;
export using ::WOLFSSL_ERROR_ZERO_RETURN;
export using ::WOLFSSL_CBIO_ERR_CONN_CLOSE;
export using ::WOLFSSL_CBIO_ERR_WANT_READ;
export using ::WOLFSSL_CBIO_ERR_GENERAL;

export using ::WC_RNG;
export using ::ecc_key;
export using ::Cert;
export using ::wc_InitRng;
export using ::wc_FreeRng;
export using ::wc_ecc_init;
export using ::wc_ecc_free;
export using ::wc_ecc_make_key_ex;
export using ::ECC_SECP256R1;
export using ::wc_InitCert;
export using ::wc_MakeCert;
export using ::wc_SignCert;
export using ::wc_SetCustomExtension;
export using ::wc_EccKeyToDer;
export using ::wc_DerToPem;
export using ::CERT_TYPE;
export using ::ECC_PRIVATEKEY_TYPE;
export using ::CTC_SHA256wECDSA;
export using ::wolfSSL_X509_load_certificate_file;
export using ::wolfSSL_X509_free;
export using ::wolfSSL_X509_notAfter;
export using ::wc_GetDateInfo;
export using ::wc_GetDateAsCalendarTime;

export using ::wolfSSL_get_verify_result;
export using ::WOLFSSL_CBIO_ERR_WANT_WRITE;
export using ::DOMAIN_NAME_MISMATCH;
export using ::VERIFY_CERT_ERROR;
export using ::ASN_BEFORE_DATE_E;
export using ::ASN_AFTER_DATE_E;
export using ::ASN_SIG_CONFIRM_E;
export using ::ASN_NO_SIGNER_E;
export using ::ASN_SELF_SIGNED_E;
