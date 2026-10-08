module;

#include <nghttp3/nghttp3.h>

export module httpant.dependencies.nghttp3;

// Export the API used by Httpant; keep the upstream declarations in the global module.
namespace httpant::dependencies::detail { inline constexpr auto module_NGHTTP3_DATA_FLAG_EOF = NGHTTP3_DATA_FLAG_EOF; }
#undef NGHTTP3_DATA_FLAG_EOF
export inline constexpr auto NGHTTP3_DATA_FLAG_EOF = httpant::dependencies::detail::module_NGHTTP3_DATA_FLAG_EOF;
namespace httpant::dependencies::detail { inline constexpr auto module_NGHTTP3_ERR_CALLBACK_FAILURE = NGHTTP3_ERR_CALLBACK_FAILURE; }
#undef NGHTTP3_ERR_CALLBACK_FAILURE
export inline constexpr auto NGHTTP3_ERR_CALLBACK_FAILURE = httpant::dependencies::detail::module_NGHTTP3_ERR_CALLBACK_FAILURE;
namespace httpant::dependencies::detail { inline constexpr auto module_NGHTTP3_ERR_H3_FRAME_UNEXPECTED = NGHTTP3_ERR_H3_FRAME_UNEXPECTED; }
#undef NGHTTP3_ERR_H3_FRAME_UNEXPECTED
export inline constexpr auto NGHTTP3_ERR_H3_FRAME_UNEXPECTED = httpant::dependencies::detail::module_NGHTTP3_ERR_H3_FRAME_UNEXPECTED;
namespace httpant::dependencies::detail { inline constexpr auto module_NGHTTP3_ERR_MALFORMED_HTTP_HEADER = NGHTTP3_ERR_MALFORMED_HTTP_HEADER; }
#undef NGHTTP3_ERR_MALFORMED_HTTP_HEADER
export inline constexpr auto NGHTTP3_ERR_MALFORMED_HTTP_HEADER = httpant::dependencies::detail::module_NGHTTP3_ERR_MALFORMED_HTTP_HEADER;
namespace httpant::dependencies::detail { inline constexpr auto module_NGHTTP3_ERR_MALFORMED_HTTP_MESSAGING = NGHTTP3_ERR_MALFORMED_HTTP_MESSAGING; }
#undef NGHTTP3_ERR_MALFORMED_HTTP_MESSAGING
export inline constexpr auto NGHTTP3_ERR_MALFORMED_HTTP_MESSAGING = httpant::dependencies::detail::module_NGHTTP3_ERR_MALFORMED_HTTP_MESSAGING;
namespace httpant::dependencies::detail { inline constexpr auto module_NGHTTP3_ERR_QPACK_DECODER_STREAM_ERROR = NGHTTP3_ERR_QPACK_DECODER_STREAM_ERROR; }
#undef NGHTTP3_ERR_QPACK_DECODER_STREAM_ERROR
export inline constexpr auto NGHTTP3_ERR_QPACK_DECODER_STREAM_ERROR = httpant::dependencies::detail::module_NGHTTP3_ERR_QPACK_DECODER_STREAM_ERROR;
namespace httpant::dependencies::detail { inline constexpr auto module_NGHTTP3_ERR_QPACK_DECOMPRESSION_FAILED = NGHTTP3_ERR_QPACK_DECOMPRESSION_FAILED; }
#undef NGHTTP3_ERR_QPACK_DECOMPRESSION_FAILED
export inline constexpr auto NGHTTP3_ERR_QPACK_DECOMPRESSION_FAILED = httpant::dependencies::detail::module_NGHTTP3_ERR_QPACK_DECOMPRESSION_FAILED;
namespace httpant::dependencies::detail { inline constexpr auto module_NGHTTP3_ERR_QPACK_ENCODER_STREAM_ERROR = NGHTTP3_ERR_QPACK_ENCODER_STREAM_ERROR; }
#undef NGHTTP3_ERR_QPACK_ENCODER_STREAM_ERROR
export inline constexpr auto NGHTTP3_ERR_QPACK_ENCODER_STREAM_ERROR = httpant::dependencies::detail::module_NGHTTP3_ERR_QPACK_ENCODER_STREAM_ERROR;
namespace httpant::dependencies::detail { inline constexpr auto module_NGHTTP3_ERR_WOULDBLOCK = NGHTTP3_ERR_WOULDBLOCK; }
#undef NGHTTP3_ERR_WOULDBLOCK
export inline constexpr auto NGHTTP3_ERR_WOULDBLOCK = httpant::dependencies::detail::module_NGHTTP3_ERR_WOULDBLOCK;
namespace httpant::dependencies::detail { inline constexpr auto module_NGHTTP3_H3_CLOSED_CRITICAL_STREAM = NGHTTP3_H3_CLOSED_CRITICAL_STREAM; }
#undef NGHTTP3_H3_CLOSED_CRITICAL_STREAM
export inline constexpr auto NGHTTP3_H3_CLOSED_CRITICAL_STREAM = httpant::dependencies::detail::module_NGHTTP3_H3_CLOSED_CRITICAL_STREAM;
namespace httpant::dependencies::detail { inline constexpr auto module_NGHTTP3_H3_EXCESSIVE_LOAD = NGHTTP3_H3_EXCESSIVE_LOAD; }
#undef NGHTTP3_H3_EXCESSIVE_LOAD
export inline constexpr auto NGHTTP3_H3_EXCESSIVE_LOAD = httpant::dependencies::detail::module_NGHTTP3_H3_EXCESSIVE_LOAD;
namespace httpant::dependencies::detail { inline constexpr auto module_NGHTTP3_H3_FRAME_ERROR = NGHTTP3_H3_FRAME_ERROR; }
#undef NGHTTP3_H3_FRAME_ERROR
export inline constexpr auto NGHTTP3_H3_FRAME_ERROR = httpant::dependencies::detail::module_NGHTTP3_H3_FRAME_ERROR;
namespace httpant::dependencies::detail { inline constexpr auto module_NGHTTP3_H3_FRAME_UNEXPECTED = NGHTTP3_H3_FRAME_UNEXPECTED; }
#undef NGHTTP3_H3_FRAME_UNEXPECTED
export inline constexpr auto NGHTTP3_H3_FRAME_UNEXPECTED = httpant::dependencies::detail::module_NGHTTP3_H3_FRAME_UNEXPECTED;
namespace httpant::dependencies::detail { inline constexpr auto module_NGHTTP3_H3_ID_ERROR = NGHTTP3_H3_ID_ERROR; }
#undef NGHTTP3_H3_ID_ERROR
export inline constexpr auto NGHTTP3_H3_ID_ERROR = httpant::dependencies::detail::module_NGHTTP3_H3_ID_ERROR;
namespace httpant::dependencies::detail { inline constexpr auto module_NGHTTP3_H3_INTERNAL_ERROR = NGHTTP3_H3_INTERNAL_ERROR; }
#undef NGHTTP3_H3_INTERNAL_ERROR
export inline constexpr auto NGHTTP3_H3_INTERNAL_ERROR = httpant::dependencies::detail::module_NGHTTP3_H3_INTERNAL_ERROR;
namespace httpant::dependencies::detail { inline constexpr auto module_NGHTTP3_H3_MESSAGE_ERROR = NGHTTP3_H3_MESSAGE_ERROR; }
#undef NGHTTP3_H3_MESSAGE_ERROR
export inline constexpr auto NGHTTP3_H3_MESSAGE_ERROR = httpant::dependencies::detail::module_NGHTTP3_H3_MESSAGE_ERROR;
namespace httpant::dependencies::detail { inline constexpr auto module_NGHTTP3_H3_MISSING_SETTINGS = NGHTTP3_H3_MISSING_SETTINGS; }
#undef NGHTTP3_H3_MISSING_SETTINGS
export inline constexpr auto NGHTTP3_H3_MISSING_SETTINGS = httpant::dependencies::detail::module_NGHTTP3_H3_MISSING_SETTINGS;
namespace httpant::dependencies::detail { inline constexpr auto module_NGHTTP3_H3_NO_ERROR = NGHTTP3_H3_NO_ERROR; }
#undef NGHTTP3_H3_NO_ERROR
export inline constexpr auto NGHTTP3_H3_NO_ERROR = httpant::dependencies::detail::module_NGHTTP3_H3_NO_ERROR;
namespace httpant::dependencies::detail { inline constexpr auto module_NGHTTP3_H3_REQUEST_CANCELLED = NGHTTP3_H3_REQUEST_CANCELLED; }
#undef NGHTTP3_H3_REQUEST_CANCELLED
export inline constexpr auto NGHTTP3_H3_REQUEST_CANCELLED = httpant::dependencies::detail::module_NGHTTP3_H3_REQUEST_CANCELLED;
namespace httpant::dependencies::detail { inline constexpr auto module_NGHTTP3_H3_REQUEST_INCOMPLETE = NGHTTP3_H3_REQUEST_INCOMPLETE; }
#undef NGHTTP3_H3_REQUEST_INCOMPLETE
export inline constexpr auto NGHTTP3_H3_REQUEST_INCOMPLETE = httpant::dependencies::detail::module_NGHTTP3_H3_REQUEST_INCOMPLETE;
namespace httpant::dependencies::detail { inline constexpr auto module_NGHTTP3_H3_STREAM_CREATION_ERROR = NGHTTP3_H3_STREAM_CREATION_ERROR; }
#undef NGHTTP3_H3_STREAM_CREATION_ERROR
export inline constexpr auto NGHTTP3_H3_STREAM_CREATION_ERROR = httpant::dependencies::detail::module_NGHTTP3_H3_STREAM_CREATION_ERROR;
namespace httpant::dependencies::detail { inline constexpr auto module_NGHTTP3_NV_FLAG_NEVER_INDEX = NGHTTP3_NV_FLAG_NEVER_INDEX; }
#undef NGHTTP3_NV_FLAG_NEVER_INDEX
export inline constexpr auto NGHTTP3_NV_FLAG_NEVER_INDEX = httpant::dependencies::detail::module_NGHTTP3_NV_FLAG_NEVER_INDEX;
namespace httpant::dependencies::detail { inline constexpr auto module_NGHTTP3_NV_FLAG_NONE = NGHTTP3_NV_FLAG_NONE; }
#undef NGHTTP3_NV_FLAG_NONE
export inline constexpr auto NGHTTP3_NV_FLAG_NONE = httpant::dependencies::detail::module_NGHTTP3_NV_FLAG_NONE;
export using ::NGHTTP3_QPACK_INDEXING_STRAT_EAGER;
export using ::nghttp3_callbacks;
export using ::nghttp3_conn;
export using ::nghttp3_conn_add_ack_offset;
export using ::nghttp3_conn_add_write_offset;
export using ::nghttp3_conn_bind_control_stream;
export using ::nghttp3_conn_bind_qpack_streams;
export using ::nghttp3_conn_close_stream;
export using ::nghttp3_conn_del;
export using ::nghttp3_conn_read_stream;
export using ::nghttp3_conn_resume_stream;
export using ::nghttp3_conn_set_stream_user_data;
export using ::nghttp3_conn_shutdown;
export using ::nghttp3_conn_submit_request;
export using ::nghttp3_conn_submit_response;
export using ::nghttp3_conn_submit_shutdown_notice;
export using ::nghttp3_conn_writev_stream;
export using ::nghttp3_data_reader;
export using ::nghttp3_err_infer_quic_app_error_code;
export using ::nghttp3_get_uvarint;
export using ::nghttp3_get_uvarintlen;
export using ::nghttp3_mem_default;
export using ::nghttp3_nv;
export using ::nghttp3_proto_settings;
export using ::nghttp3_rcbuf;
export using ::nghttp3_rcbuf_get_buf;
export using ::nghttp3_settings;
export using ::nghttp3_ssize;
export using ::nghttp3_strerror;
export using ::nghttp3_vec;

// Version-selecting upstream macros become typed module functions.
#undef nghttp3_settings_default
export inline void nghttp3_settings_default(nghttp3_settings* settings) {
    nghttp3_settings_default_versioned(NGHTTP3_SETTINGS_VERSION, settings);
}
#undef nghttp3_conn_client_new
export inline int nghttp3_conn_client_new(nghttp3_conn** conn, const nghttp3_callbacks* callbacks,
    const nghttp3_settings* settings, const nghttp3_mem* mem, void* user_data) {
    return nghttp3_conn_client_new_versioned(conn, NGHTTP3_CALLBACKS_VERSION, callbacks,
        NGHTTP3_SETTINGS_VERSION, settings, mem, user_data);
}
#undef nghttp3_conn_server_new
export inline int nghttp3_conn_server_new(nghttp3_conn** conn, const nghttp3_callbacks* callbacks,
    const nghttp3_settings* settings, const nghttp3_mem* mem, void* user_data) {
    return nghttp3_conn_server_new_versioned(conn, NGHTTP3_CALLBACKS_VERSION, callbacks,
        NGHTTP3_SETTINGS_VERSION, settings, mem, user_data);
}
