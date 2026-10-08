module;

#include <llhttp.h>

export module httpant.dependencies.llhttp;

// Export the API used by Httpant; keep the upstream declarations in the global module.
export using ::HPE_INVALID_HEADER_TOKEN;
export using ::HPE_OK;
export using ::HPE_PAUSED;
export using ::HPE_PAUSED_UPGRADE;
export using ::HTTP_CONNECT;
export using ::HTTP_DELETE;
export using ::HTTP_GET;
export using ::HTTP_HEAD;
export using ::HTTP_OPTIONS;
export using ::HTTP_PATCH;
export using ::HTTP_POST;
export using ::HTTP_PUT;
export using ::HTTP_REQUEST;
export using ::HTTP_RESPONSE;
export using ::HTTP_TRACE;
export using ::llhttp_errno_name;
export using ::llhttp_errno_t;
export using ::llhttp_execute;
export using ::llhttp_finish;
export using ::llhttp_get_error_pos;
export using ::llhttp_get_error_reason;
export using ::llhttp_get_upgrade;
export using ::llhttp_init;
export using ::llhttp_method_t;
export using ::llhttp_reset;
export using ::llhttp_resume;
export using ::llhttp_set_lenient_headers;
export using ::llhttp_settings_init;
export using ::llhttp_settings_t;
export using ::llhttp_should_keep_alive;
export using ::llhttp_t;
export using ::llhttp_type_t;

export using ::F_TRAILING;
export using ::F_CHUNKED;
