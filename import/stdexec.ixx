module;

#include <stdexec/execution.hpp>

export module httpant.dependencies.stdexec;

export namespace stdexec {
using ::stdexec::completion_signatures;
using ::stdexec::connect;
using ::stdexec::connect_result_t;
using ::stdexec::env_of_t;
using ::stdexec::error_types_of_t;
using ::stdexec::get_env;
using ::stdexec::get_stop_token;
using ::stdexec::inplace_stop_source;
using ::stdexec::inplace_stop_token;
using ::stdexec::operation_state_tag;
using ::stdexec::prop;
using ::stdexec::receiver_t;
using ::stdexec::sender;
using ::stdexec::sender_tag;
using ::stdexec::sends_stopped;
using ::stdexec::start;
using ::stdexec::stop_callback_for_t;
using ::stdexec::stop_token_of_t;
using ::stdexec::unstoppable_token;
using ::stdexec::set_error;
using ::stdexec::set_error_t;
using ::stdexec::set_stopped;
using ::stdexec::set_stopped_t;
using ::stdexec::set_value;
using ::stdexec::set_value_t;
using ::stdexec::sync_wait;
using ::stdexec::then;
using ::stdexec::value_types_of_t;
using ::stdexec::when_all;
using ::stdexec::write_env;
}
