#include <boost/ut.hpp>

#include <cstdint>
#include <stdexcept>
#include <string_view>
#include <type_traits>
#include <variant>

import httpant;

namespace httpant::testing {

using namespace boost::ut;
using namespace std::literals;

static_assert(std::is_base_of_v<std::runtime_error, http::protocol_error>);
static_assert(std::is_final_v<http::protocol_error>);

static suite<"error"> error_suite = [] {
    "protocol_versions_are_explicit"_test = [] {
        expect(static_cast<std::uint8_t>(http::protocol_version::http1) == 1_u);
        expect(static_cast<std::uint8_t>(http::protocol_version::http2) == 2_u);
        expect(static_cast<std::uint8_t>(http::protocol_version::http3) == 3_u);
    };

    "action_scope_invariants_are_enforced"_test = [] {
        // Internal construction invariants (not RFC wire behavior): a stream
        // reset is only meaningful at stream scope, and a connection close
        // only at connection scope — both are rejected at construction.
        auto threw = false;
        try {
            static_cast<void>(http::protocol_error{
                http::error_info{
                    .version = http::protocol_version::http2,
                    .scope = http::error_scope::message,
                    .condition = http::error_condition::malformed_message,
                    .exchange_identity = std::nullopt,
                    .library_code = std::nullopt,
                    .retryable = false,
                },
                http::reset_stream{http::v2::error_code{0x1}},
                "message error cannot reset a stream",
            });
        } catch (const std::invalid_argument&) {
            threw = true;
        }
        expect(threw);

        threw = false;
        try {
            static_cast<void>(http::protocol_error{
                http::error_info{
                    .version = http::protocol_version::http2,
                    .scope = http::error_scope::message,
                    .condition = http::error_condition::malformed_message,
                    .exchange_identity = std::nullopt,
                    .library_code = std::nullopt,
                    .retryable = false,
                },
                http::close_connection{http::v2::error_code{0x1}},
                "message error cannot close the connection",
            });
        } catch (const std::invalid_argument&) {
            threw = true;
        }
        expect(threw);
    };

    "protocol_error_preserves_metadata_and_message"_test = [] {
        // RFC 9113 §5.4.2 — "A stream error is an error related to a specific
        // stream that does not affect processing of other streams." — stream
        // failures retain the identity of the affected exchange and the RFC 9113
        // §7 error code carried on the RST_STREAM.
        const auto error = http::protocol_error{
            http::error_info{
                .version = http::protocol_version::http2,
                .scope = http::error_scope::stream,
                .condition = http::error_condition::stream_reset,
                .exchange_identity = 17,
                .library_code = std::nullopt,
                .retryable = false,
            },
            http::reset_stream{http::v2::error_code{0x8}},
            "http/2: stream reset",
        };

        expect(std::string_view{error.what()} == "http/2: stream reset"sv);
        expect(error.info().version == http::protocol_version::http2);
        expect(error.info().scope == http::error_scope::stream);
        expect(error.info().condition == http::error_condition::stream_reset);
        expect(error.info().exchange_identity.has_value());
        expect(*error.info().exchange_identity == 17_u);
        expect(!error.info().library_code.has_value());
        expect(!error.info().retryable);

        // The action carries the typed HTTP/2 wire code (RFC 9113 §7).
        expect(std::holds_alternative<http::reset_stream>(error.action()));
        const auto& reset = std::get<http::reset_stream>(error.action());
        expect(std::holds_alternative<http::v2::error_code>(reset.code));
        expect(std::get<http::v2::error_code>(reset.code).value == 8_u);
    };

    "h1_errors_use_response_and_close_actions"_test = [] {
        // RFC 9112 §3.2 — "A server MUST respond with a 400 (Bad Request) status
        // code to any HTTP/1.1 request message that lacks a Host header field."
        // The send_response action carries the response status; HTTP/1.1 has no
        // integer protocol error code, so close_connection carries none.
        const auto error = http::protocol_error{
            http::error_info{
                .version = http::protocol_version::http1,
                .scope = http::error_scope::message,
                .condition = http::error_condition::malformed_message,
                .exchange_identity = std::nullopt,
                .library_code = std::nullopt,
                .retryable = false,
            },
            http::send_response{400, true},
            "http/1.1: missing Host header",
        };

        expect(std::holds_alternative<http::send_response>(error.action()));
        const auto& response = std::get<http::send_response>(error.action());
        expect(response.status == 400_u);
        expect(response.close_after);

        const auto close = http::protocol_error{
            http::error_info{
                .version = http::protocol_version::http1,
                .scope = http::error_scope::connection,
                .condition = http::error_condition::peer_closed,
                .exchange_identity = std::nullopt,
                .library_code = std::nullopt,
                .retryable = false,
            },
            http::close_connection{std::nullopt},
            "http/1.1: connection closed before headers",
        };
        expect(std::holds_alternative<http::close_connection>(close.action()));
        expect(!std::get<http::close_connection>(close.action()).code.has_value());
    };

    "h2_and_h3_code_spaces_are_distinct"_test = [] {
        // RFC 9113 §7 — HTTP/2 error codes are 32-bit fields used in RST_STREAM
        // and GOAWAY; RFC 9114 §8.1 — HTTP/3 application error codes live in
        // their own 62-bit registry. The two spaces are distinct types and
        // cannot be interchanged.
        static_assert(!std::is_same_v<http::v2::error_code, http::v3::error_code>);
        static_assert(std::is_assignable_v<http::protocol_code, http::v2::error_code>);
        static_assert(std::is_assignable_v<http::protocol_code, http::v3::error_code>);
        static_assert(!std::is_assignable_v<http::v2::error_code, http::v3::error_code>);
        static_assert(!std::is_assignable_v<http::v3::error_code, http::v2::error_code>);

        // RFC 9114 §8.1 — connection closure carries an application error code.
        const auto error = http::protocol_error{
            http::error_info{
                .version = http::protocol_version::http3,
                .scope = http::error_scope::connection,
                .condition = http::error_condition::malformed_frame,
                .exchange_identity = std::nullopt,
                .library_code = std::nullopt,
                .retryable = false,
            },
            http::close_connection{http::v3::error_code{0x0106}},
            "http/3: malformed frame",
        };

        expect(std::holds_alternative<http::close_connection>(error.action()));
        const auto& close = std::get<http::close_connection>(error.action());
        expect(close.code.has_value());
        expect(std::holds_alternative<http::v3::error_code>(*close.code));
        expect(std::get<http::v3::error_code>(*close.code).value == 262_u);
    };

    "library_failure_does_not_require_wire_code"_test = [] {
        // A backend library failure is diagnostic-only: it has no RFC wire
        // action, so protocol_error carries no_action and the library code.
        const auto error = http::protocol_error{
            http::error_info{
                .version = http::protocol_version::http1,
                .scope = http::error_scope::implementation,
                .condition = http::error_condition::library_failure,
                .exchange_identity = std::nullopt,
                .library_code = 23,
                .retryable = false,
            },
            http::no_action{},
            "http/1.1: parser failed",
        };

        expect(std::holds_alternative<http::no_action>(error.action()));
        expect(error.info().library_code.has_value());
        expect(*error.info().library_code == 23);
    };

    "mismatched_version_and_scope_actions_are_rejected"_test = [] {
        // The action/version/scope invariants are enforced at construction: an
        // HTTP/2 connection error cannot reset a stream, and an HTTP/2 code
        // cannot ride on an HTTP/3 error.
        auto threw = false;
        try {
            static_cast<void>(http::protocol_error{
                http::error_info{
                    .version = http::protocol_version::http2,
                    .scope = http::error_scope::connection,
                    .condition = http::error_condition::malformed_frame,
                    .exchange_identity = std::nullopt,
                    .library_code = std::nullopt,
                    .retryable = false,
                },
                http::reset_stream{http::v2::error_code{0x1}},
                "connection error cannot reset a stream",
            });
        } catch (const std::invalid_argument&) {
            threw = true;
        }
        expect(threw);

        threw = false;
        try {
            static_cast<void>(http::protocol_error{
                http::error_info{
                    .version = http::protocol_version::http3,
                    .scope = http::error_scope::connection,
                    .condition = http::error_condition::malformed_frame,
                    .exchange_identity = std::nullopt,
                    .library_code = std::nullopt,
                    .retryable = false,
                },
                http::close_connection{http::v2::error_code{0x1}},
                "http/2 code cannot close an http/3 connection",
            });
        } catch (const std::invalid_argument&) {
            threw = true;
        }
        expect(threw);
    };

    "goaway_rejection_can_be_retryable"_test = [] {
        // RFC 9113 §6.8 — "The GOAWAY frame ... allows an endpoint to gracefully
        // stop accepting new streams while still finishing processing of previously
        // established streams." — retry policy is explicit metadata and remains an
        // application decision; the rejection itself requires no wire action.
        const auto error = http::protocol_error{
            http::error_info{
                .version = http::protocol_version::http2,
                .scope = http::error_scope::stream,
                .condition = http::error_condition::goaway_rejected,
                .exchange_identity = 19,
                .library_code = std::nullopt,
                .retryable = true,
            },
            http::no_action{},
            "http/2: request rejected by GOAWAY",
        };

        expect(error.info().retryable);
        expect(error.info().exchange_identity.has_value());
        expect(*error.info().exchange_identity == 19_u);
        expect(std::holds_alternative<http::no_action>(error.action()));
    };
};

} // namespace httpant::testing
