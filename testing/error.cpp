import httpant.dependencies.boost.ut;
import std;
import httpant;

namespace httpant::testing {

    using namespace boost::ut;
    using namespace std::literals;

    static_assert(std::is_base_of_v<std::runtime_error, http::protocol_error>);

    // RFC 9114 §8.1 / §11.2.3 — the protocol has one application error-code space,
    // so the library has one error-code type. There is no per-version code type and
    // nothing to check: the engine that raises the error is the type that says which
    // frame format the code is written in.
    static_assert(std::is_same_v<http::error_code, std::uint64_t>);

    // The action implies the scope, so the type of the action is the invariant: no
    // constructor can produce a stream reset that claims connection scope.
    static_assert(std::is_constructible_v<http::protocol_error, http::error_info, http::reset_stream, std::string>);
    static_assert(std::is_constructible_v<http::protocol_error, http::error_info, http::close_connection, std::string>);
    static_assert(std::is_constructible_v<http::protocol_error, http::error_info, http::no_action, std::string>);

    static suite<"error"> error_suite = [] {
        "retry_is_read_from_the_condition"_test = [] {
            // RFC 9114 §4.1.1 — a reset stream "MAY be retried... on a new stream";
            // RFC 9113 §6.8 — a stream above the GOAWAY boundary was not processed.
            // Both are properties of the condition, so the answer is derived instead
            // of being written next to every construction site.
            expect(http::retryable(http::error_info{
                .scope = http::error_scope::stream,
                .condition = http::error_condition::stream_reset,
                .exchange_identity = 1,
                .library_code = std::nullopt,
            }));
            expect(http::retryable(http::error_info{
                .scope = http::error_scope::message,
                .condition = http::error_condition::goaway_rejected,
                .exchange_identity = std::nullopt,
                .library_code = std::nullopt,
            }));
            expect(!http::retryable(http::error_info{
                .scope = http::error_scope::connection,
                .condition = http::error_condition::malformed_frame,
                .exchange_identity = std::nullopt,
                .library_code = std::nullopt,
            }));
            expect(!http::retryable(http::error_info{
                .scope = http::error_scope::stream,
                .condition = http::error_condition::peer_closed,
                .exchange_identity = 1,
                .library_code = std::nullopt,
            }));
        };

        "the_action_decides_the_scope"_test = [] {
            // RFC 9113 §5.4.2 — a reset terminates one stream; RFC 9113 §5.4.1 — a
            // close terminates the connection. Whatever the caller wrote for the
            // scope, the action is what it is.
            const auto reset = http::protocol_error{
                http::error_info{
                    .scope = http::error_scope::message,
                    .condition = http::error_condition::malformed_message,
                    .exchange_identity = 4,
                    .library_code = std::nullopt,
                },
                http::reset_stream{0x1},
                "stream reset",
            };
            expect(reset.info().scope == http::error_scope::stream);

            const auto close = http::protocol_error{
                http::error_info{
                    .scope = http::error_scope::stream,
                    .condition = http::error_condition::peer_closed,
                    .exchange_identity = std::nullopt,
                    .library_code = std::nullopt,
                },
                http::close_connection{0x100},
                "connection closed",
            };
            expect(close.info().scope == http::error_scope::connection);

            // A failure with no protocol action keeps the scope it names.
            const auto none = http::protocol_error{
                http::error_info{
                    .scope = http::error_scope::implementation,
                    .condition = http::error_condition::library_failure,
                    .exchange_identity = std::nullopt,
                    .library_code = 7,
                },
                http::no_action{},
                "parser failed",
            };
            expect(none.info().scope == http::error_scope::implementation);
        };

        "library_failure_does_not_require_wire_code"_test = [] {
            // A backend library failure is diagnostic-only: it has no RFC wire
            // action, so protocol_error has no_action and the library code.
            const auto error = http::protocol_error{
                http::error_info{
                    .scope = http::error_scope::implementation,
                    .condition = http::error_condition::library_failure,
                    .exchange_identity = std::nullopt,
                    .library_code = 23,
                },
                http::no_action{},
                "http/1.1: parser failed",
            };

            expect(std::holds_alternative<http::no_action>(error.action()));
            expect(error.info().library_code.has_value());
            expect(*error.info().library_code == 23);
            expect(!http::retryable(error.info()));
        };
    };

} // namespace httpant::testing
