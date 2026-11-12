export module httpant:serialize.nghttp2;

import httpant.dependencies.nghttp2;
import std;
import :session.nghttp2;
import :trait;
import :message;

export namespace http::v2 {

    namespace detail {

        inline auto setting_identifier(setting_name name) -> std::int32_t { return static_cast<std::int32_t>(std::to_underlying(name)); }

        inline auto make_settings(std::span<const setting> settings) -> std::vector<nghttp2_settings_entry> {
            std::vector<nghttp2_settings_entry> entries;
            entries.reserve(settings.size());
            for (const auto& setting : settings)
                entries.push_back({setting_identifier(setting.name), setting.value});
            return entries;
        }

        inline auto read_outbound_body(nghttp2_session*, std::int32_t, std::uint8_t* buf, std::size_t length, std::uint32_t* flags, nghttp2_data_source* src,
                                       void*) -> nghttp2_ssize {
            auto* state = static_cast<outbound_body_state*>(src->ptr);
            if (state == nullptr)
                return NGHTTP2_ERR_CALLBACK_FAILURE;
            bool eof = false;
            auto n = state->read(buf, length, eof);
            if (eof) {
                state->deferred = false;
                *flags |= NGHTTP2_DATA_FLAG_EOF;
                return static_cast<nghttp2_ssize>(n.value_or(0));
            }
            if (!n) {
                state->deferred = true;
                return NGHTTP2_ERR_DEFERRED;
            }
            state->deferred = false;
            return static_cast<nghttp2_ssize>(*n);
        }

        // The outbound body machinery shared by client requests and server (including
        // pushed) responses: a body_bridge the exchange coroutine refills, an
        // outbound_body_state nghttp2's data provider drains, and the provider binding
        // the two. One shared allocation owns both objects; a registry reference to
        // the state keeps its inline bridge alive after the exchange completes.
        template <body_stream Body> struct outbound_body_binding {
            body_bridge<Body>* bridge;
            std::shared_ptr<outbound_body_state> state;
            nghttp2_data_provider2 provider;
        };

        template <body_stream Body> inline auto bind_outbound_body(Body& body) -> outbound_body_binding<Body> {
            struct state_with_body : outbound_body_state {
                explicit state_with_body(Body& body) : bridge(body) {}
                body_bridge<Body> bridge;
            };
            auto state = std::make_shared<state_with_body>(body);
            auto* bridge = &state->bridge;
            state->read = outbound_reader{
                .bridge = bridge,
                .read = +[](void* object, std::uint8_t* destination, std::size_t size,
                            bool& eof) { return static_cast<body_bridge<Body>*>(object)->read(destination, size, eof); },
            };
            outbound_body_state* raw_state = state.get();
            return {
                .bridge = bridge,
                .state = std::move(state),
                .provider =
                    nghttp2_data_provider2{
                        .source = nghttp2_data_source{.ptr = raw_state},
                        .read_callback = &read_outbound_body,
                    },
            };
        }

        inline auto make_nv(std::string_view name, std::string_view value) -> nghttp2_nv {
            auto sensitive = http::detail::is_sensitive_field_name(name);
            // The const_cast is safe: nghttp2 never mutates the name/value bytes — it
            // copies them into its own buffers at submit time (nghttp2_submit_request2
            // / nghttp2_submit_response2 document that the nv arrays may be freed once
            // the call returns); the non-const pointer is a C API artifact.
            return {
                .name = reinterpret_cast<std::uint8_t*>(const_cast<char*>(name.data())),
                .value = reinterpret_cast<std::uint8_t*>(const_cast<char*>(value.data())),
                .namelen = name.size(),
                .valuelen = value.size(),
                // RFC 7541 §7.1.3 — sensitive fields can use the literal never-indexed
                // representation so intermediaries do not add them to a dynamic table.
                .flags = static_cast<std::uint8_t>(sensitive ? NGHTTP2_NV_FLAG_NO_INDEX : NGHTTP2_NV_FLAG_NONE),
            };
        }

    } // namespace detail
} // namespace http::v2
