import httpant.dependencies.boost.ut;
import httpant.dependencies.stdexec;
import std;
import httpant.testing;
import httpant;

namespace httpant::testing {

    using namespace boost::ut;
    using namespace std::literals;

    namespace {

        auto request_for(std::string_view target) -> http::request {
            return http::request{
                .method = http::method::POST,
                .target = std::string{target},
                .scheme = "https",
                .authority = "example.com",
            };
        }

        // HEADERS (0x1) with END_HEADERS | END_STREAM (0x5) on stream 1; HPACK 0x88 is
        // the indexed ":status: 200" (RFC 7541 §6.1).
        void push_final_h2_response(async_pipe& s2c) {
            const std::vector<std::byte> block{std::byte{0x88}};
            push_http2_frame(s2c, 0x01, 0x05, 1, block);
        }

        struct sender_transport {
            mock_stream& inner;
            auto read_some(std::span<std::byte> buffer) {
                return stdexec::then(stdexec::just(), [this, buffer] { return inner.async_read(buffer, {}).await_resume(); });
            }
            auto write_some(std::span<const std::byte> buffer) {
                return stdexec::then(stdexec::just(), [this, buffer] { return inner.async_write(buffer, {}).await_resume(); });
            }
        };

    } // namespace

    static suite<"fetch"> fetch_suite = [] {
        // RFC 3986 §3.2 / RFC 9110 §4.2 — where a request goes comes from the
        // request itself: authority (or Host, or an absolute-form target) for the
        // host and optional port, and the scheme for the default port.
        "request_origin_comes_from_the_request"_test = [] {
            auto origin_of = [](http::request req) { return http::request_origin(req); };

            auto https = origin_of({.target = "/x", .scheme = "https", .authority = "example.com"});
            expect(https.has_value() && https->host == "example.com"sv && https->port == 443_u);

            auto explicit_port = origin_of({.target = "/x", .scheme = "http", .authority = "example.com:8080"});
            expect(explicit_port.has_value() && explicit_port->port == 8080_u);

            auto ipv6 = origin_of({.target = "/x", .scheme = "https", .authority = "[::1]:8443"});
            expect(ipv6.has_value() && ipv6->host == "::1"sv && ipv6->port == 8443_u);

            auto ipv6_default = origin_of({.target = "/x", .scheme = "http", .authority = "[2001:db8::1]"});
            expect(ipv6_default.has_value() && ipv6_default->host == "2001:db8::1"sv && ipv6_default->port == 80_u);

            auto userinfo = origin_of({.target = "/x", .scheme = "https", .authority = "user:pw@example.com"});
            expect(userinfo.has_value() && userinfo->host == "example.com"sv && userinfo->port == 443_u);

            auto absolute = origin_of({.target = "http://example.org/path"});
            expect(absolute.has_value() && absolute->host == "example.org"sv && absolute->port == 80_u);

            auto from_host_field = origin_of({.target = "/x", .scheme = "https", .fields = {{"host", "example.net:9000"}}});
            expect(from_host_field.has_value() && from_host_field->port == 9000_u);

            expect(!origin_of({.target = "/x", .scheme = "https"}).has_value());          // no host
            expect(!origin_of({.target = "/x", .authority = "example.com"}).has_value()); // no port, no scheme
            expect(!origin_of({.target = "/x", .scheme = "ftp", .authority = "example.com"}).has_value());
            expect(!origin_of({.target = "/x", .scheme = "https", .authority = "example.com:abc"}).has_value());
            expect(!origin_of({.target = "/x", .scheme = "https", .authority = "example.com:70000"}).has_value());
            expect(!origin_of({.target = "/x", .scheme = "https", .authority = "[::1"}).has_value());
        };

        // RFC 9110 §5.6.1 — list members across field lines, trimmed, case-insensitive.
        "field_contains_token_reads_lists"_test = [] {
            http::headers fields{{"Connection", "keep-alive, Upgrade"}, {"connection", "\tTE "}, {"x", "upgrade"}};
            expect(http::field_contains_token(fields, "connection", "upgrade"));
            expect(http::field_contains_token(fields, "CONNECTION", "te"));
            expect(http::field_contains_token(fields, "connection", "keep-alive"));
            expect(!http::field_contains_token(fields, "connection", "close"));
            expect(!http::field_contains_token(fields, "connection", "upgrad"));
            expect(!http::field_contains_token(fields, "missing", "upgrade"));
            expect(!http::field_contains_token(http::headers{{"connection", ""}}, "connection", ""));
        };

        // The surfaces and entry points of the library's conventions: a per-version
        // namespace function (no template argument), string bodies, and the P2300
        // surface; all reach the same exchange.
        "fetch_per_version_entry_points_and_sender_surface"_test = [] {
            auto serve = [](pipe& s2c) { push_text(s2c, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"); };
            auto request = [] { return request_for("/v1"); };

            {
                pipe c2s, s2c;
                serve(s2c);
                mock_stream transport{.input = s2c, .output = c2s};
                http::v1::client client{transport};
                auto result = run_sync(http::coroutine::fetch(client, request(), "text body"sv));
                expect(result.text() == "ok"sv);
                expect(bytes_to_string(c2s.buffer).ends_with("\r\n\r\ntext body"));
            }
            {
                pipe c2s, s2c;
                serve(s2c);
                mock_stream transport{.input = s2c, .output = c2s};
                http::v1::client client{transport};
                http::buffer_body streamed{std::vector<std::byte>{std::byte{'x'}, std::byte{'y'}}};
                auto head = request();
                head.fields.push_back({"content-length", "2"});
                auto result = run_sync(http::coroutine::fetch(client, std::move(head), streamed));
                expect(result.text() == "ok"sv);
                expect(bytes_to_string(c2s.buffer).ends_with("\r\n\r\nxy"));
            }
            {
                pipe c2s, s2c;
                serve(s2c);
                mock_stream transport{.input = s2c, .output = c2s};
                http::v1::client client{transport};
                auto outcome = stdexec::sync_wait(http::execution::fetch(client, request()));
                expect(outcome.has_value());
                expect(std::get<0>(*outcome).text() == "ok"sv);
            }
        };

        // RFC 7301 — ALPN identifiers are constants of the client type, which is the
        // protocol: nothing maps a version value to a string at run time.
        "alpn_identifiers"_test = [] {
            expect(std::string_view{http::v1::client<mock_stream>::alpn}.empty());
            expect(http::v2::client<mock_stream>::alpn == "h2"sv);
            expect(http::v3::client<mock_stream_factory>::alpn == "h3"sv);
        };

        // RFC 9112 §3.2 — an HTTP/1.1 request has exactly one Host field; fetch
        // derives it from the authority, adds Content-Length for the body, and
        // reads the Content-Length-framed response to its end.
        "fetch_http1_derives_host_and_reads_the_body"_test = [] {
            pipe c2s, s2c;
            push_text(s2c, "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello");
            mock_stream transport{.input = s2c, .output = c2s};
            http::v1::client client{transport};

            const auto payload = std::as_bytes(std::span{"ab", 2});
            auto result = run_sync(http::coroutine::fetch(client, request_for("/order"), payload));

            expect(result.head.status == 200_u);
            expect(result.text() == "hello"sv);
            auto sent = bytes_to_string(c2s.buffer);
            expect(sent.starts_with("POST /order HTTP/1.1\r\n"));
            expect(sent.find("example.com") != std::string::npos);
            expect(sent.find("ontent-") != std::string::npos);
            expect(sent.ends_with("\r\n\r\nab"));
        };

        // Closing from the application's response wake-up must join the reader.
        "fetch_http2_closes_at_the_callers_scope_boundary"_test = [] {
            async_pipe c2s{};
            async_pipe s2c{};
            async_mock_stream transport{.input = s2c, .output = c2s};
            http::v2::client client{transport};
            push_http2_settings_frame(s2c);

            static constexpr auto run_session = [](auto& endpoint) -> http::task<http::fetched> {
                co_return co_await http::coroutine::fetch(endpoint, request_for("/h2"));
            };
            auto pending = http::coroutine::scoped(client, run_session);
            pending.start();
            expect(!pending.done());
            push_final_h2_response(s2c);
            expect(pending.done());
            auto result = run_sync(std::move(pending));
            expect(result.head.status == 200_u);
            expect(result.body.empty());
        };

        // RFC 9110 §7.8 — a 101 switches the connection to the requested protocol;
        // the bytes the server sent after the head already belong to it.
        "upgrade_reports_the_switch_and_the_bytes_after_the_head"_test = [] {
            pipe c2s, s2c;
            push_text(s2c, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
                           "Connection: Upgrade\r\nX-Probe: 1\r\n\r\nFIRST-BYTES");
            mock_stream transport{.input = s2c, .output = c2s};
            http::v1::client client{transport};

            http::request head{.method = http::method::GET,
                               .target = "/ws",
                               .scheme = "https",
                               .authority = "example.com",
                               .fields = {{"upgrade", "websocket"}, {"connection", "Upgrade"}}};
            auto result = run_sync(http::coroutine::upgrade(client, std::move(head)));

            expect(result.switched);
            expect(result.head.status == 101_u);
            expect(http::find_header(result.head.fields, "x-probe").value_or("") == "1"sv);
            expect(bytes_to_string(result.pending) == "FIRST-BYTES"sv);
            auto sent = bytes_to_string(c2s.buffer);
            expect(sent.starts_with("GET /ws HTTP/1.1\r\n"));
            expect(sent.find("example.com") != std::string::npos);
        };

        // A server that answers with a plain response did not switch: the head
        // says what it answered and no bytes are handed over.
        "upgrade_refused_is_not_a_switch"_test = [] {
            pipe c2s, s2c;
            push_text(s2c, "HTTP/1.1 426 Upgrade Required\r\nContent-Length: 6\r\n\r\nDenied"
                           "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK");
            mock_stream transport{.input = s2c, .output = c2s};
            http::v1::client client{transport};

            http::request head{.method = http::method::GET,
                               .target = "/ws",
                               .scheme = "https",
                               .authority = "example.com",
                               .fields = {{"upgrade", "websocket"}, {"connection", "Upgrade"}}};
            auto result = run_sync(http::coroutine::upgrade(client, std::move(head)));

            expect(!result.switched);
            expect(result.head.status == 426_u);
            expect(result.pending.empty());
            expect(bytes_to_string(result.body) == "Denied"sv);
            auto next = run_sync(http::coroutine::fetch(client, http::request{.method = http::method::GET, .target = "/", .authority = "example.com"}));
            expect(next.text() == "OK"sv);
        };

        "refused_upgrade_obeys_the_response_body_limit"_test = [] {
            pipe c2s, s2c;
            push_text(s2c, "HTTP/1.1 426 Upgrade Required\r\nContent-Length: 6\r\n\r\nDenied");
            mock_stream transport{.input = s2c, .output = c2s};
            http::v1::client client{transport};
            bool limited = false;
            try {
                run_sync(http::coroutine::upgrade(client, http::request{.method = http::method::GET, .target = "/ws", .authority = "example.com"},
                                                  {.body_limit = 3}));
            } catch (const http::protocol_error&) {
                limited = true;
            }
            expect(limited);
        };

        // The application closes and destroys the client from the continuation of
        // its own request, which the HTTP/2 reader has just woken. close() joins
        // the reader, so the client is destroyed only after the reader finished.
        "http2_client_closed_by_the_coroutine_the_reader_woke"_test = [] {
            async_pipe c2s{};
            async_pipe s2c{};
            async_mock_stream transport{.input = s2c, .output = c2s};
            auto client = std::make_unique<http::v2::client<async_mock_stream>>(transport);
            push_http2_settings_frame(s2c);
            run_sync(http::coroutine::start(*client));

            bool destroyed = false;
            auto make_app = [&]() -> http::task<void> {
                {
                    auto response = co_await http::coroutine::request(*client, basic_get("/x"));
                    expect(response.head.status == 200_u);
                }
                co_await http::coroutine::close(*client);
                client.reset();
                destroyed = true;
            };
            auto app = make_app();
            app.start();
            expect(!destroyed);

            push_final_h2_response(s2c);

            expect(destroyed);
            expect(app.done());
        };

        // Structured close: an exchange still waiting on the connection when the
        // application closes the client finishes with http::stopped, and close
        // completes once the reader has been joined.
        "http2_close_wakes_a_parked_request_with_stopped"_test = [] {
            async_pipe c2s{};
            async_pipe s2c{};
            async_mock_stream transport{.input = s2c, .output = c2s};
            http::v2::client<async_mock_stream> client{transport};
            push_http2_settings_frame(s2c);
            run_sync(http::coroutine::start(client));

            bool stopped = false;
            auto make_pending = [&]() -> http::task<void> {
                try {
                    static_cast<void>(co_await http::coroutine::request(client, basic_get("/never")));
                } catch (const http::stopped&) {
                    stopped = true;
                }
            };
            auto pending = make_pending();
            pending.start();
            expect(!pending.done());

            run_sync(http::coroutine::close(client));
            expect(pending.done());
            expect(stopped);
        };

        // The buffer limit is a plain policy value of this fetch operation.
        "fetch_enforces_its_body_limit"_test = [] {
            pipe c2s, s2c;
            push_text(s2c, "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n0123456789");
            mock_stream transport{.input = s2c, .output = c2s};
            http::v1::client client{transport};
            auto limited = false;
            try {
                static_cast<void>(run_sync(http::coroutine::fetch(client, request_for("/big"), http::fetch_options{.body_limit = 4})));
            } catch (const http::protocol_error& failure) {
                limited = failure.info().condition == http::error_condition::resource_limit;
            }
            expect(limited);
        };
        "fetch_sender_forms_share_the_callers_connection"_test = [] {
            pipe c2s, s2c;
            for (int i = 0; i < 3; ++i)
                push_text(s2c, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
            mock_stream transport{.input = s2c, .output = c2s};
            http::v1::client client{transport};
            int prepared = 0;
            auto input = stdexec::then(stdexec::just(), [&] {
                ++prepared;
                return request_for("/pipe");
            });
            auto piped = std::move(input) | http::execution::fetch(client);
            expect(prepared == 0_i && c2s.buffer.empty());
            auto first = stdexec::sync_wait(std::move(piped));
            expect(prepared == 1_i && std::get<0>(*first).text() == "ok"sv);
            auto second = stdexec::sync_wait(http::execution::fetch(stdexec::just(request_for("/upstream")), client));
            expect(std::get<0>(*second).text() == "ok"sv);
            auto third = stdexec::sync_wait(http::execution::fetch(client, request_for("/direct")));
            expect(std::get<0>(*third).text() == "ok"sv);
            auto sent = bytes_to_string(c2s.buffer);
            expect(sent.find("/pipe") != std::string::npos && sent.find("/upstream") != std::string::npos && sent.find("/direct") != std::string::npos);
        };

        "fetch_owns_text_before_the_sender_or_task_starts"_test = [] {
            for (bool sender : {false, true}) {
                pipe c2s, s2c;
                push_text(s2c, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
                mock_stream transport{.input = s2c, .output = c2s};
                http::v1::client client{transport};
                std::string payload = "original";
                if (sender) {
                    auto pending = http::execution::fetch(client, request_for("/owned"), std::string_view{payload});
                    payload.assign("modified");
                    static_cast<void>(stdexec::sync_wait(std::move(pending)));
                } else {
                    auto pending = http::coroutine::fetch(client, request_for("/owned"), std::string_view{payload});
                    payload.assign("modified");
                    static_cast<void>(run_sync(std::move(pending)));
                }
                expect(bytes_to_string(c2s.buffer).ends_with("\r\n\r\noriginal"));
            }
        };

        "both_http_stacks_use_sender_native_streams"_test = [] {
            for (bool sender : {false, true}) {
                pipe c2s, s2c;
                push_text(s2c, "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello");
                mock_stream mock{.input = s2c, .output = c2s};
                sender_transport transport{mock};
                http::stream stream{transport};
                static_assert(http::byte_stream<decltype(stream)>);
                http::v1::client client{stream};
                if (sender) {
                    auto value = stdexec::sync_wait(stdexec::just(request_for("/sender")) | http::execution::fetch(client));
                    expect(std::get<0>(*value).text() == "hello"sv);
                } else {
                    auto value = run_sync(http::coroutine::fetch(client, request_for("/coroutine")));
                    expect(value.text() == "hello"sv);
                }
            }
        };
    };

} // namespace httpant::testing
