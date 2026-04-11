#include <boost/ut.hpp>

namespace httpant::testing {

using namespace boost::ut;

static suite<"tls"> tls_suite = [] {
    "tls13_handshake_behavior_is_exposed"_test = [] {
        expect(false);
    };

    "tls13_post_handshake_events_are_exposed"_test = [] {
        expect(false);
    };
};

} // namespace httpant::testing
