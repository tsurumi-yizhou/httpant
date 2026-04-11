#include <boost/ut.hpp>

namespace httpant::testing {

using namespace boost::ut;

static suite<"compression"> compression_suite = [] {
    "header_compression_exposes_dynamic_table_controls"_test = [] {
        expect(false);
    };

    "header_compression_surfaces_decoder_errors"_test = [] {
        expect(false);
    };
};

} // namespace httpant::testing
