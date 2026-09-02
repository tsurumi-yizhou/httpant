// Toolchain workaround, not protocol logic.
//
// Homebrew LLVM 22.1.8 combines C++20 named modules with libc++'s
// std::stop_callback in a way that leaves
//
//   std::__1::__atomic_unique_lock<unsigned int, 2u>::__set_locked_bit
//
// as an *undefined external* reference in any translation unit that both
// imports the httpant module and instantiates std::stop_callback at -O3
// (reverse_proxy.cpp). The module interface records the symbol as
// "available from the module", so the importing TU does not emit a
// definition — but no module object actually instantiates
// std::stop_callback, so the definition never exists in the link.
//
// This translation unit deliberately does NOT import any module. It
// force-instantiates the stop-callback machinery once so the weak
// definition of __set_locked_bit is emitted and can satisfy the references
// from reverse_proxy.cpp. It performs no I/O and is not part of the
// library: it is the transport-glue half of the example.

#include <functional>
#include <memory>
#include <optional>
#include <stop_token>

namespace httpant::examples {

namespace {

struct stop_callback_anchor final : std::enable_shared_from_this<stop_callback_anchor> {
    std::optional<std::stop_callback<std::function<void()>>> callback_;

    void arm(std::stop_token stop) {
        if (!stop.stop_possible())
            return;
        auto weak = weak_from_this();
        callback_.emplace(stop, [weak] {
            static_cast<void>(weak.lock());
        });
    }
};

} // namespace

void stop_support_anchor() {
    auto state = std::make_shared<stop_callback_anchor>();
    std::stop_source source;
    state->arm(source.get_token());
}

} // namespace httpant::examples
