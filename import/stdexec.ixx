module;

#include <cassert>
#include <chrono>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>

#if __has_include(<dispatch/dispatch.h>)
#  include <dispatch/dispatch.h>
#endif

#define STDEXEC_IN_MODULE_PURVIEW

#include <stdexec/__detail/__config.hpp>

#if STDEXEC_ENABLE_NUMA
#  include <numa.h>
#endif

// The standard execution core and its extensions have one module owner.
export module httpant.dependencies.stdexec;

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Winclude-angled-in-module-purview"
#include <stdexec/execution.hpp>
#include <exec/completion_signatures.hpp>
#include <exec/materialize.hpp>
#include <exec/static_thread_pool.hpp>
#include <exec/timed_scheduler.hpp>
#pragma clang diagnostic pop

// stdexec marks the core execution.hpp declarations for module export, but the
// extension headers (materialize, timed_scheduler) still have module linkage.
// A module cannot re-export a module-linkage declaration with a using-
// declaration, so expose the few extensions the I/O engine names as new
// exported entities here.
export namespace httpant::stdexec_ext {
    using materialize_t = experimental::execution::materialize_t;
    inline constexpr materialize_t materialize{};

    using now_t = experimental::execution::now_t;
    inline constexpr now_t now{};

    using schedule_after_t = experimental::execution::schedule_after_t;
    inline constexpr schedule_after_t schedule_after{};

    using schedule_at_t = experimental::execution::schedule_at_t;
    inline constexpr schedule_at_t schedule_at{};

    template <class Scheduler>
    concept timed_scheduler = experimental::execution::timed_scheduler<Scheduler>;
}
