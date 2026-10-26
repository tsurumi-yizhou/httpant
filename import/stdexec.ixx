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
