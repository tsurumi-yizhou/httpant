module;

#if __has_include(<unistd.h>) && __has_include(<sys/wait.h>)
#include <sys/wait.h>
#include <unistd.h>
#endif

export module httpant.dependencies.boost.ut;

import std;

// Boost.UT supports attaching its declarations to a named module.
#define BOOST_UT_CXX_MODULES
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Winclude-angled-in-module-purview"
#include <boost/ut.hpp>
#pragma clang diagnostic pop
