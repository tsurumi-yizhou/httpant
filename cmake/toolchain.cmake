# Standalone builds: a C++23 module compiler from an xclang tree, and vcpkg for
# the three C libraries the protocol code wraps.
#
#   export XCLANG_ROOT=/path/to/xclang
#   export VCPKG_ROOT=/path/to/vcpkg
#   cmake -B build -DCMAKE_TOOLCHAIN_FILE=cmake/toolchain.cmake
#
# A consumer does not use this file: an installed httpant only needs
# find_package(httpant), and the vcpkg port builds with the triplet's toolchain.
# These variables are read from the environment so a checkout stays portable
# between machines, which is also how CI passes them.
set(XCLANG_ROOT "$ENV{XCLANG_ROOT}" CACHE PATH "xclang tree")
set(VCPKG_ROOT "$ENV{VCPKG_ROOT}" CACHE PATH "vcpkg checkout")

# Named as vcpkg and xclang read them, so they keep those spellings. The triplet
# is optional: without one vcpkg uses its built-in default, and the xclang
# compiler still builds both the dependencies and httpant. Reproduce the registry
# build by pointing VCPKG_OVERLAY_TRIPLETS at vcpkg-registry/triplets and setting
# VCPKG_TARGET_TRIPLET to an *-xclang triplet.
set(XCLANG_TARGET "$ENV{XCLANG_TARGET}" CACHE STRING "xclang target triple")
if(DEFINED ENV{VCPKG_TARGET_TRIPLET})
    set(VCPKG_TARGET_TRIPLET "$ENV{VCPKG_TARGET_TRIPLET}" CACHE STRING "vcpkg target triplet")
endif()
if(DEFINED ENV{VCPKG_OVERLAY_TRIPLETS})
    set(VCPKG_OVERLAY_TRIPLETS "$ENV{VCPKG_OVERLAY_TRIPLETS}" CACHE STRING "vcpkg overlay triplets")
endif()

# The dependencies have to be built by the same compiler as httpant: liburing's
# compat header assumes the kernel uapi headers that a sysrooted xclang does not
# have, so a system-compiler liburing does not compile here. Only an *-xclang
# triplet builds both sides consistently, and those live in vcpkg-registry.
if(HTTPANT_ENABLE_IO AND NOT VCPKG_TARGET_TRIPLET MATCHES "xclang")
    message(WARNING
        "HTTPANT_ENABLE_IO needs a vcpkg triplet that builds dependencies with xclang.\n"
        "Point VCPKG_OVERLAY_TRIPLETS at vcpkg-registry/triplets and set\n"
        "VCPKG_TARGET_TRIPLET to x64-linux-xclang, arm64-osx-xclang or x64-windows-xclang.\n"
        "The engine is off for this configure.")
    set(HTTPANT_ENABLE_IO OFF CACHE BOOL "" FORCE)
endif()

set(ENV{XCLANG_ROOT} "${XCLANG_ROOT}")
list(APPEND CMAKE_TRY_COMPILE_PLATFORM_VARIABLES VCPKG_ROOT XCLANG_ROOT XCLANG_TARGET VCPKG_TARGET_TRIPLET VCPKG_OVERLAY_TRIPLETS)

if(NOT XCLANG_ROOT)
    message(FATAL_ERROR "XCLANG_ROOT is not set: httpant needs an xclang tree to build C++23 modules")
endif()
if(NOT VCPKG_ROOT)
    message(FATAL_ERROR "VCPKG_ROOT is not set: httpant's dependencies come from vcpkg")
endif()

# vcpkg chains to the xclang toolchain, which is the order that keeps both
# generators happy: vcpkg owns the compiler and the target, xclang owns the module
# scanning and the standard library module.
set(VCPKG_CHAINLOAD_TOOLCHAIN_FILE "${XCLANG_ROOT}/lib/cmake/xclang/toolchain.cmake")
find_program(CMAKE_CXX_COMPILER_CLANG_SCAN_DEPS NAMES clang-scan-deps
    PATHS "${XCLANG_ROOT}/bin" NO_DEFAULT_PATH NO_CACHE REQUIRED)
include("${VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake")
