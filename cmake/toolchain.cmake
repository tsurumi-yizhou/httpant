# Two inputs, both from the environment, both required by something external:
#
#   XCLANG_ROOT   the compiler tree (C++23 modules plus the standard library as a
#                 module). Not on any registry — this is the only value a person
#                 has to supply.
#   VCPKG_ROOT    vcpkg's own convention for its checkout location.
#
# Everything else is derived: the xclang target from the host, and the
# dependency triplet from that target. Cross-build by setting XCLANG_TARGET;
# nothing else changes. A consumer does not use this file: an installed httpant
# only needs find_package(httpant).
set(XCLANG_ROOT "$ENV{XCLANG_ROOT}" CACHE PATH "xclang tree")
set(VCPKG_ROOT "$ENV{VCPKG_ROOT}" CACHE PATH "vcpkg checkout")

if(NOT XCLANG_ROOT)
    message(FATAL_ERROR "XCLANG_ROOT is not set: the compiler tree cannot be derived from anything")
endif()
if(NOT VCPKG_ROOT)
    message(FATAL_ERROR "VCPKG_ROOT is not set: vcpkg's own variable names its checkout")
endif()

# The tree is a cross toolchain with many targets, so the target comes from the
# host, not from the tree. Cross-compiling is the one case that needs
# XCLANG_TARGET.
if(NOT XCLANG_TARGET)
    if(CMAKE_HOST_SYSTEM_PROCESSOR MATCHES "^(arm64|aarch64)")
        set(HOST_ARCH aarch64)
    else()
        set(HOST_ARCH x86_64)
    endif()
    if(CMAKE_HOST_SYSTEM_NAME STREQUAL "Darwin")
        set(HOST_TRIPLE "${HOST_ARCH}-apple-darwin")
    elseif(CMAKE_HOST_SYSTEM_NAME STREQUAL "Windows")
        set(HOST_TRIPLE "${HOST_ARCH}-pc-windows-msvc")
    else()
        set(HOST_TRIPLE "${HOST_ARCH}-unknown-linux-gnu")
    endif()
    if(EXISTS "${XCLANG_ROOT}/${HOST_TRIPLE}")
        set(XCLANG_TARGET "${HOST_TRIPLE}")
    else()
        file(GLOB XCLANG_TARGETS RELATIVE "${XCLANG_ROOT}" "${XCLANG_ROOT}/*-*-*")
        message(FATAL_ERROR
            "The xclang tree has no ${HOST_TRIPLE}. Set XCLANG_TARGET to one of: ${XCLANG_TARGETS}")
    endif()
endif()
set(XCLANG_TARGET "${XCLANG_TARGET}" CACHE STRING "xclang target triple")

# The dependency triplet follows the target: same architecture, same platform, and
# the xclang toolchain that keeps dependencies on the same compiler.
if(NOT VCPKG_TARGET_TRIPLET)
    if(XCLANG_TARGET MATCHES "^(aarch64|arm64)")
        set(ARCH arm64)
    else()
        set(ARCH x64)
    endif()
    if(XCLANG_TARGET MATCHES "apple")
        set(PLATFORM osx)
    elseif(XCLANG_TARGET MATCHES "windows|msvc")
        set(PLATFORM windows)
    elseif(XCLANG_TARGET MATCHES "linux")
        set(PLATFORM linux)
    else()
        message(FATAL_ERROR "No dependency triplet for ${XCLANG_TARGET}")
    endif()
    set(VCPKG_TARGET_TRIPLET "${ARCH}-${PLATFORM}-xclang" CACHE STRING "vcpkg target triplet")
endif()

set(ENV{XCLANG_ROOT} "${XCLANG_ROOT}")
list(APPEND CMAKE_TRY_COMPILE_PLATFORM_VARIABLES VCPKG_ROOT XCLANG_ROOT XCLANG_TARGET)

set(VCPKG_CHAINLOAD_TOOLCHAIN_FILE "${XCLANG_ROOT}/lib/cmake/xclang/toolchain.cmake")
find_program(CMAKE_CXX_COMPILER_CLANG_SCAN_DEPS NAMES clang-scan-deps
  PATHS "${XCLANG_ROOT}/bin" NO_DEFAULT_PATH NO_CACHE REQUIRED)

# The triplets live in the registry checkout beside this one, with the ports it
# serves: they are what makes "same compiler for dependencies" true, so they are
# not optional.
set(VCPKG_OVERLAY_TRIPLETS "${CMAKE_CURRENT_LIST_DIR}/../../vcpkg-registry/triplets")
set(VCPKG_INSTALL_OPTIONS
  "--x-buildtrees-root=${CMAKE_BINARY_DIR}/vcpkg-buildtrees"
  "--x-packages-root=${CMAKE_BINARY_DIR}/vcpkg-packages")
set(ENV{VCPKG_DOWNLOADS} "${CMAKE_BINARY_DIR}/vcpkg-downloads")

include("${VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake")

message(STATUS "xclang ${XCLANG_TARGET} -> vcpkg ${VCPKG_TARGET_TRIPLET}")
