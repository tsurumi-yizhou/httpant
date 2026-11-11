# The project and every vcpkg dependency build with one xclang for one target.
# Two environment variables name the checkouts:
#
#   XCLANG_ROOT   the xclang tree
#   VCPKG_ROOT    vcpkg's checkout
#
# XCLANG_TARGET picks the target, the host's by default with MSVC on Windows.
# The dependency triplet beside this file follows from it, and builds the
# dependencies with xclang's own toolchain for the same target.
set(XCLANG_ROOT "$ENV{XCLANG_ROOT}" CACHE PATH "xclang tree")
set(VCPKG_ROOT "$ENV{VCPKG_ROOT}" CACHE PATH "vcpkg checkout")
if(NOT XCLANG_ROOT OR NOT VCPKG_ROOT)
  message(FATAL_ERROR "Set XCLANG_ROOT to the xclang tree and VCPKG_ROOT to the vcpkg checkout")
endif()
set(ENV{XCLANG_ROOT} "${XCLANG_ROOT}")
# try_compile projects read this file again, without the cache.
list(APPEND CMAKE_TRY_COMPILE_PLATFORM_VARIABLES XCLANG_ROOT VCPKG_ROOT XCLANG_TARGET)

if(CMAKE_HOST_SYSTEM_PROCESSOR MATCHES "^(arm64|aarch64|ARM64)$")
  set(HOST_ARCH aarch64)
else()
  set(HOST_ARCH x86_64)
endif()
if(CMAKE_HOST_APPLE)
  set(HOST_TARGET "${HOST_ARCH}-apple-darwin")
elseif(CMAKE_HOST_WIN32)
  set(HOST_TARGET "${HOST_ARCH}-pc-windows-msvc")
else()
  set(HOST_TARGET "${HOST_ARCH}-unknown-linux-gnu")
endif()
set(XCLANG_TARGET "${HOST_TARGET}" CACHE STRING "xclang target triple")

if(NOT XCLANG_TARGET MATCHES "^(x86_64|aarch64)-(unknown-linux-gnu|apple-darwin|pc-windows-msvc)$")
  message(FATAL_ERROR "No dependency triplet for ${XCLANG_TARGET}")
endif()
set(TRIPLET_ARCH "${CMAKE_MATCH_1}")
set(TRIPLET_PLATFORM "${CMAKE_MATCH_2}")
string(REPLACE x86_64 x64 TRIPLET_ARCH "${TRIPLET_ARCH}")
string(REPLACE aarch64 arm64 TRIPLET_ARCH "${TRIPLET_ARCH}")
string(REPLACE unknown-linux-gnu linux TRIPLET_PLATFORM "${TRIPLET_PLATFORM}")
string(REPLACE apple-darwin osx TRIPLET_PLATFORM "${TRIPLET_PLATFORM}")
string(REPLACE pc-windows-msvc windows TRIPLET_PLATFORM "${TRIPLET_PLATFORM}")
set(VCPKG_TARGET_TRIPLET "${TRIPLET_ARCH}-${TRIPLET_PLATFORM}-xclang" CACHE STRING "vcpkg target triplet")

set(VCPKG_CHAINLOAD_TOOLCHAIN_FILE "${XCLANG_ROOT}/lib/cmake/xclang/toolchain.cmake")
set(VCPKG_OVERLAY_TRIPLETS "${CMAKE_CURRENT_LIST_DIR}/triplets")
# vcpkg's scratch space stays in the build directory.
set(VCPKG_INSTALL_OPTIONS
  "--x-buildtrees-root=${CMAKE_BINARY_DIR}/vcpkg-buildtrees"
  "--x-packages-root=${CMAKE_BINARY_DIR}/vcpkg-packages")
set(ENV{VCPKG_DOWNLOADS} "${CMAKE_BINARY_DIR}/vcpkg-downloads")

include("${VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake")
