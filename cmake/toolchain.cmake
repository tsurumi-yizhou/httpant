# The project and every vcpkg dependency build with one xclang for one target.
# Two environment variables name the checkouts:
#
#   XCLANG_ROOT   the xclang tree
#   VCPKG_ROOT    vcpkg's checkout
#
# XCLANG_TARGET picks the target, the host's by default with MSVC on Windows.
# The dependency triplet follows from it.
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
set(TARGET_ARCH "${CMAKE_MATCH_1}")
set(TRIPLET_ARCH "${CMAKE_MATCH_1}")
set(TRIPLET_PLATFORM "${CMAKE_MATCH_2}")
string(REPLACE x86_64 x64 TRIPLET_ARCH "${TRIPLET_ARCH}")
string(REPLACE aarch64 arm64 TRIPLET_ARCH "${TRIPLET_ARCH}")
string(REPLACE unknown-linux-gnu linux TRIPLET_PLATFORM "${TRIPLET_PLATFORM}")
string(REPLACE apple-darwin osx TRIPLET_PLATFORM "${TRIPLET_PLATFORM}")
string(REPLACE pc-windows-msvc windows TRIPLET_PLATFORM "${TRIPLET_PLATFORM}")
set(VCPKG_TARGET_TRIPLET "${TRIPLET_ARCH}-${TRIPLET_PLATFORM}-xclang" CACHE STRING "vcpkg target triplet")

# The triplet is written from the target, so every dependency builds with
# xclang's own toolchain for it: static libraries everywhere, the static CRT
# on Windows. A Linux triplet makes every port build a cross build, where
# CMake leaves the processor unset; port builds read it.
set(TRIPLET "set(VCPKG_TARGET_ARCHITECTURE ${TRIPLET_ARCH})\nset(VCPKG_LIBRARY_LINKAGE static)\n")
set(TRIPLET_OPTIONS "-DXCLANG_TARGET=${XCLANG_TARGET}")
if(TRIPLET_PLATFORM STREQUAL "windows")
  string(APPEND TRIPLET "set(VCPKG_CRT_LINKAGE static)\nset(VCPKG_LOAD_VCVARS_ENV ON)\n")
elseif(TRIPLET_PLATFORM STREQUAL "linux")
  string(APPEND TRIPLET "set(VCPKG_CRT_LINKAGE dynamic)\nset(VCPKG_CMAKE_SYSTEM_NAME Linux)\n")
  string(APPEND TRIPLET_OPTIONS " -DCMAKE_SYSTEM_PROCESSOR=${TARGET_ARCH}")
else()
  string(APPEND TRIPLET "set(VCPKG_CRT_LINKAGE dynamic)\nset(VCPKG_CMAKE_SYSTEM_NAME Darwin)\nset(VCPKG_OSX_ARCHITECTURES ${TARGET_ARCH})\n")
endif()
string(APPEND TRIPLET
  "set(VCPKG_CHAINLOAD_TOOLCHAIN_FILE \"\$ENV{XCLANG_ROOT}/lib/cmake/xclang/toolchain.cmake\")\n"
  "set(VCPKG_CMAKE_CONFIGURE_OPTIONS ${TRIPLET_OPTIONS})\n"
  "set(VCPKG_ENV_PASSTHROUGH XCLANG_ROOT)\n")
set(VCPKG_OVERLAY_TRIPLETS "${CMAKE_BINARY_DIR}/vcpkg-triplets")
file(CONFIGURE OUTPUT "${VCPKG_OVERLAY_TRIPLETS}/${VCPKG_TARGET_TRIPLET}.cmake" CONTENT "${TRIPLET}" @ONLY)

set(VCPKG_CHAINLOAD_TOOLCHAIN_FILE "${XCLANG_ROOT}/lib/cmake/xclang/toolchain.cmake")
# vcpkg's scratch space stays in the build directory.
set(VCPKG_INSTALL_OPTIONS
  "--x-buildtrees-root=${CMAKE_BINARY_DIR}/vcpkg-buildtrees"
  "--x-packages-root=${CMAKE_BINARY_DIR}/vcpkg-packages")
set(ENV{VCPKG_DOWNLOADS} "${CMAKE_BINARY_DIR}/vcpkg-downloads")

include("${VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake")
