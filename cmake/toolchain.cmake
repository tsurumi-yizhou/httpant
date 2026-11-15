# The project and every vcpkg dependency build with one clang and one C++
# standard library. Two environment variables name the trees:
#
#   CLANG_ROOT    a clang tree to compile with; unset to use the host's
#                 driver from PATH
#   VCPKG_ROOT    vcpkg's checkout
#
# A CMAKE_CXX_COMPILER given on the command line wins over both. The C
# compiler, the scanner and the archivers are the ones beside the compiler's
# real path, since CMake searches PATH first and a distribution package names
# them after the version (clang-scan-deps-23).
#
# CLANG_STDLIB selects the standard library clang compiles and CLANG_SANITIZER
# names the sanitizers, if any. CMake 4.5's import std support synthesizes the
# std module from the selected library's own manifest, so the compiler, the
# library and the module always agree.
#
# The same file serves every repository that builds with it.
set(CLANG_ROOT "$ENV{CLANG_ROOT}" CACHE PATH "clang tree")
set(VCPKG_ROOT "$ENV{VCPKG_ROOT}" CACHE PATH "vcpkg checkout")
if(NOT VCPKG_ROOT)
  message(FATAL_ERROR "Set VCPKG_ROOT to the vcpkg checkout")
endif()

## Hosts
#
# Each host names its drivers, the standard libraries it offers (the first
# is the default), the option that selects one, the option that keeps frame
# pointers, and the target clang compiles for when its default is not the
# one wanted. Windows uses clang-cl and the MSVC ABI, whose configuration
# file in the clang tree already selects libc++.

set(CLANG_ARCH_x86_64 x86_64)
set(CLANG_ARCH_AMD64 x86_64)
set(CLANG_ARCH_aarch64 aarch64)
set(CLANG_ARCH_arm64 aarch64)
set(CLANG_ARCH_ARM64 aarch64)
set(CLANG_DRIVERS_Linux clang++ clang++-23)
set(CLANG_STDLIBS_Linux libc++ libstdc++)
set(CLANG_STDLIB_OPTION_Linux "-stdlib=@CLANG_STDLIB@")
set(CLANG_FRAME_POINTER_OPTION_Linux -fno-omit-frame-pointer)
set(CLANG_DRIVERS_Darwin clang++)
set(CLANG_STDLIBS_Darwin libc++)
set(CLANG_STDLIB_OPTION_Darwin "-stdlib=@CLANG_STDLIB@")
set(CLANG_FRAME_POINTER_OPTION_Darwin -fno-omit-frame-pointer)
set(CLANG_DRIVERS_Windows clang-cl)
set(CLANG_STDLIBS_Windows libc++)
set(CLANG_FRAME_POINTER_OPTION_Windows /Oy-)
set(CLANG_TARGET_Windows "@CLANG_ARCH@-pc-windows-msvc")

set(CLANG_ARCH "${CLANG_ARCH_${CMAKE_HOST_SYSTEM_PROCESSOR}}")
set(CLANG_STDLIBS ${CLANG_STDLIBS_${CMAKE_HOST_SYSTEM_NAME}})
if(NOT CLANG_ARCH OR NOT CLANG_STDLIBS)
  message(FATAL_ERROR "No clang settings for ${CMAKE_HOST_SYSTEM_PROCESSOR} ${CMAKE_HOST_SYSTEM_NAME}")
endif()
list(GET CLANG_STDLIBS 0 CLANG_DEFAULT_STDLIB)
set(CLANG_STDLIB "${CLANG_DEFAULT_STDLIB}" CACHE STRING "C++ standard library clang compiles")
set_property(CACHE CLANG_STDLIB PROPERTY STRINGS ${CLANG_STDLIBS})
if(NOT CLANG_STDLIB IN_LIST CLANG_STDLIBS)
  message(FATAL_ERROR "CLANG_STDLIB is one of ${CLANG_STDLIBS}, not '${CLANG_STDLIB}'")
endif()
set(CLANG_SANITIZER "" CACHE STRING "Sanitizers clang instruments with, as -fsanitize= takes them")
string(CONFIGURE "${CLANG_STDLIB_OPTION_${CMAKE_HOST_SYSTEM_NAME}}" CLANG_STDLIB_OPTION @ONLY)
string(CONFIGURE "${CLANG_TARGET_${CMAKE_HOST_SYSTEM_NAME}}" CLANG_TARGET @ONLY)
# try_compile projects read this file again, without the cache.
list(APPEND CMAKE_TRY_COMPILE_PLATFORM_VARIABLES CLANG_ROOT VCPKG_ROOT CLANG_SANITIZER CLANG_STDLIB)

## Compiler and tools

list(TRANSFORM CLANG_ROOT APPEND /bin OUTPUT_VARIABLE CLANG_HINTS)
find_program(CMAKE_CXX_COMPILER NAMES ${CLANG_DRIVERS_${CMAKE_HOST_SYSTEM_NAME}} HINTS ${CLANG_HINTS} NAMES_PER_DIR REQUIRED)
# The C compiler for the ports is the sibling of the same name: clang++-23
# pairs with clang-23, and clang-cl compiles both.
cmake_path(GET CMAKE_CXX_COMPILER PARENT_PATH CLANG_DRIVER_DIR)
cmake_path(GET CMAKE_CXX_COMPILER FILENAME CLANG_DRIVER)
string(REPLACE "clang++" "clang" CLANG_DRIVER "${CLANG_DRIVER}")
find_program(CMAKE_C_COMPILER NAMES "${CLANG_DRIVER}" HINTS "${CLANG_DRIVER_DIR}" NO_DEFAULT_PATH REQUIRED)
file(REAL_PATH "${CMAKE_CXX_COMPILER}" CLANG_BIN)
cmake_path(GET CLANG_BIN PARENT_PATH CLANG_BIN)
cmake_path(GET CLANG_BIN PARENT_PATH CLANG_PREFIX)
find_program(CMAKE_CXX_COMPILER_CLANG_SCAN_DEPS NAMES clang-scan-deps HINTS "${CLANG_BIN}" NO_DEFAULT_PATH REQUIRED)
foreach(LANGUAGE C CXX)
  set(CMAKE_${LANGUAGE}_COMPILER_TARGET "${CLANG_TARGET}")
  find_program(CMAKE_${LANGUAGE}_COMPILER_AR NAMES llvm-ar HINTS "${CLANG_BIN}" NO_DEFAULT_PATH REQUIRED)
  find_program(CMAKE_${LANGUAGE}_COMPILER_RANLIB NAMES llvm-ranlib HINTS "${CLANG_BIN}" NO_DEFAULT_PATH REQUIRED)
endforeach()
# The static CRT on an MSVC target; other targets ignore it.
set(CMAKE_MSVC_RUNTIME_LIBRARY MultiThreaded)
# A per-target library directory holds the manifest the target's driver does
# not report; elsewhere CMake asks the driver.
find_file(CMAKE_CXX_STDLIB_MODULES_JSON "${CLANG_STDLIB}.modules.json"
  HINTS "${CLANG_PREFIX}/${CLANG_TARGET}/lib" NO_DEFAULT_PATH NO_CACHE)

# The library and the sanitizers initialize CMAKE_CXX_FLAGS, which compiler
# detection, try_compile projects and every target read; a CMAKE_CXX_FLAGS
# given in the cache replaces them. The chainload file below sets them for the
# ports and, since vcpkg.cmake loads it into the project as well, for the
# project.
set(CLANG_FLAGS "${CLANG_STDLIB_OPTION}")
if(CLANG_SANITIZER)
  # Frame pointers keep sanitizer stacks symbolized by function name.
  string(APPEND CLANG_FLAGS " -fsanitize=${CLANG_SANITIZER} ${CLANG_FRAME_POINTER_OPTION_${CMAKE_HOST_SYSTEM_NAME}}")
endif()

## Dependencies
#
# vcpkg builds every port for the host with the same compiler, tools and
# flags: static libraries everywhere, the static CRT on Windows. A host gets a
# triplet from the tables below. On Windows, libtool unpacks archives with
# lib /EXTRACT, which llvm-lib lacks, so the ports archive with Microsoft's
# lib from the vcvars environment vcpkg loads for them; the triplet reads
# that environment when a port builds.

set(TRIPLET_ARCH_x86_64 x64)
set(TRIPLET_ARCH_aarch64 arm64)
set(TRIPLET_PLATFORM_Linux linux)
set(TRIPLET_SETTINGS_Linux "set(VCPKG_CRT_LINKAGE dynamic)\nset(VCPKG_CMAKE_SYSTEM_NAME Linux)")
set(TRIPLET_PLATFORM_Darwin osx)
set(TRIPLET_SETTINGS_Darwin "set(VCPKG_CRT_LINKAGE dynamic)\nset(VCPKG_CMAKE_SYSTEM_NAME Darwin)\nset(VCPKG_OSX_ARCHITECTURES ${CMAKE_HOST_SYSTEM_PROCESSOR})")
set(TRIPLET_PLATFORM_Windows windows)
set(TRIPLET_SETTINGS_Windows [[
set(VCPKG_CRT_LINKAGE static)
set(VCPKG_LOAD_VCVARS_ENV ON)
file(TO_CMAKE_PATH "$ENV{VCToolsInstallDir}" VCPKG_MSVC_TOOLS)
set(VCPKG_CMAKE_CONFIGURE_OPTIONS "-DCMAKE_AR=${VCPKG_MSVC_TOOLS}/bin/Host${VCPKG_TARGET_ARCHITECTURE}/${VCPKG_TARGET_ARCHITECTURE}/lib.exe")]])

set(TRIPLET_ARCH "${TRIPLET_ARCH_${CLANG_ARCH}}")
# An MSVC link embeds its manifest with a manifest tool, which the clang tree
# lacks; the newest Windows SDK, which names architectures as vcpkg does,
# ships one. Other hosts have no SDK and keep CMake's own search.
cmake_host_system_information(RESULT WINDOWS_KITS QUERY WINDOWS_REGISTRY
  "HKLM/SOFTWARE/Microsoft/Windows Kits/Installed Roots" VALUE KitsRoot10)
cmake_path(CONVERT "${WINDOWS_KITS}" TO_CMAKE_PATH_LIST WINDOWS_KITS NORMALIZE)
list(TRANSFORM WINDOWS_KITS APPEND "bin/10.*" OUTPUT_VARIABLE WINDOWS_KITS_BINS)
file(GLOB WINDOWS_KITS_BINS LIST_DIRECTORIES true ${WINDOWS_KITS_BINS})
list(SORT WINDOWS_KITS_BINS COMPARE NATURAL ORDER DESCENDING)
list(TRANSFORM WINDOWS_KITS_BINS APPEND "/${TRIPLET_ARCH}")
find_program(CMAKE_MT NAMES llvm-mt mt HINTS "${CLANG_BIN}" ${WINDOWS_KITS_BINS} NAMES_PER_DIR)
set(TRIPLET_PLATFORM "${TRIPLET_PLATFORM_${CMAKE_HOST_SYSTEM_NAME}}")
set(TRIPLET_SETTINGS "${TRIPLET_SETTINGS_${CMAKE_HOST_SYSTEM_NAME}}")
string(REPLACE "+" "p" TRIPLET_STDLIB "${CLANG_STDLIB}")
set(VCPKG_TARGET_TRIPLET "${TRIPLET_ARCH}-${TRIPLET_PLATFORM}-${TRIPLET_STDLIB}" CACHE STRING "vcpkg target triplet")

set(VCPKG_CHAINLOAD_TOOLCHAIN_FILE "${CMAKE_BINARY_DIR}/clang-chainload.cmake")
file(CONFIGURE OUTPUT "${VCPKG_CHAINLOAD_TOOLCHAIN_FILE}" @ONLY CONTENT [[
set(CMAKE_C_COMPILER "@CMAKE_C_COMPILER@")
set(CMAKE_CXX_COMPILER "@CMAKE_CXX_COMPILER@")
set(CMAKE_C_COMPILER_TARGET "@CLANG_TARGET@")
set(CMAKE_CXX_COMPILER_TARGET "@CLANG_TARGET@")
set(CMAKE_CXX_COMPILER_CLANG_SCAN_DEPS "@CMAKE_CXX_COMPILER_CLANG_SCAN_DEPS@")
set(CMAKE_C_COMPILER_AR "@CMAKE_C_COMPILER_AR@")
set(CMAKE_CXX_COMPILER_AR "@CMAKE_CXX_COMPILER_AR@")
set(CMAKE_C_COMPILER_RANLIB "@CMAKE_C_COMPILER_RANLIB@")
set(CMAKE_CXX_COMPILER_RANLIB "@CMAKE_CXX_COMPILER_RANLIB@")
set(CMAKE_MSVC_RUNTIME_LIBRARY "@CMAKE_MSVC_RUNTIME_LIBRARY@")
set(CMAKE_CXX_FLAGS_INIT "@CLANG_FLAGS@")
]])
set(VCPKG_OVERLAY_TRIPLETS "${CMAKE_BINARY_DIR}/vcpkg-triplets")
file(CONFIGURE OUTPUT "${VCPKG_OVERLAY_TRIPLETS}/${VCPKG_TARGET_TRIPLET}.cmake" @ONLY CONTENT [[
set(VCPKG_TARGET_ARCHITECTURE @TRIPLET_ARCH@)
set(VCPKG_LIBRARY_LINKAGE static)
@TRIPLET_SETTINGS@
set(VCPKG_CHAINLOAD_TOOLCHAIN_FILE "@VCPKG_CHAINLOAD_TOOLCHAIN_FILE@")
]])

# vcpkg's scratch space stays in the build directory, and so do its downloads
# unless VCPKG_DOWNLOADS names a shared directory.
set(VCPKG_INSTALL_OPTIONS
  "--x-buildtrees-root=${CMAKE_BINARY_DIR}/vcpkg-buildtrees"
  "--x-packages-root=${CMAKE_BINARY_DIR}/vcpkg-packages")
if(NOT DEFINED ENV{VCPKG_DOWNLOADS})
  set(ENV{VCPKG_DOWNLOADS} "${CMAKE_BINARY_DIR}/vcpkg-downloads")
endif()

include("${VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake")
