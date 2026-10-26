cmake_minimum_required(VERSION 4.0)

## Options
#
# Declared before project(): the vcpkg toolchain installs the manifest during
# that call, and QUIC is the one part with dependencies of its own.

option(HTTPANT_ENABLE_TLS "Build TLS over caller transports (module httpant.tls)" OFF)
option(HTTPANT_ENABLE_IO "Build the native I/O engine (module httpant.io)" OFF)
option(HTTPANT_ENABLE_QUIC "Build QUIC with msquic and engine posts (module httpant.quic)" OFF)
option(BUILD_TESTING "Build the testing tree." ON)
option(BUILD_EXAMPLES "Build the examples" OFF)
option(BUILD_BENCHMARKS "Build the benchmarks" OFF)

if(HTTPANT_ENABLE_QUIC)
  if(NOT HTTPANT_ENABLE_IO)
    message(FATAL_ERROR "HTTPANT_ENABLE_QUIC requires HTTPANT_ENABLE_IO=ON")
  endif()
endif()
set(HTTPANT_BUILD_SUPPORT OFF)
if(BUILD_TESTING OR BUILD_EXAMPLES)
  set(HTTPANT_BUILD_SUPPORT ON)
endif()
if(HTTPANT_BUILD_SUPPORT)
  set(HTTPANT_ENABLE_TLS ON)
endif()
if(HTTPANT_ENABLE_TLS)
  list(APPEND VCPKG_MANIFEST_FEATURES tls)
else()
  list(REMOVE_ITEM VCPKG_MANIFEST_FEATURES tls)
endif()
if(HTTPANT_ENABLE_QUIC OR HTTPANT_BUILD_SUPPORT)
  list(APPEND VCPKG_MANIFEST_FEATURES quic)
else()
  list(REMOVE_ITEM VCPKG_MANIFEST_FEATURES quic)
endif()

if(HTTPANT_ENABLE_IO AND HTTPANT_IO_BACKEND STREQUAL "uring")
  list(APPEND VCPKG_MANIFEST_FEATURES uring)
else()
  list(REMOVE_ITEM VCPKG_MANIFEST_FEATURES uring)
endif()

project(httpant VERSION 0.2.0 LANGUAGES CXX)

## Language
#
# C++23 modules with the standard library as a module; the compiler comes from
# the xclang tree that cmake/toolchain.cmake selects.

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_SCAN_FOR_MODULES ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

include(CTest)

## Dependencies and modules

include(cmake/dependencies.cmake)
set(HTTPANT_SOURCE "${PROJECT_SOURCE_DIR}")
include(cmake/modules.cmake)

## Package
#
# Sources, not BMIs: a module package installs what the consumer must compile,
# together with the two files that register its targets.

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)
set(HTTPANT_INSTALL_SHARE "${CMAKE_INSTALL_DATADIR}/httpant")
install(DIRECTORY modules/ DESTINATION "${HTTPANT_INSTALL_SHARE}/modules" FILES_MATCHING PATTERN "*.cppm")
install(FILES import/llhttp.ixx import/nghttp2.ixx import/nghttp3.ixx import/msquic.ixx
  import/wolfssl.ixx import/stdexec.ixx import/memory.ixx import/queue.ixx import/asio.ixx DESTINATION "${HTTPANT_INSTALL_SHARE}/import")
install(FILES cmake/dependencies.cmake cmake/modules.cmake DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/httpant")
configure_package_config_file(cmake/httpant-config.cmake.in "${CMAKE_CURRENT_BINARY_DIR}/httpant-config.cmake"
  INSTALL_DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/httpant" PATH_VARS HTTPANT_INSTALL_SHARE)
write_basic_package_version_file("${CMAKE_CURRENT_BINARY_DIR}/httpant-config-version.cmake"
  VERSION "${PROJECT_VERSION}" COMPATIBILITY SameMajorVersion ARCH_INDEPENDENT)
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/httpant-config.cmake" "${CMAKE_CURRENT_BINARY_DIR}/httpant-config-version.cmake"
  DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/httpant")
install(FILES LICENSE DESTINATION "${CMAKE_INSTALL_DATADIR}/licenses/httpant")

## Tests, examples and benchmarks
#
# Executables stay at the top of the build tree, where bench/run.py looks for
# them. Two support modules are shared: the Asio, wolfSSL and MsQuic adapters,
# and the protocol over the native engine.

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${PROJECT_BINARY_DIR}")
set(HTTPANT_DATA_DIR "${PROJECT_BINARY_DIR}" CACHE PATH "Existing directory for I/O test data")

if(BUILD_TESTING OR BUILD_EXAMPLES)
  find_package(asio CONFIG REQUIRED)
  find_package(wolfssl CONFIG REQUIRED)
  httpant_add_module(httpant-example-support
    examples/asio_support.ixx examples/quic_support.ixx)
  target_link_libraries(httpant-example-support PUBLIC httpant httpant-asio
    httpant-tls httpant-quic-imports)
endif()

if(HTTPANT_ENABLE_IO AND (BUILD_TESTING OR BUILD_EXAMPLES OR BUILD_BENCHMARKS))
  httpant_add_module(httpant-io-support examples/io.ixx)
  target_link_libraries(httpant-io-support PUBLIC httpant httpant-io)
endif()

if(BUILD_TESTING)
  add_subdirectory(testing)
endif()

if(BUILD_EXAMPLES)
  add_subdirectory(examples)
endif()

if(BUILD_BENCHMARKS)
  add_executable(httpant-boundary-cost bench/execution.cpp)
  target_link_libraries(httpant-boundary-cost PRIVATE httpant)
  if(HTTPANT_ENABLE_IO)
    add_executable(io-bench bench/io.cpp)
    target_link_libraries(io-bench PRIVATE httpant-io-support)
    target_compile_definitions(io-bench PRIVATE
      BENCH_BUILD="$<CONFIG>"
      BENCH_COMPILER="${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}")
    if(BUILD_TESTING)
      add_test(NAME io-bench-smoke COMMAND io-bench
        --directory "${HTTPANT_DATA_DIR}" --iterations 8 --warmup 2
        --concurrency 2 --bytes 1024 --samples 1 --timer-us 100)
      set_tests_properties(io-bench-smoke PROPERTIES TIMEOUT 40)
    endif()
  endif()
endif()
