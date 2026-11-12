cmake_minimum_required(VERSION 4.0)
project(httpant VERSION 0.2.0 LANGUAGES CXX)

## Options
#
# A consumer that adds httpant as a subproject sets these as normal variables
# before it does.

option(HTTPANT_ENABLE_TLS "Build TLS over caller transports (module httpant.tls)" ${PROJECT_IS_TOP_LEVEL})
option(HTTPANT_ENABLE_IO "Build the native I/O engine (module httpant.io)" OFF)
option(HTTPANT_BUILD_TESTS "Build the testing tree" ${PROJECT_IS_TOP_LEVEL})
option(HTTPANT_BUILD_EXAMPLES "Build the examples" OFF)
option(HTTPANT_BUILD_BENCHMARKS "Build the benchmarks" OFF)
if((HTTPANT_BUILD_TESTS OR HTTPANT_BUILD_EXAMPLES) AND NOT HTTPANT_ENABLE_TLS)
  message(FATAL_ERROR "The tests and examples need HTTPANT_ENABLE_TLS")
endif()

# One I/O mechanism is compiled in; the first one listed is the platform's
# default.
if(WIN32)
  set(HTTPANT_IO_BACKENDS asio ioring iocp)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  set(HTTPANT_IO_BACKENDS asio uring epoll)
elseif(APPLE OR CMAKE_SYSTEM_NAME MATCHES "BSD")
  set(HTTPANT_IO_BACKENDS asio kqueue)
else()
  set(HTTPANT_IO_BACKENDS asio)
endif()
list(GET HTTPANT_IO_BACKENDS 0 HTTPANT_DEFAULT_IO_BACKEND)
set(HTTPANT_IO_BACKEND "${HTTPANT_DEFAULT_IO_BACKEND}" CACHE STRING "Native I/O mechanism")
set_property(CACHE HTTPANT_IO_BACKEND PROPERTY STRINGS ${HTTPANT_IO_BACKENDS})
if(NOT HTTPANT_IO_BACKEND IN_LIST HTTPANT_IO_BACKENDS)
  message(FATAL_ERROR "HTTPANT_IO_BACKEND=${HTTPANT_IO_BACKEND} is not one of: ${HTTPANT_IO_BACKENDS}")
endif()

## Language
#
# C++23 modules with the standard library as a module; the compiler comes from
# the xclang tree that cmake/toolchain.cmake selects.

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_SCAN_FOR_MODULES ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Warnings stay on for the first-party tree but never fail the build.
if(CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
  # Disable Debug symbols even when configuring without a preset.
  add_compile_options(-Wall -Wextra "$<$<CONFIG:Debug>:-g0>")
endif()

## Dependencies and modules

list(APPEND CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake")
include(cmake/dependencies.cmake)
include(cmake/modules.cmake)

## Package
#
# The libraries with their interface units; the consumer compiles the units
# again, since module BMIs are not portable.

if(PROJECT_IS_TOP_LEVEL)
  include(GNUInstallDirs)
  include(CMakePackageConfigHelpers)
  set(HTTPANT_INSTALL_CMAKE "${CMAKE_INSTALL_LIBDIR}/cmake/httpant")
  install(TARGETS ${HTTPANT_TARGETS} EXPORT httpant-targets
    ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    FILE_SET CXX_MODULES DESTINATION "${CMAKE_INSTALL_DATADIR}/httpant")
  install(EXPORT httpant-targets NAMESPACE httpant:: DESTINATION "${HTTPANT_INSTALL_CMAKE}"
    CXX_MODULES_DIRECTORY cxx-modules)
  configure_package_config_file(cmake/httpant-config.cmake.in "${PROJECT_BINARY_DIR}/httpant-config.cmake"
    INSTALL_DESTINATION "${HTTPANT_INSTALL_CMAKE}")
  write_basic_package_version_file("${PROJECT_BINARY_DIR}/httpant-config-version.cmake"
    COMPATIBILITY SameMajorVersion)
  install(FILES "${PROJECT_BINARY_DIR}/httpant-config.cmake" "${PROJECT_BINARY_DIR}/httpant-config-version.cmake"
    cmake/dependencies.cmake cmake/FindNghttp2.cmake cmake/FindLiburing.cmake
    DESTINATION "${HTTPANT_INSTALL_CMAKE}")
  install(FILES LICENSE DESTINATION "${CMAKE_INSTALL_DATADIR}/licenses/httpant")
endif()

## Tests, examples and benchmarks
#
# Executables stay at the top of the build tree, where bench/run.py looks for
# them. Two support modules are shared: the Asio and wolfSSL adapters, and the
# protocol over the native engine.

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${PROJECT_BINARY_DIR}")
set(HTTPANT_DATA_DIR "${PROJECT_BINARY_DIR}" CACHE PATH "Existing directory for I/O test data")

if(HTTPANT_BUILD_TESTS OR HTTPANT_BUILD_EXAMPLES)
  httpant_add_module(httpant-example-support example-support examples/asio_support.ixx)
  target_link_libraries(httpant-example-support PUBLIC httpant httpant-asio httpant-tls)
endif()

if(HTTPANT_ENABLE_IO AND (HTTPANT_BUILD_TESTS OR HTTPANT_BUILD_EXAMPLES OR HTTPANT_BUILD_BENCHMARKS))
  httpant_add_module(httpant-io-support io-support examples/io.ixx)
  target_link_libraries(httpant-io-support PUBLIC httpant httpant-io)
endif()

if(HTTPANT_BUILD_TESTS)
  enable_testing()
  add_subdirectory(testing)
endif()

if(HTTPANT_BUILD_EXAMPLES)
  add_subdirectory(examples)
endif()

if(HTTPANT_BUILD_BENCHMARKS)
  add_executable(httpant-boundary-cost bench/execution.cpp)
  target_link_libraries(httpant-boundary-cost PRIVATE httpant)
  if(HTTPANT_ENABLE_IO)
    add_executable(io-bench bench/io.cpp)
    target_link_libraries(io-bench PRIVATE httpant-io-support)
    target_compile_definitions(io-bench PRIVATE
      BENCH_BUILD="$<CONFIG>"
      BENCH_COMPILER="${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}")
    if(HTTPANT_BUILD_TESTS)
      add_test(NAME io-bench-smoke COMMAND io-bench
        --directory "${HTTPANT_DATA_DIR}" --iterations 8 --warmup 2
        --concurrency 2 --bytes 1024 --samples 1 --timer-us 100)
      set_tests_properties(io-bench-smoke PROPERTIES TIMEOUT 40)
    endif()
  endif()
endif()
