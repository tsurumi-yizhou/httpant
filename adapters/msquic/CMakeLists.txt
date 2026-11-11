cmake_minimum_required(VERSION 4.0)
project(httpant-msquic VERSION 0.1.0 LANGUAGES CXX)

## httpant core
#
# The adapter is a consumer of httpant, not part of it. It builds the core
# from a sibling checkout unless the parent already added it.

set(HTTPANT_SOURCE_DIR "${CMAKE_CURRENT_LIST_DIR}/../.." CACHE PATH "httpant core checkout")
if(NOT TARGET httpant)
  set(HTTPANT_ENABLE_IO ON)
  set(HTTPANT_ENABLE_TLS OFF)
  set(HTTPANT_IO_BACKEND asio)
  add_subdirectory("${HTTPANT_SOURCE_DIR}" "${CMAKE_BINARY_DIR}/httpant" EXCLUDE_FROM_ALL)
endif()

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_SCAN_FOR_MODULES ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

## msquic
#
# msquic builds from source at the release the adapter targets; the vcpkg port
# lags behind it. TLS comes from the platform on Windows (schannel) and from the
# manifest's OpenSSL, which provides the QUIC API since 3.5, elsewhere, so none
# of msquic's submodules are needed. msquic's own install rules are skipped:
# its package would point into this build tree, and the consumer deploys the
# shared library itself.

include(FetchContent)
set(QUIC_BUILD_SHARED ON)
set(QUIC_EMBED_GIT_HASH OFF)
if(NOT WIN32)
  set(QUIC_TLS_LIB openssl CACHE STRING "TLS Library to use")
  set(QUIC_USE_EXTERNAL_OPENSSL ON)
endif()
FetchContent_Declare(msquic
  GIT_REPOSITORY https://github.com/microsoft/msquic.git
  GIT_TAG v2.6.4
  GIT_SHALLOW TRUE
  GIT_SUBMODULES ""
  EXCLUDE_FROM_ALL)
set(CMAKE_SKIP_INSTALL_RULES ON)
FetchContent_MakeAvailable(msquic)
unset(CMAKE_SKIP_INSTALL_RULES)

add_library(httpant-msquic STATIC)
target_sources(httpant-msquic PUBLIC FILE_SET CXX_MODULES
  BASE_DIRS "${CMAKE_CURRENT_SOURCE_DIR}"
  FILES
    "${CMAKE_CURRENT_SOURCE_DIR}/import/msquic.ixx"
    "${CMAKE_CURRENT_SOURCE_DIR}/modules/quic.cppm")
target_link_libraries(httpant-msquic PUBLIC httpant::httpant httpant::io msquic)
add_library(httpant::msquic ALIAS httpant-msquic)
