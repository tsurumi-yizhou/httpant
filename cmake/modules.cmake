# Every target of httpant: its module units and what they link. The
# repository's build and the installed package both include this file, with
# HTTPANT_SOURCE naming the directory that holds import/ and modules/.
#
# The targets are real static libraries, since CMake refuses a CXX_MODULES file
# set in INTERFACE scope, and their names stay plain because a name containing
# "::" can only be an alias or an imported target. The aliases are the package
# interface:
#
#   httpant::httpant   the protocol (module httpant)
#   httpant::imports   the wrappers over llhttp, nghttp2, nghttp3 and stdexec,
#                      linked PUBLIC by httpant::httpant
#   httpant::io        the native I/O engine (module httpant.io), also
#                      httpant::default-io; with HTTPANT_ENABLE_IO
#   httpant::quic      QUIC with msquic and engine posts (module httpant.quic); with
#                      HTTPANT_ENABLE_QUIC

function(httpant_add_module TARGET)
  list(TRANSFORM ARGN PREPEND "${HTTPANT_SOURCE}/" OUTPUT_VARIABLE SOURCES)
  add_library(${TARGET} STATIC)
  target_link_libraries(${TARGET} PUBLIC xclang::std)
  target_sources(${TARGET} PUBLIC FILE_SET CXX_MODULES
    BASE_DIRS "${HTTPANT_SOURCE}" FILES ${SOURCES})
endfunction()

## Imports
#
# The C libraries and stdexec reach the protocol through module wrappers. They
# are targets of their own: CMake rejects a public module source that imports a
# module provided by a private source of the same target.

httpant_add_module(httpant-stdexec import/stdexec.ixx import/memory.ixx import/queue.ixx)
target_link_libraries(httpant-stdexec PUBLIC STDEXEC::stdexec)
target_compile_definitions(httpant-stdexec PRIVATE STDEXEC_BUILD_MODULES=1)

# The xclang triplets link every dependency statically.
httpant_add_module(httpant-imports import/llhttp.ixx import/nghttp2.ixx import/nghttp3.ixx)
target_link_libraries(httpant-imports PUBLIC httpant-stdexec
  llhttp::llhttp_static nghttp2::nghttp2 nghttp3::nghttp3_static)
target_compile_definitions(httpant-imports PRIVATE NGHTTP2_NO_SSIZE_T NGHTTP2_STATICLIB NGHTTP3_STATICLIB)
add_library(httpant::imports ALIAS httpant-imports)

httpant_add_module(httpant-asio import/asio.ixx)
target_link_libraries(httpant-asio PUBLIC asio::asio)

## Protocol

httpant_add_module(httpant
  # interface, and the types every protocol shares
  modules/httpant.cppm
  modules/error.cppm
  modules/trait.cppm
  modules/message.cppm
  modules/role.cppm
  # HTTP/1.1 over llhttp
  modules/validate/llhttp.cppm
  modules/parse/llhttp.cppm
  modules/serialize/llhttp.cppm
  modules/client/llhttp.cppm
  modules/server/llhttp.cppm
  # session state shared by HTTP/2 and HTTP/3
  modules/session/core.cppm
  # HTTP/2 over nghttp2
  modules/session/nghttp2.cppm
  modules/parse/nghttp2.cppm
  modules/serialize/nghttp2.cppm
  modules/endpoint/nghttp2.cppm
  modules/client/nghttp2.cppm
  modules/server/nghttp2.cppm
  # HTTP/3 over nghttp3
  modules/session/nghttp3.cppm
  modules/parse/nghttp3.cppm
  modules/serialize/nghttp3.cppm
  modules/endpoint/nghttp3.cppm
  modules/client/nghttp3.cppm
  modules/server/nghttp3.cppm
  # protocol-independent helpers
  modules/coroutine.cppm
  modules/execution.cppm
  modules/fetch.cppm
  modules/fetch/coroutine.cppm
  modules/fetch/execution.cppm
  modules/websocket.cppm
  modules/caching.cppm
  modules/cookie.cppm)
target_link_libraries(httpant PUBLIC httpant-imports)
add_library(httpant::httpant ALIAS httpant)

## Native I/O engine
#
# Opt-in: httpant's default identity is the sans-I/O protocol library. The
# engine uses stdexec and platform APIs with no dependency on the protocol, so
# it is a separate target and a protocol consumer never links it. One
# mechanism is compiled in, chosen by HTTPANT_IO_BACKEND; the first one listed
# for a platform is its default.

if(HTTPANT_ENABLE_IO)
  if(WIN32)
    set(HTTPANT_IO_BACKENDS asio ioring iocp)
  elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    set(HTTPANT_IO_BACKENDS asio uring epoll)
  elseif(APPLE OR CMAKE_SYSTEM_NAME MATCHES "^(FreeBSD|OpenBSD|NetBSD|DragonFly)$")
    set(HTTPANT_IO_BACKENDS asio kqueue)
  else()
    set(HTTPANT_IO_BACKENDS asio)
  endif()
  list(GET HTTPANT_IO_BACKENDS 0 HTTPANT_IO_DEFAULT)
  set(HTTPANT_IO_BACKEND "${HTTPANT_IO_DEFAULT}" CACHE STRING "Native I/O mechanism")
  set_property(CACHE HTTPANT_IO_BACKEND PROPERTY STRINGS ${HTTPANT_IO_BACKENDS})
  if(NOT HTTPANT_IO_BACKEND IN_LIST HTTPANT_IO_BACKENDS)
    message(FATAL_ERROR "HTTPANT_IO_BACKEND=${HTTPANT_IO_BACKEND} is invalid for ${CMAKE_SYSTEM_NAME}; choose ${HTTPANT_IO_BACKENDS}")
  endif()

  httpant_add_module(httpant-io modules/io/native.cppm modules/io/native/core.cppm modules/io/execution.cppm)
  target_link_libraries(httpant-io PUBLIC httpant-stdexec)

  set(HTTPANT_IO_PARTITIONS modules/io/native/queue.cppm modules/io/native/${HTTPANT_IO_BACKEND}.cppm)
  set(HTTPANT_IO_UNITS)
  if(WIN32)
    list(APPEND HTTPANT_IO_PARTITIONS modules/io/native/windows.cppm)
    target_link_libraries(httpant-io PRIVATE ws2_32 kernel32)
  else()
    list(APPEND HTTPANT_IO_UNITS modules/io/native/posix.cppm)
  endif()
  if(HTTPANT_IO_BACKEND STREQUAL "asio")
    list(APPEND HTTPANT_IO_UNITS modules/io/native/context.cppm)
    target_link_libraries(httpant-io PRIVATE httpant-asio)
  endif()
  if(HTTPANT_IO_BACKEND STREQUAL "uring")
    target_link_libraries(httpant-io PRIVATE liburing::liburing)
  endif()
  list(TRANSFORM HTTPANT_IO_PARTITIONS PREPEND "${HTTPANT_SOURCE}/")
  list(TRANSFORM HTTPANT_IO_UNITS PREPEND "${HTTPANT_SOURCE}/")
  target_sources(httpant-io PUBLIC FILE_SET internal_modules TYPE CXX_MODULES
    BASE_DIRS "${HTTPANT_SOURCE}" FILES ${HTTPANT_IO_PARTITIONS})
  target_sources(httpant-io PRIVATE ${HTTPANT_IO_UNITS})
  set_source_files_properties(${HTTPANT_IO_UNITS} PROPERTIES LANGUAGE CXX)

  add_library(httpant::io ALIAS httpant-io)
  add_library(httpant::default-io ALIAS httpant-io)
endif()

## QUIC
#
# QUIC uses msquic for transport and the engine for application resumptions.

if(HTTPANT_ENABLE_QUIC OR HTTPANT_BUILD_SUPPORT)
  httpant_add_module(httpant-quic-imports import/msquic.ixx)
  target_link_libraries(httpant-quic-imports PUBLIC msquic)
endif()
if(HTTPANT_ENABLE_QUIC)
  httpant_add_module(httpant-quic modules/quic.cppm)
  target_link_libraries(httpant-quic PUBLIC httpant httpant-io httpant-quic-imports)
  add_library(httpant::quic ALIAS httpant-quic)
endif()

if(HTTPANT_ENABLE_TLS)
  httpant_add_module(httpant-tls-imports import/wolfssl.ixx)
  target_link_libraries(httpant-tls-imports PUBLIC wolfssl::wolfssl)
  httpant_add_module(httpant-tls modules/tls.cppm)
  target_link_libraries(httpant-tls PUBLIC httpant httpant-tls-imports)
  add_library(httpant::tls ALIAS httpant-tls)
endif()
