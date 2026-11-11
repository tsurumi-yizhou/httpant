# Every target of httpant: its module units and what they link.
#
# The targets are real static libraries, since CMake refuses a CXX_MODULES file
# set in INTERFACE scope. Their aliases are the names the build tree and the
# installed package share:
#
#   httpant::httpant   the protocol (module httpant)
#   httpant::imports   the wrappers over llhttp, nghttp2, nghttp3 and stdexec,
#                      linked PUBLIC by httpant::httpant
#   httpant::io        the native I/O engine (module httpant.io), with
#                      HTTPANT_ENABLE_IO
#   httpant::tls       TLS over caller transports (module httpant.tls), with
#                      HTTPANT_ENABLE_TLS
#
# HTTPANT_TARGETS collects what the package installs.

# xclang::std is built by each project that finds xclang, so the targets reach
# it through this interface target: httpant-config.cmake links the installed
# one to the consumer's xclang::std.
add_library(httpant-std INTERFACE)
set_target_properties(httpant-std PROPERTIES EXPORT_NAME std)
target_link_libraries(httpant-std INTERFACE $<BUILD_INTERFACE:xclang::std>)
set(HTTPANT_TARGETS httpant-std)

# httpant_add_module(<target> <export name> <interface unit>...)
function(httpant_add_module TARGET NAME)
  add_library(${TARGET} STATIC)
  add_library(httpant::${NAME} ALIAS ${TARGET})
  set_target_properties(${TARGET} PROPERTIES EXPORT_NAME ${NAME})
  target_link_libraries(${TARGET} PUBLIC httpant-std)
  target_sources(${TARGET} PUBLIC FILE_SET CXX_MODULES FILES ${ARGN})
  set(HTTPANT_TARGETS ${HTTPANT_TARGETS} ${TARGET} PARENT_SCOPE)
endfunction()

## Imports
#
# The C libraries and stdexec reach the protocol through module wrappers. They
# are targets of their own: CMake rejects a public module source that imports a
# module provided by a private source of the same target.

httpant_add_module(httpant-stdexec stdexec import/stdexec.ixx import/memory.ixx import/queue.ixx import/exception.ixx)
target_link_libraries(httpant-stdexec PUBLIC STDEXEC::stdexec)
target_compile_definitions(httpant-stdexec PRIVATE STDEXEC_BUILD_MODULES=1)

# The xclang triplets link every dependency statically.
httpant_add_module(httpant-imports imports import/llhttp.ixx import/nghttp2.ixx import/nghttp3.ixx)
target_link_libraries(httpant-imports PUBLIC httpant-stdexec
  llhttp::llhttp_static Nghttp2::nghttp2 nghttp3::nghttp3_static)
target_compile_definitions(httpant-imports PRIVATE NGHTTP2_NO_SSIZE_T NGHTTP2_STATICLIB NGHTTP3_STATICLIB)

httpant_add_module(httpant-asio asio import/asio.ixx)
target_link_libraries(httpant-asio PUBLIC asio::asio)

## Protocol

httpant_add_module(httpant httpant
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

## Native I/O engine
#
# Opt-in: httpant's default identity is the sans-I/O protocol library. The
# engine uses stdexec and platform APIs with no dependency on the protocol, so
# it is a separate target and a protocol consumer never links it. One
# mechanism is compiled in, chosen by HTTPANT_IO_BACKEND; the first one listed
# for a platform is its default.

if(HTTPANT_ENABLE_IO)
  httpant_add_module(httpant-io io modules/io/native.cppm modules/io/native/core.cppm modules/io/execution.cppm
    modules/io/native/queue.cppm modules/io/native/${HTTPANT_IO_BACKEND}.cppm)
  target_link_libraries(httpant-io PUBLIC httpant-stdexec)
  set(HTTPANT_IO_UNITS)
  if(WIN32)
    target_sources(httpant-io PUBLIC FILE_SET CXX_MODULES FILES modules/io/native/windows.cppm)
    target_link_libraries(httpant-io PRIVATE ws2_32 kernel32)
  else()
    list(APPEND HTTPANT_IO_UNITS modules/io/native/posix.cppm)
  endif()
  if(HTTPANT_IO_BACKEND STREQUAL "asio")
    list(APPEND HTTPANT_IO_UNITS modules/io/native/context.cppm)
    target_link_libraries(httpant-io PRIVATE httpant-asio)
  elseif(HTTPANT_IO_BACKEND STREQUAL "uring")
    target_link_libraries(httpant-io PRIVATE Liburing::liburing)
  endif()
  # Implementation units. clang reads a .cppm file as an interface unit unless
  # CMake passes the language to the compiler.
  target_sources(httpant-io PRIVATE ${HTTPANT_IO_UNITS})
  set_source_files_properties(${HTTPANT_IO_UNITS} PROPERTIES LANGUAGE CXX)
endif()

if(HTTPANT_ENABLE_TLS)
  httpant_add_module(httpant-tls-imports tls-imports import/wolfssl.ixx)
  target_link_libraries(httpant-tls-imports PUBLIC wolfssl::wolfssl)
  httpant_add_module(httpant-tls tls modules/tls.cppm)
  target_link_libraries(httpant-tls PUBLIC httpant httpant-tls-imports)
endif()
