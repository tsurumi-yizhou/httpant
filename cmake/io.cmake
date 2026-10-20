# The native I/O engine: io_uring, kqueue and IORing behind one completion
# interface, in the httpant.io module. CMakeLists.txt includes this file only
# when HTTPANT_ENABLE_IO is on, so a sans-I/O build defines none of it.
#
# The engine depends on nothing but the standard library and the platform API,
# which is why it is a separate target rather than a partition of `httpant`.
add_library(httpant-io STATIC)
target_sources(httpant-io PUBLIC FILE_SET CXX_MODULES FILES
    modules/io/native.cppm
)
target_sources(httpant-io PRIVATE FILE_SET internal_modules TYPE CXX_MODULES FILES
    modules/io/native/queue.cppm
)
target_link_libraries(httpant-io PUBLIC xclang::std)

# One implementation unit per mechanism, and only the one this platform uses.
if(WIN32)
    set(HTTPANT_IO_MECHANISM modules/io/native/ioring.cppm)
    target_link_libraries(httpant-io PRIVATE ws2_32 kernel32)
elseif(APPLE OR CMAKE_SYSTEM_NAME MATCHES "^(FreeBSD|OpenBSD|NetBSD|DragonFly)$")
    set(HTTPANT_IO_MECHANISM modules/io/native/kqueue.cppm modules/io/native/posix.cppm)
else()
    httpant_find_liburing(HTTPANT_LIBURING_TARGET liburing::liburing uring::uring)
    set(HTTPANT_IO_MECHANISM modules/io/native/uring.cppm modules/io/native/posix.cppm)
    target_link_libraries(httpant-io PRIVATE ${HTTPANT_LIBURING_TARGET})
endif()
target_sources(httpant-io PRIVATE ${HTTPANT_IO_MECHANISM})
set_source_files_properties(${HTTPANT_IO_MECHANISM} PROPERTIES LANGUAGE CXX)

# The two aliases are the published names; `default-io` says which mechanism the
# platform picked without naming it.
add_library(httpant::io ALIAS httpant-io)
add_library(httpant::default-io ALIAS httpant-io)
