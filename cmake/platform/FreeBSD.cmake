# FreeBSD: Asio by default, or kqueue, as on macOS.
include("${CMAKE_CURRENT_LIST_DIR}/posix.cmake")
set(HTTPANT_IO_BACKENDS asio kqueue)
