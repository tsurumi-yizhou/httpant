# macOS: Asio by default, or kqueue.
include("${CMAKE_CURRENT_LIST_DIR}/posix.cmake")
set(HTTPANT_IO_BACKENDS asio kqueue)
