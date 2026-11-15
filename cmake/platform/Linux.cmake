# Linux: Asio by default, io_uring or epoll.
include("${CMAKE_CURRENT_LIST_DIR}/posix.cmake")
set(HTTPANT_IO_BACKENDS asio uring epoll)
