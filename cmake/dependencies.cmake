# The packages httpant's modules build against, all from vcpkg.json.

find_package(xclang CONFIG REQUIRED)
find_package(stdexec CONFIG REQUIRED)
find_package(asio CONFIG REQUIRED)
find_package(llhttp CONFIG REQUIRED)
find_package(nghttp3 CONFIG REQUIRED)
# nghttp2 and liburing install no CMake package: cmake/Find*.cmake.
find_package(Nghttp2 REQUIRED)
if(HTTPANT_ENABLE_IO AND HTTPANT_IO_BACKEND STREQUAL "uring")
  find_package(Liburing REQUIRED)
endif()
if(HTTPANT_ENABLE_TLS)
  find_package(wolfssl CONFIG REQUIRED)
endif()
