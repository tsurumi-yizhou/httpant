# The packages httpant's modules build against, all from vcpkg.json.

find_package(stdexec CONFIG REQUIRED)
find_package(asio CONFIG REQUIRED)
find_package(llhttp CONFIG REQUIRED)
find_package(nghttp3 CONFIG REQUIRED)
# nghttp2 and liburing install no CMake package: cmake/Find*.cmake.
find_package(Nghttp2 REQUIRED)
# The packages each I/O mechanism adds.
set(HTTPANT_IO_PACKAGES_uring Liburing)
if(HTTPANT_ENABLE_IO)
  foreach(PACKAGE IN LISTS HTTPANT_IO_PACKAGES_${HTTPANT_IO_BACKEND})
    find_package(${PACKAGE} REQUIRED)
  endforeach()
endif()
if(HTTPANT_ENABLE_TLS)
  find_package(wolfssl CONFIG REQUIRED)
endif()
