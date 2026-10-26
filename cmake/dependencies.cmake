# The packages httpant's modules build against. The repository's build and the
# installed package (httpant-config.cmake) both include this file, after
# HTTPANT_ENABLE_IO and HTTPANT_ENABLE_QUIC are known.
#
# Everything comes from vcpkg: the manifest is vcpkg.json, and
# vcpkg-configuration.json adds the registry's reviewed overlay ports.

find_package(xclang CONFIG REQUIRED)
find_package(stdexec CONFIG REQUIRED)
find_package(asio CONFIG REQUIRED)
find_package(llhttp CONFIG REQUIRED)
find_package(nghttp3 CONFIG REQUIRED)

# nghttp2's and liburing's vcpkg ports ship headers and archives without a CMake
# package, so their targets are built by hand. IMPORTED_LOCATION is the
# single-config default and the per-config entries are what multi-config
# generators read; setting only one of them breaks a configure that has no
# CMAKE_BUILD_TYPE. A release-only triplet has no debug archive, so Debug links
# the release one.
function(httpant_import_library TARGET LIBRARY)
  set(PREFIX "${VCPKG_INSTALLED_DIR}/${VCPKG_TARGET_TRIPLET}")
  find_library(RELEASE_LIBRARY NAMES "${LIBRARY}" PATHS "${PREFIX}/lib"
    NO_DEFAULT_PATH NO_CACHE REQUIRED)
  find_library(DEBUG_LIBRARY NAMES "${LIBRARY}" PATHS "${PREFIX}/debug/lib"
    NO_DEFAULT_PATH NO_CACHE)
  if(NOT DEBUG_LIBRARY)
    set(DEBUG_LIBRARY "${RELEASE_LIBRARY}")
  endif()
  add_library(${TARGET} STATIC IMPORTED GLOBAL)
  set_target_properties(${TARGET} PROPERTIES
    INTERFACE_INCLUDE_DIRECTORIES "${PREFIX}/include"
    IMPORTED_LOCATION "${RELEASE_LIBRARY}"
    IMPORTED_LOCATION_DEBUG "${DEBUG_LIBRARY}"
    IMPORTED_LOCATION_RELEASE "${RELEASE_LIBRARY}"
    IMPORTED_LOCATION_RELWITHDEBINFO "${RELEASE_LIBRARY}"
    IMPORTED_LOCATION_MINSIZEREL "${RELEASE_LIBRARY}")
endfunction()

httpant_import_library(nghttp2::nghttp2 nghttp2)

if(HTTPANT_ENABLE_IO AND HTTPANT_IO_BACKEND STREQUAL "uring")
  httpant_import_library(liburing::liburing uring)
endif()

if(HTTPANT_ENABLE_QUIC OR HTTPANT_BUILD_SUPPORT)
  find_package(msquic CONFIG REQUIRED)
endif()

if(HTTPANT_ENABLE_TLS)
  find_package(wolfssl CONFIG REQUIRED)
endif()
