# liburing's library and headers, as Liburing::liburing.

find_path(Liburing_INCLUDE_DIR NAMES liburing.h)
find_library(Liburing_LIBRARY NAMES uring)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Liburing REQUIRED_VARS Liburing_LIBRARY Liburing_INCLUDE_DIR)

if(Liburing_FOUND AND NOT TARGET Liburing::liburing)
  add_library(Liburing::liburing UNKNOWN IMPORTED)
  set_target_properties(Liburing::liburing PROPERTIES
    IMPORTED_LOCATION "${Liburing_LIBRARY}"
    INTERFACE_INCLUDE_DIRECTORIES "${Liburing_INCLUDE_DIR}")
endif()
