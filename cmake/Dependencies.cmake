# Reuse targets supplied by the parent project (including FetchContent),
# and only search for installed packages when none of their targets exist.
function(httpant_find_dependency output package)
    foreach(candidate IN LISTS ARGN)
        if(TARGET "${candidate}")
            set(${output} "${candidate}" PARENT_SCOPE)
            return()
        endif()
    endforeach()
    find_package(${package} CONFIG REQUIRED)
    foreach(candidate IN LISTS ARGN)
        if(TARGET "${candidate}")
            set(${output} "${candidate}" PARENT_SCOPE)
            return()
        endif()
    endforeach()
    message(FATAL_ERROR "${package} did not provide a supported target: ${ARGN}")
endfunction()

httpant_find_dependency(HTTPANT_LLHTTP_TARGET llhttp
    llhttp::llhttp llhttp::llhttp_static llhttp_static llhttp_shared)
httpant_find_dependency(HTTPANT_NGHTTP3_TARGET nghttp3
    nghttp3::nghttp3 nghttp3::nghttp3_static nghttp3 nghttp3_static)
httpant_find_dependency(HTTPANT_STDEXEC_TARGET stdexec STDEXEC::stdexec stdexec)

# nghttp2's vcpkg port may only provide headers and libraries, while its
# source build and other packages provide a CMake target.
foreach(candidate IN ITEMS nghttp2::nghttp2 nghttp2::nghttp2_static nghttp2 nghttp2_static)
    if(TARGET "${candidate}")
        set(HTTPANT_NGHTTP2_TARGET "${candidate}")
        break()
    endif()
endforeach()
if(NOT HTTPANT_NGHTTP2_TARGET)
    find_package(nghttp2 CONFIG QUIET)
    foreach(candidate IN ITEMS nghttp2::nghttp2 nghttp2::nghttp2_static nghttp2 nghttp2_static)
        if(TARGET "${candidate}")
            set(HTTPANT_NGHTTP2_TARGET "${candidate}")
            break()
        endif()
    endforeach()
endif()
if(NOT HTTPANT_NGHTTP2_TARGET)
    find_path(NGHTTP2_INCLUDE_DIR
        NAMES nghttp2/nghttp2.h
        REQUIRED
    )
    find_library(NGHTTP2_LIBRARY_RELEASE
        NAMES nghttp2
        PATH_SUFFIXES lib
    )
    find_library(NGHTTP2_LIBRARY_DEBUG
        NAMES nghttp2
        PATH_SUFFIXES debug/lib
    )
    if(NOT NGHTTP2_LIBRARY_RELEASE AND NOT NGHTTP2_LIBRARY_DEBUG)
        message(FATAL_ERROR "Failed to locate nghttp2 library.")
    endif()

    set(NGHTTP2_LIBRARY "${NGHTTP2_LIBRARY_RELEASE}")
    if(NOT NGHTTP2_LIBRARY)
        set(NGHTTP2_LIBRARY "${NGHTTP2_LIBRARY_DEBUG}")
    endif()

    add_library(nghttp2::nghttp2 UNKNOWN IMPORTED)
    set_target_properties(
        nghttp2::nghttp2 PROPERTIES
        IMPORTED_LOCATION "${NGHTTP2_LIBRARY}"
        INTERFACE_INCLUDE_DIRECTORIES "${NGHTTP2_INCLUDE_DIR}"
    )
    if(NGHTTP2_LIBRARY_RELEASE)
        set_property(TARGET nghttp2::nghttp2 APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
        set_target_properties(
            nghttp2::nghttp2 PROPERTIES
            IMPORTED_LOCATION_RELEASE "${NGHTTP2_LIBRARY_RELEASE}"
        )
    endif()
    if(NGHTTP2_LIBRARY_DEBUG)
        set_property(TARGET nghttp2::nghttp2 APPEND PROPERTY IMPORTED_CONFIGURATIONS DEBUG)
        set_target_properties(
            nghttp2::nghttp2 PROPERTIES
            IMPORTED_LOCATION_DEBUG "${NGHTTP2_LIBRARY_DEBUG}"
        )
    endif()
    set(HTTPANT_NGHTTP2_TARGET nghttp2::nghttp2)
endif()

if(BUILD_TESTING OR ENABLE_EXAMPLES)
    httpant_find_dependency(HTTPANT_ASIO_TARGET asio asio::asio asio)
    if(NOT TARGET OpenSSL::SSL OR NOT TARGET OpenSSL::Crypto)
        find_package(OpenSSL REQUIRED)
    endif()
    httpant_find_dependency(HTTPANT_MSQUIC_TARGET msquic msquic)
endif()
if(BUILD_TESTING)
    httpant_find_dependency(HTTPANT_UT_TARGET ut Boost::ut)
endif()
