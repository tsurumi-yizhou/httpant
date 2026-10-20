cmake_minimum_required(VERSION 4.0.0)

option(ENABLE_EXAMPLES "Build examples" ON)

# Only the standalone build selects features for Httpant's vcpkg manifest.
# A parent project owns dependency acquisition for its whole project tree.
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    # Match CTest's default before project() installs the vcpkg dependencies.
    if(NOT DEFINED BUILD_TESTING OR BUILD_TESTING)
        list(APPEND VCPKG_MANIFEST_FEATURES "tests")
    endif()
    if(ENABLE_EXAMPLES)
        list(APPEND VCPKG_MANIFEST_FEATURES "examples")
    endif()
endif()

if(NOT CMAKE_CXX_STANDARD OR CMAKE_CXX_STANDARD LESS 23)
    set(CMAKE_CXX_STANDARD 23)
endif()
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_SCAN_FOR_MODULES ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

project(httpant VERSION 0.1.0 LANGUAGES CXX)

include(CTest)
if(NOT TARGET xclang::std)
    find_package(xclang CONFIG REQUIRED)
endif()

if(WIN32 AND (BUILD_TESTING OR ENABLE_EXAMPLES))
    add_compile_definitions(_WIN32_WINNT=0x0601)
endif()

include(cmake/Dependencies.cmake)

# The library reaches three C libraries and the standard async model through
# module wrappers (import/*.ixx). They cannot live in the same target as the
# protocol modules: CMake rejects a public module source that imports a module
# provided by a private source. So they are one small target of their own, and
# the package publishes three names: httpant, httpant-io, httpant-imports.
set(HTTPANT_IMPORTS
    import/llhttp.ixx
    import/nghttp2.ixx
    import/nghttp3.ixx
    import/stdexec.ixx
)
set(HTTPANT_DEPENDENCY_DEFINITIONS NGHTTP2_NO_SSIZE_T)
get_target_property(HTTPANT_NGHTTP2_TYPE ${HTTPANT_NGHTTP2_TARGET} TYPE)
if(HTTPANT_NGHTTP2_TYPE STREQUAL "STATIC_LIBRARY" OR HTTPANT_NGHTTP2_TYPE STREQUAL "UNKNOWN_LIBRARY")
    list(APPEND HTTPANT_DEPENDENCY_DEFINITIONS NGHTTP2_STATICLIB)
endif()
get_target_property(HTTPANT_NGHTTP3_TYPE ${HTTPANT_NGHTTP3_TARGET} TYPE)
if(HTTPANT_NGHTTP3_TYPE STREQUAL "STATIC_LIBRARY")
    list(APPEND HTTPANT_DEPENDENCY_DEFINITIONS NGHTTP3_STATICLIB)
endif()

add_library(httpant-imports STATIC)
target_sources(httpant-imports PUBLIC FILE_SET CXX_MODULES FILES ${HTTPANT_IMPORTS})
target_compile_definitions(httpant-imports PRIVATE ${HTTPANT_DEPENDENCY_DEFINITIONS})
target_link_libraries(httpant-imports PUBLIC
    xclang::std
    ${HTTPANT_LLHTTP_TARGET}
    ${HTTPANT_NGHTTP2_TARGET}
    ${HTTPANT_NGHTTP3_TARGET}
    ${HTTPANT_STDEXEC_TARGET}
)
add_library(httpant::imports ALIAS httpant-imports)

# Native I/O engine: io_uring, kqueue and IORing behind one completion interface,
# in the httpant.io module. It is opt-in: httpant's default identity is the
# sans-I/O protocol library, which moves bytes for nobody and opens nothing.
# Consumers that want the engine turn it on and link httpant-io.
option(HTTPANT_ENABLE_IO "Build the native I/O engine (module httpant.io)" OFF)
if(HTTPANT_ENABLE_IO)
    add_library(httpant-io STATIC)
    target_sources(httpant-io PUBLIC FILE_SET CXX_MODULES FILES
        modules/io/native.cppm
    )
    target_sources(httpant-io PRIVATE FILE_SET internal_modules TYPE CXX_MODULES FILES
        modules/io/native/queue.cppm
    )
    target_link_libraries(httpant-io PUBLIC xclang::std)

    if(WIN32)
        set(HTTPANT_IO_IMPLEMENTATIONS modules/io/native/ioring.cppm)
        target_link_libraries(httpant-io PRIVATE ws2_32 kernel32)
    elseif(APPLE OR CMAKE_SYSTEM_NAME MATCHES "^(FreeBSD|OpenBSD|NetBSD|DragonFly)$")
        set(HTTPANT_IO_IMPLEMENTATIONS modules/io/native/kqueue.cppm modules/io/native/posix.cppm)
    else()
        httpant_find_liburing(HTTPANT_LIBURING_TARGET liburing::liburing uring::uring)
        set(HTTPANT_IO_IMPLEMENTATIONS modules/io/native/uring.cppm modules/io/native/posix.cppm)
        target_link_libraries(httpant-io PRIVATE ${HTTPANT_LIBURING_TARGET})
    endif()
    target_sources(httpant-io PRIVATE ${HTTPANT_IO_IMPLEMENTATIONS})
    set_source_files_properties(${HTTPANT_IO_IMPLEMENTATIONS} PROPERTIES LANGUAGE CXX)

    add_library(httpant::io ALIAS httpant-io)
    add_library(httpant::default-io ALIAS httpant-io)
endif()

add_library(${PROJECT_NAME} STATIC)
target_sources(
    ${PROJECT_NAME} PUBLIC FILE_SET CXX_MODULES FILES
    modules/httpant.cppm
    modules/error.cppm
    modules/trait.cppm
    modules/message.cppm
    modules/role.cppm
    modules/validate/llhttp.cppm
    modules/parse/llhttp.cppm
    modules/serialize/llhttp.cppm
    modules/client/llhttp.cppm
    modules/server/llhttp.cppm
    modules/session/core.cppm
    modules/session/nghttp2.cppm
    modules/parse/nghttp2.cppm
    modules/serialize/nghttp2.cppm
    modules/endpoint/nghttp2.cppm
    modules/client/nghttp2.cppm
    modules/server/nghttp2.cppm
    modules/session/nghttp3.cppm
    modules/parse/nghttp3.cppm
    modules/serialize/nghttp3.cppm
    modules/endpoint/nghttp3.cppm
    modules/client/nghttp3.cppm
    modules/server/nghttp3.cppm
    modules/coroutine.cppm
    modules/execution.cppm
    modules/fetch.cppm
    modules/caching.cppm
    modules/cookie.cppm
)
target_link_libraries(${PROJECT_NAME} PUBLIC httpant-imports)
add_library(httpant::httpant ALIAS ${PROJECT_NAME})

if(BUILD_TESTING OR ENABLE_EXAMPLES)
    add_library(httpant-example-support STATIC)
    target_sources(httpant-example-support PUBLIC FILE_SET CXX_MODULES FILES
        import/asio.ixx
        import/openssl.ixx
        import/msquic.ixx
        examples/asio_support.ixx
        examples/quic_support.ixx
    )
    target_link_libraries(httpant-example-support PUBLIC
        httpant ${HTTPANT_ASIO_TARGET} OpenSSL::SSL OpenSSL::Crypto ${HTTPANT_MSQUIC_TARGET}
    )
endif()

if(BUILD_TESTING)
    file(GLOB_RECURSE TEST_FILES CONFIGURE_DEPENDS testing/*.cpp)
    add_executable(${PROJECT_NAME}-test ${TEST_FILES})
    target_sources(${PROJECT_NAME}-test PRIVATE FILE_SET CXX_MODULES FILES
        import/boost.ut.ixx
        testing/test_support.ixx
    )
    target_link_libraries(${PROJECT_NAME}-test PRIVATE httpant-example-support ${HTTPANT_UT_TARGET})
    add_test(NAME ${PROJECT_NAME}-test COMMAND ${PROJECT_NAME}-test)
    set_tests_properties(${PROJECT_NAME}-test PROPERTIES TIMEOUT 60)

    if(HTTPANT_ENABLE_IO)
        add_executable(httpant-io-test testing/native_io.cpp)
        target_link_libraries(httpant-io-test PRIVATE httpant-io)
        add_test(NAME httpant-io COMMAND httpant-io-test "${CMAKE_BINARY_DIR}")
    endif()
endif()

if(ENABLE_EXAMPLES)
    add_library(httpant-client-support STATIC)
    target_sources(httpant-client-support PUBLIC FILE_SET CXX_MODULES FILES examples/client_support.ixx)
    target_link_libraries(httpant-client-support PUBLIC httpant)
    add_subdirectory(examples)
endif()

# --- install ---------------------------------------------------------------
# Sources, not BMIs: a module package installs what the consumer must compile.
include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

set(HTTPANT_INSTALL_SHARE "${CMAKE_INSTALL_DATADIR}/httpant")
set(HTTPANT_MODULE_EXCLUDES)
if(NOT HTTPANT_ENABLE_IO)
    list(APPEND HTTPANT_MODULE_EXCLUDES PATTERN "io" EXCLUDE)
endif()
install(DIRECTORY modules/ DESTINATION "${HTTPANT_INSTALL_SHARE}/modules"
    FILES_MATCHING PATTERN "*.cppm" ${HTTPANT_MODULE_EXCLUDES})
install(FILES import/llhttp.ixx import/nghttp2.ixx import/nghttp3.ixx import/stdexec.ixx
    DESTINATION "${HTTPANT_INSTALL_SHARE}/import")
install(FILES cmake/Dependencies.cmake
    DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/httpant")

configure_package_config_file(cmake/httpant-config.cmake.in
    "${CMAKE_CURRENT_BINARY_DIR}/httpant-config.cmake"
    INSTALL_DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/httpant"
    PATH_VARS HTTPANT_INSTALL_SHARE)
write_basic_package_version_file("${CMAKE_CURRENT_BINARY_DIR}/httpant-config-version.cmake"
    VERSION "${PROJECT_VERSION}"
    COMPATIBILITY SameMajorVersion
    ARCH_INDEPENDENT)
install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/httpant-config.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/httpant-config-version.cmake"
    DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/httpant")
install(FILES LICENSE DESTINATION "${CMAKE_INSTALL_DATADIR}/licenses/${PROJECT_NAME}")
