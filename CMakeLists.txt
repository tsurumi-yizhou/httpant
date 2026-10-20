cmake_minimum_required(VERSION 4.0.0)

# A standalone build owns its dependencies through the vcpkg manifest; a parent
# project owns them for the whole tree. This has to be decided before project(),
# because vcpkg reads VCPKG_MANIFEST_FEATURES during that call.
set(httpant_top_level OFF)
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    set(httpant_top_level ON)
endif()

# Off by default: the examples need OpenSSL and msquic, and a protocol library's
# consumers should not have to fetch a QUIC stack to build it.
option(ENABLE_EXAMPLES "Build the examples" OFF)

# The engine is opt-in too, and it is what asks vcpkg for liburing.
option(HTTPANT_ENABLE_IO "Build the native I/O engine (module httpant.io)" OFF)

if(httpant_top_level)
    if(NOT DEFINED BUILD_TESTING OR BUILD_TESTING)
        list(APPEND VCPKG_MANIFEST_FEATURES tests)
    endif()
    if(ENABLE_EXAMPLES)
        list(APPEND VCPKG_MANIFEST_FEATURES examples)
    endif()
    if(HTTPANT_ENABLE_IO)
        list(APPEND VCPKG_MANIFEST_FEATURES io)
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

# Defines BUILD_TESTING (CTest's default is ON for a standalone build) and
# enables add_test; harmless in an embedded build, where the parent owns it.
include(CTest)

if(NOT TARGET xclang::std)
    find_package(xclang CONFIG REQUIRED)
endif()

if(WIN32 AND (BUILD_TESTING OR ENABLE_EXAMPLES))
    add_compile_definitions(_WIN32_WINNT=0x0601)
endif()

include(cmake/Dependencies.cmake)

# Test and example dependencies. Never reached from the installed package: an
# installed config must not re-run these, and a consumer that happens to set
# BUILD_TESTING must not make them appear. Dependencies.cmake stays a file
# because the installed httpant-config.cmake includes it.
if(BUILD_TESTING OR ENABLE_EXAMPLES)
    httpant_find_dependency(HTTPANT_ASIO_TARGET asio asio::asio asio)
    if(NOT TARGET OpenSSL::SSL OR NOT TARGET OpenSSL::Crypto)
        find_package(OpenSSL REQUIRED)
    endif()
    httpant_find_dependency(HTTPANT_MSQUIC_TARGET msquic msquic)
endif()

# The library reaches three C libraries and the standard async model through
# module wrappers (import/*.ixx). They cannot live in the same target as the
# protocol modules: CMake rejects a public module source that imports a module
# provided by a private source. So they are one small target of their own, and
# the package publishes three names: httpant, httpant-io, httpant-imports.
set(httpant_imports
    import/llhttp.ixx
    import/nghttp2.ixx
    import/nghttp3.ixx
    import/stdexec.ixx
)
set(httpant_dependency_definitions NGHTTP2_NO_SSIZE_T)
get_target_property(httpant_nghttp2_type ${HTTPANT_NGHTTP2_TARGET} TYPE)
if(httpant_nghttp2_type STREQUAL "STATIC_LIBRARY" OR httpant_nghttp2_type STREQUAL "UNKNOWN_LIBRARY")
    list(APPEND httpant_dependency_definitions NGHTTP2_STATICLIB)
endif()
get_target_property(httpant_nghttp3_type ${HTTPANT_NGHTTP3_TARGET} TYPE)
if(httpant_nghttp3_type STREQUAL "STATIC_LIBRARY")
    list(APPEND httpant_dependency_definitions NGHTTP3_STATICLIB)
endif()

add_library(httpant-imports STATIC)
target_sources(httpant-imports PUBLIC FILE_SET CXX_MODULES FILES ${httpant_imports})
target_compile_definitions(httpant-imports PRIVATE ${httpant_dependency_definitions})
target_link_libraries(httpant-imports PUBLIC
    xclang::std
    ${HTTPANT_LLHTTP_TARGET}
    ${HTTPANT_NGHTTP2_TARGET}
    ${HTTPANT_NGHTTP3_TARGET}
    ${HTTPANT_STDEXEC_TARGET}
)
add_library(httpant::imports ALIAS httpant-imports)

## Native I/O engine (module httpant.io)
#
# Opt-in: httpant's default identity is the sans-I/O protocol library, which
# moves bytes for nobody and opens nothing. The engine depends on nothing but the
# standard library and the platform API, so it is a separate target rather than a
# partition of `httpant` — a consumer that only wants the protocol never links it.
if(HTTPANT_ENABLE_IO)
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
        set(httpant_io_mechanism modules/io/native/ioring.cppm)
        target_link_libraries(httpant-io PRIVATE ws2_32 kernel32)
    elseif(APPLE OR CMAKE_SYSTEM_NAME MATCHES "^(FreeBSD|OpenBSD|NetBSD|DragonFly)$")
        set(httpant_io_mechanism modules/io/native/kqueue.cppm modules/io/native/posix.cppm)
    else()
        httpant_find_liburing(httpant_liburing_target liburing::liburing uring::uring)
        set(httpant_io_mechanism modules/io/native/uring.cppm modules/io/native/posix.cppm)
        target_link_libraries(httpant-io PRIVATE ${httpant_liburing_target})
    endif()
    target_sources(httpant-io PRIVATE ${httpant_io_mechanism})
    set_source_files_properties(${httpant_io_mechanism} PROPERTIES LANGUAGE CXX)

    # The two aliases are the published names; `default-io` says which mechanism the
    # platform picked without naming it.
    add_library(httpant::io ALIAS httpant-io)
    add_library(httpant::default-io ALIAS httpant-io)
endif()

add_library(${PROJECT_NAME} STATIC)
target_sources(
    ${PROJECT_NAME} PUBLIC FILE_SET CXX_MODULES FILES
    # interface, and the vocabulary every protocol shares
    modules/httpant.cppm
    modules/error.cppm
    modules/trait.cppm
    modules/message.cppm
    modules/role.cppm
    # HTTP/1.1 over llhttp
    modules/validate/llhttp.cppm
    modules/parse/llhttp.cppm
    modules/serialize/llhttp.cppm
    modules/client/llhttp.cppm
    modules/server/llhttp.cppm
    # session state shared by HTTP/2 and HTTP/3
    modules/session/core.cppm
    # HTTP/2 over nghttp2
    modules/session/nghttp2.cppm
    modules/parse/nghttp2.cppm
    modules/serialize/nghttp2.cppm
    modules/endpoint/nghttp2.cppm
    modules/client/nghttp2.cppm
    modules/server/nghttp2.cppm
    # HTTP/3 over nghttp3
    modules/session/nghttp3.cppm
    modules/parse/nghttp3.cppm
    modules/serialize/nghttp3.cppm
    modules/endpoint/nghttp3.cppm
    modules/client/nghttp3.cppm
    modules/server/nghttp3.cppm
    # protocol-independent helpers
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
    # its own executable: it has a main() and needs a scratch directory
    list(FILTER TEST_FILES EXCLUDE REGEX "/testing/native_io\\.cpp$")
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

set(httpant_install_share "${CMAKE_INSTALL_DATADIR}/httpant")
set(httpant_module_excludes)
if(NOT HTTPANT_ENABLE_IO)
    list(APPEND httpant_module_excludes PATTERN "io" EXCLUDE)
endif()
install(DIRECTORY modules/ DESTINATION "${httpant_install_share}/modules"
    FILES_MATCHING PATTERN "*.cppm" ${httpant_module_excludes})
install(FILES import/llhttp.ixx import/nghttp2.ixx import/nghttp3.ixx import/stdexec.ixx
    DESTINATION "${httpant_install_share}/import")
install(FILES cmake/Dependencies.cmake
    DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/httpant")

configure_package_config_file(cmake/httpant-config.cmake.in
    "${CMAKE_CURRENT_BINARY_DIR}/httpant-config.cmake"
    INSTALL_DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/httpant"
    PATH_VARS httpant_install_share)
write_basic_package_version_file("${CMAKE_CURRENT_BINARY_DIR}/httpant-config-version.cmake"
    VERSION "${PROJECT_VERSION}"
    COMPATIBILITY SameMajorVersion
    ARCH_INDEPENDENT)
install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/httpant-config.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/httpant-config-version.cmake"
    DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/httpant")
install(FILES LICENSE DESTINATION "${CMAKE_INSTALL_DATADIR}/licenses/${PROJECT_NAME}")
