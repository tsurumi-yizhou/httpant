cmake_minimum_required(VERSION 4.0.0)

# A standalone build owns its dependencies through the vcpkg manifest; a parent
# project owns them for the whole tree. This has to be decided before project(),
# because vcpkg reads VCPKG_MANIFEST_FEATURES during that call.
set(HTTPANT_TOP_LEVEL OFF)
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    set(HTTPANT_TOP_LEVEL ON)
endif()

# Off by default: the examples need OpenSSL and msquic, and a protocol library's
# consumers should not have to fetch a QUIC stack to build it.
option(ENABLE_EXAMPLES "Build the examples" OFF)

if(HTTPANT_TOP_LEVEL)
    if(NOT DEFINED BUILD_TESTING OR BUILD_TESTING)
        list(APPEND VCPKG_MANIFEST_FEATURES tests)
    endif()
    if(ENABLE_EXAMPLES)
        list(APPEND VCPKG_MANIFEST_FEATURES examples)
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
if(BUILD_TESTING OR ENABLE_EXAMPLES)
    include(cmake/Dependencies-development.cmake)
endif()

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

# Native I/O engine (module httpant.io): opt-in, and its own file because it is
# the only optional component this project builds.
option(HTTPANT_ENABLE_IO "Build the native I/O engine (module httpant.io)" OFF)
if(HTTPANT_ENABLE_IO)
    include(cmake/io.cmake)
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
