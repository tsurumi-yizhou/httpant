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

add_library(httpant-dependencies STATIC)
target_sources(httpant-dependencies PUBLIC FILE_SET CXX_MODULES FILES
    import/llhttp.ixx
    import/nghttp2.ixx
    import/nghttp3.ixx
    import/stdexec.ixx
)
target_compile_definitions(httpant-dependencies PRIVATE NGHTTP2_NO_SSIZE_T)
get_target_property(HTTPANT_NGHTTP2_TYPE ${HTTPANT_NGHTTP2_TARGET} TYPE)
if(HTTPANT_NGHTTP2_TYPE STREQUAL "STATIC_LIBRARY" OR HTTPANT_NGHTTP2_TYPE STREQUAL "UNKNOWN_LIBRARY")
    target_compile_definitions(httpant-dependencies PRIVATE NGHTTP2_STATICLIB)
endif()
get_target_property(HTTPANT_NGHTTP3_TYPE ${HTTPANT_NGHTTP3_TARGET} TYPE)
if(HTTPANT_NGHTTP3_TYPE STREQUAL "STATIC_LIBRARY")
    target_compile_definitions(httpant-dependencies PRIVATE NGHTTP3_STATICLIB)
endif()
target_link_libraries(httpant-dependencies PUBLIC
    xclang::std
    ${HTTPANT_LLHTTP_TARGET}
    ${HTTPANT_NGHTTP2_TARGET}
    ${HTTPANT_NGHTTP3_TARGET}
    ${HTTPANT_STDEXEC_TARGET}
)

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
target_link_libraries(${PROJECT_NAME} PUBLIC httpant-dependencies)

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
endif()

if(ENABLE_EXAMPLES)
    add_library(httpant-client-support STATIC)
    target_sources(httpant-client-support PUBLIC FILE_SET CXX_MODULES FILES examples/client_support.ixx)
    target_link_libraries(httpant-client-support PUBLIC httpant)
    add_subdirectory(examples)
endif()
