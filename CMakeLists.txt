cmake_minimum_required(VERSION 4.3.1)

set(CMAKE_EXPERIMENTAL_CXX_IMPORT_STD
    "451f2fe2-a8a2-47c3-bc32-94786d8fc91b"
    CACHE STRING "Enable experimental import std support" FORCE)

option(ENABLE_TESTING "Build Tests" ON)
if(ENABLE_TESTING)
    list(APPEND VCPKG_MANIFEST_FEATURES "tests")
endif()

option(ENABLE_EXAMPLES "Build examples" ON)
if(ENABLE_EXAMPLES)
    list(APPEND VCPKG_MANIFEST_FEATURES "examples")
endif()

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_MODULE_STD ON CACHE BOOL "Enable import std support" FORCE)
set(CMAKE_CXX_SCAN_FOR_MODULES ON)
set(BOOST_UT_DISABLE_MODULE OFF)

project(httpant VERSION 0.1.0 LANGUAGES CXX)

if(WIN32 AND (ENABLE_TESTING OR ENABLE_EXAMPLES))
    add_compile_definitions(_WIN32_WINNT=0x0601)
endif()

find_package(llhttp CONFIG REQUIRED)
find_package(nghttp3 CONFIG REQUIRED)
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

if(ENABLE_TESTING OR ENABLE_EXAMPLES)
    find_package(asio CONFIG REQUIRED)
endif()

if(ENABLE_EXAMPLES)
    find_package(OpenSSL REQUIRED)
    find_package(msquic CONFIG REQUIRED)
endif()

if(ENABLE_TESTING)
    include(CTest)
    find_package(ut CONFIG REQUIRED)
endif()

add_library(${PROJECT_NAME} STATIC)
target_sources(
    ${PROJECT_NAME} PUBLIC FILE_SET CXX_MODULES FILES
    modules/httpant.cppm
    modules/trait.cppm
    modules/message.cppm
    modules/codec.cppm
    modules/session.cppm
    modules/channel.cppm
    modules/exchange.cppm
    modules/caching.cppm
    modules/cookie.cppm
)
target_compile_definitions(
    ${PROJECT_NAME} PUBLIC
    NGHTTP2_STATICLIB
    NGHTTP2_NO_SSIZE_T
    NGHTTP3_STATICLIB
)
target_link_libraries(
    ${PROJECT_NAME} PUBLIC
    llhttp::llhttp_static
    nghttp2::nghttp2
    $<IF:$<TARGET_EXISTS:nghttp3::nghttp3>,nghttp3::nghttp3,nghttp3::nghttp3_static>
)

if(ENABLE_TESTING)
    file(GLOB_RECURSE TEST_FILES CONFIGURE_DEPENDS testing/*.cpp)
    add_executable(${PROJECT_NAME}-test ${TEST_FILES})
    target_link_libraries(${PROJECT_NAME}-test PRIVATE
        ${PROJECT_NAME}
        Boost::ut
        asio::asio
        OpenSSL::SSL OpenSSL::Crypto
        msquic
    )
    add_test(NAME ${PROJECT_NAME}-test COMMAND ${PROJECT_NAME}-test)
endif()

if(ENABLE_EXAMPLES)
    add_subdirectory(examples)
endif()
