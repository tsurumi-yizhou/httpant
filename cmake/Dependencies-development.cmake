# Test and example dependencies. Included only when this repository is the thing
# being built — never from an installed package.
include("${CMAKE_CURRENT_LIST_DIR}/Dependencies.cmake")

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
