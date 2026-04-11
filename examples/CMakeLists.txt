add_executable(httpant-reverse-proxy reverse_proxy.cpp)

target_link_libraries(httpant-reverse-proxy PRIVATE
    httpant
    asio::asio
    OpenSSL::SSL
    OpenSSL::Crypto
    msquic
)
