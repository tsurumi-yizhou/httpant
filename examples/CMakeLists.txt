add_executable(httpant-reverse-proxy reverse_proxy.cpp stop_support.cpp)

add_executable(httpant.coroutine.client coroutine/client.cpp)
target_link_libraries(httpant.coroutine.client PRIVATE httpant)

add_executable(httpant.execution.client execution/client.cpp)
target_link_libraries(httpant.execution.client PRIVATE httpant)

target_link_libraries(httpant-reverse-proxy PRIVATE
    httpant
    asio::asio
    OpenSSL::SSL
    OpenSSL::Crypto
    msquic
)
