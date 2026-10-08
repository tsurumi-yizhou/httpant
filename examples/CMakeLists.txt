add_executable(httpant-reverse-proxy reverse_proxy.cpp)
target_link_libraries(httpant-reverse-proxy PRIVATE httpant-example-support)

add_executable(httpant.coroutine.client coroutine/client.cpp)
target_link_libraries(httpant.coroutine.client PRIVATE httpant-client-support)

add_executable(httpant.execution.client execution/client.cpp)
target_link_libraries(httpant.execution.client PRIVATE httpant-client-support)
