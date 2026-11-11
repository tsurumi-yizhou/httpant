# The examples, included when HTTPANT_BUILD_EXAMPLES is on.

httpant_add_module(httpant-client-support client-support client_support.ixx)
target_link_libraries(httpant-client-support PUBLIC httpant)

add_executable(httpant.coroutine.client coroutine/client.cpp)
target_link_libraries(httpant.coroutine.client PRIVATE httpant-client-support)

add_executable(httpant.execution.client execution/client.cpp)
target_link_libraries(httpant.execution.client PRIVATE httpant-client-support)

# The protocol over the native engine; with HTTPANT_BUILD_TESTS its round trips are
# tests, for both interfaces.
if(NOT HTTPANT_ENABLE_IO)
  return()
endif()

add_executable(http-example http.cpp)
target_link_libraries(http-example PRIVATE httpant-io-support httpant-example-support)

if(NOT HTTPANT_BUILD_TESTS)
  return()
endif()

set(CREDENTIALS --cert "${PROJECT_BINARY_DIR}/quic-cert.pem" --key "${PROJECT_BINARY_DIR}/quic-key.pem"
  --ca "${PROJECT_BINARY_DIR}/quic-cert.pem")
foreach(INTERFACE IN ITEMS coroutine execution)
  foreach(PROTOCOL IN ITEMS h1 h2)
    add_test(NAME http-${PROTOCOL}-${INTERFACE} COMMAND http-example
      --protocol ${PROTOCOL} --interface ${INTERFACE} --requests 8 --bytes 131072)
    set_tests_properties(http-${PROTOCOL}-${INTERFACE} PROPERTIES TIMEOUT 40)
    add_test(NAME http-${PROTOCOL}-tls-${INTERFACE} COMMAND http-example
      --protocol ${PROTOCOL} --interface ${INTERFACE} --tls --requests 8 --bytes 131072 ${CREDENTIALS})
    set_tests_properties(http-${PROTOCOL}-tls-${INTERFACE} PROPERTIES TIMEOUT 40 FIXTURES_REQUIRED tls-credentials)
  endforeach()
endforeach()

add_test(NAME http-tls-hostname COMMAND http-example --protocol h2 --tls
  --requests 1 --server-name wrong.localhost ${CREDENTIALS})
set_tests_properties(http-tls-hostname PROPERTIES TIMEOUT 40
  FIXTURES_REQUIRED tls-credentials WILL_FAIL TRUE)
