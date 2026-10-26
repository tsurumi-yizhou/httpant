# Test registration, included when BUILD_TESTING is on.

find_package(ut CONFIG REQUIRED)

# The protocol suite: every source here except the engine's, which are
# executables of their own with a main() and a scratch directory.
file(GLOB_RECURSE SOURCES RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}" CONFIGURE_DEPENDS *.cpp)
list(FILTER SOURCES EXCLUDE REGEX "^io/|^certificate[.]cpp$")
add_executable(httpant-test ${SOURCES})
target_sources(httpant-test PRIVATE FILE_SET CXX_MODULES BASE_DIRS "${PROJECT_SOURCE_DIR}"
  FILES "${PROJECT_SOURCE_DIR}/import/boost.ut.ixx" test_support.ixx)
target_link_libraries(httpant-test PRIVATE httpant-example-support Boost::ut)
add_test(NAME httpant-test COMMAND httpant-test)
set_tests_properties(httpant-test PROPERTIES TIMEOUT 60 FIXTURES_REQUIRED quic-credentials
  WORKING_DIRECTORY "${PROJECT_BINARY_DIR}")

if(HTTPANT_ENABLE_IO)
  add_executable(io-test io/native.cpp)
  target_link_libraries(io-test PRIVATE httpant-io)
  add_test(NAME io COMMAND io-test "${HTTPANT_DATA_DIR}")
  add_executable(execution-test io/execution.cpp)
  target_link_libraries(execution-test PRIVATE httpant-io)
  add_test(NAME execution COMMAND execution-test "${HTTPANT_DATA_DIR}")
  set_tests_properties(io execution PROPERTIES TIMEOUT 60)
endif()

add_executable(httpant-certificate certificate.cpp)
target_link_libraries(httpant-certificate PRIVATE httpant-example-support)
add_test(NAME quic-credentials COMMAND "${CMAKE_COMMAND}"
  "-DDIRECTORY=${PROJECT_BINARY_DIR}" "-DGENERATOR=$<TARGET_FILE:httpant-certificate>"
  -P "${CMAKE_CURRENT_SOURCE_DIR}/quic.cmake")
set_tests_properties(quic-credentials PROPERTIES FIXTURES_SETUP quic-credentials)

if(HTTPANT_ENABLE_QUIC)
  add_executable(quic-test io/quic.cpp)
  target_link_libraries(quic-test PRIVATE httpant-quic httpant-io-support)
  add_test(NAME quic COMMAND quic-test "${PROJECT_BINARY_DIR}")
  set_tests_properties(quic PROPERTIES TIMEOUT 60 FIXTURES_REQUIRED quic-credentials)
endif()
