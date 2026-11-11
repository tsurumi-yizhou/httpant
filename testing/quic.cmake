# Generate a local trust anchor in the existing build directory.
execute_process(COMMAND "${GENERATOR}" "${DIRECTORY}" RESULT_VARIABLE result)
if(NOT result EQUAL 0)
    message(FATAL_ERROR "Could not generate test credentials")
endif()
