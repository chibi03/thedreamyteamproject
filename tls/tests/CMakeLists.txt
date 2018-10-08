add_definitions(${CHECK_DEFINITIONS})
include_directories(${CHECK_INCLUDE_DIRS})
link_directories(${CHECK_LIBRARY_DIRS})

foreach(target IN ITEMS hkdf nonce sha2 hmac_sha2 ascon aesgcm random task1_custom)
  add_executable("test_${target}" "${target}.cpp")
  target_link_libraries("test_${target}" primitives utils ${CHECK_LIBRARIES})

  add_test(NAME ${target}
           COMMAND $<TARGET_FILE:test_${target}> "${CMAKE_CURRENT_BINARY_DIR}/${target}.xml"
           WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}")

  add_custom_target("valgrind_test_${target}"
    env CK_FORK=no valgrind ${VALGRIND_ARGUMENTS}
    $<TARGET_FILE:test_${target}>
    DEPENDS test_${target}
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}")
endforeach(target)
