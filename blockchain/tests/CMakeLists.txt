add_definitions("-DSOURCE_DIR=\"${CMAKE_CURRENT_SOURCE_DIR}/data/\"")
add_definitions("-DGROUP_NUMBER=\"${GROUP_NUMBER}\"")
foreach(target IN ITEMS ring-signature commitment merkletree blockchain attack task3_custom)
  add_executable("test_${target}" "${target}.cpp")
  target_link_libraries("test_${target}" bc_primitives utils ${CHECK_LIBRARIES})

  add_test(NAME ${target} COMMAND $<TARGET_FILE:test_${target}> "${CMAKE_CURRENT_BINARY_DIR}/${target}.xml")

  add_custom_target("valgrind_test_${target}"
    env CK_FORK=no valgrind ${VALGRIND_ARGUMENTS}
    $<TARGET_FILE:test_${target}>
    DEPENDS test_${target})
endforeach(target)
