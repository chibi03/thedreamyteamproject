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

add_executable(test_tls_encrypted_record tls-encrypted-record.cpp)
target_link_libraries(test_tls_encrypted_record primitives utils ${CHECK_LIBRARIES})

foreach(idx RANGE 1 6)
  foreach(cipher IN ITEMS ascon aes128gcm)
    add_test(NAME "tls_${cipher}_${idx}" COMMAND test_tls_encrypted_record ${cipher}
      "${CMAKE_CURRENT_SOURCE_DIR}/data/${cipher}-testcase-${idx}.chal"
      "${CMAKE_CURRENT_SOURCE_DIR}/data/${cipher}-testcase-${idx}.sol")

    add_custom_target("valgrind_test_tls_${cipher}_${idx}"
      env CK_FORK=no valgrind ${VALGRIND_ARGUMENTS}
      $<TARGET_FILE:test_tls_encrypted_record> ${cipher}
      "${CMAKE_CURRENT_SOURCE_DIR}/data/${cipher}-testcase-${idx}.chal"
      "${CMAKE_CURRENT_SOURCE_DIR}/data/${cipher}-testcase-${idx}.sol"
      DEPENDS test_tls_encrypted_record)
  endforeach(cipher)
endforeach(idx)

add_library(playback SHARED playback.cpp)
target_link_libraries(playback utils Boost::boost Boost::system)

add_definitions("-DSOURCE_DIR=\"${CMAKE_CURRENT_SOURCE_DIR}/\"")
foreach(target IN ITEMS ecdh tls_record_layer tls_handshake task2_custom)
  add_executable("test_${target}" "${target}.cpp")
  target_link_libraries("test_${target}" primitives playback utils Boost::boost Boost::system ${CHECK_LIBRARIES})

  add_test(NAME ${target}
           COMMAND $<TARGET_FILE:test_${target}> "${CMAKE_CURRENT_BINARY_DIR}/${target}.xml"
           WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}")

  add_custom_target("valgrind_test_${target}"
    env CK_FORK=no valgrind ${VALGRIND_ARGUMENTS}
    $<TARGET_FILE:test_${target}>
    DEPENDS test_${target}
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}")
endforeach(target)
