set(BC_PRIMITIVES_SOURCES
    ecclib-glue.cpp
    merkletree.cpp
    io.cpp
    utils.cpp
    ring-signature.cpp
    commitment.cpp
    blockchain.cpp
    attack.cpp)

set(BC_SOURCES
    main.cpp)

add_library(bc_primitives SHARED ${BC_PRIMITIVES_SOURCES})
target_link_libraries(bc_primitives
                      primitives
                      ecc_lib
                      utils)

add_executable(blockchain ${BC_SOURCES})
target_link_libraries(blockchain
                      bc_primitives
                      primitives
                      ecc_lib
                      utils)

add_custom_target("blockchain_attack_miner"
    $<TARGET_FILE:blockchain>
    deanonymize_miner
    ${CMAKE_CURRENT_SOURCE_DIR}/challenges/blockchain
    ${CMAKE_CURRENT_SOURCE_DIR}/challenges/miner.pub
    DEPENDS blockchain)

add_custom_target("valgrind_blockchain_attack_miner"
    valgrind ${VALGRIND_ARGUMENTS}
    $<TARGET_FILE:blockchain>
    $<TARGET_FILE:blockchain>
    deanonymize_miner
    ${CMAKE_CURRENT_SOURCE_DIR}/challenges/blockchain
    ${CMAKE_CURRENT_SOURCE_DIR}/challenges/miner.pub
    DEPENDS blockchain)

add_custom_target("blockchain_attack_spender"
    $<TARGET_FILE:blockchain>
    deanonymize_spender
    ${CMAKE_CURRENT_SOURCE_DIR}/challenges/blockchain
    ${CMAKE_CURRENT_SOURCE_DIR}/challenges/spender.pub
    DEPENDS blockchain)

add_custom_target("valgrind_blockchain_attack_spender"
    valgrind ${VALGRIND_ARGUMENTS}
    $<TARGET_FILE:blockchain>
    $<TARGET_FILE:blockchain>
    deanonymize_spender
    ${CMAKE_CURRENT_SOURCE_DIR}/challenges/blockchain
    ${CMAKE_CURRENT_SOURCE_DIR}/challenges/spender.pub
    DEPENDS blockchain)

add_subdirectory(tests)
