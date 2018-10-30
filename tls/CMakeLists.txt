check_cxx_compiler_flag(-maes CXX_SUPPORTS_MAES)

set(PRIMITIVES_SOURCES
    aes/aes128.cpp
    ascon128.cpp
    aes128gcm.cpp
    counter.cpp
    hmac-sha2.cpp
    hkdf.cpp
    random.cpp
    sha2.cpp
    basic-ae.cpp
    tls-server.cpp
    tls-ascon.cpp
    tls-aesgcm.cpp
    tls-record-layer.cpp
    tls-handshake-client.cpp
    tls-handshake-server.cpp
    tls.cpp
    tls-cipher.cpp
    ecclib-glue.cpp
    ecdh.cpp
    secrets.cpp)

add_library(primitives SHARED ${PRIMITIVES_SOURCES})
target_link_libraries(primitives Boost::boost Boost::system ecc_lib ascon utils)
if(CXX_SUPPORTS_MAES)
  target_compile_options(primitives PRIVATE "-maes")
  target_compile_definitions(primitives PRIVATE -DHAVE_AESNI)
endif()

add_executable(server server.cpp)
target_link_libraries(server primitives utils)

add_executable(client client.cpp)
target_link_libraries(client primitives utils)

add_subdirectory(tests)
