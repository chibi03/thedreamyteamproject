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
    basic-ae.cpp)

add_library(primitives SHARED ${PRIMITIVES_SOURCES})
target_link_libraries(primitives Boost::boost Boost::system ecc_lib ascon utils)
if(CXX_SUPPORTS_MAES)
  target_compile_options(primitives PRIVATE "-maes")
  target_compile_definitions(primitives PRIVATE -DHAVE_AESNI)
endif()

add_subdirectory(tests)
