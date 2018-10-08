#ifndef BASIC_BLOCK_CIPHER_H
#define BASIC_BLOCK_CIPHER_H

#include <cstddef>
#include <cstdint>
#include <array>

template <std::size_t K, std::size_t B>
struct basic_block_cipher
{
  static constexpr std::size_t block_size = B;
  static constexpr std::size_t key_size   = K;

  typedef std::array<uint8_t, block_size> block_storage;
};

#endif
