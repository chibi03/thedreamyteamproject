#ifndef BASIC_HASH_H
#define BASIC_HASH_H

#include <array>
#include <cstddef>
#include <cstdint>

template <std::size_t B, std::size_t D>
struct basic_hash
{
  static constexpr std::size_t block_size  = B;
  static constexpr std::size_t digest_size = D;

  typedef std::array<uint8_t, digest_size> digest_storage;
};

#endif
