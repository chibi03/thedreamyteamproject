#ifndef SHA2_H
#define SHA2_H

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>

#include "basic-hash.h"

/// SHA2
///
/// This class is intended to be used in the following way:
///
/// * Call update as long as data should be feed to the hash function. Note that
///   the message can be given in full using one call to update or by calling
///   update multiple times with consecutive parts of the message.
/// * Call digest to get the digest.
///
/// In the following example, both instances produce the same digest:
/// \code
/// uint8_t data[data_size]; // assume data_size % 2 == 0
/// sha2 h1, h2;
/// h1.update(data, data_size);
/// h2.update(data, data_size / 2);
/// h2.update(data + data_size / 2, data_size / 2)
/// const auto d1 = h1.digest(), d2 = h2.digest();
/// assert(memcmp(d1.data(), d2.data(), digest_size) == 0);
/// \endcode

class sha2 : private basic_hash<64, 32>
{
public:
  typedef basic_hash<64, 32> base;
  typedef typename base::digest_storage digest_storage;

  using base::block_size;
  using base::digest_size;

private:
  union
  {
    uint32_t b32[block_size / sizeof(uint32_t)];
    uint8_t b8[sizeof(b32)];
  } chunck_;
  union
  {
    uint32_t b32[digest_size / sizeof(uint32_t)];
    uint8_t b8[sizeof(b32)];
  } digest_;
  uint64_t counter_;

  void compress();

public:
  sha2();

  /// Feed data to hash function.
  void update(const uint8_t* data, std::size_t size);
  /// Compute final digest.
  digest_storage digest();

  static std::string name()
  {
    return "SHA256";
  }
};

#endif
