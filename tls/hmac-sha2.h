#ifndef HMAC_SHA2_H
#define HMAC_SHA2_H

#include "sha2.h"

#include <array>
#include <cstdint>

/// HMAC using SHA2
///
/// This class is intended to be used in the following way:
///
/// * Initialize on construction with the key.
/// * Call update as long as data should be feed to the HMAC. Note that the
///   message can be given in full using one call to update or by calling update
///   multiple times with consecutive parts of the message.
/// * Call digest to get the HMAC.
///
/// In the following example, both instances produce the same HMAC:
/// \code
/// uint8_t data[data_size]; // assume data_size % 2 == 0
/// hmac_sha2 h1(key, key_size), h2(key, key_size);
/// h1.update(data, data_size);
/// h2.update(data, data_size / 2);
/// h2.update(data + data_size / 2, data_size / 2)
/// const auto d1 = h1.digest(), d2 = h2.digest();
/// assert(memcmp(d1.data(), d2.data(), digest_size) == 0);
/// \endcode
class hmac_sha2
{
public:
  /// Size (in bytes) of the digest.
  static constexpr std::size_t digest_size = sha2::digest_size;
  /// Block size.
  static constexpr std::size_t block_size = sha2::block_size;
  /// Array containing the digest.
  typedef std::array<uint8_t, digest_size> digest_storage;

  /// Initialize with key of the given size.
  hmac_sha2(const uint8_t* key, std::size_t keysize);

  /// Feed data to the HMAC.
  void update(const uint8_t* bytes, std::size_t size);
  /// Compute the digest.
  digest_storage digest();
};

#endif
