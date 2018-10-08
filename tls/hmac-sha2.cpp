#include "hmac-sha2.h"

hmac_sha2::hmac_sha2(const uint8_t* key, std::size_t keysize)
{
  /// \todo Initialze with given key.
}

void hmac_sha2::update(const uint8_t* bytes, std::size_t size)
{
  /// \todo Feed data to HMAC.
}

hmac_sha2::digest_storage hmac_sha2::digest()
{
  /// \todo Finalize HMAC compuation and return computed digest.
  return digest_storage();
}
