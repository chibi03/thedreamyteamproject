#include "ascon128.h"
#include "../ascon/crypto_aead.h"

ascon128::ascon128(){
/// \todo Initialize with an all 0 key.
}

ascon128::ascon128(const key_storage& key)
{
  /// \todo Initialize with given key.
}

void ascon128::set_key(const key_storage& key)
{
  /// \todo Reset key
}

bool ascon128::encrypt(std::vector<uint8_t>& ciphertext, const std::vector<uint8_t>& plaintext,
                       const std::vector<uint8_t>& nonce_data,
                       const std::vector<uint8_t>& additional_data) const
{
  /// \todo Encrypt data using Ascon with the given nonce and additional data.
  return false;
}

bool ascon128::decrypt(std::vector<uint8_t>& plaintext, const std::vector<uint8_t>& ciphertext,
                       const std::vector<uint8_t>& nonce_data,
                       const std::vector<uint8_t>& additional_data) const
{
  /// \todo Decrypt ciphertext using Ascon with the given nonce and additional
  /// data.
  return false;
}
