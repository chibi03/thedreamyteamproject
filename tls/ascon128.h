#ifndef ASCON128_H
#define ASCON128_H

#include <array>
#include <vector>

#include "../ascon/api.h"
#include "basic-ae.h"

/// ASCON with 128 bit keys and 128 bit nonces.
class ascon128 : public basic_ae<CRYPTO_KEYBYTES, CRYPTO_ABYTES>
{
public:
  static constexpr std::size_t nonce_size = CRYPTO_NPUBBYTES;

  /// Initialize Object
  ascon128();
  /// Initialize object with given key.
  ///
  /// \param key 128 bit key
  ascon128(const key_storage& key);

  /// Implementations of required methods from basic_ae:

  void set_key(const key_storage& key) override;
  bool encrypt(std::vector<uint8_t>& ciphertext, const std::vector<uint8_t>& plaintext,
               const std::vector<uint8_t>& nonce_data,
               const std::vector<uint8_t>& additional_data = std::vector<uint8_t>()) const override;
  bool decrypt(std::vector<uint8_t>& plaintext, const std::vector<uint8_t>& ciphertext,
               const std::vector<uint8_t>& nonce_data,
               const std::vector<uint8_t>& additional_data = std::vector<uint8_t>()) const override;
};

#endif
