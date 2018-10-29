#ifndef AES128GCM_H
#define AES128GCM_H

#include <array>
#include <vector>

#include "aes/aes128.h"
#include "basic-ae.h"

/// AES-GCM with 128 bit keys and 96 bit nonces.
class aes128gcm : public basic_ae<16, 16>
{
private:
  std::vector<uint8_t> key;
  std::vector<uint8_t> plaintext;
  std::vector<uint8_t> ciphertext;
  std::vector<uint8_t> random_data;
  std::vector<uint8_t> tag;
  aes128 aes128_memb;

  void gmult(std::vector<uint8_t> tag, std::vector<uint8_t> data);

public:
  static constexpr std::size_t nonce_size = 12;

  /// Initialize object
  aes128gcm();
  /// Initialize object with given key.
  ///
  /// \param key 128 bit key
  aes128gcm(const key_storage& key);

  /// Implementations of required methods from basic_ae:

  void set_key(const key_storage& key) override;

  bool encrypt(std::vector<uint8_t>& ciphertext, const std::vector<uint8_t>& plaintext,
               const std::vector<uint8_t>& nonce_data,
               const std::vector<uint8_t>& additional_data = std::vector<uint8_t>()) const override;

  bool decrypt(std::vector<uint8_t>& plaintext, const std::vector<uint8_t>& ciphertext,
               const std::vector<uint8_t>& nonce_data,
               const std::vector<uint8_t>& additional_data = std::vector<uint8_t>()) const override;

  void gmult(std::vector<uint8_t>& tag, std::vector<uint8_t>& data);

};

#endif // AES128GCM_H
