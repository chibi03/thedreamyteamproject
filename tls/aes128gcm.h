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
  key_storage key_locker;
  std::vector<uint8_t> hash_arg_calc (const std::vector<uint8_t>& additional_data, const std::vector<uint8_t> c) const;
  std::array<uint8_t, 16>  increment(std::array<uint8_t, 16> const &bitstring) const;
  std::vector<uint8_t> ghash(std::array<uint8_t, 16>const &H, std::vector<uint8_t>const &plaintext)const;
  std::vector<uint8_t> gctr(std::array<uint8_t, 16>const &k, std::array<uint8_t, 16>const &c, std::vector<uint8_t>const &plaintext)const;
  std::array<uint8_t, 16> multiply(std::array<uint8_t, 16>const &X, std::array<uint8_t, 16> const &Y)const;

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
};

#endif // AES128GCM_H
