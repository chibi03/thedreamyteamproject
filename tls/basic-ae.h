#ifndef BASIC_AE_H
#define BASIC_AE_H

#include <cstddef>
#include <cstdint>

#include <array>
#include <vector>

/// Basic Authenticated Encryption Cipher
template <std::size_t K, std::size_t A>
class basic_ae
{
public:
  /// Size of the key in bytes
  static constexpr std::size_t key_size = K;
  /// Size of the additional data in bytes
  static constexpr std::size_t additional_size = A;
  /// Key Datatype
  typedef std::array<uint8_t, key_size> key_storage;

  virtual ~basic_ae();

  /// Returns the ciphertext size for some plaintext size
  ///
  /// \param size plaintext size
  /// \return ciphertext size
  static std::size_t ciphertext_size(const std::size_t size);

  /// Returns the plaintext size for some ciphertext size
  ///
  /// \param size ciphertext size
  /// \return plaintext size
  static std::size_t plaintext_size(const std::size_t size);

  /// Sets the #key_ with given input
  /// \param key key value
  virtual void set_key(const key_storage& key) = 0;

  /// Performs authenticated encryption
  /// \param ciphertext output ciphertext
  /// \param plaintext  input plaintext
  /// \param nonce_data input nonce data from pr_nonce
  /// \param additional_data additional data to be used for the tag
  /// \return true if encryption successful, false otherwise
  virtual bool
  encrypt(std::vector<uint8_t>& ciphertext, const std::vector<uint8_t>& plaintext,
          const std::vector<uint8_t>& nonce_data,
          const std::vector<uint8_t>& additional_data = std::vector<uint8_t>()) const = 0;

  /// Performs authenticated encryption
  /// \param ciphertext input ciphertext
  /// \param plaintext  output plaintext
  /// \param nonce_data input nonce data from pr_nonce
  /// \param additional_data additional data which was used for the tag
  /// \return true if decryption successful, false otherwise
  virtual bool
  decrypt(std::vector<uint8_t>& plaintext, const std::vector<uint8_t>& ciphertext,
          const std::vector<uint8_t>& nonce_data,
          const std::vector<uint8_t>& additional_data = std::vector<uint8_t>()) const = 0;

};

extern template class basic_ae<16, 16>;

#endif
