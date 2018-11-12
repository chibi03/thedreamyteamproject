#ifndef TLS_CIPHER_H
#define TLS_CIPHER_H

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

#include "basic-ae.h"
#include "tls.h"


/// Abstraction of an AEAD cipher for TLS.
class tls13_cipher
{
public:
  /// TLSCipherText for a generic block cipher consisting of a type, version,
  /// length, the explicit part of the nonce and the encrypted fragment.
  struct record
  {
    record_layer_header header;      /// Record header
    std::vector<uint8_t> ciphertext; /// Ciphertext fragment

    bool operator==(const record& other) const;
    bool operator!=(const record& other) const;
  };

  /// Shorthand for key usage
  typedef basic_ae<16, 16>::key_storage key_storage;

  virtual ~tls13_cipher();

  /// Create an encrypted record for the given plaintext. If successful, this function increments
  /// the internal nonce.
  virtual record encrypt(content_type type, const std::vector<uint8_t>& plaintext) = 0;

  /// Decrypt an encrypted record and store the data in plaintext iff the record
  /// can be decrypted and verified. The content type of the decrypted fragment will be stored in
  /// type. If successful, this function increments the internal nonce.
  virtual bool decrypt(const record& record, std::vector<uint8_t>& plaintext,
                       content_type& type)                                         = 0;

};

#endif // TLS_CIPHER_H
