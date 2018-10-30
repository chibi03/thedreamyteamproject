#include "tls-aesgcm.h"
#include "endian.h"

#include "aes128gcm.h"

tls13_aesgcm::tls13_aesgcm(const key_storage& key, const std::vector<uint8_t>& nonce_data)
{
  // \todo Initialize with given key
}

tls13_aesgcm::~tls13_aesgcm() {}

tls13_aesgcm::record tls13_aesgcm::encrypt(content_type type, const std::vector<uint8_t>& plaintext)
{
  /// \todo Implement ciphertext record generation for given plaintext.
  return record();
}

bool tls13_aesgcm::decrypt(const record& record, std::vector<uint8_t>& plaintext,
                           content_type& type)
{
  /// \todo Implement decryption for the given record.
  return false;
}
