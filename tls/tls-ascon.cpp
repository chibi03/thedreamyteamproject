#include "tls-ascon.h"
#include "ascon128.h"
#include "endian.h"

tls13_ascon::tls13_ascon(const key_storage& key, const std::vector<uint8_t>& nonce_data)
{
  // \todo Initialize with given key and nonce
}

tls13_ascon::~tls13_ascon() {}

tls13_ascon::record tls13_ascon::encrypt(content_type type, const std::vector<uint8_t>& plaintext)
{
  /// \todo Implement ciphertext record generation for given plaintext.
  return record();
}

bool tls13_ascon::decrypt(const record& record, std::vector<uint8_t>& plaintext, content_type& type)
{
  /// \todo Implement decryption for the given record.
  return false;
}
