#include "tls-aesgcm.h"
#include "endian.h"

#include "aes128gcm.h"

tls13_aesgcm::tls13_aesgcm(const key_storage& key, const std::vector<uint8_t>& nonce_data)
{
  // \todo Initialize with given key
  key_locker = key;
  nonce = incrementing_nonce(nonce_data);
}

tls13_aesgcm::~tls13_aesgcm() {}

tls13_aesgcm::record tls13_aesgcm::encrypt(content_type type, const std::vector<uint8_t>& plaintext)
{
  /// \todo Implement ciphertext record generation for given plaintext.
  aes128gcm gcm = aes128gcm(key_locker);

  record rec = record();
  rec.header.type = TLS_APPLICATION_DATA;
  rec.header.version = TLSv1_2;

  std::vector<uint8_t> the_input(plaintext), add_data;
  the_input.push_back(type);
  add_data.insert(add_data.end(), {TLS_APPLICATION_DATA, TLSv1_2.major, TLSv1_2.minor});

  size_t ciph_size = basic_ae<16,16>::ciphertext_size(the_input.size());
  const uint16_t size16 = static_cast<uint16_t>(ciph_size);
  add_data.insert(add_data.end(), {((uint8_t*)&size16)[1], ((uint8_t*)&size16)[0]});

  gcm.encrypt(rec.ciphertext, the_input, nonce.nonce(), add_data);
  rec.header.length = (uint16_t)(rec.ciphertext.size());
  ++nonce;

  return rec;
}

bool tls13_aesgcm::decrypt(const record& record, std::vector<uint8_t>& plaintext,
                           content_type& type)
{
  /// \todo Implement decryption for the given record.
  aes128gcm gcm = aes128gcm(key_locker);

  std::vector<uint8_t> ciphtext(record.ciphertext), add_data;
  add_data.insert(add_data.end(), {record.header.type, record.header.version.major, record.header.version.minor});

  size_t ciph_size = record.ciphertext.size();
  const uint16_t size16 = static_cast<uint16_t>(ciph_size);
  add_data.insert(add_data.end(), {((uint8_t*)&size16)[1], ((uint8_t*)&size16)[0]});


  gcm.decrypt(plaintext, ciphtext , nonce.nonce(), add_data);
  type = (content_type) plaintext.back();
  plaintext.pop_back();
  ++nonce;
  return true;
}
