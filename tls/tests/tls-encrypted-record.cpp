#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#include "../../utils/io.h"
#include "../aes128gcm.h"
#include "../ascon128.h"
#include "../endian.h"
#include "../hkdf.h"
#include "../tls-aesgcm.h"
#include "../tls-ascon.h"
#include "helpers.h"

namespace
{
  template <class T, class AE>
  int run_test(const std::string& input_fn, const std::string& expected_fn)
  {
    std::ifstream ifs_input(input_fn), ifs_expected(expected_fn);
    if (!ifs_input || !ifs_expected)
    {
      std::cout << "Unable to open input files." << std::endl;
      return -1;
    }

    std::vector<uint8_t> salt, ikm, key_label, nonce_label;
    util::read(ifs_input, salt, true);
    util::read(ifs_input, ikm, true);
    util::read(ifs_input, key_label, true);
    util::read(ifs_input, nonce_label, true);

    hkdf kdf(salt, ikm);

    const auto key_data = kdf.expand(key_label, AE::key_size);
    typename AE::key_storage ascon_key;
    std::copy(key_data.begin(), key_data.end(), ascon_key.begin());

    const auto nonce_data = kdf.expand(nonce_label, AE::nonce_size);

    T tls(ascon_key, nonce_data);
    T tls_decrypt(ascon_key, nonce_data);

    for (std::size_t s = 0; s != 5; ++s)
    {
      std::vector<uint8_t> plaintext;
      util::read(ifs_input, plaintext, true);

      uint8_t expected_type;
      uint16_t expected_length;
      typename T::record expected_record;
      util::read(ifs_expected, expected_type);
      expected_record.header.type = static_cast<content_type>(expected_type);
      util::read(ifs_expected, expected_record.header.version.major);
      util::read(ifs_expected, expected_record.header.version.minor);
      util::read(ifs_expected, expected_length);
      expected_record.header.length = expected_length;
      util::read(ifs_expected, expected_record.ciphertext, true);

      if (!ifs_input || !ifs_expected)
      {
        std::cout << "Failed to read data." << std::endl;
        return -1;
      }

      const auto actual_record = tls.encrypt(TLS_APPLICATION_DATA, plaintext);
      if (actual_record != expected_record)
      {
        std::cout << "Records do not match." << std::endl;
        return -1;
      }

      std::vector<uint8_t> decrypted_plaintext;
      content_type type;
      if (!tls_decrypt.decrypt(actual_record, decrypted_plaintext, type))
      {
        std::cout << "Decryption failed." << std::endl;
        return -1;
      }

      if (plaintext.size() != decrypted_plaintext.size() ||
          !std::equal(plaintext.begin(), plaintext.end(), decrypted_plaintext.begin()))
      {
        std::cout << "Plaintexts do not match." << std::endl;
        return -1;
      }
    }

    return 0;
  }
} // namespace

int main(int argc, char** argv)
{
  if (argc != 4)
  {
    std::cout << argv[0] << " [ascon|aes128gcm] challenge solution" << std::endl;
    return -1;
  }

  const std::string cipher = argv[1];
  if (cipher == "ascon")
    return run_test<tls13_ascon, ascon128>(argv[2], argv[3]);
  else if (cipher == "aes128gcm")
    return run_test<tls13_aesgcm, aes128gcm>(argv[2], argv[3]);

  std::cout << "invalid cipher: " << cipher << std::endl;
  return -1;
}
