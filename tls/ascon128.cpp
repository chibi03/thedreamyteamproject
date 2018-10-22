#include "ascon128.h"
#include "../ascon/crypto_aead.h"
 
ascon128::ascon128(){
/// \todo Initialize with an all 0 key.
	key_storage zero_key;
	for (unsigned int i = 0; i < sizeof(zero_key[0]); i++) {
		zero_key[i] = 0;
	}
	set_key(zero_key);
}

ascon128::ascon128(const key_storage& key)
{
  /// \todo Initialize with given key.
	set_key(key);
}

void ascon128::set_key(const key_storage& key)
{
  /// \todo Reset key
	this->key = key;
}

bool ascon128::encrypt(std::vector<uint8_t>& ciphertext, const std::vector<uint8_t>& plaintext,
                       const std::vector<uint8_t>& nonce_data,
                       const std::vector<uint8_t>& additional_data) const
{

	/// \todo Encrypt data using Ascon with the given nonce and additional data.
	unsigned long long c_sz;
	bool r=crypto_aead_encrypt(ciphertext.data(), &c_sz, plaintext.data(), plaintext.size(), additional_data.data(), additional_size, 0, nonce_data.data(), key.data()) == 0 ? false : true;

  return r;
}

bool ascon128::decrypt(std::vector<uint8_t>& plaintext, const std::vector<uint8_t>& ciphertext,
                       const std::vector<uint8_t>& nonce_data,
                       const std::vector<uint8_t>& additional_data) const
{
  /// \todo Decrypt ciphertext using Ascon with the given nonce and additional
  /// data.
	unsigned long long p_sz;

	bool r = crypto_aead_decrypt(plaintext.data(), &p_sz, 0, ciphertext.data(), ciphertext.size(), additional_data.data(), additional_size, nonce_data.data(), key.data()) == 0 ? false : true;
  return r;
}
