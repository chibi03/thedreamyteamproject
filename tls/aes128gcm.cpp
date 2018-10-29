#include "aes128gcm.h"
#include "aes/aes128.h"
#include <iostream>
#include <math.h>

#include "random.h"

// Take care to program the GCM specific functions in constant time,
// meaning that no conditional branches or conditional loads that depend
// on the key, the nonce or the data are allowed. This means that the
// program flow should be fully independent from the input data.
// Do not make any assumptions on the cache line sizes and stack alignment.


aes128gcm::aes128gcm(){
/// \todo Initialize with an all 0 key.
  for(unsigned int i = 0; i < 16; i++) {
    this->key.push_back(0);
  }
  get_random_data(this->random_data.data(), 32);
  this->aes128_memb = aes128(this->key.data());
}

aes128gcm::aes128gcm(const key_storage& key)
{
  /// \todo Initialise with the given key.
  for(auto it = key.begin(); it != key.end(); it++) {
    this->key.push_back(*it);
  }
  get_random_data(this->random_data.data(), 32); 
  this->aes128_memb = aes128(this->key.data());
}

void aes128gcm::set_key(const key_storage& key)
{
  /// \todo Reset the key.
  uint8_t size_diff = this->key.size() - key.size();
  for(unsigned int i = 0; i < size_diff; i++) {
    this->key.push_back(0);
  }
  for(unsigned int i = 0; i < key.size(); i++) {
    this->key[i] = key[i];
  }
  this->aes128_memb.set_key(this->key.data());
}

void aes128gcm::gmult(std::vector<uint8_t>& tag, std::vector<uint8_t>& data) {
//  //TODO: GMULT the last element of the tag with the data and append to the tag vector
}

bool aes128gcm::encrypt(std::vector<uint8_t>& ciphertext, const std::vector<uint8_t>& plaintext,
                        const std::vector<uint8_t>& nonce_data,
                        const std::vector<uint8_t>& additional_data) const
{
  if(plaintext.empty() || nonce_data.empty()) {
    return false;
  }

//  /// \todo Encrypt plaintext using AES-GCM with the given nonce and additional data.
//  uint8_t N = (int)ceil((float)plaintext.size()/(float)128);
//  this->ciphertext.resize(plaintext.size() + additional_data.size());
//
//  // Galois Multiplication
//  // Append each gmult to this->tag
//  // gmult(vector this->tag, vector data_to_mult)
//  gmult(this->tag, additional_data);
//  std::vector<uint8_t> e_counter_zero;
//  this->aes128_memb.encrypt(e_counter_zero, nonce_data);
//
//  // AES GMC
//  for(unsigned int i = 0; i < N; i++) {
//    std::vector sub_plaintext;
//    std::vector sub_ciphertext;
//    // Separate plaintext/ciphertexts into blocks of 128 bits (16 bytes)
//    for(auto p_it = plaintext.begin() + N * 16,
//          auto c_it = ciphertext.begin() + N * 16,
//            uint8_t i = 0; i < 16; p_it++, c_it++, i++) {
//      if(p_it = plaintext.end() || c_it == ciphertext.end()) {
//        break;
//      }
//      sub_plaintext.push_back(*p_it);
//      sub_ciphertext.push_back(*c_it);
//    }
//    // increase counter
//    nonce_data++;
//    // encrypt the counter with our key
//    this->aes128_memb.encrypt(sub_ciphertext, nonce_data);
//    // ciphertext = encrypted_counter XOR plaintext
//    sub_ciphertext ^= sub_plaintext;
//    // tag = collection of ciphertexts XOR with previous tag
//    gmult(this->tag, sub_ciphertext ^ this->tag);
//
//    for(auto c_it = ciphertext.begin() + N * 16,
//          auto tmp_c_it = sub_ciphertext.begin();
//            c_it != ciphertext.end() || tmp_c_it != sub_ciphertext.end();
//              c_it++, tmp_c_it++, i++) {
//      *c_it = *tmp_c_it;
//    }
//  }
//  // gmult last element of tag = hash of concatenated additional_data and ciphertext size
//  std::vector<uint8_t> sizes;
//  sizes.push_back(this->ciphertext.size());
//  sizes.push_back(additional_data.size());
//  gmult(this->tag, tag.back() ^ sizes.data());
//  // last element in tag is (gmult(last_tag_element XOR ciphertext_size)) XOR encrypted_zero_counter
//  this->tag.back() ^= e_counter_zero;

  return true;
}

bool aes128gcm::decrypt(std::vector<uint8_t>& plaintext, const std::vector<uint8_t>& ciphertext,
                        const std::vector<uint8_t>& nonce_data,
                        const std::vector<uint8_t>& additional_data) const
{
  /// \todo Decrypt ciphertext using AEs-GCM with the given nonce and additional data.
  // TODO: Validate encryption with the tag
  bool res = encrypt(plaintext, ciphertext, nonce_data, additional_data);

  return res;
}
