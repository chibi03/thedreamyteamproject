#include "aes128gcm.h"
#include "aes/aes128.h"
#include <iostream>
#include <math.h>
#include <cstring>

#include "random.h"

// Take care to program the GCM specific functions in constant time,
// meaning that no conditional branches or conditional loads that depend
// on the key, the nonce or the data are allowed. This means that the
// program flow should be fully independent from the input data.
// Do not make any assumptions on the cache line sizes and stack alignment.


aes128gcm::aes128gcm(){
/// \todo Initialize with an all 0 key.
}

aes128gcm::aes128gcm(const key_storage& key)
{
  /// \todo Initialise with the given key.
}

void aes128gcm::set_key(const key_storage& key)
{
  /// \todo Reset the key.
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

  return true;
}

bool aes128gcm::decrypt(std::vector<uint8_t>& plaintext, const std::vector<uint8_t>& ciphertext,
                        const std::vector<uint8_t>& nonce_data,
                        const std::vector<uint8_t>& additional_data) const
{
  /// \todo Decrypt ciphertext using AEs-GCM with the given nonce and additional data.
  return true;
}
