#include "ecdh.h"

#include "../ecclib/gfp/gfp.h"
#include "../ecclib/protocols/ecdh.h"
#include "../ecclib/protocols/eckeygen.h"
#include "../ecclib/utils/param.h"
#include "../ecclib/utils/rand.h"
#include "random.h"
#include "endian.h"

#include <iostream>

#define param (&param_)

ecdh::ecdh(const curve_type_t type)
{
  // Load curve data
  param_load(&param_, type);
}

void ecdh::generate_key_pair()
{
  // Generate key pair
  eckeygen(private_key_, &public_key_, &param_);
}

void ecdh::set_private_key(const gfp_t private_key)
{
  // Copy private key
  gfp_copy(private_key_, private_key);
  // Compute public key
  ecdh_phase_one(&public_key_, private_key_, &param_);
}

std::vector<uint8_t> ecdh::get_data() const
{
  /// \todo Encode public key.

  union {
    uint8_t key[64];
    uint32_t w[16];
  };
  memcpy(key, &public_key_, 64);
  for (int i=0; i<16; ++i){
    w[i] = ntoh(w[i]);
  }

  std::vector<uint8_t> buffer;
  uint8_t legacy_form = 4;
  buffer.push_back(legacy_form);
  for (int i=0; i<64; ++i){
    buffer.push_back(key[i]);
  }
  return buffer;
}

std::vector<uint8_t> ecdh::get_shared_secret(const std::vector<uint8_t>& other_party_data) const
{
  /// \todo Decode second public key and run phase 2 of ECDH. Return the shared secret.
    eccp_point_affine_t point;
    uint_t word_x, word_y = 0;
    size_t point_size = sizeof(point.x)/ sizeof(point.x[0]);

    for(size_t i = 0; i < point_size; i++) {
        for(int j = 3; j >= 0; j--) {
            auto counter = 1 + (i*4) + (3-j);
            auto add_x = (other_party_data[counter] << (j*8 & 0xFF));
            auto add_y = (other_party_data[counter + (point_size*4)] << (j*8 & 0xFF));
            word_x |= add_x;
            word_y |= add_y;
        }
        point.x[i] = word_x;
        point.y[i] = word_y;
        word_x = word_y = 0;
    }

    point.identity = 0;
    eccp_point_affine_t shared_secret;

    ecdh_phase_two(&shared_secret, private_key_, &point, &param_);

    std::vector<uint8_t> secret;
    for(size_t i = 0; i < point_size; i++) {
        auto double_word = (int)shared_secret.x[i];
        for(int j = sizeof(double_word)-1; j >= 0; j--) {
            secret.push_back((double_word >> j*8) & 0xFF );
        }
    }

    return secret;
}

