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
    std::vector<uint8_t> buffer;

    union {
    uint8_t key[64];
    uint32_t w[16];
    };
    memcpy(key, &other_party_data, 64);  ///storing value to make conversion to network byte order

    for (int i=0; i<16; ++i){
    w[i] = hton(w[i]);
    }
    for (int i=0; i<64; ++i){
    buffer.push_back(key[i]);
    }

    eccp_point_affine_t newPub;  ///creating and filling new point for x,y coords from other party
    memcpy(&newPub.x, &buffer, 32);
    memcpy(&newPub.y, &buffer[buffer.size() / 2], 32);
    newPub.identity = 0;
    eccp_point_affine_t newnenw;

    ecdh_phase_two(&newnenw, private_key_, &newPub, &param_);

    return buffer;
}

