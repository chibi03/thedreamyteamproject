#include "ecdh.h"

#include "../ecclib/gfp/gfp.h"
#include "../ecclib/protocols/ecdh.h"
#include "../ecclib/protocols/eckeygen.h"
#include "../ecclib/utils/param.h"
#include "../ecclib/utils/rand.h"
#include "random.h"

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
  return {};
}

std::vector<uint8_t> ecdh::get_shared_secret(const std::vector<uint8_t>& other_party_data) const
{
  /// \todo Decode second public key and run phase 2 of ECDH. Return the shared secret.
  return {};
}
