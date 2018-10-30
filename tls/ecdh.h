#ifndef ECDH_H
#define ECDH_H

#include "../ecclib/types.h"
#include <vector>

/// Wrapper for ECDH key exchange
class ecdh
{
private:
  eccp_parameters_t param_;
  gfp_t private_key_;
  eccp_point_affine_t public_key_;

public:
  /// Initialize ECDH key exchange
  ecdh(const curve_type_t curve_type);

  /// Create key pair
  void generate_key_pair();
  /// Initialize key pair from private key
  void set_private_key(const gfp_t private_key);

  /// Encode public key.
  std::vector<uint8_t> get_data() const;
  /// Compute shared secret from private key and the second (encoded) public key.
  std::vector<uint8_t> get_shared_secret(const std::vector<uint8_t>& other_party_data) const;
};

#endif
