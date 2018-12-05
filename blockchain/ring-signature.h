#ifndef BLOCKCHAIN_RING_SIGNATURE_H
#define BLOCKCHAIN_RING_SIGNATURE_H

/// Ring signature implementation based on the ring signature from
/// https://eprint.iacr.org/2012/577.pdf, Figure 3.

#include "../ecclib/protocols/eckeygen.h"
#include "../ecclib/types.h"

#include <iosfwd>
#include <set>
#include <utility>
#include <vector>

namespace blockchain
{
  /// Private key of an user
  struct rs_private_key
  {
    gfp_t x;
  };

  /// Public key of an user
  struct rs_public_key
  {
    ecc_public_key_t y;
  };

  /// Set of public keys, i.e. the ring
  typedef std::set<rs_public_key> rs_ring;

  /// A ring signature
  struct rs_signature
  {
    eccp_point_affine_t HmRxi;

    struct challenge_response
    {
      gfp_t c;
      gfp_t t;
    };
    std::vector<challenge_response> cts;
  };

  /// Generate a new key pair
  std::pair<rs_private_key, rs_public_key> rs_generate_key();

  /// Create signature using the given private key and ring for the given data.
  ///
  /// @param private_key private key
  /// @param ring ring
  /// @param message message to sign
  /// @return new signature
  rs_signature rs_sha2_sign(const rs_private_key& private_key, const rs_ring& ring,
                            const std::vector<uint8_t>& message);
  rs_signature rs_sha2_sign(const rs_private_key& private_key, const rs_ring& ring,
                            const uint8_t* begin, const uint8_t* end);

  /// Verify a signature for the given data under the given ring.
  ///
  /// @pqaram ring ring
  /// @param signature signature to verify
  /// @param message message to verify
  /// @return true if the signature is valid.
  bool rs_sha2_verify(const rs_ring& ring, const std::vector<uint8_t>& message,
                      const rs_signature& signature);
  bool rs_sha2_verify(const rs_ring& ring, const uint8_t* begin, const uint8_t* end,
                      const rs_signature& signature);

  bool operator<(const rs_public_key& lhs, const rs_public_key& rhs);
  bool operator==(const rs_public_key& lhs, const rs_public_key& rhs);
} // namespace blockchain

#endif
