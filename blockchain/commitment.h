#ifndef BLOCKCHAIN_COMMITMENT_H
#define BLOCKCHAIN_COMMITMENT_H

#include "ring-signature.h"

namespace blockchain
{
  struct ac_commitment
  {
    eccp_point_affine_t c;
  };

  struct ac_opening
  {
    rs_public_key pk;
    gfp_t o;
  };

  using ac_co = std::pair<ac_commitment, ac_opening>;

  struct ac_proof
  {
    std::vector<rs_signature::challenge_response> cts;
  };

  ac_co ac_generate(const rs_public_key& pk, uint32_t amount);
  bool ac_verify(const ac_co& co, uint32_t amount);
  ac_proof ac_generate_proof(const ac_co& co, uint32_t amount, const rs_ring& ring);
  bool ac_verify_proof(const ac_commitment&, uint32_t amount, const rs_ring& ring,
                       const ac_proof& proof);
} // namespace blockchain

#endif
