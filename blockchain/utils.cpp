#include "utils.h"

#include "../ecclib/eccp/eccp.h"
#include "../ecclib/gfp/gfp.h"
#include "ecclib-glue.h"

namespace blockchain
{
  void hash_update(sha2& hash, const gfp_t& v)
  {
    hash.update(reinterpret_cast<const uint8_t*>(&v[0]), sizeof(v));
  }

  void hash_update(sha2& hash, const std::vector<uint8_t>& v)
  {
    hash.update(v.data(), v.size());
  }

  void hash_update(sha2& hash, const eccp_point_affine_t& p)
  {
    const auto prime = &secp256_params.prime_data;
    if (!p.identity)
    {
      hash.update(reinterpret_cast<const uint8_t*>(&p.x[0]), sizeof(uint_t) * prime->words);
      hash.update(reinterpret_cast<const uint8_t*>(&p.y[0]), sizeof(uint_t) * prime->words);
    }
    else
    {
      const std::vector<uint8_t> tmp(2 * sizeof(uint_t) * prime->words, 0);
      hash_update(hash, tmp);
    }
  }

  void hash_update(sha2& hash, const rs_public_key& pk)
  {
    hash_update(hash, pk.y);
  }

  void hash_update(sha2& hash, const rs_signature::challenge_response& cts)
  {
    hash_update(hash, cts.c);
    hash_update(hash, cts.t);
  }

  void hash_update(sha2& hash, const rs_signature& sig)
  {
    hash_update(hash, sig.HmRxi);
    hash_update(hash, sig.cts);
  }

  void hash_update(sha2& hash, const ac_commitment& com)
  {
    hash_update(hash, com.c);
  }

  void hash_update(sha2& hash, const ac_proof& proof)
  {
    hash_update(hash, proof.cts);
  }

  void hash_update(sha2& hash, const transaction_output& to)
  {
    hash_update(hash, to.ring.begin(), to.ring.end());
    hash_update(hash, to.commitment);
    hash_update(hash, to.amount);
  }

  void hash_update(sha2& hash, const transaction_input& ti)
  {
    hash_update(hash, ti.transaction_hash);
    hash_update(hash, ti.output_index);
    hash_update(hash, ti.signature);
    hash_update(hash, ti.commitment_proof);
  }

  digest_storage compute_block_hash(const block_header& b)
  {
    sha2 hash;
    hash_update(hash, b.seed);
    hash_update(hash, b.previous);
    hash_update(hash, b.root_hash);
    return hash.digest();
  }

  digest_storage compute_transaction_hash(const transaction& t)
  {
    sha2 hash;
    hash_update(hash, t.inputs);
    hash_update(hash, t.outputs);
    hash_update(hash, t.timestamp);
    return hash.digest();
  }
} // namespace blockchain
