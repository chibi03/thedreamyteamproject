#include "commitment.h"
#include "ecclib-glue.h"

#include "../ecclib/eccp/eccp.h"
#include "../ecclib/gfp/gfp.h"
#include "../ecclib/utils/rand.h"

namespace blockchain
{
  ac_co ac_generate(const rs_public_key& pk, uint32_t amount)
  {
    const auto param   = &secp256_params;
    const auto order_n = &secp256_params.order_n_data;
    const gfp_t famount{amount, 0};

    ac_commitment c;
    ac_opening o{pk, {0}};
    gfp_rand(o.o, order_n);

    // g^r pk^amount
    eccp_point_affine_t a, tmp = to_montgomery(pk.y);
    eccp_jacobian_point_multiply_L2R_DA(&a, &param->base_point, o.o, param);
    eccp_jacobian_point_multiply_L2R_DA(&c.c, &tmp, famount, param);
    eccp_affine_point_add(&c.c, &a, &c.c, param);
    c.c = from_montomery(c.c);

    return std::make_pair(c, o);
  }


  bool ac_verify(const ac_co& co, uint32_t amount)
  {
    const auto param = &secp256_params;
    const gfp_t famount{amount, 0};

    // g^r pk^amount
    eccp_point_affine_t a, check_c = to_montgomery(co.second.pk.y);
    eccp_jacobian_point_multiply_L2R_DA(&a, &param->base_point, co.second.o, param);
    eccp_jacobian_point_multiply_L2R_DA(&check_c, &check_c, famount, param);
    eccp_affine_point_add(&check_c, &a, &check_c, param);

    return from_montomery(check_c) == co.first.c;
  }

  ac_proof ac_generate_proof(const ac_co& co, uint32_t amount, const rs_ring& ring)
  {
    const auto param = &secp256_params;
    const auto prime = &secp256_params.order_n_data;

    const rs_public_key& public_key = co.second.pk;

    gfp_t famount{amount, 0};
    gfp_gen_negate(famount, famount, prime);

    const eccp_point_affine_t tmp2 = to_montgomery(co.first.c);

    // H'(A_1 || A_2 || ...)
    hasher_Zq hash_Zq;
    ac_proof proof;
    gfp_t ri, ci{0};
    auto key_it = ring.end();
    for (auto it = ring.begin(); it != ring.end(); ++it)
    {
      rs_signature::challenge_response cr;
      if (it->y != public_key.y)
      {
        gfp_rand(cr.c, prime);
        gfp_rand(cr.t, prime);

        eccp_point_affine_t a, tmp = to_montgomery(it->y);
        // g^{t_j} (C pk_j^{-amount})^{c_j}
        eccp_jacobian_point_multiply_L2R_DA(&a, &param->base_point, cr.t, param);
        eccp_jacobian_point_multiply_L2R_DA(&tmp, &tmp, famount, param);
        eccp_affine_point_add(&tmp, &tmp, &tmp2, param);
        eccp_jacobian_point_multiply_L2R_DA(&tmp, &tmp, cr.c, param);
        eccp_affine_point_add(&a, &a, &tmp, param);
        hash_Zq.update(from_montomery(a));

        gfp_gen_subtract(ci, ci, cr.c, prime);
      }
      else
      {
        key_it = it;
        gfp_rand(ri, prime);

        eccp_point_affine_t a;
        // g^{r_i}
        eccp_jacobian_point_multiply_L2R_DA(&a, &param->base_point, ri, param);
        hash_Zq.update(from_montomery(a));
      }
      proof.cts.emplace_back(cr);
    }

    if (key_it == ring.end())
      throw std::invalid_argument("key not contained in ring");

    auto& cti = proof.cts[std::distance(ring.begin(), key_it)];

    const auto c = hash_Zq.digest();
    gfp_gen_add(cti.c, ci, c.d, prime);

    // r_i - c_i * x_i
    gfp_t tmp;
    gfp_normal_to_montgomery(tmp, co.second.o, prime);
    gfp_normal_to_montgomery(ci, cti.c, prime);
    gfp_mont_multiply(tmp, ci, tmp, prime);
    gfp_montgomery_to_normal(tmp, tmp, prime);
    gfp_gen_subtract(cti.t, ri, tmp, prime);

    return proof;
  }

  bool ac_verify_proof(const ac_commitment& com, uint32_t amount, const rs_ring& ring,
                       const ac_proof& proof)
  {
    if (ring.size() != proof.cts.size())
      return false;

    const auto param = &secp256_params;
    const auto prime = &secp256_params.order_n_data;

    hasher_Zq hash_Zq;
    auto it = ring.begin();

    const eccp_point_affine_t tmp2 = to_montgomery(com.c);

    gfp_t famount{amount, 0};
    gfp_gen_negate(famount, famount, prime);

    gfp_t c{0};
    for (const auto& cr : proof.cts)
    {
      eccp_point_affine_t a, tmp = to_montgomery(it->y);
      // g^{t_j} (C pk_j^{-amount})^{c_j}
      eccp_jacobian_point_multiply_L2R_DA(&a, &param->base_point, cr.t, param);
      eccp_jacobian_point_multiply_L2R_DA(&tmp, &tmp, famount, param);
      eccp_affine_point_add(&tmp, &tmp, &tmp2, param);
      eccp_jacobian_point_multiply_L2R_DA(&tmp, &tmp, cr.c, param);
      eccp_affine_point_add(&a, &a, &tmp, param);
      hash_Zq.update(from_montomery(a));

      gfp_gen_add(c, c, cr.c, prime);
      ++it;
    }

    const auto check_c = hash_Zq.digest();
    return bigint_compare_var(c, check_c.d, prime->words) == 0;
  }
} // namespace blockchain
