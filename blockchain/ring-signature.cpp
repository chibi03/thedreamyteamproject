#include "ring-signature.h"
#include "ecclib-glue.h"

#include "../ecclib/eccp/eccp.h"
#include "../ecclib/gfp/gfp.h"
#include "../ecclib/protocols/ecdsa.h"
#include "../ecclib/utils/rand.h"
#include "../tls/sha2.h"

#include <iostream>
#include <iterator>

namespace blockchain
{
  std::pair<rs_private_key, rs_public_key> rs_generate_key()
  {
    std::pair<rs_private_key, rs_public_key> ret;

    gfp_rand(ret.first.x, &secp256_params.order_n_data);
    eccp_jacobian_point_multiply_L2R_DA(&ret.second.y, &secp256_params.base_point, ret.first.x,
                                        &secp256_params);
    ret.second.y = from_montomery(ret.second.y);

    return ret;
  }

  namespace
  {
    template <class It>
    rs_signature rs_sha2_sign_impl(const rs_private_key& private_key, const rs_ring& ring, It begin,
                                   It end)
    {
      const auto param = &secp256_params;
      const auto prime = &secp256_params.order_n_data;

      rs_public_key public_key;
      eccp_jacobian_point_multiply_L2R_DA(&public_key.y, &secp256_params.base_point, private_key.x,
                                          param);
      public_key.y = from_montomery(public_key.y);

      // H(m||R)
      hasher_G hash_G;
      hash_G.update(begin, end);
      std::for_each(ring.begin(), ring.end(),
                    [&hash_G](const rs_public_key& it) { hash_G.update(it.y); });
      const eccp_point_affine_t HmR = hash_G.digest();

      rs_signature signature;
      eccp_point_affine_t HmRxi;
      // H(m||R)^{x_i}
      eccp_jacobian_point_multiply_L2R_DA(&HmRxi, &HmR, private_key.x, param);
      signature.HmRxi = from_montomery(HmRxi);

      // H'(m||R||H(m||R)^{x_i}||...)
      hasher_Zq hash_Zq;
      hash_Zq.update(begin, end);
      std::for_each(ring.begin(), ring.end(),
                    [&hash_Zq](const rs_public_key& it) { hash_Zq.update(it.y); });
      hash_Zq.update(signature.HmRxi);

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
          // g^{t_j} y_j^{c_j}
          eccp_jacobian_point_multiply_L2R_DA(&a, &param->base_point, cr.t, param);
          eccp_jacobian_point_multiply_L2R_DA(&tmp, &tmp, cr.c, param);
          eccp_affine_point_add(&a, &a, &tmp, param);
          hash_Zq.update(from_montomery(a));

          // H(m||R)^{t_j} (H(m||R)^{x_i})^{c_j}
          eccp_jacobian_point_multiply_L2R_DA(&a, &HmR, cr.t, param);
          eccp_jacobian_point_multiply_L2R_DA(&tmp, &HmRxi, cr.c, param);
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

          // H(m || R)^{r_i}
          eccp_jacobian_point_multiply_L2R_DA(&a, &HmR, ri, param);
          hash_Zq.update(from_montomery(a));
        }
        signature.cts.emplace_back(cr);
      }

      if (key_it == ring.end())
        throw std::invalid_argument("public key is not part of the ring");

      auto& cti = signature.cts[std::distance(ring.begin(), key_it)];

      const auto c = hash_Zq.digest();
      gfp_gen_add(cti.c, ci, c.d, prime);

      // r_i - c_i * x_i
      gfp_t tmp;
      gfp_normal_to_montgomery(tmp, private_key.x, prime);
      gfp_normal_to_montgomery(ci, cti.c, prime);
      gfp_mont_multiply(tmp, ci, tmp, prime);
      gfp_montgomery_to_normal(tmp, tmp, prime);
      gfp_gen_subtract(cti.t, ri, tmp, prime);

      return signature;
    }
  } // namespace

  rs_signature rs_sha2_sign(const rs_private_key& private_key, const rs_ring& ring,
                            const std::vector<uint8_t>& message)
  {
    return rs_sha2_sign_impl(private_key, ring, message.begin(), message.end());
  }

  rs_signature rs_sha2_sign(const rs_private_key& private_key, const rs_ring& ring,
                            const uint8_t* begin, const uint8_t* end)
  {
    return rs_sha2_sign_impl(private_key, ring, begin, end);
  }

  namespace
  {
    template <class It>
    bool rs_sha2_verify_impl(const rs_ring& ring, It begin, It end, const rs_signature& signature)
    {
      if (ring.size() != signature.cts.size())
        return false;

      const auto param = &secp256_params;
      const auto prime = &secp256_params.order_n_data;

      hasher_G hash_G;
      hash_G.update(begin, end);
      std::for_each(ring.begin(), ring.end(),
                    [&hash_G](const rs_public_key& it) { hash_G.update(it.y); });
      const eccp_point_affine_t HmR = hash_G.digest();

      hasher_Zq hash_Zq;
      hash_Zq.update(begin, end);
      std::for_each(ring.begin(), ring.end(),
                    [&hash_Zq](const rs_public_key& it) { hash_Zq.update(it.y); });
      hash_Zq.update(signature.HmRxi);

      auto it = ring.begin();

      const eccp_point_affine_t HmRxi = to_montgomery(signature.HmRxi);
      gfp_t c{0};
      for (const auto& cr : signature.cts)
      {
        eccp_point_affine_t a, tmp = to_montgomery(it->y);
        // g^{t_j} y_j^{c_j}
        eccp_jacobian_point_multiply_L2R_DA(&a, &param->base_point, cr.t, param);
        eccp_jacobian_point_multiply_L2R_DA(&tmp, &tmp, cr.c, param);
        eccp_affine_point_add(&a, &a, &tmp, param);
        hash_Zq.update(from_montomery(a));

        // H(m||R)^{t_j} (H(m||R)^{x_i})^{c_j}
        eccp_jacobian_point_multiply_L2R_DA(&a, &HmR, cr.t, param);
        eccp_jacobian_point_multiply_L2R_DA(&tmp, &HmRxi, cr.c, param);
        eccp_affine_point_add(&a, &a, &tmp, param);
        hash_Zq.update(from_montomery(a));

        gfp_gen_add(c, c, cr.c, prime);
        ++it;
      }

      const auto check_c = hash_Zq.digest();
      return bigint_compare_var(c, check_c.d, prime->words) == 0;
    }
  } // namespace

  bool rs_sha2_verify(const rs_ring& ring, const std::vector<uint8_t>& message,
                      const rs_signature& signature)
  {
    return rs_sha2_verify_impl(ring, message.begin(), message.end(), signature);
  }

  bool rs_sha2_verify(const rs_ring& ring, const uint8_t* begin, const uint8_t* end,
                      const rs_signature& signature)
  {
    return rs_sha2_verify_impl(ring, begin, end, signature);
  }

  bool operator<(const rs_public_key& l, const rs_public_key& r)
  {
    return l.y < r.y;
  }

  bool operator==(const rs_public_key& l, const rs_public_key& r)
  {
    return l.y == r.y;
  }
} // namespace blockchain
