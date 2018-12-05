#include "ecclib-glue.h"

#include "utils.h"

#include "../ecclib/eccp/eccp.h"
#include "../ecclib/gfp/gfp.h"
#include "../ecclib/protocols/ecdsa.h"
#include "../ecclib/utils/param.h"

eccp_parameters_t secp256_params;

void __attribute__((constructor)) init_blockchain_ecclib_glue()
{
  param_load(&secp256_params, SECP256R1);
}

bool operator==(const eccp_point_affine_t& lhs, const eccp_point_affine_t& rhs)
{
  if (lhs.identity != rhs.identity)
    return false;
  if (lhs.identity)
    return true;

  const auto param = &secp256_params;
  return gfp_compare(lhs.x, rhs.x) == 0 && gfp_compare(lhs.y, rhs.y) == 0;
}

bool operator!=(const eccp_point_affine_t& lhs, const eccp_point_affine_t& rhs)
{
  if (lhs.identity != rhs.identity)
    return true;
  if (lhs.identity)
    return false;

  const auto param = &secp256_params;
  return gfp_compare(lhs.x, rhs.x) != 0 || gfp_compare(lhs.y, rhs.y) != 0;
}

bool operator<(const eccp_point_affine_t& lhs, const eccp_point_affine_t& rhs)
{
  if (lhs.identity)
    return false;
  if (rhs.identity)
    return true;

  const auto param = &secp256_params;
  const int x      = gfp_compare(lhs.x, rhs.x);
  if (x < 0)
    return true;
  if (x > 0)
    return false;

  return gfp_compare(lhs.y, rhs.y) < 0;
}

eccp_point_affine_t to_montgomery(const eccp_point_affine_t& p)
{
  if (p.identity)
    return p;

  const auto prime = &secp256_params.prime_data;

  eccp_point_affine_t r;
  gfp_normal_to_montgomery(r.x, p.x, prime);
  gfp_normal_to_montgomery(r.y, p.y, prime);
  r.identity = 0;

  return r;
}

eccp_point_affine_t from_montomery(const eccp_point_affine_t& p)
{
  if (p.identity)
    return p;

  const auto prime = &secp256_params.prime_data;

  eccp_point_affine_t r;
  gfp_montgomery_to_normal(r.x, p.x, prime);
  gfp_montgomery_to_normal(r.y, p.y, prime);
  r.identity = 0;

  return r;
}

bool recover_y(eccp_point_affine_t& t)
{
  const auto param = &secp256_params;
  const auto prime = &secp256_params.prime_data;

  gfp_t left, right;
  gfp_square(left, t.x);
  gfp_multiply(right, t.x, left);
  gfp_multiply(left, t.x, param->param_a);
  gfp_add(right, right, left);
  gfp_add(right, right, param->param_b);
  gfp_mont_sqrt(t.y, right, prime);

  return eccp_affine_point_is_valid(&t, param) == 1;
}

void hasher_base::update(const std::vector<uint8_t>& data)
{
  blockchain::hash_update(hash_, data);
}

void hasher_base::update(const eccp_point_affine_t& p)
{
  blockchain::hash_update(hash_, p);
}

eccp_point_affine_t hasher_G::digest()
{
  const sha2::digest_storage hash = hash_.digest();
  eccp_point_affine_t t;
  t.identity = 0;

  const auto param = &secp256_params;
  const auto prime = &secp256_params.prime_data;

  ecdsa_hash_to_gfp(t.x, hash.data(), hash.size() * 8, prime);
  gfp_normal_to_montgomery(t.x, t.x, prime);
  while (true)
  {
    if (recover_y(t))
      break;

    gfp_add(t.x, t.x, prime->gfp_one);
  }

  return t;
}

hasher_Zq::digest_storage hasher_Zq::digest()
{
  const sha2::digest_storage hash = hash_.digest();

  digest_storage ds{0};
  ecdsa_hash_to_gfp(ds.d, hash.data(), hash.size() * 8, &secp256_params.order_n_data);
  return ds;
}
