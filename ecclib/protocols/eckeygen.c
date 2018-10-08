#include "eckeygen.h"

#include "../eccp/eccp.h"
#include "../gfp/gfp.h"
#include "../utils/rand.h"

/**
 * Generate an elliptic curve key pair
 * @param private_key resulting private key
 * @param public_key resulting public key
 * @param param elliptic curve parameters
 */
void eckeygen(gfp_t private_key, eccp_point_affine_t* public_key, eccp_parameters_t* param)
{
  gfp_rand(private_key, &param->order_n_data);

  eccp_jacobian_point_multiply_L2R_DA(public_key, &param->base_point, private_key, param);

  // convert to normal basis such that other party has no problem
  if (param->prime_data.montgomery_domain == 1)
  {
    gfp_montgomery_to_normal(public_key->x, public_key->x, &param->prime_data);
    gfp_montgomery_to_normal(public_key->y, public_key->y, &param->prime_data);
  }
}
