#ifndef ECDH_H_
#define ECDH_H_

#include "../types.h"

#ifdef __cplusplus
extern "C"
{
#endif

  void ecdh_phase_one(eccp_point_affine_t* res, const gfp_t scalar, const eccp_parameters_t* param);
  void ecdh_phase_two(eccp_point_affine_t* res, const gfp_t scalar,
                      eccp_point_affine_t* other_party_point, const eccp_parameters_t* param);

#ifdef __cplusplus
}
#endif

#endif /* ECDH_H_ */
