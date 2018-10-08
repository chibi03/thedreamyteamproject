#ifndef ECKEYGEN_H_
#define ECKEYGEN_H_

#include "../types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef eccp_point_affine_t ecc_public_key_t;

void eckeygen(gfp_t private_key, eccp_point_affine_t* public_key, eccp_parameters_t* param);

#ifdef __cplusplus
}
#endif

#endif /* ECKEYGEN_H_ */
