#ifndef ECDSA_H_
#define ECDSA_H_

#include "../types.h"

#ifdef __cplusplus
extern "C" {
#endif

void ecdsa_sign(ecdsa_signature_t* signature, const gfp_t hash_of_message, const gfp_t private_key,
                const eccp_parameters_t* param);
int ecdsa_is_valid(const ecdsa_signature_t* signature, const gfp_t hash_of_message,
                   const eccp_point_affine_t* public_key, const eccp_parameters_t* param);

void ecdsa_hash_to_gfp(gfp_t element, const uint8_t* hash, const size_t hash_length,
                       const gfp_prime_data_t* prime);

#ifdef __cplusplus
}
#endif

#endif /* ECDSA_H_ */
