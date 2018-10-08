#ifndef ECCP_AFFINE_H_
#define ECCP_AFFINE_H_

#include "../types.h"

#ifdef __cplusplus
extern "C" {
#endif

void eccp_affine_point_clear(eccp_point_affine_t* A);

int eccp_affine_point_is_valid(const eccp_point_affine_t* A, const eccp_parameters_t* param);

int eccp_affine_point_compare(const eccp_point_affine_t* A, const eccp_point_affine_t* B,
                              const eccp_parameters_t* param);

void eccp_affine_point_copy(eccp_point_affine_t* dest, const eccp_point_affine_t* src,
                            const eccp_parameters_t* param);

void eccp_affine_point_add(eccp_point_affine_t* res, const eccp_point_affine_t* A,
                           const eccp_point_affine_t* B, const eccp_parameters_t* param);
void eccp_affine_point_double(eccp_point_affine_t* res, const eccp_point_affine_t* A,
                              const eccp_parameters_t* param);
void eccp_affine_point_negate(eccp_point_affine_t* res, const eccp_point_affine_t* P,
                              const eccp_parameters_t* param);

#ifdef __cplusplus
}
#endif

#endif /* ECCP_AFFINE_H_ */
