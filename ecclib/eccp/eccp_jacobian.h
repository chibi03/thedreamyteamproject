#ifndef ECCP_JACOBIAN_H_
#define ECCP_JACOBIAN_H_

#include "../types.h"

#ifdef __cplusplus
extern "C" {
#endif

int eccp_jacobian_point_is_valid(const eccp_point_projective_t* a, const eccp_parameters_t* param);

int eccp_jacobian_point_equals(const eccp_point_projective_t* a, const eccp_point_projective_t* b,
                               const eccp_parameters_t* param);
void eccp_jacobian_point_copy(eccp_point_projective_t* dest, const eccp_point_projective_t* src,
                              const eccp_parameters_t* param);

void eccp_jacobian_to_affine(eccp_point_affine_t* res, const eccp_point_projective_t* a,
                             const eccp_parameters_t* param);

void eccp_affine_to_jacobian(eccp_point_projective_t* res, const eccp_point_affine_t* a,
                             const eccp_parameters_t* param);

void eccp_jacobian_point_double(eccp_point_projective_t* res, const eccp_point_projective_t* a,
                                const eccp_parameters_t* param);

void eccp_jacobian_point_add(eccp_point_projective_t* res, const eccp_point_projective_t* a,
                             const eccp_point_projective_t* b, const eccp_parameters_t* param);

void eccp_jacobian_point_add_affine(eccp_point_projective_t* res, const eccp_point_projective_t* a,
                                    const eccp_point_affine_t* b, const eccp_parameters_t* param);

void eccp_jacobian_point_negate(eccp_point_projective_t* res, const eccp_point_projective_t* P,
                                const eccp_parameters_t* param);

void eccp_jacobian_point_multiply_L2R_DA(eccp_point_affine_t* result, const eccp_point_affine_t* P,
                                         const gfp_t scalar, const eccp_parameters_t* param);

void eccp_jacobian_point_multiply_R2L_DA(eccp_point_affine_t* result, const eccp_point_affine_t* P,
                                         const gfp_t scalar, const eccp_parameters_t* param);

void eccp_jacobian_point_multiply_L2R_NAF(eccp_point_affine_t* result, const eccp_point_affine_t* P,
                                          const gfp_t scalar, const eccp_parameters_t* param);

void eccp_jacobian_point_multiply_COMB(eccp_point_affine_t* result,
                                       const eccp_point_affine_t* P_table, const unsigned int width,
                                       const gfp_t scalar, const eccp_parameters_t* param);

void eccp_jacobian_point_multiply_COMB_precompute(eccp_point_affine_t* P_table,
                                                  const eccp_point_affine_t* P, const int width,
                                                  const eccp_parameters_t* param);

#ifdef __cplusplus
}
#endif

#endif /* ECCP_JACOBIAN_H_ */
