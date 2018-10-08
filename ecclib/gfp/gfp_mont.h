#ifndef GFP_MONT_H_
#define GFP_MONT_H_

#include "../types.h"

#ifdef __cplusplus
extern "C" {
#endif

void gfp_normal_to_montgomery(gfp_t res, const gfp_t src, const gfp_prime_data_t* prime_data);
void gfp_montgomery_to_normal(gfp_t res, const gfp_t src, const gfp_prime_data_t* prime_data);

void gfp_mont_compute_R(gfp_t res, gfp_prime_data_t* prime_data);
void gfp_mont_compute_R_squared(gfp_t res, gfp_prime_data_t* prime_data);
void gfp_mont_compute_n(gfp_prime_data_t* prime_data);
uint_t gfp_mont_compute_n0(const gfp_prime_data_t* prime_data);
void gfp_mont_inverse(gfp_t result, const gfp_t a, const gfp_prime_data_t* prime_data);
void gfp_mont_exponent(gfp_t res, const gfp_t a, const uint_t* exponent, const int exponent_length,
                       const gfp_prime_data_t* prime_data);

void gfp_mont_multiply(gfp_t res, const gfp_t a, const gfp_t b, const gfp_prime_data_t* prime_data);
void gfp_mult_two_mont(gfp_t res, const gfp_t a, const gfp_t b, const gfp_prime_data_t* prime_data);
void gfp_mont_sqrt(gfp_t res, const gfp_t a, const gfp_prime_data_t* prime_data);
void gfp_mont_square(gfp_t res, const gfp_t a, const gfp_prime_data_t* prime_data);

#ifdef __cplusplus
}
#endif

#endif /* GFP_MONT_H_ */
