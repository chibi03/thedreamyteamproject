#ifndef GFP_GEN_H_
#define GFP_GEN_H_

#include "../types.h"

#include "../bi/bi.h"

#ifdef __cplusplus
extern "C" {
#endif

void gfp_gen_add(gfp_t res, const gfp_t a, const gfp_t b, const gfp_prime_data_t* prime_data);
void gfp_gen_subtract(gfp_t res, const gfp_t a, const gfp_t b, const gfp_prime_data_t* prime_data);
void gfp_gen_halving(gfp_t res, const gfp_t a, const gfp_prime_data_t* prime_data);
void gfp_gen_negate(gfp_t res, const gfp_t a, const gfp_prime_data_t* prime_data);
void gfp_gen_multiply_div(gfp_t res, const gfp_t a, const gfp_t b,
                          const gfp_prime_data_t* prime_data);
void gfp_reduce(gfp_t a, const gfp_prime_data_t* prime_data);
void gfp_binary_euclidean_inverse(gfp_t result, const gfp_t to_invert,
                                  const gfp_prime_data_t* prime_data);

#ifdef __cplusplus
}
#endif

#endif /* GFP_GEN_H_ */
