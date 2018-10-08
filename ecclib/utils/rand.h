#ifndef RAND_H_
#define RAND_H_

#include "../types.h"

#ifdef __cplusplus
extern "C" {
#endif

void gfp_rand(gfp_t dest, const gfp_prime_data_t* prime_data);

/**
 * pointer to rand function
 * @return the random integer
 */
typedef uint_t (*rand_t)(void);

/**
 * globally used rand function
 */
extern rand_t rand_f;

#ifdef __cplusplus
}
#endif

#endif /* RAND_H_ */
