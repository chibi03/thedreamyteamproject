#ifndef BI_GEN_H_
#define BI_GEN_H_

#include "../types.h"

#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

/** test if a big integer is even */
#define BIGINT_IS_EVEN(a) ((a[0] & 1) == 0)
/** test if a big integer is odd */
#define BIGINT_IS_ODD(a) ((a[0] & 1) == 1)

int bigint_add_var(uint_t* res, const uint_t* a, const uint_t* b, const int length);
int bigint_add_carry_var(uint_t* res, const uint_t* a, const uint_t* b, const int length,
                         const int carry);
int bigint_subtract_var(uint_t* res, const uint_t* a, const uint_t* b, const int length);
int bigint_subtract_carry_var(uint_t* res, const uint_t* a, const uint_t* b, const int length,
                              const int carry);
void bigint_shift_left_var(uint_t* res, const uint_t* a, const int left, const int length);
void bigint_shift_right_var(uint_t* res, const uint_t* a, const int right, const int length);
void bigint_shift_right_one_var(uint_t* res, const uint_t* a, const int length);
int bigint_compare_var(const uint_t* a, const uint_t* b, const int length);
int bigint_is_zero_var(const uint_t* a, const int length);
int bigint_is_one_var(const uint_t* a, const int length);
void bigint_multiply_var(uint_t* result, const uint_t* a, const uint_t* b, const int length_a,
                         const int length_b);
void bigint_set_bit_var(uint_t* a, const int bit, const int value, const int length);
int bigint_test_bit_var(const uint_t* a, const int bit, const int length);
int bigint_get_msb_var(const uint_t* a, const int length);
uint8_t bigint_get_byte_var(const uint_t* a, const int length, const int index);
void bigint_set_byte_var(uint_t* a, const int length, const int index, const uint8_t value);
void bigint_divide_simple_var(uint_t* Q, uint_t* R, const uint_t* N, const uint_t* D,
                              const int words);
void bigint_extended_euclidean_var(bigint_t g, bigint_t x, bigint_t y, const bigint_t a,
                                   const bigint_t b, const int words);

#define bigint_copy_var(dest, source, length) memcpy(dest, source, length * sizeof(uint_t))
#define bigint_clear_var(dest, length) memset(dest, 0, length * sizeof(uint_t))

extern const gfp_t bigint_one;
extern const gfp_t bigint_zero;

#ifdef __cplusplus
}
#endif

#endif /* BI_GEN_H_ */
