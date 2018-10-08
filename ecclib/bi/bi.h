#ifndef BI_H_
#define BI_H_

#include "bi_gen.h"

#ifdef __cplusplus
extern "C" {
#endif

/// use with bigint_t one = BIGINT_ONE;
#define BIGINT_ONE                                                                                 \
  {                                                                                                \
    1,                                                                                             \
  }

#ifdef __cplusplus
}
#endif

#endif /* BI_H_ */
