#ifndef PARAM_H_
#define PARAM_H_

#include "../types.h"

#ifdef __cplusplus
extern "C" {
#endif

void param_load(eccp_parameters_t* param, const curve_type_t type);

#ifdef __cplusplus
}
#endif

#endif /* PARAM_H_ */
