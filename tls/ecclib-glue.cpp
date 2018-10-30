#include "../ecclib/utils/rand.h"
#include "random.h"

extern "C"
{
  static uint_t rand_impl(void)
  {
    uint_t v = 0;
    get_random_data(reinterpret_cast<uint8_t*>(&v), sizeof(v));
    return v;
  }
}

void __attribute__((constructor)) init_tls_ecclib_glue()
{
  rand_f = &rand_impl;
}
