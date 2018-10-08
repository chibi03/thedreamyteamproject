#ifndef HELPERS_H
#define HELPERS_H

#include <array>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>

#include "../../utils/tests.h"
#include "../../utils/utils.h"

namespace
{
  template <class H>
  std::string compute_hash(const uint8_t* data, const std::size_t data_size,
                           const std::size_t loops)
  {
    H hash;
    for (std::size_t l = 0; l < loops; ++l)
      hash.update(data, data_size);

    return util::to_hex_string(hash.digest());
  }

  template <class H>
  std::string compute_hmac(const uint8_t* key, std::size_t key_size, const uint8_t* data,
                           const std::size_t data_size)
  {
    H hmac(key, key_size);
    hmac.update(data, data_size);

    return util::to_hex_string(hmac.digest());
  }

  template <class H>
  std::string compute_hmac_i(const uint8_t* key, std::size_t key_size, const uint8_t* data,
                             const std::size_t data_size)
  {
    H hmac(key, key_size);
    for (std::size_t idx = 0; idx != data_size; ++idx, ++data)
      hmac.update(data, 1);

    return util::to_hex_string(hmac.digest());
  }
} // namespace

#endif
