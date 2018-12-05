#ifndef BLOCKCHAIN_UTILS_H
#define BLOCKCHAIN_UTILS_H

#include "../tls/sha2.h"
#include "transaction.h"
#include <type_traits>

namespace blockchain
{

  template <class T, class = std::enable_if_t<std::is_integral<T>::value>>
  void hash_update(sha2& hash, T v)
  {
    hash.update(reinterpret_cast<const uint8_t*>(&v), sizeof(v));
  }

  template <class T>
  void hash_update(sha2& hash, const std::vector<T>& v)
  {
    for (const auto& t : v)
      hash_update(hash, t);
  }

  template <class It>
  void hash_update(sha2& hash, It begin, It end)
  {
    for (; begin != end; ++begin)
      hash_update(hash, *begin);
  }

  template <class T, size_t S>
  void hash_update(sha2& hash, const std::array<T, S>& v)
  {
    for (const auto& t : v)
      hash_update(hash, t);
  }

  template <size_t S>
  void hash_update(sha2& hash, const std::array<uint8_t, S>& v)
  {
    hash.update(v.data(), S);
  }

  void hash_update(sha2& hash, const gfp_t& v);
  void hash_update(sha2& hash, const rs_public_key& pk);
  void hash_update(sha2& hash, const rs_signature& sig);
  void hash_update(sha2& hash, const ac_commitment& com);
  void hash_update(sha2& hash, const ac_proof& proof);
  void hash_update(sha2& hash, const std::vector<uint8_t>& v);
  void hash_update(sha2& hash, const eccp_point_affine_t& p);
  void hash_update(sha2& hash, const transaction_output& to);
  void hash_update(sha2& hash, const transaction_input& ti);

  digest_storage compute_block_hash(const block_header& b);
  digest_storage compute_transaction_hash(const transaction& t);
} // namespace blockchain

#endif
