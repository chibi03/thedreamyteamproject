#ifndef BLOCKCHAIN_ECCLIB_GLUE_H
#define BLOCKCHAIN_ECCLIB_GLUE_H

#include "../ecclib/types.h"
#include "../tls/sha2.h"

#include <iterator>
#include <vector>

/// Parameters for the curve used for ECDSA.
extern eccp_parameters_t secp256_params;

bool operator==(const eccp_point_affine_t& lhs, const eccp_point_affine_t& rhs);
bool operator!=(const eccp_point_affine_t& lhs, const eccp_point_affine_t& rhs);
bool operator<(const eccp_point_affine_t& lhs, const eccp_point_affine_t& rhs);

/// Convert a point from "normal" representation to "Montgomery" representation.
eccp_point_affine_t to_montgomery(const eccp_point_affine_t& p);
/// Convert a point from "Montgomery" representation to "normal" representation.
eccp_point_affine_t from_montomery(const eccp_point_affine_t& p);
/// Recover y coordinate for a point given an x coordinate.
bool recover_y(eccp_point_affine_t& p);

class hasher_base
{
protected:
  sha2 hash_;

public:
  void update(const std::vector<uint8_t>& data);

  template <class It>
  void update(It begin, It end, std::random_access_iterator_tag)
  {
    hash_.update(&*begin, std::distance(begin, end));
  }

  template <class It>
  void update(It begin, It end, std::input_iterator_tag)
  {
    for (; begin != end; ++begin)
      update(*begin);
  }

  template <class It>
  void update(It begin, It end)
  {
    update(begin, end, typename std::iterator_traits<It>::iterator_category());
  }

  void update(const eccp_point_affine_t& p);
};

/// hash to elliptic curve group G
class hasher_G : public hasher_base
{
public:
  eccp_point_affine_t digest();
};

/// hash to Z mod q
class hasher_Zq : public hasher_base
{
public:
  struct digest_storage
  {
    gfp_t d;
  };

  digest_storage digest();
};

#endif
