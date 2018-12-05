#ifndef BLOCKCHAIN_IO_H
#define BLOCKCHAIN_IO_H

#include "commitment.h"
#include "ring-signature.h"
#include "transaction.h"

#include <iosfwd>

namespace util
{
  void read(std::istream& is, gfp_t& x);
  void write(std::ostream& os, const gfp_t& x);

  void read(std::istream& is, eccp_point_affine_t& pk);
  void write(std::ostream& os, const eccp_point_affine_t& pk);

  void read(std::istream& is, blockchain::transaction_input& ti);
  void write(std::ostream& os, const blockchain::transaction_input& ti);

  void read(std::istream& is, blockchain::transaction_output& to);
  void write(std::ostream& os, const blockchain::transaction_output& to);

  void read(std::istream& is, blockchain::transaction& t);
  void write(std::ostream& os, const blockchain::transaction& t);

  void read(std::istream& is, blockchain::block_header& b);
  void write(std::ostream& os, const blockchain::block_header& b);

  void read(std::istream& is, blockchain::full_block& b);
  void write(std::ostream& os, const blockchain::full_block& b);

  void read(std::istream& is, blockchain::rs_private_key& key);
  void write(std::ostream& os, const blockchain::rs_private_key& key);

  void read(std::istream& is, blockchain::rs_public_key& key);
  void write(std::ostream& os, const blockchain::rs_public_key& key);

  void read(std::istream& is, blockchain::rs_signature& signature);
  void write(std::ostream& os, const blockchain::rs_signature& signature);

  void read(std::istream& is, blockchain::rs_ring& ring);
  void write(std::ostream& os, const blockchain::rs_ring& ring);

  void read(std::istream& is, blockchain::ac_commitment& com);
  void write(std::ostream& os, const blockchain::ac_commitment& com);

  void read(std::istream& is, blockchain::ac_proof& proof);
  void write(std::ostream& os, const blockchain::ac_proof& proof);
} // namespace util

#endif
