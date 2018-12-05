#include "io.h"

#include "../ecclib/gfp/gfp.h"
#include "ecclib-glue.h"

#include <iostream>

namespace util
{
  namespace
  {
    void read(std::istream& is, blockchain::rs_signature::challenge_response& ct)
    {
      util::read(is, ct.c);
      util::read(is, ct.t);
    }

    void write(std::ostream& os, const blockchain::rs_signature::challenge_response& ct)
    {
      util::write(os, ct.c);
      util::write(os, ct.t);
    }
  } // namespace
} // namespace util

#include "../utils/io.h"

namespace util
{
  void read(std::istream& is, gfp_t& x)
  {
    for (size_t s = 0; s != WORDS_PER_GFP; ++s)
      read(is, x[s]);
  }

  void write(std::ostream& os, const gfp_t& x)
  {
    for (size_t s = 0; s != WORDS_PER_GFP; ++s)
      write(os, x[s]);
  }

  void read(std::istream& is, eccp_point_affine_t& p)
  {
    uint8_t type;
    read(is, type);
    if (!type)
    {
      p.identity = 1;
      return;
    }
    else if (!(type & 0x02))
    {
      is.setstate(std::ios_base::failbit);
      return;
    }
    p.identity = 0;

    const auto prime = &secp256_params.prime_data;
    read(is, p.x);
    gfp_normal_to_montgomery(p.x, p.x, prime);
    if (!recover_y(p))
    {
      is.setstate(std::ios_base::failbit);
      return;
    }

    p = from_montomery(p);
    if ((p.y[0] & 0x1) ^ (type & 0x1))
      gfp_gen_negate(p.y, p.y, prime);
  }

  void write(std::ostream& os, const eccp_point_affine_t& p)
  {
    if (p.identity)
      write(os, uint8_t(0));
    else
    {
      const uint8_t type = 0x02 | (p.y[0] & 0x01);
      write(os, type);
      write(os, p.x);
    }
  }

  void read(std::istream& is, blockchain::transaction_input& ti)
  {
    read(is, ti.transaction_hash);
    read(is, ti.output_index);
    read(is, ti.signature);
    read(is, ti.commitment_proof);
  }

  void write(std::ostream& os, const blockchain::transaction_input& ti)
  {
    write(os, ti.transaction_hash);
    write(os, ti.output_index);
    write(os, ti.signature);
    write(os, ti.commitment_proof);
  }

  void read(std::istream& is, blockchain::transaction_output& to)
  {
    read(is, to.ring);
    read(is, to.commitment);
    read(is, to.amount);
  }

  void write(std::ostream& os, const blockchain::transaction_output& to)
  {
    write(os, to.ring);
    write(os, to.commitment);
    write(os, to.amount);
  }

  void read(std::istream& is, blockchain::transaction& t)
  {
    read(is, t.inputs, true);
    read(is, t.outputs, true);
    read(is, t.timestamp);
  }

  void write(std::ostream& os, const blockchain::transaction& t)
  {
    write(os, t.inputs, true);
    write(os, t.outputs, true);
    write(os, t.timestamp);
  }

  void read(std::istream& is, blockchain::block_header& b)
  {
    read(is, b.previous);
    read(is, b.seed);
    read(is, b.root_hash);
  }

  void write(std::ostream& os, const blockchain::block_header& b)
  {
    write(os, b.previous);
    write(os, b.seed);
    write(os, b.root_hash);
  }

  void read(std::istream& is, blockchain::full_block& b)
  {
    read(is, b.block);
    read(is, b.transactions, true);
    read(is, b.reward);
  }

  void write(std::ostream& os, const blockchain::full_block& b)
  {
    write(os, b.block);
    write(os, b.transactions, true);
    write(os, b.reward);
  }

  void read(std::istream& is, blockchain::rs_private_key& key)
  {
    util::read(is, key.x);
  }
  void write(std::ostream& os, const blockchain::rs_private_key& key)
  {
    util::write(os, key.x);
  }

  void read(std::istream& is, blockchain::rs_public_key& key)
  {
    util::read(is, key.y);
  }

  void write(std::ostream& os, const blockchain::rs_public_key& key)
  {
    util::write(os, key.y);
  }

  void read(std::istream& is, blockchain::rs_signature& signature)
  {
    util::read(is, signature.HmRxi);
    uint16_t s;
    util::read(is, s);
    signature.cts.resize(s);
    for (auto& ct : signature.cts)
      read(is, ct);
  }

  void write(std::ostream& os, const blockchain::rs_signature& signature)
  {
    util::write(os, signature.HmRxi);
    util::write<uint16_t>(os, signature.cts.size());
    for (const auto& ct : signature.cts)
      write(os, ct);
  }

  void read(std::istream& is, blockchain::rs_ring& ring)
  {
    uint16_t s;
    util::read(is, s);
    while (s--)
    {
      blockchain::rs_public_key pk;
      read(is, pk);
      ring.emplace(pk);
    }
  }

  void write(std::ostream& os, const blockchain::rs_ring& ring)
  {
    util::write<uint16_t>(os, ring.size());
    for (const auto& pk : ring)
      write(os, pk);
  }

  void read(std::istream& is, blockchain::ac_commitment& com)
  {
    read(is, com.c);
  }

  void write(std::ostream& os, const blockchain::ac_commitment& com)
  {
    write(os, com.c);
  }

  void read(std::istream& is, blockchain::ac_proof& proof)
  {
    read(is, proof.cts, true);
  }

  void write(std::ostream& os, const blockchain::ac_proof& proof)
  {
    write(os, proof.cts, true);
  }
} // namespace util
