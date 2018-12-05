#ifndef BLOCKCHAIN_ATTACK_H
#define BLOCKCHAIN_ATTACK_H

#include "blockchain.h"

namespace blockchain
{
  /// Implements the spender deanonymization attack.
  ///
  /// @param blockchain_filename path to the block chain
  /// @returns public key of the spender
  rs_public_key deanonymize_spender(const std::string& blockchain_filename);

  /// Implements the miner deanonymization attack.
  ///
  /// @param blockchain_filename path to the block chain
  /// @returns public key of the miner
  rs_public_key deanonymize_miner(const std::string& blockchain_filename);
} // namespace blockchain

#endif
