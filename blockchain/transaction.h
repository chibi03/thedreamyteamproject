#ifndef TRANSACTION_H
#define TRANSACTION_H

#include "../tls/sha2.h"
#include "commitment.h"
#include "ring-signature.h"

#include <ctime>
#include <vector>

namespace blockchain
{
  typedef sha2::digest_storage digest_storage;

  /// Represents a transaction input
  ///
  /// It references a previous transaction via its hash and the output index. The
  /// signature must be a valid signature for the redeemed transaction output.
  ///
  /// When hashing transaction inputs, hash transaction_hash || output_index || signature ||
  /// commitment_proof.
  struct transaction_input
  {
    digest_storage transaction_hash;
    uint8_t output_index;
    rs_signature signature;
    ac_proof commitment_proof;
  };

  /// Represents a transaction output
  ///
  /// The ECDSA public key specifies the user that is able to redeem the
  /// transaction. The amount specifies the number of redemable coins.
  ///
  /// When hashing transaction outputs, hash ring || commitment || amount.
  struct transaction_output
  {
    rs_ring ring;
    ac_commitment commitment;
    uint32_t amount;
  };

  /// Represents a transaction
  ///
  /// A transaction consists of inputs and outputs such that:
  /// * the redeemed amount exactly matches the spent amount
  /// * all signatures of the inputs are valid
  /// * inputs do not refer to already redeemed transactions
  ///
  /// When hashing transactions, hash inputs || outputs || timestamp.
  struct transaction
  {
    std::vector<transaction_input> inputs;
    std::vector<transaction_output> outputs;
    std::time_t timestamp;
  };

  /// Header of a block
  ///
  /// It contains the hash of the previos block, contains a seed used to compute
  /// proof of work, and the root hash of the Merkle tree consisting of all
  /// transactions.
  ///
  /// In case the block is the first block, previous must be all zeroes.
  ///
  /// When hashing blocks, hash seed || previous || root_hash.
  struct block_header
  {
    digest_storage seed;
    digest_storage previous;
    digest_storage root_hash;
  };

  /// A full block
  ///
  /// A full block consists of the header, all its transactions and a reward
  /// transaction for the mainer. A block is valid if:
  ///
  /// * The transaction reward is non-zero and less than or equal 100.
  /// * If it is the first block, it may not contain any transactions.
  /// * If is is not the first block, it must contain transactions.
  /// * The root hash stored in the header must equal the the root hash of the
  ///   Merkle tree consisting of hash(reward), hash(transaction_1),
  ///   ..., hash(transaction_n)
  struct full_block
  {
    block_header block;
    std::vector<transaction> transactions;
    transaction reward;
  };
} // namespace blockchain

#endif
