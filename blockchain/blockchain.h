#ifndef BLOCKCHAIN_BLOCKCHAIN_H
#define BLOCKCHAIN_BLOCKCHAIN_H

#include "transaction.h"

#include <cmath>
#include <map>
#include <set>
#include <vector>

namespace blockchain
{
  /// Blockchain for KUcoin.
  class block_chain
  {
  private:
        std::vector<full_block> blocks;
        sha2::digest_storage block_hash;
        bool verify_root_hash(const full_block& fb);
        std::array<uint8_t, 32UL> null_hash = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};

  public:
    /// Compute the difficulty based on the number of blocks.
    ///
    /// @param number_of_blocks current number of blocks in the chain
    /// @return current difficulty
    static constexpr std::size_t difficulty(std::size_t number_of_blocks)
    {
      return static_cast<std::size_t>(std::log(number_of_blocks + 1) / std::log(100)) + 1;
    }

    /// Verify the block header, i.e. checks if the block hash solves the hash puzzle and if the
    /// pointer to previous block is set up correctly.
    ///
    /// @param fb a block to check
    /// @returns true if the block header is valid, false otherwise
    bool verify_block_header(const full_block& fb);

    //// Verify if an transaction input referencing a transaction output is valid, i.e. that the
    /// ring signature and the proof verifies.
    ///
    /// @param to the referenced transaction output
    /// @param ti transaction input to verify
    /// @param true if the transaction input is valid, false otherwise
    bool verify_transaction(const transaction_output& to, const transaction_input& ti);

    /// Add a block to the block chain with the given transactions and the reward
    /// transaction. In case the block is invalid, false is returned.
    ///
    /// Valid blocks are:
    /// - previous matches the hash of the previous block
    /// - if the block is the first block, previous must be all zeroes
    /// - root must be the root hash for the Merkle tree with reward
    ///   and all transactions in the same order as they appear in transactions
    /// - reward transactions have empty inputs and exactly one output
    /// - the output of reward transactions may not exeed 100
    /// - all other transactions need to be valid
    /// - unless the block is the first one, the block must consist of at least
    ///   one transaction
    /// - the block hash needs to solve the hash puzzle
    ///
    /// Valid transactions are:
    /// - The hash in transaction input must refer to valid transactions recorded
    ///   in any previous block.
    /// - The output index in the transaction input must refer to a valid output
    ///   in the referenced transaction.
    /// - The (hash,index) pair must be unique.
    /// - The ring signature must be a valid signature for (hash, index)
    ///   matching the ring in the referenced output.
    /// - The proof must be a valid proof for the the commitment in the
    ///   referenced output.
    /// - Each amount in output needs to be positive.
    /// - The total amount of all outputs must match the total amount of all
    ///   inputs.
    ///
    /// @param fb the block to process
    /// @return true if the block is valid and was added to the blockchain, false
    /// otherwise
    bool add_block(const full_block& fb);

    /// Access the information on the i-th block.
    ///
    /// @param index of the block
    /// @return return full information of the given block
    const full_block& operator[](std::size_t index) const;

    /// Lookup a transaction output based on a transaction hash and the output index.
    ///
    /// @param hash transaction hash
    /// @return return transaction output if it exists, nullptr otherwise
    const transaction_output* lookup_output(const digest_storage& hash, const uint8_t index) const;

    /// Return number of stored blocks
    ///
    /// @return number of stored blocks
    std::size_t size() const;
  };

  /// Read a blockchain from a file and add all blocks.
  ///
  /// @param bc destination block chain
  /// @param filename path to the block chain
  /// @param true if all blocks from the file could be added to the blckchain
  bool read_blockchain(block_chain& bc, const std::string& filename);
} // namespace blockchain

#endif
