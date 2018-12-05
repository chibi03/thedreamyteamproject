#include "blockchain.h"

#include "../utils/io.h"
#include "io.h"

#include <fstream>
#include <iostream>


namespace blockchain
{
  bool read_blockchain(block_chain& bc, const std::string& filename)
  {
    std::ifstream is(filename);

    std::size_t number_of_blocks = 0;
    util::read(is, number_of_blocks);
    if (!is)
    {
      std::cout << "Failed to read blockchain (number of blocks)!" << std::endl;
      return false;
    }

    while (number_of_blocks--)
    {
      full_block b;
      util::read(is, b);
      if (!is)
      {
        std::cout << "Failed to read blockchain (full block)!" << std::endl;
        return false;
      }

      if (!bc.add_block(b))
      {
        std::cout << "Failed to add block to blockchain!" << std::endl;
        return false;
      }
    }

    return true;
  }


  bool block_chain::verify_block_header(const full_block& fb)
  {
    /// \todo Check if block hash solves puzzle and if the pointer to the previous block is set up
    /// correctly.
    return false;
  }

  bool block_chain::verify_transaction(const transaction_output& to, const transaction_input& ti)
  {
    /// \todo Verify signature and proof sotred in transaction input using given transaction output.
    return false;
  }

  const transaction_output* block_chain::lookup_output(const digest_storage& hash,
                                                       const uint8_t index) const
  {
    /// \todo Lookup a transaction output based on the transaction hash and output index.
    return nullptr;
  }

  bool block_chain::add_block(const full_block& fb)
  {
    /// \todo Add a block to the chain if it is valid.
    return false;
  }

  const full_block& block_chain::operator[](std::size_t index) const
  {
    /// \todo Return the index-th block.
  }

  std::size_t block_chain::size() const
  {
    /// \todo Return the number of blocks stored in the block chain
    return 0;
  }
} // namespace blockchain
