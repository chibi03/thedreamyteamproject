#include "blockchain.h"

#include "../utils/io.h"
#include "io.h"

#include <fstream>
#include <iostream>

#include "merkletree.h"


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
    auto prev = fb.block.previous;
    auto root_hash = fb.block.root_hash;
    //auto seed = sha2::digest_storage(fb.block.seed);

    auto hash = sha2();
    hash.update(prev.data(), sha2::digest_size);
    hash.update(root_hash.data(), sha2::digest_size);

    auto digest = hash.digest();

    for (size_t i = 0; i < difficulty(blocks.size()); i++) {
      if (digest[i] != 0) {
          return false;
      }
    }
    block_hash = digest; //temporary
    return true;
  }

  bool block_chain::verify_transaction(const transaction_output& to, const transaction_input& ti)
  {
    /// \todo Verify signature and proof sotred in transaction input using given transaction output.
    auto hash = ti.transaction_hash;

    bool signature = rs_sha2_verify(to.ring, hash.begin(), hash.end(), ti.signature);
    bool proof = ac_verify_proof(to.commitment, to.amount, to.ring, ti.commitment_proof);

    return signature && proof;
  }

  const transaction_output* block_chain::lookup_output(const digest_storage& hash,
                                                       const uint8_t index) const
  {
    /// \todo Lookup a transaction output based on the transaction hash and output index.
    transaction_input ti;
    transaction_output to;
    for (auto i = 0; i<to.amount; i++)
    {
        if
    }
    return nullptr;
  }

  bool block_chain::add_block(const full_block& fb)
  {
    /// \todo Add a block to the chain if it is valid.

    //no reward
    if (fb.reward.inputs.size() != 0 || fb.reward.outputs.size() != 1){
        return false;
    }

    if (fb.reward.outputs[0].amount == 0 || fb.reward.outputs[0].amount > 100) {
        return false;
    }

    if (blocks.size() == 0)
    {
      if ( fb.transactions.size() != 0 ){
          return false;
      }
      if (fb.block.previous != null_hash ){
          return false;
      }

      blocks.push_back(fb);
      return true;
    }

    else{
      if ( fb.transactions.size() == 0 ){
          return false;
      }

      if (!verify_block_header(fb)){
          return false;
      }

      blocks.push_back(fb);
      return true;
    }

  }

  const full_block& block_chain::operator[](std::size_t index) const
  {
    /// \todo Return the index-th block.
    return blocks[index];
  }

  std::size_t block_chain::size() const
  {
    /// \todo Return the number of blocks stored in the block chain
    return blocks.size();
  }

  bool verify_root_hash(const full_block& fb){

    for(auto i = fb.transactions.begin(); i < fb.transactions.end(); i++) {

    }

  }


} // namespace blockchain
