#include "attack.h"

#include "../utils/io.h"
#include "ecclib-glue.h"
#include "io.h"
#include "blockchain.h"

#include <fstream>
#include <iostream>


namespace blockchain
{

  rs_public_key deanonymize_spender(const std::string& blockchain_filename)
  {
    std::vector<full_block> bc;
    if (!read_blockchain(bc, blockchain_filename)) {
      return {};
    }

    std::vector<rs_ring> rings;
    std::vector<rs_ring> small_rings;
    std::vector<rs_public_key> susp_ring;
    std::vector<int> times_susp_ring;
    unsigned int average_ring_size;

    // Store the rings from transactions in a vector
    for(unsigned int i = 0; i < bc.block_chain_data.size(); i++) {
      if (bc.block_chain_data[i].transactions.size() > 0) {
        for(unsigned int j = 0; j < bc.block_chain_data[i].transactions.size(); j++){
          for(unsigned int k = 0; k < bc.block_chain_data[i].transactions[j].outputs.size(); k++) {
            rs_ring x_ring = bc.block_chain_data[i].transactions[j].outputs[k].ring;
            rings.push_back(x_ring);
            average_ring_size += x_ring.size();
          }
        }
      }
      if (i == bc.block_chain_data.size() - 1) {
        average_ring_size /= ++i;
      }
    }

    // Check if there is at least 1 ring
    if(!average_ring_size) {
      return {};
    }

    // Get rings whose sizes are smol
    for(unsigned int i = 0; i < rings.size(); i++) {
      if(rings[i].size() < average_ring_size) {
        small_rings.push_back(rings[i]);
      }
    }

    // Create a vector with the public keys of the first ring  
    for(std::set<rs_public_key>::iterator it = small_rings[0].begin(); 
                                              it != small_rings[0].end(); it++){
      susp_ring.push_back(*it);
      times_susp_ring.push_back(0);
    }

    // Count how many times the public_keys from the first ring are repeated in 
    // the rest of the rings
    for(unsigned int i = 0; small_rings.size(); i++) {
      for(std::set<rs_public_key>::iterator it = small_rings[i].begin(); 
                                        it != small_rings[i].end(); it++) {
        for(unsigned int j = 0; j < susp_ring.size(); j++) {
          if(susp_ring[j] == *it) {
            times_susp_ring[j]++;
          }
        }
      }
    }

    // The key repeated the most is the spender we are looking for
    rs_public_key spender_deanonymized = susp_ring[0];
    int largest = times_susp_ring[0];

    for(unsigned int i = 0; i < susp_ring.size(); i++) {
      if(largest < times_susp_ring[i]) {
        largest = times_susp_ring[i];
        spender_deanonymized = susp_ring[i];
      }
    }
    
    // return spender
    return spender_deanonymized;
  }

  rs_public_key deanonymize_miner(const std::string& blockchain_filename)
  {
    /// \todo Deanonymize the miner producing transactions containing incorrectly
    /// computed commitments.
    return {};
  }
} // namespace blockchain
