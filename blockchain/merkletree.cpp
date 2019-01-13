#include "merkletree.h"

merkle_tree::merkle_tree(const std::vector<sha2::digest_storage>& hashes)
{
  /// \todo Initialize Merkle tree using given hashes of values.

    size_t size = hashes.size();
    size_t pow2 = 1;
    while(pow2 < size) {
        pow2 *= 2;
    }
    size_t pads = pow2 - size;

    std::vector<sha2::digest_storage> leafs;
    for (auto i : hashes){
        leafs.push_back(i);
    }
    leafs.insert(leafs.end(), pads, hashes.back());
    tree.push_back(leafs);

    for (num_levels = 0; tree.back().size() != 1 ; num_levels++) {
        auto previous_level = tree.back();
        auto level_size = previous_level.size();
        std::vector<sha2::digest_storage> new_level;
        for(uint8_t i = 0; i < level_size; i += 2){
            auto hash = sha2();
            hash.update(previous_level[i].data(), sha2::digest_size);
            hash.update(previous_level[i+1].data(), sha2::digest_size);
            new_level.push_back(hash.digest());
        }
        tree.push_back(new_level);
    }
    root_hash_ = tree.back().back();
}

merkle_tree::merkle_tree(const sha2::digest_storage& root_hash)
{
  /// \todo Set up Merkle tree using the root hash for verification of proofs.
    root_hash_ = root_hash;
}

std::vector<merkle_tree::proof_node> merkle_tree::proof(const sha2::digest_storage& value) const
{
  /// \todo Generate an inclusion proof for the given value.
    std::vector<merkle_tree::proof_node> proof;
    auto value_in_tree = std::find(tree[0].begin(), tree[0].end(), value);
    auto index = std::distance(tree[0].begin(), value_in_tree);
    auto sibling = 0;
    for (uint8_t level = 0; level != num_levels; level++) { //going through the nodes till reaching root node
        auto node = proof_node();
        if(index % 2 == 0){
            node.pos = left;
            sibling = index+1;
        }
        else{
            node.pos = right;
            sibling = index-1;
        }
        node.digest = tree[level][sibling];
        index /= 2;
        proof.push_back(node);
    }
    return proof;
}

bool merkle_tree::verify(const sha2::digest_storage& value,
                         const std::vector<proof_node>& proof) const
{
  /// \todo Verify if value is included in the Merkle tree using the given proof.
    auto hash_value = value;
    for (auto node = proof.begin(); node != proof.end(); node++ ) {
        auto hash = sha2();
        if (node->pos == left) {
            hash.update(hash_value.data(), sha2::digest_size);
            hash.update(node->digest.data(), sha2::digest_size);
        }
        else {
            hash.update(node->digest.data(), sha2::digest_size);
            hash.update(hash_value.data(), sha2::digest_size);
        }
        hash_value = hash.digest();
    }

    if (hash_value == root_hash_) {
        return true;
    }
    else {
        return false;
    }

}

sha2::digest_storage merkle_tree::root_hash() const
{
  /// \todo Return the root hash of the tree.
  return root_hash_ ;
}
