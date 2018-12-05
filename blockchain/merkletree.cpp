#include "merkletree.h"

merkle_tree::merkle_tree(const std::vector<sha2::digest_storage>& hashes)
{
  /// \todo Initialize Merkle tree using given hashes of values.
}

merkle_tree::merkle_tree(const sha2::digest_storage& root_hash)
{
  /// \todo Set up Merkle tree using the root hash for verification of proofs.
}

std::vector<merkle_tree::proof_node> merkle_tree::proof(const sha2::digest_storage& value) const
{
  /// \todo Generate an inclusion proof for the given value.

  return {};
}

bool merkle_tree::verify(const sha2::digest_storage& value,
                         const std::vector<proof_node>& proof) const
{
  /// \todo Verify if value is included in the Merkle tree using the given proof.

  return false;
}

sha2::digest_storage merkle_tree::root_hash() const
{
  /// \todo Return the root hash of the tree.

  return {};
}
