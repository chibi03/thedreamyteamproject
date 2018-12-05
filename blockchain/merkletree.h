#ifndef MERKLETREE_H
#define MERKLETREE_H

#include "../tls/sha2.h"

#include <vector>


/// A Merkle tree
class merkle_tree
{

public:
  enum position
  {
    left,
    right
  };
  struct proof_node
  {
    sha2::digest_storage digest;
    position pos;
  };

  /// Initialize Merkle tree from digests.
  ///
  /// Given the vector of hashes, builds a Merkle tree where the hashes are
  /// placed in the the leaf nodes.
  ///
  /// @param hashes hashes in the leaf nodes
  merkle_tree(const std::vector<sha2::digest_storage>& hashes);
  /// Initialize Merkle tree from a root hash.
  ///
  /// In this configuration, the Merkle tree can only be used for verification.
  ///
  /// @param root_hash the root hash
  merkle_tree(const sha2::digest_storage& root_hash);

  /// Create a member ship proof for the given digest.
  ///
  /// A proof consists of a sequence of proof_node instances, where each
  /// proof_node declares if the proven value is the left or right input to the
  /// hash function and contains the digest of the sibling.
  ///
  /// @param value digest to proof
  /// @return sequence of proof nodes or an empty sequence of the value is not
  /// contained in the tree
  std::vector<proof_node> proof(const sha2::digest_storage& value) const;
  /// Verify the membership of a given value and its proof against the root hash.
  ///
  /// @param value value to be tested
  /// @param proof proof for the given value
  /// @return true if the value is contained in the tree, i.e. the proof matches
  /// the root hash
  bool verify(const sha2::digest_storage& value, const std::vector<proof_node>& proof) const;

  /// Return root hash of the Merkle tree
  ///
  /// @return root hash
  sha2::digest_storage root_hash() const;

};

#endif
