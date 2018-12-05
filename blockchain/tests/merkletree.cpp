#include "../merkletree.h"
#include "../../utils/tests.h"

#include <vector>

#include <check.h>

using util::operator""_b;
using util::operator""_h;

namespace
{
  sha2::digest_storage hash(const std::vector<uint8_t>& data)
  {
    sha2 h;
    h.update(data.data(), data.size());
    return h.digest();
  }
} // namespace

START_TEST(root_hash_1)
{
  const sha2::digest_storage ha = hash("a"_b);
  std::vector<sha2::digest_storage> hashes{{ha}};

  merkle_tree mt(hashes);
  ck_assert_array_split_eq(mt.root_hash(), ha);
}
END_TEST

START_TEST(root_hash_4)
{
  std::vector<sha2::digest_storage> hashes{{hash("a"_b), hash("b"_b), hash("c"_b), hash("d"_b)}};

  merkle_tree mt(hashes);
  ck_assert_array_split_eq(mt.root_hash(),
                           "14ede5e8e97ad9372327728f5099b95604a39593cac3bd38a343ad76205213e7"_h);
}
END_TEST

START_TEST(root_hash_3)
{
  std::vector<sha2::digest_storage> hashes{{hash("a"_b), hash("b"_b), hash("c"_b)}};

  merkle_tree mt(hashes);
  ck_assert_array_split_eq(mt.root_hash(),
                           "d31a37ef6ac14a2db1470c4316beb5592e6afd4465022339adafda76a18ffabe"_h);
}
END_TEST

START_TEST(proof_4)
{
  std::vector<sha2::digest_storage> hashes{{hash("a"_b), hash("b"_b), hash("c"_b), hash("d"_b)}};

  merkle_tree mt(hashes);

  const auto proof = mt.proof(hash("a"_b));
  ck_assert_uint_eq(proof.size(), 2);
  ck_assert_uint_eq(proof[0].pos, merkle_tree::left);
  ck_assert_uint_eq(proof[1].pos, merkle_tree::left);

  ck_assert_array_split_eq(proof[0].digest,
                           "3e23e8160039594a33894f6564e1b1348bbd7a0088d42c4acb73eeaed59c009d"_h);
  ck_assert_array_split_eq(proof[1].digest,
                           "bffe0b34dba16bc6fac17c08bac55d676cded5a4ade41fe2c9924a5dde8f3e5b"_h);
}
END_TEST

START_TEST(proof_4_2)
{
  std::vector<sha2::digest_storage> hashes{{hash("a"_b), hash("b"_b), hash("c"_b), hash("d"_b)}};

  merkle_tree mt(hashes);
  merkle_tree mt2(mt.root_hash());

  const auto proof = mt.proof(hash("a"_b));
  ck_assert_uint_eq(proof.size(), 2);

  ck_assert_uint_eq(mt.verify(hash("a"_b), proof), true);
  ck_assert_uint_eq(mt2.verify(hash("a"_b), proof), true);

  ck_assert_uint_eq(mt.verify(hash("b"_b), proof), false);
  ck_assert_uint_eq(mt2.verify(hash("b"_b), proof), false);
}
END_TEST

START_TEST(mt_size)
{
  std::vector<sha2::digest_storage> hashes{
      {hash("a"_b), hash("b"_b), hash("c"_b), hash("d"_b), hash("e"_b)}};
  merkle_tree mt_5(hashes);

  const auto proof = mt_5.proof(hash("e"_b));

  hashes.push_back(hashes[4]);
  merkle_tree mt_6(hashes);

  hashes.push_back(hashes[4]);
  merkle_tree mt_7(hashes);

  hashes.push_back(hashes[4]);
  merkle_tree mt_8(hashes);

  ck_assert_array_split_eq(mt_5.root_hash(), mt_6.root_hash());
  ck_assert_array_split_eq(mt_5.root_hash(), mt_7.root_hash());
  ck_assert_array_split_eq(mt_5.root_hash(), mt_8.root_hash());

  ck_assert_uint_eq(mt_5.verify(hash("e"_b), proof), true);
  ck_assert_uint_eq(mt_6.verify(hash("e"_b), proof), true);
  ck_assert_uint_eq(mt_7.verify(hash("e"_b), proof), true);
  ck_assert_uint_eq(mt_8.verify(hash("e"_b), proof), true);
}
END_TEST

int main(int argc, char** argv)
{
  Suite* suite = suite_create("Merkle tree");

  TCase* tcase = tcase_create("Merkle tree");
  tcase_add_test(tcase, root_hash_1);
  tcase_add_test(tcase, root_hash_3);
  tcase_add_test(tcase, root_hash_4);
  tcase_add_test(tcase, proof_4);
  tcase_add_test(tcase, proof_4_2);
  tcase_add_test(tcase, mt_size);
  suite_add_tcase(suite, tcase);

  SRunner* suite_runner = srunner_create(suite);
  srunner_run(suite_runner, argc, argv);
  int number_failed = srunner_ntests_failed(suite_runner);
  srunner_free(suite_runner);

  return !number_failed ? EXIT_SUCCESS : EXIT_FAILURE;
}
