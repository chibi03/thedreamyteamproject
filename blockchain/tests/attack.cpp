#include "../attack.h"
#include "../../tls/sha2.h"
#include "../../utils/io.h"
#include "../../utils/tests.h"
#include "../blockchain.h"
#include "../io.h"
#include "../utils.h"

#include <fstream>
#include <string>

#include <check.h>

using namespace blockchain;

namespace
{
  const std::string blockchain_filename   = SOURCE_DIR "../../challenges/blockchain";
  const std::string spender_filename      = SOURCE_DIR "../../challenges/spender.pub";
  const std::string spender_hash_filename = SOURCE_DIR "spender.hash";
  const std::string miner_filename        = SOURCE_DIR "../../challenges/miner.pub";
  const std::string miner_hash_filename   = SOURCE_DIR "miner.hash";
} // namespace

START_TEST(testcase_verify_spender)
{
  const rs_public_key result = deanonymize_spender(blockchain_filename);
  rs_public_key check_pk;
  {
    std::ifstream is(spender_filename);
    util::read(is, check_pk);

    ck_assert(!!is);
  }

  ck_assert(result == check_pk);
}
END_TEST

START_TEST(testcase_verify_miner)
{
  const rs_public_key result = deanonymize_miner(blockchain_filename);
  rs_public_key check_pk;
  {
    std::ifstream is(miner_filename);
    util::read(is, check_pk);

    ck_assert(!!is);
  }

  ck_assert(result == check_pk);
}
END_TEST

START_TEST(testcase_verify_spender_hash)
{
  rs_public_key check_pk;
  {
    std::ifstream is(spender_filename);
    util::read(is, check_pk);

    ck_assert(!!is);
  }

  sha2 hash;
  hash_update(hash, check_pk);
  const sha2::digest_storage check_digest = hash.digest();

  sha2::digest_storage digest;
  {
    std::ifstream is(spender_hash_filename);
    util::read(is, digest);

    ck_assert(!!is);
  }

  ck_assert_array_split_eq(check_digest, digest);
}
END_TEST

START_TEST(testcase_verify_miner_hash)
{
  rs_public_key check_pk;
  {
    std::ifstream is(miner_filename);
    util::read(is, check_pk);

    ck_assert(!!is);
  }

  sha2 hash;
  hash_update(hash, check_pk);
  const sha2::digest_storage check_digest = hash.digest();

  sha2::digest_storage digest;
  {
    std::ifstream is(miner_hash_filename);
    util::read(is, digest);

    ck_assert(!!is);
  }

  ck_assert_array_split_eq(check_digest, digest);
}
END_TEST

int main(int argc, char** argv)
{
  Suite* suite = suite_create("Attack");

  TCase* tcase = tcase_create("Attack");
  tcase_set_timeout(tcase, 0);
  tcase_add_test(tcase, testcase_verify_spender);
  tcase_add_test(tcase, testcase_verify_miner);
  suite_add_tcase(suite, tcase);

  tcase = tcase_create("Hashes");
  tcase_add_test(tcase, testcase_verify_spender_hash);
  tcase_add_test(tcase, testcase_verify_miner_hash);
  suite_add_tcase(suite, tcase);

  SRunner* suite_runner = srunner_create(suite);
  srunner_run(suite_runner, argc, argv);
  int number_failed = srunner_ntests_failed(suite_runner);
  srunner_free(suite_runner);

  return !number_failed ? EXIT_SUCCESS : EXIT_FAILURE;
}
