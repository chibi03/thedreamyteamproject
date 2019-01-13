#include "../blockchain.h"
#include "../../utils/io.h"
#include "../../utils/tests.h"
#include "../io.h"

#include <fstream>
#include <string>
#include <vector>

#include <check.h>

using namespace blockchain;

// testcase 1: previous hash of first block is not zero
START_TEST(testcase_1)
{
  block_chain bc;
  full_block fb;
  {
    std::ifstream is(SOURCE_DIR "testcase_1");
    util::read(is, fb);
  }

  ck_assert_uint_eq(bc.size(), 0);
  ck_assert_uint_eq(bc.add_block(fb), false);
  ck_assert_uint_eq(bc.size(), 0);
}
END_TEST

// testcase 2: first block has transaction
START_TEST(testcase_2)
{
  block_chain bc;
  full_block fb;
  {
    std::ifstream is(SOURCE_DIR "testcase_2");
    util::read(is, fb);
  }

  ck_assert_uint_eq(bc.size(), 0);
  ck_assert_uint_eq(bc.add_block(fb), false);
  ck_assert_uint_eq(bc.size(), 0);
}
END_TEST

// testcase 3: root hash is wrong
START_TEST(testcase_3)
{
  block_chain bc;
  full_block fb;
  {
    std::ifstream is(SOURCE_DIR "testcase_3");
    util::read(is, fb);
  }

  ck_assert_uint_eq(bc.size(), 0);
  ck_assert_uint_eq(bc.add_block(fb), false);
  ck_assert_uint_eq(bc.size(), 0);
}
END_TEST

// testcase 4: no reward transaction
START_TEST(testcase_4)
{
  block_chain bc;
  full_block fb;
  {
    std::ifstream is(SOURCE_DIR "testcase_4");
    util::read(is, fb);
  }

  ck_assert_uint_eq(bc.size(), 0);
  ck_assert_uint_eq(bc.add_block(fb), false);
  ck_assert_uint_eq(bc.size(), 0);
}
END_TEST

// testcase 5: two reward transactions
START_TEST(testcase_5)
{
  block_chain bc;
  full_block fb;
  {
    std::ifstream is(SOURCE_DIR "testcase_5");
    util::read(is, fb);
  }
  ck_assert_uint_eq(bc.size(), 0);
  ck_assert_uint_eq(bc.add_block(fb), false);
  ck_assert_uint_eq(bc.size(), 0);
}
END_TEST

// testcase 6: reward transactions with one input
START_TEST(testcase_6)
{
  block_chain bc;
  full_block fb;
  {
    std::ifstream is(SOURCE_DIR "testcase_6");
    util::read(is, fb);
  }

  ck_assert_uint_eq(bc.size(), 0);
  ck_assert_uint_eq(bc.add_block(fb), false);
  ck_assert_uint_eq(bc.size(), 0);
}
END_TEST

// testcase 7: too much reward
START_TEST(testcase_7)
{
  block_chain bc;
  full_block fb;
  {
    std::ifstream is(SOURCE_DIR "testcase_7");
    util::read(is, fb);
  }

  ck_assert_uint_eq(bc.size(), 0);
  ck_assert_uint_eq(bc.add_block(fb), false);
  ck_assert_uint_eq(bc.size(), 0);
}
END_TEST

// testcase 8: seed doesn't solve puzzle
START_TEST(testcase_8)
{
  block_chain bc;
  full_block fb;
  {
    std::ifstream is(SOURCE_DIR "testcase_8");
    util::read(is, fb);
  }

  ck_assert_uint_eq(bc.size(), 0);
  ck_assert_uint_eq(bc.add_block(fb), false);
  ck_assert_uint_eq(bc.size(), 0);
}
END_TEST

START_TEST(testcase_gensis)
{
  block_chain bc;
  full_block genesis;
  {
    std::ifstream is(SOURCE_DIR "genesis");
    util::read(is, genesis);
  }

  ck_assert_uint_eq(bc.size(), 0);
  ck_assert_uint_eq(bc.add_block(genesis), true);
  ck_assert_uint_eq(bc.size(), 1);
}
END_TEST

// testcase 9: 0 transactions on second block
START_TEST(testcase_9)
{
  block_chain bc;
  full_block genesis, fb;
  {
    std::ifstream is(SOURCE_DIR "genesis");
    util::read(is, genesis);
  }
  {
    std::ifstream is(SOURCE_DIR "testcase_9");
    util::read(is, fb);
  }

  ck_assert_uint_eq(bc.size(), 0);
  ck_assert_uint_eq(bc.add_block(genesis), true);
  ck_assert_uint_eq(bc.size(), 1);
  ck_assert_uint_eq(bc.add_block(fb), false);
  ck_assert_uint_eq(bc.size(), 1);
}
END_TEST

// testcase 10: wrong previous hash on second block
START_TEST(testcase_10)
{
  block_chain bc;
  full_block genesis, fb;
  {
    std::ifstream is(SOURCE_DIR "genesis");
    util::read(is, genesis);
  }
  {
    std::ifstream is(SOURCE_DIR "testcase_10");
    util::read(is, fb);
  }

  ck_assert_uint_eq(bc.size(), 0);
  ck_assert_uint_eq(bc.add_block(genesis), true);
  ck_assert_uint_eq(bc.size(), 1);
  ck_assert_uint_eq(bc.add_block(fb), false);
  ck_assert_uint_eq(bc.size(), 1);
}
END_TEST

// testcase 11: wrong transaction input hash on second block
START_TEST(testcase_11)
{
  block_chain bc;
  full_block genesis, fb;
  {
    std::ifstream is(SOURCE_DIR "genesis");
    util::read(is, genesis);
  }
  {
    std::ifstream is(SOURCE_DIR "testcase_11");
    util::read(is, fb);
  }

  ck_assert_uint_eq(bc.size(), 0);
  ck_assert_uint_eq(bc.add_block(genesis), true);
  ck_assert_uint_eq(bc.size(), 1);
  ck_assert_uint_eq(bc.add_block(fb), false);
  ck_assert_uint_eq(bc.size(), 1);
}
END_TEST

// testcase 12: wrong transaction input index on second block
START_TEST(testcase_12)
{
  block_chain bc;
  full_block genesis, fb;
  {
    std::ifstream is(SOURCE_DIR "genesis");
    util::read(is, genesis);
  }
  {
    std::ifstream is(SOURCE_DIR "testcase_12");
    util::read(is, fb);
  }

  ck_assert_uint_eq(bc.size(), 0);
  ck_assert_uint_eq(bc.add_block(genesis), true);
  ck_assert_uint_eq(bc.size(), 1);
  ck_assert_uint_eq(bc.add_block(fb), false);
  ck_assert_uint_eq(bc.size(), 1);
}
END_TEST

// testcase 13: double spending on second block
START_TEST(testcase_13)
{
  block_chain bc;
  full_block genesis, fb;
  {
    std::ifstream is(SOURCE_DIR "genesis");
    util::read(is, genesis);
  }
  {
    std::ifstream is(SOURCE_DIR "testcase_13");
    util::read(is, fb);
  }

  ck_assert_uint_eq(bc.size(), 0);
  ck_assert_uint_eq(bc.add_block(genesis), true);
  ck_assert_uint_eq(bc.size(), 1);
  ck_assert_uint_eq(bc.add_block(fb), false);
  ck_assert_uint_eq(bc.size(), 1);
}
END_TEST

// testcase 14: invalid signature in transaction on second block
START_TEST(testcase_14)
{
  block_chain bc;
  full_block genesis, fb;
  {
    std::ifstream is(SOURCE_DIR "genesis");
    util::read(is, genesis);
  }
  {
    std::ifstream is(SOURCE_DIR "testcase_14");
    util::read(is, fb);
  }

  ck_assert_uint_eq(bc.size(), 0);
  ck_assert_uint_eq(bc.add_block(genesis), true);
  ck_assert_uint_eq(bc.size(), 1);
  ck_assert_uint_eq(bc.add_block(fb), false);
  ck_assert_uint_eq(bc.size(), 1);
}
END_TEST

// testcase 15: transaction input amount is less than output amount on second block
START_TEST(testcase_15)
{
  block_chain bc;
  full_block genesis, fb;
  {
    std::ifstream is(SOURCE_DIR "genesis");
    util::read(is, genesis);
  }
  {
    std::ifstream is(SOURCE_DIR "testcase_15");
    util::read(is, fb);
  }

  ck_assert_uint_eq(bc.size(), 0);
  ck_assert_uint_eq(bc.add_block(genesis), true);
  ck_assert_uint_eq(bc.size(), 1);
  ck_assert_uint_eq(bc.add_block(fb), false);
  ck_assert_uint_eq(bc.size(), 1);
}
END_TEST

// testcase 16: transaction input amount is more than output amount on second block
START_TEST(testcase_16)
{
  block_chain bc;
  full_block genesis, fb;
  {
    std::ifstream is(SOURCE_DIR "genesis");
    util::read(is, genesis);
  }
  {
    std::ifstream is(SOURCE_DIR "testcase_16");
    util::read(is, fb);
  }

  ck_assert_uint_eq(bc.size(), 0);
  ck_assert_uint_eq(bc.add_block(genesis), true);
  ck_assert_uint_eq(bc.size(), 1);
  ck_assert_uint_eq(bc.add_block(fb), false);
  ck_assert_uint_eq(bc.size(), 1);
}
END_TEST

// testcase 17: invalid commitment proof
START_TEST(testcase_17)
{
  block_chain bc;
  full_block genesis, fb;
  {
    std::ifstream is(SOURCE_DIR "genesis");
    util::read(is, genesis);
  }
  {
    std::ifstream is(SOURCE_DIR "testcase_17");
    util::read(is, fb);
  }

  ck_assert_uint_eq(bc.size(), 0);
  ck_assert_uint_eq(bc.add_block(genesis), true);
  ck_assert_uint_eq(bc.size(), 1);
  ck_assert_uint_eq(bc.add_block(fb), false);
  ck_assert_uint_eq(bc.size(), 1);
}
END_TEST

START_TEST(testcase_all)
{
  block_chain bc;
  {
    std::ifstream is(SOURCE_DIR "genesis");

    full_block genesis;
    util::read(is, genesis);
    bc.add_block(genesis);
  }

  for (unsigned int i = 1; i < 17; ++i)
  {
    std::ostringstream oss;
    oss << SOURCE_DIR "testcase_" << i;
    std::ifstream is(oss.str());

    full_block fb;
    util::read(is, fb);
    bc.add_block(fb);
  }

  ck_assert_uint_eq(bc.size(), 1);
}
END_TEST

START_TEST(testcase_read_full_blockchain)
{
  block_chain bc;

  const std::string blockchain_filename = SOURCE_DIR "../../challenges/blockchain";
  ck_assert(read_blockchain(bc, blockchain_filename));
}
END_TEST

START_TEST(testcase_lookup_transactions)
{
  block_chain bc;

  const std::string blockchain_filename = SOURCE_DIR "../../challenges/blockchain";
  ck_assert(read_blockchain(bc, blockchain_filename));

  std::ifstream is(SOURCE_DIR "transactions");
  std::size_t size = 0;
  util::read(is, size);
  while (size--)
  {
    sha2::digest_storage hash;
    uint32_t output_index;
    uint32_t amount;

    util::read(is, hash);
    util::read(is, output_index);
    util::read(is, amount);
    ck_assert(!!is);

    const transaction_output* to = bc.lookup_output(hash, output_index);
    ck_assert(to);
    ck_assert_uint_eq(to->amount, amount);
  }

  ck_assert(!!is);
}
END_TEST

int main(int argc, char** argv)
{
  Suite* suite = suite_create("Blockchain");

  TCase* tcase = tcase_create("Invalid Blocks and Transactions");
  tcase_add_test(tcase, testcase_1);
  tcase_add_test(tcase, testcase_2);
  tcase_add_test(tcase, testcase_3);
  tcase_add_test(tcase, testcase_4);
  tcase_add_test(tcase, testcase_5);
  tcase_add_test(tcase, testcase_6);
  tcase_add_test(tcase, testcase_7);
  tcase_add_test(tcase, testcase_8);
  tcase_add_test(tcase, testcase_9);
  tcase_add_test(tcase, testcase_10);
  tcase_add_test(tcase, testcase_11);
  tcase_add_test(tcase, testcase_12);
  tcase_add_test(tcase, testcase_13);
  tcase_add_test(tcase, testcase_14);
  tcase_add_test(tcase, testcase_15);
  tcase_add_test(tcase, testcase_16);
  tcase_add_test(tcase, testcase_17);
  tcase_add_test(tcase, testcase_all);
  suite_add_tcase(suite, tcase);

  tcase = tcase_create("Valid Blocks and Transactions");
  tcase_set_timeout(tcase, 0);
  tcase_add_test(tcase, testcase_gensis);
  tcase_add_test(tcase, testcase_read_full_blockchain);
  tcase_add_test(tcase, testcase_lookup_transactions);
  suite_add_tcase(suite, tcase);

  SRunner* suite_runner = srunner_create(suite);
  srunner_run(suite_runner, argc, argv);
  int number_failed = srunner_ntests_failed(suite_runner);
  srunner_free(suite_runner);

  return !number_failed ? EXIT_SUCCESS : EXIT_FAILURE;
}
