#include "../commitment.h"
#include "../../utils/tests.h"
#include "../ring-signature.h"

#include <check.h>
#include <tuple>

using namespace blockchain;

namespace
{
  rs_ring ring, ring2;
  rs_private_key private_key;
  rs_public_key public_key;

  void generate_keys()
  {
    for (unsigned int i = 0; i < 5; ++i)
    {
      rs_public_key pk;
      std::tie(std::ignore, pk) = rs_generate_key();
      ring.emplace(pk);
    }
    ring2 = ring;

    std::tie(private_key, public_key) = rs_generate_key();
    ring.emplace(public_key);
  }
} // namespace

START_TEST(commit_and_open)
{
  const ac_co co = ac_generate(public_key, 32);
  const bool ret = ac_verify(co, 32);
  ck_assert_uint_eq(ret, true);
}
END_TEST

START_TEST(commit_and_proof)
{
  const ac_co co       = ac_generate(public_key, 32);
  const ac_proof proof = ac_generate_proof(co, 32, ring);
  const bool ret       = ac_verify_proof(co.first, 32, ring, proof);
  ck_assert_uint_eq(ret, true);
}
END_TEST

START_TEST(commit_and_proof_invalid_amount)
{
  const ac_co co       = ac_generate(public_key, 32);
  const ac_proof proof = ac_generate_proof(co, 32, ring);
  const bool ret       = ac_verify_proof(co.first, 31, ring, proof);
  ck_assert_uint_eq(ret, false);
}
END_TEST

START_TEST(commit_and_proof_invalid_ring)
{
  const ac_co co       = ac_generate(public_key, 32);
  const ac_proof proof = ac_generate_proof(co, 32, ring);
  const bool ret       = ac_verify_proof(co.first, 32, ring2, proof);
  ck_assert_uint_eq(ret, false);
}
END_TEST

int main(int argc, char** argv)
{
  generate_keys();
  Suite* suite = suite_create("Amount Commitment");

  TCase* tcase = tcase_create("Amount Commitment");
  tcase_add_test(tcase, commit_and_open);
  tcase_add_test(tcase, commit_and_proof);
  tcase_add_test(tcase, commit_and_proof_invalid_amount);
  tcase_add_test(tcase, commit_and_proof_invalid_ring);
  suite_add_tcase(suite, tcase);

  SRunner* suite_runner = srunner_create(suite);
  srunner_run(suite_runner, argc, argv);
  int number_failed = srunner_ntests_failed(suite_runner);
  srunner_free(suite_runner);

  return !number_failed ? EXIT_SUCCESS : EXIT_FAILURE;
}
