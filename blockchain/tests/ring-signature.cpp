#include "../ring-signature.h"
#include "../../utils/tests.h"

#include <check.h>
#include <tuple>

using util::operator""_b;
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

START_TEST(sign_and_verify)
{
  const rs_signature sig = rs_sha2_sign(private_key, ring, "abcd"_b);
  const bool ret         = rs_sha2_verify(ring, "abcd"_b, sig);

  ck_assert_uint_eq(ret, true);
}
END_TEST

START_TEST(sign_and_verify_invalid_msg)
{
  const rs_signature sig = rs_sha2_sign(private_key, ring, "abcd"_b);
  const bool ret         = rs_sha2_verify(ring, "abdc"_b, sig);

  ck_assert_uint_eq(ret, false);
}
END_TEST

START_TEST(sign_and_verify_invalid_ring)
{
  const rs_signature sig = rs_sha2_sign(private_key, ring, "abcd"_b);
  const bool ret         = rs_sha2_verify(ring2, "abcd"_b, sig);

  ck_assert_uint_eq(ret, false);
}
END_TEST

int main(int argc, char** argv)
{
  generate_keys();
  Suite* suite = suite_create("Ring Signature");

  TCase* tcase = tcase_create("Ring Signature");
  tcase_add_test(tcase, sign_and_verify);
  tcase_add_test(tcase, sign_and_verify_invalid_msg);
  tcase_add_test(tcase, sign_and_verify_invalid_ring);
  suite_add_tcase(suite, tcase);

  SRunner* suite_runner = srunner_create(suite);
  srunner_run(suite_runner, argc, argv);
  int number_failed = srunner_ntests_failed(suite_runner);
  srunner_free(suite_runner);

  return !number_failed ? EXIT_SUCCESS : EXIT_FAILURE;
}
