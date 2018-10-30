#include "../ecdh.h"
#include "../secrets.h"

#include "../../utils/tests.h"
#include "../../utils/utils.h"

using util::operator""_x;

START_TEST(ecdh_serialization)
{
  ecdh e(SECP256R1);
  e.set_private_key(secrets::server_ecdh_key);
  const std::vector<uint8_t> data = e.get_data();

  ck_assert_array_split_eq(data,
                           "0499484aed20b35a570d06af3f84194eee23a1af431800c52e0c9356f123ffdc"
                           "0588ae598e18bd9ff892fd3251fe4bea0a5512ac7da7fcb474656f59ab3ad9684e"_x);
}
END_TEST

START_TEST(ecdh_phase_two)
{
  ecdh e1(SECP256R1), e2(SECP256R1);
  e1.set_private_key(secrets::server_ecdh_key);
  e2.set_private_key(secrets::client_ecdh_key);

  const std::vector<uint8_t> data1 = e1.get_shared_secret(e2.get_data());
  const std::vector<uint8_t> data2 = e2.get_shared_secret(e1.get_data());

  ck_assert_array_split_eq(data1,
                           "86e94ce15c700d63c13433f73839bdfb23617c631a149e395aa646ac762da770"_x);
  ck_assert_array_split_eq(data1, data2);
}
END_TEST

int main(int argc, char** argv)
{
  Suite* suite = suite_create("TLS");

  // Test cases for the record layer
  TCase* tcase = tcase_create("ECDH");
  tcase_add_test(tcase, ecdh_serialization);
  tcase_add_test(tcase, ecdh_phase_two);
  suite_add_tcase(suite, tcase);

  SRunner* suite_runner = srunner_create(suite);
  srunner_run(suite_runner, argc, argv);
  int number_failed = srunner_ntests_failed(suite_runner);
  srunner_free(suite_runner);

  return !number_failed ? EXIT_SUCCESS : EXIT_FAILURE;
}
