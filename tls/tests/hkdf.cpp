#include "../hkdf.h"
#include "helpers.h"

#include <cstring>
#include <string>
#include <vector>

#include <check.h>

using util::to_hex_string;
using util::operator""_x;

// RFC 5869 Test Case 1
START_TEST(short_input)
{
  const std::vector<uint8_t> ikm  = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"_x;
  const std::vector<uint8_t> salt = "000102030405060708090a0b0c"_x;
  const std::vector<uint8_t> info = "f0f1f2f3f4f5f6f7f8f9"_x;
  const uint8_t l                 = 42;
  const std::vector<uint8_t> okm_expected =
      "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"_x;

  hkdf kdf(salt, ikm);
  const auto okm = kdf.expand(info, l);
  ck_assert_array_split_eq(okm, okm_expected);
}
END_TEST

// RFC 5869 Test Case 2
START_TEST(long_input)
{
  const std::vector<uint8_t> ikm =
      "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f"_x;
  const std::vector<uint8_t> salt =
      "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf"_x;
  const std::vector<uint8_t> info =
      "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"_x;
  const uint8_t l                         = 82;
  const std::vector<uint8_t> okm_expected = "b11e398dc80327a1c8e7f78c596a4934"
                                            "4f012eda2d4efad8a050cc4c19afa97c"
                                            "59045a99cac7827271cb41c65e590e09"
                                            "da3275600c2f09b8367793a9aca3db71"
                                            "cc30c58179ec3e87c14c01d5c1f3434f"
                                            "1d87"_x;

  hkdf kdf(salt, ikm);
  const auto okm = kdf.expand(info, l);
  ck_assert_array_split_eq(okm, okm_expected);
}
END_TEST

// RFC 5869 Test Case 3
START_TEST(zero_input)
{
  const std::vector<uint8_t> ikm          = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"_x;
  const std::vector<uint8_t> salt         = {};
  const std::vector<uint8_t> info         = {};
  const uint8_t l                         = 42;
  const std::vector<uint8_t> okm_expected = "8da4e775a563c18f715f802a063c5a31"
                                            "b8a11f5c5ee1879ec3454e5f3c738d2d"
                                            "9d201395faa4b61a96c8"_x;

  hkdf kdf(salt, ikm);
  const auto okm = kdf.expand(info, l);
  ck_assert_array_split_eq(okm, okm_expected);
}
END_TEST


START_TEST(expand_label)
{
  const std::vector<uint8_t> salt = "0b0b0ba9a9a9a9a9"_x;
  const std::vector<uint8_t> ikm  = "91726354"_x;
  hkdf kdf_early_secret(salt, ikm);

  const std::vector<uint8_t> label   = kdf_early_secret.expand_label("label", "ab"_x, 16);
  ck_assert_array_split_eq(label, "513139538a91572c2d8696a4c83db810"_x);

}
END_TEST

START_TEST(derive_secret)
{
  const std::vector<uint8_t> salt = "0b0b0ba9a9a9a9a9"_x;
  const std::vector<uint8_t> ikm  = "91726354"_x;
  hkdf kdf_early_secret(salt, ikm);

  const std::vector<uint8_t> messages = "012345678901234567890123456789"_x;
  const std::vector<uint8_t> secret   = kdf_early_secret.derive_secret("derived", messages);
  ck_assert_array_split_eq(secret,
                           "6ca9b004d14bae6d3425cf65993e6f9c3c640be3cc1fff502ac78cd39de6e4ba"_x);
}
END_TEST

int main(int argc, char** argv)
{
  Suite* suite = suite_create("HKDF");

  TCase* tcase = tcase_create("RFC 5869");
  tcase_set_timeout(tcase, 0);
  tcase_add_test(tcase, short_input);
  tcase_add_test(tcase, long_input);
  tcase_add_test(tcase, zero_input);
  suite_add_tcase(suite, tcase);

  tcase = tcase_create("TLS");
  tcase_set_timeout(tcase, 0);
  tcase_add_test(tcase, expand_label);
  tcase_add_test(tcase, derive_secret);
  suite_add_tcase(suite, tcase);


  SRunner* suite_runner = srunner_create(suite);
  srunner_run(suite_runner, argc, argv);
  int number_failed = srunner_ntests_failed(suite_runner);
  srunner_free(suite_runner);

  return !number_failed ? EXIT_SUCCESS : EXIT_FAILURE;
}
