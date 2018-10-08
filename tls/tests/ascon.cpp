#include "../ascon128.h"
#include "../counter.h"
#include "helpers.h"

#include <algorithm>
#include <check.h>
#include <cstdlib>
#include <string>

using util::operator""_k;
using util::operator""_x;

namespace
{
  const ascon128::key_storage key       = "ffffffffffffffffffffffffffffffff"_k;
  const std::vector<uint8_t> nonce_data = "000102030405060708090a0b0c0d0e0f"_x;

  const std::string plaintext_1 = "abcdefghijklmnoqrstuvwxyz0123456789ABCDEFGHIJKLMNOQRSTUVWXYZ";
  const std::string ad_1        = util::to_hex_string(plaintext_1);
  const std::vector<uint8_t> expected_1 =
      "7fc2b392364bcfe8fbc6417889e1c908beebf6e7378f96065df6616e10eb"
      "c798f1180f8d9188c8e4672558381fb18e4165aea627fcc9f18c8a8f54e7"
      "05615a12a7d5ef18b494b75eeca98879"_x;
} // namespace

START_TEST(encrypt_decrypt)
{
  incrementing_nonce nonce(nonce_data);
  ++nonce;
  const auto n = nonce.nonce();

  ascon128 ascon(key);

  std::vector<uint8_t> plaintext{{'p'}};
  std::vector<uint8_t> ciphertext;
  bool res = ascon.encrypt(ciphertext, plaintext, n);

  ck_assert_uint_eq(res, true);
  ck_assert_uint_eq(ciphertext.size(), plaintext.size() + ascon128::additional_size);

  std::vector<uint8_t> plaintext_2;
  res = ascon.decrypt(plaintext_2, ciphertext, n);

  ck_assert_uint_eq(res, true);
  ck_assert_array_split_eq(plaintext, plaintext_2);
}
END_TEST

START_TEST(encrypt_decrypt_ad)
{
  incrementing_nonce nonce(nonce_data);
  ++nonce;
  const auto n = nonce.nonce();

  ascon128 ascon(key);

  std::vector<uint8_t> plaintext{{'p'}};
  std::vector<uint8_t> ciphertext;
  bool res = ascon.encrypt(ciphertext, plaintext, n, plaintext);
  ck_assert_uint_eq(res, true);
  ck_assert_uint_eq(ciphertext.size(), plaintext.size() + ascon128::additional_size);

  std::vector<uint8_t> plaintext_2;
  res = ascon.decrypt(plaintext_2, ciphertext, n);
  ck_assert_uint_eq(res, false);

  res = ascon.decrypt(plaintext_2, ciphertext, n, plaintext);
  ck_assert_uint_eq(res, true);
  ck_assert_uint_eq(plaintext_2.size(), plaintext.size());
  ck_assert_uint_eq(plaintext[0], plaintext_2[0]);
}
END_TEST

START_TEST(encrypt_decrypt_distinct)
{
  incrementing_nonce nonce(nonce_data);
  ++nonce;

  ascon128 ascon(key);

  std::vector<uint8_t> plaintext{{'p'}};
  std::vector<uint8_t> ciphertext, ciphertext_2;
  bool res = ascon.encrypt(ciphertext, plaintext, nonce.nonce());
  ck_assert_uint_eq(res, true);

  ++nonce;
  res = ascon.encrypt(ciphertext_2, plaintext, nonce.nonce());
  ck_assert_uint_eq(res, true);

  ck_assert_uint_eq(ciphertext.size(), ciphertext_2.size());
  ck_assert_uint_eq(std::equal(ciphertext.begin(), ciphertext.end(), ciphertext_2.begin()), false);
}
END_TEST

START_TEST(encrypt_decrypt_fail)
{
  incrementing_nonce nonce(nonce_data);
  ++nonce;

  ascon128 ascon(key);

  std::vector<uint8_t> plaintext{{'p'}};
  std::vector<uint8_t> ciphertext, ciphertext_2;
  bool res = ascon.encrypt(ciphertext, plaintext, nonce.nonce());
  ck_assert_uint_eq(res, true);
  res = ascon.encrypt(ciphertext_2, plaintext, nonce.nonce());
  ck_assert_uint_eq(res, true);

  ciphertext[0] += 1;
  ciphertext_2[1] += 1;

  res = ascon.decrypt(plaintext, ciphertext, nonce.nonce());
  ck_assert_uint_eq(res, false);

  res = ascon.decrypt(plaintext, ciphertext_2, nonce.nonce());
  ck_assert_uint_eq(res, false);
}
END_TEST

START_TEST(encrypt)
{
  incrementing_nonce nonce(nonce_data);
  ++nonce;

  ascon128 ascon(key);

  std::vector<uint8_t> plaintext{plaintext_1.begin(), plaintext_1.end()};
  std::vector<uint8_t> ad(ad_1.begin(), ad_1.end());
  std::vector<uint8_t> ciphertext;
  const bool res = ascon.encrypt(ciphertext, plaintext, nonce.nonce(), ad);

  ck_assert_uint_eq(res, true);
  ck_assert_array_split_eq(ciphertext, expected_1);
}
END_TEST

int main(int argc, char** argv)
{
  Suite* suite = suite_create("Ascon");

  TCase* tcase = tcase_create("Functionality");
  tcase_add_test(tcase, encrypt_decrypt);
  tcase_add_test(tcase, encrypt_decrypt_ad);
  tcase_add_test(tcase, encrypt_decrypt_distinct);
  tcase_add_test(tcase, encrypt_decrypt_fail);
  suite_add_tcase(suite, tcase);

  tcase = tcase_create("Test vector");
  tcase_add_test(tcase, encrypt);
  suite_add_tcase(suite, tcase);

  SRunner* suite_runner = srunner_create(suite);
  srunner_run(suite_runner, argc, argv);
  int number_failed = srunner_ntests_failed(suite_runner);
  srunner_free(suite_runner);

  return !number_failed ? EXIT_SUCCESS : EXIT_FAILURE;
}
