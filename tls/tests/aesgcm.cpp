#include "../../utils/io.h"
#include "../aes128gcm.h"
#include "../counter.h"
#include "helpers.h"

#include <algorithm>
#include <check.h>
#include <cstdlib>
#include <iostream>
#include <string>

using util::operator""_x;
using util::operator""_k;

namespace
{
  const aes128gcm::key_storage key      = "AD7A2BD03EAC835A6F620FDCB506B345"_k;
  const std::vector<uint8_t> nonce_data = "12153524C0895E81B2C28465"_x;

  const std::vector<uint8_t> plaintext1 =
      "08000F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A0002"_x;
  const std::vector<uint8_t> additional_data1 =
      "D609B1F056637A0D46DF998D88E52E00B2C2846512153524C0895E81"_x;
  const std::vector<uint8_t> expected1 =
      "701AFA1CC039C0D765128A665DAB69243899BF7318CCDC81C9931DA17FBE8EDD7D17CB8B4C26FC81E3284F2B7FBA713D4F8D55E7D3F06FD5A13C0C29B9D5B880"_x;

} // namespace

START_TEST(encrypt_decrypt)
{
  incrementing_nonce nonce(nonce_data);
  ++nonce;
  const auto n = nonce.nonce();

  aes128gcm aesgcm(key);

  std::vector<uint8_t> plaintext{{'p'}};
  std::vector<uint8_t> ciphertext;
  bool res = aesgcm.encrypt(ciphertext, plaintext, n);
  ck_assert_uint_eq(res, true);
  ck_assert_uint_eq(ciphertext.size(), plaintext.size() + aes128gcm::additional_size);

  std::vector<uint8_t> plaintext_2;
  res = aesgcm.decrypt(plaintext_2, ciphertext, n);

  ck_assert_uint_eq(res, true);
  ck_assert_array_split_eq(plaintext, plaintext_2);
}
END_TEST

START_TEST(encrypt_decrypt_ad)
{
  incrementing_nonce nonce(nonce_data);
  ++nonce;
  const auto n = nonce.nonce();

  aes128gcm aesgcm(key);

  std::vector<uint8_t> plaintext{{'p'}};
  std::vector<uint8_t> ciphertext;
  bool res = aesgcm.encrypt(ciphertext, plaintext, n, additional_data1);
  ck_assert_uint_eq(res, true);

  ck_assert_uint_eq(ciphertext.size(), plaintext.size() + aes128gcm::additional_size);

  std::vector<uint8_t> plaintext_2;
  res = aesgcm.decrypt(plaintext_2, ciphertext, n);
  ck_assert_uint_eq(res, false);

  res = aesgcm.decrypt(plaintext_2, ciphertext, n, additional_data1);
  ck_assert_uint_eq(res, true);
  ck_assert_array_split_eq(plaintext, plaintext_2);
}
END_TEST

START_TEST(encrypt_decrypt_distinct)
{
  incrementing_nonce nonce(nonce_data);
  ++nonce;

  aes128gcm aesgcm(key);

  std::vector<uint8_t> plaintext{{'p'}};
  std::vector<uint8_t> ciphertext, ciphertext_2;
  bool res = aesgcm.encrypt(ciphertext, plaintext, nonce.nonce());
  ck_assert_uint_eq(res, true);
  ++nonce;
  res = aesgcm.encrypt(ciphertext_2, plaintext, nonce.nonce());
  ck_assert_uint_eq(res, true);

  ck_assert_uint_eq(ciphertext.size(), ciphertext_2.size());
  ck_assert_uint_eq(std::equal(ciphertext.begin(), ciphertext.end(), ciphertext_2.begin()), false);
}
END_TEST

START_TEST(encrypt_decrypt_fail)
{
  incrementing_nonce nonce(nonce_data);
  ++nonce;

  aes128gcm aesgcm(key);

  std::vector<uint8_t> plaintext{{'p'}};
  std::vector<uint8_t> ciphertext, ciphertext_2;
  bool res = aesgcm.encrypt(ciphertext, plaintext, nonce.nonce());
  ck_assert_uint_eq(res, true);
  res = aesgcm.encrypt(ciphertext_2, plaintext, nonce.nonce());
  ck_assert_uint_eq(res, true);

  ciphertext[0] += 1;
  ciphertext_2[1] += 1;

  res = aesgcm.decrypt(plaintext, ciphertext, nonce.nonce());
  ck_assert_uint_eq(res, false);

  res = aesgcm.decrypt(plaintext, ciphertext_2, nonce.nonce());
  ck_assert_uint_eq(res, false);
}
END_TEST

// MACsec GCM-AES Test Vectors - IEEE 802 - 2.2.1
START_TEST(encrypt_2_2_1)
{
  incrementing_nonce nonce(nonce_data);
  const auto n = nonce.nonce();

  aes128gcm aesgcm(key);

  std::vector<uint8_t> ciphertext;
  bool res = aesgcm.encrypt(ciphertext, plaintext1, n, additional_data1);
  ck_assert_uint_eq(res, true);

  ck_assert_array_split_eq(ciphertext, expected1);
}
END_TEST


int main(int argc, char** argv)
{
  Suite* suite = suite_create("AES-GCM");

  TCase* tcase = tcase_create("Functionality");
  tcase_add_test(tcase, encrypt_decrypt);
  tcase_add_test(tcase, encrypt_decrypt_ad);
  tcase_add_test(tcase, encrypt_decrypt_distinct);
  tcase_add_test(tcase, encrypt_decrypt_fail);
  suite_add_tcase(suite, tcase);

  tcase = tcase_create("Test vectors");
  tcase_add_test(tcase, encrypt_2_2_1);
  suite_add_tcase(suite, tcase);

  SRunner* suite_runner = srunner_create(suite);
  srunner_run(suite_runner, argc, argv);
  int number_failed = srunner_ntests_failed(suite_runner);
  srunner_free(suite_runner);

  return !number_failed ? EXIT_SUCCESS : EXIT_FAILURE;
}
