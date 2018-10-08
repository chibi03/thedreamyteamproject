#include "../../utils/tests.h"
#include "../aes128gcm.h"
#include "../counter.h"
#include "../endian.h"
#include <array>
#include <cstring>
#include <vector>

#include <check.h>

namespace
{
  std::vector<uint8_t> nonce_data_1 = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
                                       0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b};
  std::vector<uint8_t> nonce_data_2 = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                       0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
  std::vector<uint8_t> nonce_data_3 = {0x00, 0x10, 0x20, 0x30, 0x40, 0x50,
                                       0x60, 0x70, 0x80, 0x90, 0xa0, 0xb0};
  std::vector<uint8_t> nonce_data_4 = {0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70,
                                       0x80, 0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0};

  constexpr uint64_t loops = 256;
} // namespace

START_TEST(simple_aesgcm)
{
  incrementing_nonce nonce1(nonce_data_1);
  std::vector<uint8_t> nonce1_raw;
  nonce1_raw = nonce1.nonce();
  ck_assert_uint_eq(std::memcmp(nonce1_raw.data(), nonce_data_1.data(), nonce_data_1.size()), 0);
}
END_TEST

START_TEST(loop_aesgcm)
{
  incrementing_nonce nonce1(nonce_data_1);
  std::vector<uint8_t> nonce1_raw;
  uint64_t counter = 0;
  std::memcpy(&counter, nonce_data_1.data() + nonce_data_1.size() - 8, 8);
  counter = ntoh<uint64_t>(counter);
  for (uint64_t i = 1; i < loops; i++)
  {
    ++nonce1;
    uint64_t cn = hton<uint64_t>(counter ^ i);
    nonce1_raw  = nonce1.nonce();
    ck_assert_uint_eq(std::memcmp(nonce1_raw.data(), nonce_data_1.data(), nonce_data_1.size() - 8),
                      0);
    ck_assert_uint_eq(std::memcmp(nonce1_raw.data() + nonce_data_1.size() - 8, &cn, 8), 0);
  }
}
END_TEST

START_TEST(reset_aesgcm)
{
  incrementing_nonce nonce1(nonce_data_1);
  std::vector<uint8_t> nonce1_raw;
  ++nonce1;
  nonce1.reset(nonce_data_3);
  nonce1_raw = nonce1.nonce();
  ck_assert_uint_eq(std::memcmp(nonce1_raw.data(), nonce_data_3.data(), nonce_data_3.size()), 0);
}
END_TEST

int main(int argc, char** argv)
{
  Suite* suite = suite_create("Nonce");

  TCase* tcase = tcase_create("Nonce");
  tcase_set_timeout(tcase, 0);
  tcase_add_test(tcase, simple_aesgcm);
  tcase_add_test(tcase, loop_aesgcm);
  tcase_add_test(tcase, reset_aesgcm);
  suite_add_tcase(suite, tcase);

  SRunner* suite_runner = srunner_create(suite);
  srunner_run(suite_runner, argc, argv);
  int number_failed = srunner_ntests_failed(suite_runner);
  srunner_free(suite_runner);

  return !number_failed ? EXIT_SUCCESS : EXIT_FAILURE;
}
