#include "helpers.h"
#include <check.h>
#include <chrono>
#include <cstring>
#include <vector>
#include "../counter.h"
#include "../aes128gcm.h"
#include "../ascon128.h"
#include "../hkdf.h"
#include "../../utils/tests.h"
#include "../endian.h"
#include <array>

// Include your custom testc ases here
// Write at LEAST 5 custom tests to verify your own implementation.
//
// TODO:
//
// Each Test is encapsulated by:
//
// START_TEST(testname){
//   #testcode
// }
// END_TEST
//
// At the end of the test a verification statement such as ck_assert_int_eq(int, int),
// wich verifies that two ints are equal, should be called.
// For further information take a look at:
// https://libcheck.github.io/check/doc/doxygen/html/check_8h.html
//
// First create a Test Suite which holds all your testcases by calling suite_create(suite_name).
// Add Each test to the corresponding testcase by first creating a testcase object with
// tcase_create(tcase_name) and then call tcase_add_test(tcase, test_name) for each test you want
// to add to this testcase. Add the Tescases to the test suite by calling: suite_add_tcase(suite,
// tcase).
//
// Run your defined test suite and verify the outcome.
// You may look into some of our tests to get a feeling for the workflow.

using util::operator""_x;
using util::operator""_k;

namespace {
    const aes128gcm::key_storage key = "AD7A2BD03EAC835A6F620FDCB506B345"_k;
    const aes128gcm::key_storage key_invalid = "AD7A2BD03EAC835A6F620FDCB506B346"_k;
    std::vector<uint8_t> nonce_data_1 = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
                                        0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b};
    std::vector<uint8_t> nonce_data_2 = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                       0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

	//invalid key and nonce
	const ascon128::key_storage keyascon = "ffffffffffffffffffffffffffffffff"_k;
	const std::vector<uint8_t> ascon_nonce = "00010203040c0d0e0f"_x;

	const std::string plaintext_1 = "abcdefghijklmnoqrstuvwxyz0123456789ABCDEFGHIJKLMNOQRSTUVWXYZ";
	const std::string ad_1 = util::to_hex_string(plaintext_1);
	const std::vector<uint8_t> expected_1 =
		"7fc2b392364bcfe8fbc6417889e1c908beebf6e7378f96065df6616e10eb"
		"c798f1180f8d9188c8e4672558381fb18e4165aea627fcc9f18c8a8f54e7"
		"05615a12a7d5ef18b494b75eeca98879"_x;


}

START_TEST(reset_nonce_diff_size)
{
  incrementing_nonce nonce1(nonce_data_1);
  std::vector<uint8_t> nonce1_raw;
  ++nonce1;
  nonce1.reset(nonce_data_2);
  nonce1_raw = nonce1.nonce();
  //ck_assert_uint_eq(std::memcmp(nonce1_raw.data(), nonce_data_2.data(), nonce_data_2.size() - 8), 0);
}
END_TEST


START_TEST(constant_time_decrypt_check){
    incrementing_nonce nonce(nonce_data_1);
    ++nonce;
    const auto n = nonce.nonce();

    aes128gcm aesgcm(key);
    aes128gcm aesgcm_inv(key_invalid);

    std::vector<uint8_t> plaintext{{ 'p' }};
    std::vector<uint8_t> ciphertext;
    aesgcm.encrypt(ciphertext, plaintext, n);

    // execution with valid key
    auto start = std::chrono::high_resolution_clock::now();
    std::vector<uint8_t> plaintext_2;

    bool res = aesgcm.decrypt(plaintext_2, ciphertext, n);
    ck_assert(res);
    auto finish = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed = finish - start;

    // execution with invalid key
    auto start1 = std::chrono::high_resolution_clock::now();
    std::vector<uint8_t> plaintext_3;
    res = aesgcm_inv.decrypt(plaintext_3, ciphertext, n);
    ck_assert(res);

    auto finish1 = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed1 = finish1 - start1;


    char elapsed_s[64], elapsed1_s[64];
    snprintf(elapsed_s, sizeof elapsed_s, "%f", elapsed.count());
    snprintf(elapsed1_s, sizeof elapsed1_s, "%f", elapsed1.count());
    ck_assert_str_eq(elapsed_s, elapsed1_s);
}

END_TEST

START_TEST(empty_label_hkdf){
    const std::vector<uint8_t> salt = "0b0b0ba9a9a9a9a9"_x;
    const std::vector<uint8_t> ikm  = "91726354"_x;
    hkdf kdf_early_secret(salt, ikm);

    try {
        const std::vector<uint8_t> label = kdf_early_secret.expand_label("", "ab"_x, 16);
    } catch (std::invalid_argument inv){
        ck_assert_str_eq(inv.what() , "A label must be supplied");
    }
}
END_TEST

START_TEST(key_nonce_ascon)
{
	incrementing_nonce nonce(ascon_nonce);
	++nonce;

	ascon128 ascon(keyascon);

	std::vector<uint8_t> plaintext{ plaintext_1.begin(), plaintext_1.end() };
	std::vector<uint8_t> ad(ad_1.begin(), ad_1.end());
	std::vector<uint8_t> ciphertext;
	const bool res = ascon.encrypt(ciphertext, plaintext, nonce.nonce(), ad);

	ck_assert_uint_eq(res, false);

}
END_TEST

int main(int argc, char **argv) {
    Suite *suite = suite_create("Student Task 1 Tests");
    TCase* tcase = tcase_create("Student Task 1 Tests");
    tcase_set_timeout(tcase, 0);
    //tcase_add_test(tcase, constant_time_decrypt_check);
    //tcase_add_test(tcase, reset_nonce_diff_size);
    tcase_add_test(tcase, empty_label_hkdf);
	//tcase_add_test(tcase, key_nonce_ascon);
    suite_add_tcase(suite, tcase);

    SRunner *suite_runner = srunner_create(suite);
    srunner_run(suite_runner, argc, argv);

    int number_failed = srunner_ntests_failed(suite_runner);
    srunner_free(suite_runner);

    return !number_failed ? EXIT_SUCCESS : EXIT_FAILURE;
}
