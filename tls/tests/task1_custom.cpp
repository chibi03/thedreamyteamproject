#include "helpers.h"
#include <check.h>
#include <chrono>

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

namespace {
    const aes128gcm::key_storage key = "AD7A2BD03EAC835A6F620FDCB506B345"_k;
    const aes128gcm::key_storage key_invalid = "ER7A2OO03EAC835A6F620FDCB511B345"_k;
}


START_TEST(constant_time_decrypt_check){
    incrementing_nonce nonce(nonce_data);
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
    res = aesgcm.decrypt(plaintext_2, ciphertext, n);
    auto finish = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed = finish - start;

    // execution with invalid key
    auto start1 = std::chrono::high_resolution_clock::now();
    std::vector<uint8_t> plaintext_3;
    res = aesgcm_inv.decrypt(plaintext_3, ciphertext, n);

    auto finish1 = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed1 = finish1 - start1;

    ck_assert_str_eq(elapsed.count(), elapsed1.count());
}

END_TEST

int main(int argc, char **argv) {
    Suite *suite = suite_create("Student Task 1 Tests");
    // TCase* tcase = tcase_create("FIRST");
    // tcase_add_test(tcase, custom_1);
    // suite_add_tcase(suite, tcase);

    SRunner *suite_runner = srunner_create(suite);
    srunner_run(suite_runner, argc, argv);

    int number_failed = srunner_ntests_failed(suite_runner);
    srunner_free(suite_runner);

    return !number_failed ? EXIT_SUCCESS : EXIT_FAILURE;
}
