#include "../../utils/tests.h"
#include <check.h>

// Include your custom testc ases here
// Write at LEAST 10 custom tests to verify your own implementation.
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

namespace
{
  // include the constants you need for your test here
  // const std::string test_string = "its_2018";
}

// Sample to illustrate test:
//
// START_TEST(custom_1){
//   std::string part1 = "its";
//   std::string part2 = "_2018";
//   std::string to_check = part1 + part2;
//   ck_assert_str_eq(test_string.c_str(), to_check.c_str());
// }
// END_TEST

int main(int argc, char** argv)
{
  Suite* suite = suite_create("Student Task 2 Tests");
  // TCase* tcase = tcase_create("FIRST");
  // tcase_add_test(tcase, custom_1);
  // suite_add_tcase(suite, tcase);

  SRunner* suite_runner = srunner_create(suite);
  srunner_run(suite_runner, argc, argv);

  int number_failed = srunner_ntests_failed(suite_runner);
  srunner_free(suite_runner);

  return !number_failed ? EXIT_SUCCESS : EXIT_FAILURE;
}
