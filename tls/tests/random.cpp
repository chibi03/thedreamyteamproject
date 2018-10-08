#include "../random.h"
#include "helpers.h"

#include <array>

#include <check.h>

using util::to_hex_string;

START_TEST(simple)
{
  std::array<uint8_t, 64> data{{0}};
  const auto rhs = to_hex_string(data);

  ck_assert(get_random_data(data.data(), data.size()));

  const auto lhs = to_hex_string(data);
  ck_assert_str_ne(lhs.c_str(), rhs.c_str());
}
END_TEST

START_TEST(twice)
{
  std::array<uint8_t, 64> data{{0}}, data2{{0}};

  ck_assert(get_random_data(data.data(), data.size()));
  ck_assert(get_random_data(data2.data(), data2.size()));

  const auto lhs = to_hex_string(data);
  const auto rhs = to_hex_string(data2);
  ck_assert_str_ne(lhs.c_str(), rhs.c_str());
}
END_TEST

int main(int argc, char** argv)
{
  Suite* suite = suite_create("Random");

  TCase* tcase = tcase_create("Basic");
  tcase_set_timeout(tcase, 0);
  tcase_add_test(tcase, simple);
  tcase_add_test(tcase, twice);
  suite_add_tcase(suite, tcase);

  SRunner* suite_runner = srunner_create(suite);
  srunner_run(suite_runner, argc, argv);
  int number_failed = srunner_ntests_failed(suite_runner);
  srunner_free(suite_runner);

  return !number_failed ? EXIT_SUCCESS : EXIT_FAILURE;
}
