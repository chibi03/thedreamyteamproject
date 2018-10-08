#include "../sha2.h"
#include "helpers.h"

#include <check.h>

namespace
{
  constexpr char expected_0[] = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

  constexpr uint8_t input_1[] = "abc";
  constexpr char expected_1[] = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

  constexpr uint8_t input_2[] = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
  constexpr char expected_2[] = "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1";

  constexpr uint8_t input_3[] = "abcdefghbcdefghicdefghijdefghijkefghijklfghijk"
                                "lmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmno"
                                "pqrsmnopqrstnopqrstu";
  constexpr char expected_3[] = "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1";

  std::string test(const uint8_t* data, const std::size_t data_size, const std::size_t loops = 1)
  {
    return compute_hash<sha2>(data, data_size, loops);
  }
} // namespace

START_TEST(test_0)
{
  const auto digest = test(nullptr, 0);
  ck_assert_str_eq(digest.c_str(), expected_0);
}
END_TEST

START_TEST(test_1)
{
  const auto digest = test(input_1, sizeof(input_1) - 1);
  ck_assert_str_eq(digest.c_str(), expected_1);
}
END_TEST

START_TEST(test_2)
{
  const auto digest = test(input_2, sizeof(input_2) - 1);
  ck_assert_str_eq(digest.c_str(), expected_2);
}
END_TEST

START_TEST(test_3)
{
  const auto digest = test(input_3, sizeof(input_3) - 1);
  ck_assert_str_eq(digest.c_str(), expected_3);
}
END_TEST

int main(int argc, char** argv)
{
  Suite* suite = suite_create("SHA2");

  TCase* tcase = tcase_create("SHA2");
  tcase_set_timeout(tcase, 0);
  tcase_add_test(tcase, test_0);
  tcase_add_test(tcase, test_1);
  tcase_add_test(tcase, test_2);
  tcase_add_test(tcase, test_3);
  suite_add_tcase(suite, tcase);

  SRunner* suite_runner = srunner_create(suite);
  srunner_run(suite_runner, argc, argv);
  int number_failed = srunner_ntests_failed(suite_runner);
  srunner_free(suite_runner);

  return !number_failed ? EXIT_SUCCESS : EXIT_FAILURE;
}
