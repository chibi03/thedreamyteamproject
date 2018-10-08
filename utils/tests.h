#ifndef UTILS_TESTS_H
#define UTILS_TESTS_H

#include <string>
#include <vector>

#include "utils.h"
#include <check.h>

namespace
{
  /// Helper function to compare strings per 16 byte blocks.
  inline void ck_assert_str_split_eq(const std::string& lhs, const std::string& rhs)
  {
    ck_assert_uint_eq(lhs.size(), rhs.size());
    static constexpr std::string::size_type c = 16;
    std::string::size_type idx                = 0;
    for (; idx < lhs.size(); idx += c)
    {
      const std::string temp_lhs = lhs.substr(idx, c);
      const std::string temp_rhs = rhs.substr(idx, c);

      ck_assert_str_eq(temp_lhs.c_str(), temp_rhs.c_str());
    }
  }

  /// Helper function to compare vectors per 8 byte blocks
  template <class C>
  void ck_assert_array_split_eq(const C& c1, const C& c2)
  {
    const std::string s1{util::to_hex_string(c1)};
    const std::string s2{util::to_hex_string(c2)};
    ck_assert_str_split_eq(s1, s2);
  }

  inline void srunner_run(SRunner* sr, int argc, char** argv)
  {
    if (argc >= 2)
    {
      // Store test results as XML
      srunner_set_xml(sr, argv[1]);
    }

    srunner_run_all(sr, CK_VERBOSE);
  }
} // namespace

#endif
