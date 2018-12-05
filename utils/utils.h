#ifndef UTILS_UTILS_H
#define UTILS_UTILS_H

#include <array>
#include <boost/io/ios_state.hpp>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <vector>

namespace util
{
  std::vector<uint8_t> operator"" _x(const char* literal, size_t s);
  std::vector<uint8_t> operator"" _b(const char* literal, size_t s);
  std::array<uint8_t, 16> operator""_k(const char* literal, size_t s);
  std::array<uint8_t, 32> operator""_h(const char* literal, size_t s);

  template <class T>
  void to_hex_string(std::ostream& oss, const T& digest)
  {
    boost::io::ios_flags_saver ifs(oss);
    oss << std::setfill('0') << std::hex;
    for (const auto v : digest)
      oss << std::setw(sizeof(digest[0]) * 2) << static_cast<uint64_t>(v);
  }

  template <class T>
  std::string to_hex_string(const T& digest)
  {
    std::ostringstream oss;
    to_hex_string(oss, digest);
    return oss.str();
  }

  void print_hex(std::ostream& os, uint8_t byte);
  void print_hex(std::ostream& os, const std::vector<uint8_t>& bytes);

  template <size_t s>
  void print_hex(std::ostream& os, const std::array<uint8_t, s>& bytes)
  {
    for (uint32_t i = 0; i < bytes.size(); i++)
      print_hex(os, bytes[i]);
    os << std::endl;
  }
} // namespace util

#endif
