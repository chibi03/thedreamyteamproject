#include "utils.h"

#include <stdexcept>

namespace
{
  constexpr uint8_t parse_hex(const char c)
  {
    if (c >= '0' && c <= '9')
      return c - '0';
    else if (c >= 'a' && c <= 'f')
      return 10 + c - 'a';
    else if (c >= 'A' && c <= 'F')
      return 10 + c - 'A';
    else
      throw std::runtime_error("invalid character in literal");
  }

  constexpr uint8_t parse_hex(const char h, const char l)
  {
    return parse_hex(h) << 4 | parse_hex(l);
  }
} // namespace

namespace util
{
  std::vector<uint8_t> operator"" _x(const char* literal, size_t s)
  {
    if (s & 1)
      throw std::runtime_error("invalid literal length");

    std::vector<uint8_t> r;
    r.reserve(s / 2);
    for (size_t i = 0; i < s; i += 2, literal += 2)
      r.emplace_back(parse_hex(*literal, *(literal + 1)));

    return r;
  }

  std::array<uint8_t, 16> operator"" _k(const char* literal, size_t s)
  {
    if (s != 32)
      throw std::runtime_error("invalid literal length");

    std::array<uint8_t, 16> r;
    for (size_t i = 0; i < s; i += 2, literal += 2)
      r[i >> 1] = parse_hex(*literal, *(literal + 1));

    return r;
  }

  void print_hex(std::ostream& os, uint8_t byte)
  {
    boost::io::ios_flags_saver ifs(os);
    os << std::hex << std::setfill('0') << std::setw(2) << static_cast<uint32_t>(byte);
  }

  void print_hex(std::ostream& os, const std::vector<uint8_t>& bytes)
  {
    for (uint32_t i = 0; i < bytes.size(); i++)
      print_hex(os, bytes[i]);
    os << std::endl;
  }
} // namespace util
