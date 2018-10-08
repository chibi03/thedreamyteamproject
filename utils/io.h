#ifndef UTILS_IO_H
#define UTILS_IO_H

#include <array>
#include <iostream>
#include <type_traits>
#include <vector>

namespace util
{
  template <class T>
  void read(std::istream& is, T& u)
  {
    static_assert(std::is_integral<T>::value, "Integer required.");
    is.read(reinterpret_cast<char*>(&u), sizeof(u));
  }

  template <class T>
  void write(std::ostream& os, T u)
  {
    static_assert(std::is_integral<T>::value, "Integer required.");
    os.write(reinterpret_cast<const char*>(&u), sizeof(u));
  }

  template <class T, std::size_t S>
  void read(std::istream& is, T (&array)[S])
  {
    for (auto& val : array)
      read(is, val);
  }

  template <class T, std::size_t S>
  void write(std::ostream& os, const T (&array)[S])
  {
    for (const auto& val : array)
      write(os, val);
  }

  template <class T, std::size_t S>
  void read(std::istream& is, std::array<T, S>& array)
  {
    for (auto& val : array)
      read(is, val);
  }

  template <class T, std::size_t S>
  void write(std::ostream& os, const std::array<T, S>& array)
  {
    for (const auto& val : array)
      write(os, val);
  }

  template <class T>
  void read(std::istream& is, std::vector<T>& array, bool with_size = false)
  {
    if (with_size)
    {
      uint64_t size = 0;
      read(is, size);
      array.resize(size);
    }

    for (auto& val : array)
      read(is, val);
  }

  template <class T>
  void write(std::ostream& os, const std::vector<T>& array, bool with_size = false)
  {
    if (with_size)
      write(os, static_cast<uint64_t>(array.size()));

    for (const auto& val : array)
      write(os, val);
  }
} // namespace util

#endif
