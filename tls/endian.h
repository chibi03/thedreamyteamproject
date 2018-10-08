#ifndef ENDIAN_H
#define ENDIAN_H

#include <cstdint>

namespace detail
{
  template <class T>
  struct endian_info;

  template <>
  struct endian_info<uint8_t>
  {
    static constexpr uint8_t swap(uint8_t v)
    {
      return v;
    }
  };

#ifdef __GNUC__
  template <>
  struct endian_info<uint16_t>
  {
    static constexpr uint16_t swap(uint16_t v)
    {
      return __builtin_bswap16(v);
    }
  };

  template <>
  struct endian_info<uint32_t>
  {
    static constexpr uint32_t swap(uint32_t v)
    {
      return __builtin_bswap32(v);
    }
  };

  template <>
  struct endian_info<uint64_t>
  {
    static constexpr uint64_t swap(uint64_t v)
    {
      return __builtin_bswap64(v);
    }
  };
#else
  template <>
  struct endian_info<uint16_t>
  {
    static constexpr uint16_t swap(uint16_t v)
    {
      return ((v & 0xff00) >> 8) | ((v & 0x00ff) << 8);
    }
  };

  template <>
  struct endian_info<uint32_t>
  {
    static constexpr uint32_t swap(uint32_t v)
    {
      return ((v & 0xff000000) >> 24) | ((v & 0x00ff0000) >> 8) | ((v & 0x0000ff00) << 8) |
             ((v & 0x000000ff) << 24);
    }
  };

  template <>
  struct endian_info<uint64_t>
  {
    static constexpr uint64_t swap(uint64_t v)
    {
      return ((v & UINT64_C(0xff00000000000000)) >> 56) |
             ((v & UINT64_C(0x00ff000000000000)) >> 40) |
             ((v & UINT64_C(0x0000ff0000000000)) >> 24) |
             ((v & UINT64_C(0x000000ff00000000)) >> 8) | ((v & UINT64_C(0x00000000ff000000)) << 8) |
             ((v & UINT64_C(0x0000000000ff0000)) << 24) |
             ((v & UINT64_C(0x000000000000ff00)) << 40) |
             ((v & UINT64_C(0x00000000000000ff)) << 56);
    }
  };
#endif
} // namespace detail

/// Swap byte values of an integer.
template <class T>
constexpr T byte_swap(T value)
{
  return detail::endian_info<T>::swap(value);
}

/// Convert integer from host byte order to little endian.
template <class T>
constexpr T htol(T value)
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
  return value;
#else
  return byte_swap(value);
#endif
}

/// Convert integer from from little endian to host byte order.
template <class T>
constexpr T ltoh(T value)
{
  return htol(value);
}

/// Convert integer from host byte order to big endian.
template <class T>
constexpr T htob(T value)
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
  return byte_swap(value);
#else
  return value;
#endif
}

/// Convert integer from from big endian to host byte order.
template <class T>
constexpr T btoh(T value)
{
  return htob(value);
}

/// Convert integer from host byte order to network byte order.
template <class T>
constexpr T hton(T value)
{
  return htob(value);
}

/// Convert integer from network byte order to host byte order.
template <class T>
constexpr T ntoh(T value)
{
  return hton(value);
}

#endif
