#ifndef COUNTER_H
#define COUNTER_H

#include <array>
#include <cstdint>
#include <vector>

// A pre-record nonce [RFC 8446, §5.3]
//
// The upper n - 8 bytes are fixed and the only thing that
// changes are the lower 8 bytes, which are a counter xored
// with some initial value
class incrementing_nonce
{
public:
  /// Initialize the nonce with given bytes.
  incrementing_nonce(const std::vector<uint8_t>& bytes);

  /// Increment the counter.
  incrementing_nonce& operator++();

  /// Reinitialise the nonce with the given bytes and reset counter to 0.
  void reset(const std::vector<uint8_t>& bytes);

  /// Return a copy of the current nonce.
  const std::vector<uint8_t>& nonce();
};

#endif
