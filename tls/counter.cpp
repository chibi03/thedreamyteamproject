#include "counter.h"
#include "endian.h"


incrementing_nonce::incrementing_nonce(const std::vector<uint8_t>& bytes)
{
  /// \todo initialise the nonce
}

incrementing_nonce& incrementing_nonce::operator++()
{
  /// \todo increment the nonce
  return *this;
}

void incrementing_nonce::reset(const std::vector<uint8_t>& bytes)
{
  /// \todo reset the nonce
}

const std::vector<uint8_t>& incrementing_nonce::nonce()
{
  /// \todo return a copy of the nonce
  return std::vector<uint8_t>();
}
