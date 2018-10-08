#ifndef RANDOM_H
#define RANDOM_H

#include <cstddef>
#include <cstdint>

/// Fetch requested number of random bytes from a random data source suitable
/// for cryptographic use.
//
/// @param data storage buffer
/// @param size size of buffer
/// @return true on success, false otherwise
bool get_random_data(uint8_t* data, std::size_t size);

#endif
