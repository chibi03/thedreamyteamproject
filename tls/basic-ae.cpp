#include "basic-ae.h"


template <std::size_t K, std::size_t A>
basic_ae<K, A>::~basic_ae()
{
}

template <std::size_t K, std::size_t A>
std::size_t basic_ae<K, A>::ciphertext_size(const std::size_t size)
{
  return size + additional_size;
}

template <std::size_t K, std::size_t A>
std::size_t basic_ae<K, A>::plaintext_size(const std::size_t size)
{
  return size - additional_size;
}

template class basic_ae<16, 16>;
