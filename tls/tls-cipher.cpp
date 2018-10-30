#include "tls-cipher.h"
#include "basic-ae.h"

bool tls13_cipher::record::operator==(const record& other) const
{
  if (header.type != other.header.type)
    return false;
  if (header.version.major != other.header.version.major)
    return false;
  if (header.version.minor != other.header.version.minor)
    return false;
  if (header.length != other.header.length)
    return false;
  return ciphertext == other.ciphertext;
}

bool tls13_cipher::record::operator!=(const record& other) const
{
  return !(*this == other);
}

tls13_cipher::~tls13_cipher() {}

