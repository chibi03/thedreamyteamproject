#include "hkdf.h"


hkdf::hkdf(const std::vector<uint8_t>& salt, const std::vector<uint8_t>& ikm)
{
/// \todo initialize based on salt and ikm using HKDF-Extract
}

hkdf::hkdf(const std::vector<uint8_t>& prk)
{
  //// \todo initialize based on the given PRK
}

std::vector<uint8_t> hkdf::expand(const std::vector<uint8_t>& info, size_t len)
{
  //// \todo Return HKDF-Expand for given info and length
  return std::vector<uint8_t>();
}

std::vector<uint8_t> hkdf::expand_label(const std::string& label,
                                        const std::vector<uint8_t>& context, size_t length)
{
  /// \todo Implement HKDF-Expand-Label from TLS.
  return std::vector<uint8_t>();
}

std::vector<uint8_t> hkdf::derive_secret(const std::string& label,
                                         const std::vector<uint8_t>& messages)
{
  /// \todo Implement Derive-Secret from TLS.
  return std::vector<uint8_t>();
}
