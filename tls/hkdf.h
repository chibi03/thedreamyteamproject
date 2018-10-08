#ifndef HKDF_H
#define HKDF_H

#include "hmac-sha2.h"
#include <string>
#include <vector>

/// HKDF using HMAC-SHA256 according to RFC 5869
class hkdf
{

public:
  typedef hmac_sha2 hmac;

  /// Derive PRK from salt and ikm using HKDF-Extract.
  hkdf(const std::vector<uint8_t>& salt, const std::vector<uint8_t>& ikm);
  /// Directly instantiate with a given PRK.
  hkdf(const std::vector<uint8_t>& prk);
  /// Run HKDF-Expand for the instance's PRK and given info and length.
  std::vector<uint8_t> expand(const std::vector<uint8_t>& info, size_t length);

  /// Run TLS' HKDF-Expand-Label.
  std::vector<uint8_t> expand_label(const std::string& label, const std::vector<uint8_t>& context,
                                    size_t length);
  /// Run TLS' Derive-Secret.
  std::vector<uint8_t> derive_secret(const std::string& label,
                                     const std::vector<uint8_t>& messages);
};

#endif
