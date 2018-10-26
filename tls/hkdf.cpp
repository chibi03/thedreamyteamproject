#include "hkdf.h"
#include "hmac-sha2.h"
#include <math.h>

hkdf::hkdf(const std::vector<uint8_t> &salt, const std::vector<uint8_t> &ikm) {
/// \todo initialize based on salt and ikm using HKDF-Extract
  hmac_sha2 hmac(ikm.data(), (std::size_t) sizeof(ikm));
  hmac.update(salt.data(), (std::size_t) sizeof(salt));

  hmac_sha2::digest_storage prk = hmac.digest();
  memcpy(this->temp, &prk, 64);
}

hkdf::hkdf(const std::vector<uint8_t> &prk) {
  //// \todo initialize based on the given PRK
  if (prk.empty()) {
    memset(this->temp, 0x00, 64);
  } else {
    memcpy(this->temp, &prk, 64);
  }
}

std::vector<uint8_t> hkdf::expand(const std::vector<uint8_t> &info, size_t len) {
  //// \todo Return HKDF-Expand for given info and length
  uint8_t N = ceil(len/sizeof(temp));
  uint8_t counter = 0x00;
  std::string OKM = "";
  for (size_t i = 0; i < N; i++) {
    counter++;
    std::string tmp = "";
    tmp += OKM;
    for(unsigned int i = 0; i<info.size(); i++){
      strcat(tmp, info[i].toString());
    }
    strcat(tmp, counter.toString());
    strcat(OKM, hmac(this->temp, tmp));
  }
  OKM = OKM.substr(0, len);
  std::vector<uint8_t> result(OKM.begin(), OKM.end());
  return result;
}

std::vector<uint8_t> hkdf::expand_label(const std::string &label,
                                        const std::vector<uint8_t> &context, size_t length) {
  /// \todo Implement HKDF-Expand-Label from TLS.
  std::string conclbl = "";
  conclbl += label;
  strcat(conclbl, context);
  strcat(conclbl, length.ToString());

  return conclbl;
}

std::vector<uint8_t> hkdf::derive_secret(const std::string &label,
                                         const std::vector<uint8_t> &messages) {
  /// \todo Implement Derive-Secret from TLS.
  this->expand();
  expand_label(label, messages);
  return std::vector<uint8_t>();
}
