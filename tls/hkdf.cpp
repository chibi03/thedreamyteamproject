#include "hkdf.h"
#include "hmac-sha2.h"
#include "endian.h"
#include <math.h>
#include <iostream>

struct HkdfLabel {
  uint16_t length;
  std::string label;
  std::vector<uint8_t> context;
} hkdflabel;

hkdf::hkdf(const std::vector<uint8_t> &salt, const std::vector<uint8_t> &ikm) {
/// \todo initialize based on salt and ikm using HKDF-Extract
  std::vector<uint8_t> valid_salt(hmac::digest_size, 0);
  if (ikm.empty()) {
    throw std::invalid_argument("The initial keying material cannot be empty.");
  }

  if (salt.empty()) {
    valid_salt = salt;
  }

  hmac hmac(valid_salt.data(), sizeof(valid_salt));
  hmac.update(ikm.data(), sizeof(ikm));
  hmac::digest_storage prk = hmac.digest();

  std::copy(prk.begin(), prk.end(), this->h_key);
  std::cout << "Hash length: " << sizeof(this->h_key) << std::endl;
}

hkdf::hkdf(const std::vector<uint8_t> &prk) {
  //// \todo initialize based on the given PRK
  if (prk.empty()) {
    throw std::invalid_argument("Missing pseudo random key value.");
  } else {
    std::copy(prk.begin(), prk.end(), this->h_key);
  }
  std::cout << "Created HKDF 2" << std::endl;
}

/**
  The output OKM is calculated as follows:
    N = ceil(L/HashLen)
    T = T(1) | T(2) | T(3) | ... | T(N)
    OKM = first L bytes of T
  where:
    T(0) = empty string (zero length)
    T(1) = HMAC-Hash(PRK, T(0) | info | 0x01)
    T(2) = HMAC-Hash(PRK, T(1) | info | 0x02)
    T(3) = HMAC-Hash(PRK, T(2) | info | 0x03)
    ...
*/
std::vector<uint8_t> hkdf::expand(const std::vector<uint8_t> &info, size_t len) {
  //// \todo Return HKDF-Expand for given info and length

  if (len <= 0) {
    throw std::invalid_argument("The length has to be larger than 0.");
  }

  if (len > 255*sizeof(this->h_key)) {
    throw std::invalid_argument("The length has to be smaller or equal to HashLen * 255.");
  }

  std::cout << "Expanding HKDF" << std::endl;
  int N = ceil(((float) len/(float) sizeof(this->h_key)));

  std::vector<uint8_t> init_t;
  hmac hmac(this->h_key, sizeof(this->h_key));

  std::vector<uint8_t> okm;
  std::vector<uint8_t> T = {};
  uint8_t constant = 0x00;
  for (int i = 0; i < N; i++) {
    T = expand_helper(T, info, ++constant, hmac);
    okm.insert(okm.end(), T.begin(), T.end());
  }

  std::cout << "Size of T: " << okm.size() << std::endl;
  okm.resize(len);
  return okm;
}

std::vector<uint8_t> hkdf::expand_helper(std::vector<uint8_t> &input,
                                         const std::vector<uint8_t> &info,
                                         uint8_t constant,
                                         hmac hmac) {
  if (!input.empty()) {
    hmac.update(input.data(), sizeof(input));
  }
  if (!info.empty()) {
    hmac.update(info.data(), sizeof(info));
  }
  hmac.update((uint8_t*) & constant, sizeof(constant));
  std::vector<uint8_t> new_input;
  hmac_sha2::digest_storage digest = hmac.digest();

  for (auto it = digest.begin(); it!=digest.end(); ++it) {
    new_input.push_back(*it);
  }

  std::cout << "Current new input length " << new_input.size() << std::endl;
  return new_input;
}

std::vector<uint8_t> hkdf::expand_label(const std::string &label,
                                        const std::vector<uint8_t> &context, size_t length) {
  /// \todo Implement HKDF-Expand-Label from TLS.
  hkdflabel.length = hton<uint16_t>(length);
  hkdflabel.label = "tls13 " + label;
  hkdflabel.context = context;

  std::string tmp_label = std::to_string(hkdflabel.length) + hkdflabel.label;
  for (unsigned int i = 0; i < hkdflabel.context.size(); i++) {
    tmp_label += hkdflabel.context[i];
  }

  std::vector<uint8_t> info(tmp_label.begin(), tmp_label.end());
  return expand(info, length);
}

std::vector<uint8_t> hkdf::derive_secret(const std::string &label,
                                         const std::vector<uint8_t> &messages) {
  /// \todo Implement Derive-Secret from TLS.
  hmac transcript_hash(this->h_key, sizeof(this->h_key));
  transcript_hash.update(messages.data(), sizeof(messages));

  hmac_sha2::digest_storage digest = transcript_hash.digest();
  std::vector<uint8_t> hashed_messages;

  for (auto it = digest.begin(); it!=digest.end(); ++it) {
    hashed_messages.push_back(*it);
  }

  return expand_label(label, hashed_messages, hashed_messages.size());
}
