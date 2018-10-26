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
  std::vector<uint8_t> data;
  data.insert(data.end(), salt.begin(), salt.end());
  data.insert(data.end(), ikm.begin(), ikm.end());

  hmac hmac(data.data(), sizeof(data));

  hmac_sha2::digest_storage prk = hmac.digest();
  memcpy(this->h_key, &prk, 64);
}

hkdf::hkdf(const std::vector<uint8_t> &prk) {
  //// \todo initialize based on the given PRK
  if (prk.empty()) {
    memset(this->h_key, 0x00, 64);
  } else {
    memcpy(this->h_key, &prk, 64);
  }
}

std::vector<uint8_t> hkdf::expand(const std::vector<uint8_t> &info, size_t len) {
  //// \todo Return HKDF-Expand for given info and length

  int N = ceil(len/sizeof(this->h_key));
  std::vector<uint8_t> init_t;
  return expand_helper(init_t, info, 0x00, N);
}

std::vector<uint8_t> hkdf::expand_helper(std::vector<uint8_t> &input,
                                         const std::vector<uint8_t> &info,
                                         int counter,
                                         int N) {
  hmac hmac(this->h_key, sizeof(this->h_key));
  if (N > 0) {
    std::vector<uint8_t> data;
    data.insert(data.end(), input.begin(), input.end());
    data.insert(data.end(), info.begin(), info.end());
    data.push_back(counter);

    hmac.update(data.data(), sizeof(data));
    std::vector<uint8_t> new_input;
    hmac_sha2::digest_storage digest = hmac.digest();

    for (auto it = digest.begin(); it!=digest.end(); ++it) {
      new_input.push_back(*it);
    }
    std::vector<uint8_t> result = expand_helper(new_input, info, counter++, N--);
    new_input.insert(new_input.end(), result.begin(), result.end());
    return new_input;
  }
  return std::vector<uint8_t>();
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
