#include "hkdf.h"
#include "hmac-sha2.h"
#include "endian.h"
#include <math.h>
#include <iostream>
#include "../utils/utils.h"
#include <bitset>

struct HkdfLabel {
  uint16_t length;
  std::vector<uint8_t> label;
  std::vector<uint8_t> context;
} hkdflabel;

hkdf::hkdf(const std::vector<uint8_t> &salt, const std::vector<uint8_t> &ikm) {
/// \todo initialize based on salt and ikm using HKDF-Extract
  std::vector<uint8_t> valid_salt(hmac::digest_size, 0);
  if (ikm.empty()) {
    throw std::invalid_argument("The initial keying material cannot be empty.");
  }

  if (!salt.empty()) {
    valid_salt = salt;
  }

  hmac hmac(valid_salt.data(), valid_salt.size());
  hmac.update(ikm.data(), ikm.size());
  hmac::digest_storage prk = hmac.digest();

  std::copy(prk.begin(), prk.end(), this->h_key);
}

hkdf::hkdf(const std::vector<uint8_t> &prk) {
  //// \todo initialize based on the given PRK
  if (prk.empty()) {
    throw std::invalid_argument("Missing pseudo random key value.");
  } else {
    std::copy(prk.begin(), prk.end(), this->h_key);
  }
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

  int N = ceil(((float) len/(float) sizeof(this->h_key)));

  hmac hmac(this->h_key, sizeof(this->h_key));

  std::vector<uint8_t> okm;
  std::vector<uint8_t> T = {};

  uint8_t constant = 0x00;
  for (int i = 0; i < N; i++) {
    T = expand_helper(T, info, ++constant, hmac);
    okm.insert(okm.end(), T.begin(), T.end());
  }

  okm.resize(len);
  return okm;
}

std::vector<uint8_t> hkdf::expand_helper(std::vector<uint8_t> &input,
                                         const std::vector<uint8_t> &info,
                                         uint8_t constant,
                                         hmac hmac) {
  if (!input.empty()) {
    hmac.update(input.data(), input.size());
  }

  if (!info.empty()) {
    hmac.update(info.data(), info.size());
  }

  hmac.update(&constant, sizeof(constant));
  hmac_sha2::digest_storage digest = hmac.digest();
  std::vector<uint8_t> new_input;

  for (auto it = digest.begin(); it != digest.end(); ++it) {
    new_input.push_back(*it);
  }

  return new_input;
}

std::vector<uint8_t> hkdf::expand_label(const std::string &label,
                                        const std::vector<uint8_t> &context, size_t length) {
  /// \todo Implement HKDF-Expand-Label from TLS.
  if(label.empty()){
    throw std::invalid_argument("A label must be supplied");
  }

  hkdflabel.length = htob<uint16_t>(length);
  hkdflabel.context = context;

  for (unsigned int i = 0; i < label.size(); ++i) {
    hkdflabel.label.push_back(label[i]);
  }

  std::string tmp_label = "tls13 ";

  if((tmp_label.size() + hkdflabel.label.size()) < 7){
    throw std::invalid_argument("The label must be at least 7 bytes large.");
  }

  std::vector<uint8_t> info;
  info.resize(info.size() + sizeof(hkdflabel.length));
  memcpy(&info[info.size() - sizeof(hkdflabel.length)], &hkdflabel.length, sizeof(hkdflabel.length));

  info.push_back(htob<uint8_t>(hkdflabel.label.size() + tmp_label.size()) );
  for (unsigned int i = 0; i < tmp_label.size(); ++i) {
    info.push_back(tmp_label[i]);
  }

  for (unsigned int i = 0; i < hkdflabel.label.size(); ++i) {
    info.push_back(hkdflabel.label[i]);
  }

  info.push_back(htob<uint8_t>(hkdflabel.context.size()));
  for (unsigned int i = 0; i < hkdflabel.context.size(); ++i) {
    info.push_back(hkdflabel.context[i]);
  }

  return expand(info, length);
}

std::vector<uint8_t> hkdf::derive_secret(const std::string &label,
                                         const std::vector<uint8_t> &messages) {
  /// \todo Implement Derive-Secret from TLS.
  hmac transcript_hash(this->h_key, sizeof(this->h_key));
  transcript_hash.update(messages.data(), messages.size());

  hmac_sha2::digest_storage digest = transcript_hash.digest();
  std::vector<uint8_t> hashed_messages;

  for (auto it = digest.begin(); it!=digest.end(); ++it) {
    hashed_messages.push_back(*it);
  }

  return expand_label(label, hashed_messages, hashed_messages.size());
}


