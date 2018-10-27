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
  //TODO: add check for IKM and allow optional Salt
  std::vector<uint8_t> data;
  data.insert(data.end(), salt.begin(), salt.end());
  data.insert(data.end(), ikm.begin(), ikm.end());

  hmac hmac(ikm.data(), sizeof(ikm));
  hmac.update(data.data(), sizeof(data));
  hmac_sha2::digest_storage prk = hmac.digest();
  std::copy(prk.begin(), prk.end(), this->h_key);

  std::cout << "Created HKDF" << std::endl;
  std::cout << "Hash length: " << sizeof(this->h_key) << std::endl;
}

hkdf::hkdf(const std::vector<uint8_t> &prk) {
  //// \todo initialize based on the given PRK
  if (prk.empty()) {
    throw std::runtime_error("Missing argument"); //TODO: need to do a proper exception
  } else {
    std::copy(prk.begin(), prk.end(), this->h_key);
  }
  std::cout << "Created HKDF 2" << std::endl;
}

std::vector<uint8_t> hkdf::expand(const std::vector<uint8_t> &info, size_t len) {
  //// \todo Return HKDF-Expand for given info and length

  std::cout << "Expanding HKDF" << std::endl;
  std::cout << len << "/" << sizeof(this->h_key)<< std::endl;
  int N = (int)ceil((float)len/(float)sizeof(this->h_key)); // N is wrong!
  std::cout << "N = " << N << std::endl;
  std::vector<uint8_t> init_t;
  hmac hmac(this->h_key, sizeof(this->h_key));
  std::vector<uint8_t> result = expand_helper(init_t, info, 0x01, N, hmac);

  return result;
}

std::vector<uint8_t> hkdf::expand_helper(std::vector<uint8_t> &input,
                                         const std::vector<uint8_t> &info,
                                         int counter,
                                         int N, hmac hmac) {

  std::cout << "Expanding Helper HKDF" << std::endl;

  if (N > 0) {
    std::cout << "Expanding Helper Inside HKDF N= " << N << std::endl;
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
    std::cout << "ßßßßßßßßßßßßßßßßßßß" << std::endl;
    for(unsigned int i = 0; i < new_input.size(); i++) {
      std::cout << (unsigned)new_input[i] << ", " ;
    }
    std::cout << "Current new input length " << new_input.size() << std::endl;
    std::vector<uint8_t> result = expand_helper(new_input, info, ++counter, --N, hmac);
    result.insert(result.begin(), new_input.begin(), new_input.end());
    std::cout << "Current result length " << result.size() << std::endl;
    return result;
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
