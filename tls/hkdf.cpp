#include "hkdf.h"
#include <math.h> 

hkdf::hkdf(const std::vector<uint8_t>& salt, const std::vector<uint8_t>& ikm)
{
/// \todo initialize based on salt and ikm using HKDF-Extract
	memccpy(temp, hmac_sha2(salt, ikm), 64);
}

hkdf::hkdf(const std::vector<uint8_t>& prk)
{
  //// \todo initialize based on the given PRK
	if(prk.empty()){
		memset(temp, 0x00, 64);
	}
	else {
		memcpy(temp, & prk, 64);
	}
}

std::vector<uint8_t> hkdf::expand(const std::vector<uint8_t>& info, size_t len)
{
  //// \todo Return HKDF-Expand for given info and length
	uint8_t N = ceil(len/temp.size());
	uint8_t counter = 0x00;
	std::string T = nullptr;
	std::string OKM = nullptr;
	for (size_t i=0; i <= N; i++) {
		T = hmac(this->temp, T | info | counter);
		strcat(OKM, T);
		counter++;
	}
	return OKM.substr(0, len);
}

std::vector<uint8_t> hkdf::expand_label(const std::string& label,
                                        const std::vector<uint8_t>& context, size_t length)
{
  /// \todo Implement HKDF-Expand-Label from TLS.
	std::string conclbl = label;
	strcat(conclbl, context);
	strcat(conclbl, length.ToString());
	
  return conclbl;
}

std::vector<uint8_t> hkdf::derive_secret(const std::string& label,
                                         const std::vector<uint8_t>& messages)
{
  /// \todo Implement Derive-Secret from TLS.
	this->expand();
	expand_label(label, messages);
	return std::vector<uint8_t>();
}
