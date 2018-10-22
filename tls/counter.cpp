#include "counter.h"
#include "endian.h"

#include <string.h>


incrementing_nonce::incrementing_nonce(const std::vector<uint8_t>& bytes) {
	for (unsigned int i = 0; i < bytes.size(); i++) {
		this->nonce_data.push_back(bytes[i]);
		this->init_nonce_data.push_back(bytes[i]);
	}
	this->internal_counter = 0;

}

incrementing_nonce& incrementing_nonce::operator++() {
	this->internal_counter++;
	uint64_t counter;
	memcpy(&counter, this->init_nonce_data.data() + this->init_nonce_data.size() - 8, sizeof counter);
	counter = counter ^ hton<uint64_t>(this->internal_counter);
	memcpy(this->nonce_data.data() + this->nonce_data.size() - 8, &counter, sizeof counter);
  return *this;
}

void incrementing_nonce::reset(const std::vector<uint8_t>& bytes) {
	memcpy(this->nonce_data.data(), bytes.data(), bytes.size());
}

const std::vector<uint8_t> incrementing_nonce::nonce() {
	std::vector<uint8_t> copy;
	for(unsigned int i = 0; i < this->nonce_data.size(); i++) {
		copy.push_back(this->nonce_data[i]);
	}
	return copy;
}
