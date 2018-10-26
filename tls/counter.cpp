#include "counter.h"
#include "endian.h"

#include <string.h>

/**
 * Initialises the counter with the given data
 */
incrementing_nonce::incrementing_nonce(const std::vector<uint8_t>& bytes) {
	for (unsigned int i = 0; i < bytes.size(); i++) {
		// initialize IV and nonce
		this->nonce_data.push_back(bytes[i]);
		this->init_nonce_data.push_back(bytes[i]);
	}
	this->internal_counter = 0;
}

/**
 * Increments the counter by one and generates a new nonce by XORing the counter and the IV.
 */
incrementing_nonce& incrementing_nonce::operator++() {
	this->internal_counter++; // increment counter

	uint64_t counter;
	memcpy(&counter, this->init_nonce_data.data() + this->init_nonce_data.size() - 8, sizeof counter);

	counter = counter ^ hton<uint64_t>(this->internal_counter); //XOR counter with Big endian counter
	memcpy(this->nonce_data.data() + this->nonce_data.size() - 8, &counter, sizeof counter);

	return *this;
}

/**
 * Replaces the current nonce with the given data
 * @param bytes
 */
void incrementing_nonce::reset(const std::vector<uint8_t>& bytes) {
	bool k = this->nonce_data.size() == bytes.size() ? true : false;
	for(unsigned int i = 0; i < this->nonce_data.size(); i++) {
		this->nonce_data[i] = (this->nonce_data[i] & !k) ^ (bytes[i] & k);
	}
}

/**
 * Returns the current nonce value
 * @return nonce value
 */
const std::vector<uint8_t> incrementing_nonce::nonce() {
	std::vector<uint8_t> copy;
	for(unsigned int i = 0; i < this->nonce_data.size(); i++) {
		copy.push_back(this->nonce_data[i]);
	}
	return copy;
}
