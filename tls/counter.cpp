#include "counter.h"
#include "endian.h"


incrementing_nonce::incrementing_nonce(const std::vector<uint8_t>& bytes) {
	for (unsigned int i = 0; i < bytes.size(); i++) {
		this.nonce_data.push_back(bytes[i]);
	}
	this.counter = 0;
}

incrementing_nonce& incrementing_nonce::operator++() {
	uint64_t counter = (this.nonce_data[this.nonce_data.size() - 8] << 56) |
						(this.nonce_data[this.nonce_data.size() - 7] << 48) |
						(this.nonce_data[this.nonce_data.size() - 6] << 40) |
						(this.nonce_data[this.nonce_data.size() - 5] << 32) |
						(this.nonce_data[this.nonce_data.size() - 4] << 24) |
						(this.nonce_data[this.nonce_data.size() - 3] << 16) |
						(this.nonce_data[this.nonce_data.size() - 2] << 8) |
						(this.nonce_data[this.nonce_data.size() - 1]);
	counter++;
	this.counter++;
	
	std::std::vector<uint8_t> tmp = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
										0x00, 0x00};
	std::memcpy(tmp, &counter, sizeof counter);

	for(unsigned int i = 0; i < tmp.size(); i++) {
		this.nonce_data[this.nonce_data.size() - 8 + i] = tmp[i];
	}
  return *this;
}

void incrementing_nonce::reset(const std::vector<uint8_t>& bytes) {
	uint64_t counter = (this.nonce_data[this.nonce_data.size() - 8] << 56) |
						(this.nonce_data[this.nonce_data.size() - 7] << 48) |
						(this.nonce_data[this.nonce_data.size() - 6] << 40) |
						(this.nonce_data[this.nonce_data.size() - 5] << 32) |
						(this.nonce_data[this.nonce_data.size() - 4] << 24) |
						(this.nonce_data[this.nonce_data.size() - 3] << 16) |
						(this.nonce_data[this.nonce_data.size() - 2] << 8) |
						(this.nonce_data[this.nonce_data.size() - 1]);
	counter -= this.counter;

	std::std::vector<uint8_t> tmp = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
										0x00, 0x00};
	std::memcpy(tmp, &counter, sizeof counter);

	for(unsigned int i = 0; i < tmp.size(); i++) {
		this.nonce_data[this.nonce_data.size() - 8 + i] = tmp[i];
	}
}

const std::vector<uint8_t>& incrementing_nonce::nonce() {
	std::vector<uint8_t> copy;
	for(unsigned int i = 0; i < this.nonce_data.size(); i++) {
		copy.push_back(this.nonce_data[i]);
	}
	return *copy;
}
