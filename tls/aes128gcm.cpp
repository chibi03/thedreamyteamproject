#include "aes128gcm.h"
#include "aes/aes128.h"
#include <iostream>
#include <math.h>
#include <cstring>
#include <algorithm>
#include "random.h"

// Take care to program the GCM specific functions in constant time,
// meaning that no conditional branches or conditional loads that depend
// on the key, the nonce or the data are allowed. This means that the
// program flow should be fully independent from the input data.
// Do not make any assumptions on the cache line sizes and stack alignment.


aes128gcm::aes128gcm(){
/// \todo Initialize with an all 0 key.
    for(auto i = key_locker.begin(); i<=key_locker.end(); i++){
        *i = 0;
    }
}

aes128gcm::aes128gcm(const key_storage& key)
{
  /// \todo Initialise with the given key.
  set_key(key);
}

void aes128gcm::set_key(const key_storage& key)
{
  /// \todo Reset the key.
  for(size_t i = 0; i < key_size; i++){
      key_locker.at(i) = key.at(i);
  }
}

bool aes128gcm::encrypt(std::vector<uint8_t>& ciphertext, const std::vector<uint8_t>& plaintext,
                        const std::vector<uint8_t>& nonce_data,
                        const std::vector<uint8_t>& additional_data) const
{
  if(plaintext.empty() || nonce_data.empty()) {
    return false;
  }
  else{
    std::array<uint8_t, 16> y = {}, H = {};
    aes128 aes = aes128(key_locker.data());
    aes.encrypt(H.data(), y.data());
    std::array<uint8_t, 16> j = {};
    j.at(15) = 1;
    for(size_t i = 0; i < nonce_data.size(); i++){
        j.at(i) = nonce_data.at(i);
    }
    std::vector<uint8_t> c = gctr(key_locker, increment(j), plaintext);
    std::vector<uint8_t> T = gctr(key_locker, j, ghash(H, hash_arg_calc(additional_data, c)));
    ciphertext.insert(ciphertext.end(), c.begin(), c.end());
    ciphertext.insert(ciphertext.end(), T.begin(), T.end());
    return true;
  }
}

bool aes128gcm::decrypt(std::vector<uint8_t>& plaintext, const std::vector<uint8_t>& ciphertext,
                        const std::vector<uint8_t>& nonce_data,
                        const std::vector<uint8_t>& additional_data) const
{
  /// \todo Decrypt ciphertext using AEs-GCM with the given nonce and additional data.
    if(ciphertext.empty() || nonce_data.empty()) {
        return false;
    }
    std::vector<uint8_t> c = {}, t = {};
    c.insert(c.end(), ciphertext.begin(), ciphertext.end() - 16);
    t.insert(t.end(), ciphertext.end() - 16, ciphertext.end());
    std::array<uint8_t, 16> y = {}, H = {};
    aes128 aes = aes128(key_locker.data());
    aes.encrypt(H.data(), y.data());
    std::array<uint8_t, 16> j = {};
    j.at(15) = 1;
    for(size_t i = 0; i < nonce_data.size(); i++){
        j.at(i) = nonce_data.at(i);
    }
    std::vector<uint8_t> T = gctr(key_locker, j, ghash(H, hash_arg_calc(additional_data, c)));
    if (std::memcmp(T.data(), t.data(), 16) != 0){
        return false;
    }
    else
        plaintext = gctr(key_locker, increment(j), c);
        return true;
}

std::vector<uint8_t> aes128gcm::hash_arg_calc (const std::vector<uint8_t>& additional_data, const std::vector<uint8_t> c) const {
    size_t ad_lenght = additional_data.size();
    size_t c_length = c.size();
    size_t u = 128 * ceil(c_length * 8/128.) - c_length * 8;
    size_t v = 128 * ceil(ad_lenght * 8/128.) - ad_lenght * 8;
    std::vector<uint8_t> args(additional_data),  add_zeros_v (v/8), add_zeros_u (u/8);
    args.insert(args.end(), add_zeros_v.begin(), add_zeros_v.end());
    args.insert(args.end(), c.begin(), c.end());
    args.insert(args.end(), add_zeros_u.begin(), add_zeros_u.end());

    ad_lenght *= 8;
    c_length *= 8;

    std::array<uint8_t, sizeof(size_t)> larray = {};

    std::memcpy(larray.data(), &ad_lenght, sizeof(ad_lenght));
    std::reverse(larray.begin(), larray.end());
    args.insert(args.end(), larray.begin(), larray.end());

    std::memcpy(larray.data(), &c_length, sizeof(c_length));
    std::reverse(larray.begin(), larray.end());
    args.insert(args.end(), larray.begin(), larray.end()); 

    return args;
}


std::array<uint8_t, 16>  aes128gcm::increment(std::array<uint8_t, 16> const &bitstring) const{
    std::array<uint8_t, 16> output;
    uint8_t r = 1;

    for(size_t i = 0; i < 13; i++){
        output.at(i) = bitstring.at(i);
    }
    for(size_t i = 0; i < 4; i++){
        output.at(15 - i) = bitstring.at(15 - i) + r;
        r = bitstring.at(15 - i) + r < bitstring.at(15 - i);
    }
    return output;
}

std::vector<uint8_t> aes128gcm::ghash(std::array<uint8_t, 16>const &H, std::vector<uint8_t>const &plaintext)const{
    std::vector<uint8_t> output;
    std::array<uint8_t, 16> y = {}, tmp1 = {}, tmp2 = {};
    size_t chunks = ceil(plaintext.size()/16);
    for(size_t i = 0; i < chunks; i++){
        for(size_t j = 0; j < 16; j++){
            bool flag = plaintext.size() >= 16 * i + j ? true : false;
            tmp1.at(j) = flag ? plaintext.at(16 * i + j) : 0;
        }
        for(size_t i = 0; i < 16; i++) {
            tmp2.at(i) = tmp1.at(i) ^ (y.at(i) * 1);
        }
        y = multiply(tmp2, H);
    }
    output.insert(output.end(), y.begin(), y.end());
    return output;
}

std::vector<uint8_t> aes128gcm::gctr(std::array<uint8_t, 16>const &k, std::array<uint8_t, 16>const &c, std::vector<uint8_t>const &plaintext)const{
    if(plaintext.size() == 0){
        return {};
    }
    std::vector<uint8_t> output;
    std::array<uint8_t, 16> ciphertext(c), n_ciphertext = {}, tmp;
    unsigned int n = plaintext.size() / 16 + 1;
    aes128 aes = aes128(k.data());

    for(unsigned int i = 0; i < n - 1; i++){
        aes.encrypt(n_ciphertext.data(), ciphertext.data());
        for(unsigned int j = 0; j < 16; j++){
            tmp = {};
            tmp.at(j) = plaintext.at(16 * i + j);
            output.push_back(tmp.at(j) ^ n_ciphertext.at(j));
        }
        ciphertext = increment(ciphertext);
    }

    aes.encrypt(n_ciphertext.data(), ciphertext.data());
    size_t chunk = plaintext.size() - 16 * n + 16;

    for(size_t i = 0; i < chunk; i++){
        output.push_back(plaintext.at(16 * n - 16 + i) ^ n_ciphertext.at(i));
    }
    return output;
}

std::array<uint8_t, 16> aes128gcm::multiply(std::array<uint8_t, 16>const &X, std::array<uint8_t, 16> const &Y)const{
    std::array<uint8_t, 16> R = {}, z = {}, tmp;
    std::array<uint8_t, 16> v(Y);
    uint8_t shift = 0;
    R.at(0) = 0xe1;

    for(int i=0;i <= 127; i++){
        shift = 0; // to cycle shifting
        tmp = {};
        int mask =  ((X.at(i/8) >> (7 - i % 8)) & 1);

        for(size_t i = 0; i < 16; i++) {
            z.at(i) = z.at(i) ^ (v.at(i) * mask);
        }
        
        for(size_t i = 0; i < 16; i++){
            tmp.at(i) = (v.at(i) >> 1) | shift;
            shift = v.at(i) & 1;
            shift <<= 7;
        }

        mask = v.at(15) & 1;
        for(size_t i = 0; i < 16; i++) {
            v.at(i) = tmp.at(i) ^ (R.at(i) * mask);
        }
    }
    return z;
}