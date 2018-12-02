#include "tls-handshake-server.h"
#include <cstring>
#include "endian.h"
#include "hkdf.h"
#include "hmac-sha2.h"
#include "random.h"



tls_handshake_server::tls_handshake_server(tls_record_layer &layer, const psk_map &psks)
    : layer_(layer), psks_(psks), ecdh_(SECP256R1), fixed_randomness_({{0}}),
      have_fixed_randomness_(false) {
  ecdh_.generate_key_pair();
}

tls_handshake_server::tls_handshake_server(tls_record_layer &layer, const psk_map &psks,
                                           const random_struct &fixed_randomness,
                                           const gfp_t &ecdh_private)
    : layer_(layer), psks_(psks), ecdh_(SECP256R1), fixed_randomness_(fixed_randomness),
      have_fixed_randomness_(true) {
  ecdh_.set_private_key(ecdh_private);
}

alert_location tls_handshake_server::process_extensions(std::vector<uint8_t> extensions) {
  if (extensions.size() < 2) { // minimal length is 2 bytes
    return {local, handshake_failure};
  }

  uint16_t index = 0;
  while ((extensions.size() - index + 1) > 0) {
    uint16_t code = make_uint16(extensions[index], extensions[index + 1]);
    index += 2;
    uint16_t size = ntoh(make_uint16(extensions[index], extensions[index + 1]));
    index += 2;

    std::vector<uint8_t> data(extensions.begin() + index, (extensions.begin() + index + size));

    Extension deserializedExt;
    deserializedExt.type = static_cast<ExtensionType>(code);
    deserializedExt.data = data;
    index += size;
    received.extentions.push_back(deserializedExt);
  }

  // If the preshared key extension is sent by the client, it has to be sent at the end.
  Extension presharedkey;
  presharedkey.type = PRE_SHARED_KEY;
  if(std::find(received.extentions.begin(), received.extentions.end(), presharedkey) != received.extentions.end()){
    if(received.extentions.back().type != PRE_SHARED_KEY){
      return {local, illegal_parameter};
    }
  }

  return {local, ok};
}

alert_location tls_handshake_server::read_client_hello() {
  /// \todo read the ClientHello message from the record layer and handle it
  std::vector<uint8_t> data;

  alert_location
      alert = layer_.read(TLS_HANDSHAKE, data, sizeof(handshake_message_header), true); // should it really block?

  if (!alert) {
    return {local, handshake_failure};
  }

  size_t index = 0;

  // check legacy protocol version
  uint8_t major = data[index++];
  uint8_t minor = data[index++];
  if (major!=TLSv1_2_MAJOR || minor!=TLSv1_2_MINOR) {
    return {local, handshake_failure};
  }
  received.legacy_version = make_uint16(major, minor);

  // get the random number
  random_struct random;
  std::vector<uint8_t> vector_rand_section(&data[index],&data[index+32]);
  memcpy(&random, vector_rand_section.data(), 32);
  received.random = random;
  index += 32;

  // process the session id
  uint8_t legacy_session_id_length(ntoh(data[index]));
  if (legacy_session_id_length > 32) {
    return {local, handshake_failure};
  } else if(legacy_session_id_length > 0 ){
    // compatiblity mode, here a session id is provided as specified in RFC 8446 Appendix D.4
    memcpy(received.legacy_session_id.data(), &data[++index], legacy_session_id_length);
  }
  index += legacy_session_id_length;


  //check cipher suites that are supported
  uint8_t cipher_suite_length = ntoh(data[index]);
  if (cipher_suite_length < 2 || cipher_suite_length > (sizeof(uint16_t)*16 - 2)) {
    return {local, handshake_failure};
  }

  index += 2; //as the length has 2 bytes to store the max length of the cipher suites

  std::vector<uint8_t> supported_cipher_suites (&data[index], &data[index+cipher_suite_length]);
  std::vector<cipher_suite> supported = get_cipher_suites(supported_cipher_suites);

  if ((std::find(supported.begin(), supported.end(), TLS_AES_128_GCM_SHA256) == supported.end()) && (std::find(supported.begin(), supported.end(), TLS_ASCON_128_SHA256) == supported.end())) {
    return {local, handshake_failure}; //check if error correct
  }
  received.cipher_suites = supported;

  uint8_t legacy_compression_methods_length = ntoh(data[index++]);
  // If the client is using TLS 1.2 the compression handling needs to be processed
  // TLS 1.3 can only receive a 1 byte entry with value 0

  if (legacy_compression_methods_length!=1 ) {
    return {local, illegal_parameter};
  }

  uint8_t legacy_compression_methods = ntoh(data[index++]);
  if (legacy_compression_methods!=0) {
    return {local, illegal_parameter};
  }

  std::vector<uint8_t> extensions(data.begin() + index, data.end());
  return process_extensions(extensions);
}

void tls_handshake_server::send_server_hello() {
/// \todo write the ServerHello message to the record layer
/// If have_fixed_randomness_ is false, generate random data.
/// If it is true, use fixed_randomness_ as random data.


  random_struct randomVal = {};
  get_random_data(randomVal.random_bytes, 32);

  HandshakePayload handshakeData;
  handshakeData.random = randomVal;
  handshakeData.legacy_version = make_uint16(TLSv1_2_MAJOR, TLSv1_2_MINOR);
  handshakeData.legacy_session_id = received.legacy_session_id;
  handshakeData.legacy_compression_methods = {0};
  handshakeData.cipher_suites = std::vector<cipher_suite>{received.cipher_suites.front()};

  std::vector<Extension> send_ext;

  //respond to extensions
  Extension keyShare;
  Extension preSharedKey;
  Extension supported_versions;

  std::vector<Extension> received_ext = received.extentions;
  for(unsigned int i = 0; i< received_ext.size(); i++){
    ExtensionType type = received_ext[i].type;

    switch (type){
      case SUPPORTED_VERSIONS:
        //select_supported_version();
        break;
      case SUPPORTED_GROUPS:
        //select_supported_group();
        break;
      case PRE_SHARED_KEY:
        //process_psk();
        break;
      case PSK_KEY_EXCHANGE_MODES:
        //select_psk_exchange_mode();
        break;
      case KEY_SHARE:
        break;
    }

  }

  handshakeData.extentions = send_ext;

  std::vector<uint8_t> payload; // the complete handshake message
  memcpy(payload.data(), &handshakeData, sizeof(handshakeData));

  this->layer_.write(TLS_HANDSHAKE, payload);
}

void tls_handshake_server::send_finished() {
/// \todo write the Finished message to the record layer
}

alert_location tls_handshake_server::read_finished() {
  /// \todo read the Finished message from the record layer and handle it
  return {local, internal_error};
}

alert_location tls_handshake_server::answer_handshake() {
  // read ClientHello
  alert_location alert = read_client_hello();
  if (!alert)
    return alert;
  // send ServerHello
  send_server_hello();
  // send Finished
  send_finished();
  // read Finished
  return read_finished();
}

std::vector<cipher_suite> tls_handshake_server::get_cipher_suites(std::vector<uint8_t> data){
  std::vector<cipher_suite> cipher_suites = {};

  for (unsigned int i = 0; i < data.size(); i+=2) {
    cipher_suite elem = {data[i], data[i+1]};
    cipher_suites.push_back(elem);
  }
  return cipher_suites;
};
