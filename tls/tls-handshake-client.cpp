#include "tls-handshake-client.h"

#include "hkdf.h"
#include "random.h"


tls_handshake_client::tls_handshake_client(tls_record_layer& layer, const psk_map& psks)
  : layer_(layer), psks_(psks), ecdh_(SECP256R1), fixed_randomness_({{0}}),
    have_fixed_randomness_(false)
{
  ecdh_.generate_key_pair();
}

tls_handshake_client::tls_handshake_client(tls_record_layer& layer,
                                           const std::map<std::string, std::vector<uint8_t>>& psks,
                                           const random_struct& fixed_randomness,
                                           const gfp_t& ecdh_private)
  : layer_(layer), psks_(psks), ecdh_(SECP256R1), fixed_randomness_(fixed_randomness),
    have_fixed_randomness_(true)
{
  ecdh_.set_private_key(ecdh_private);
}


alert_location tls_handshake_client::start_handshake(const std::vector<std::string>& psk_identities)
{
  for (const std::string& psk_identity : psk_identities)
  {
    if (psks_.find(psk_identity) == psks_.end())
      return {local, internal_error};
  }
  psk_identities_ = psk_identities;

  alert_location alert;
  // send ClientHello
  send_client_hello();
  // read ServerHello
  alert = read_server_hello();
  if (!alert)
    return alert;
  // read Finished
  alert = read_finished();
  if (!alert)
    return alert;
  // write Finished
  send_finished();
  return {local, ok};
}

void tls_handshake_client::send_client_hello()
{
/// \todo: Send ClientHello message
/// If have_fixed_randomness_ is false generate random data.
/// If it is true, use fixed_randomness_ as random data. In this case it is always 32 byte
/// large.
  random_struct rand;
  if(!have_fixed_randomness_) {
    get_random_data(rand.random_bytes, 32);
  } else {
    rand = this->fixed_randomness_;
  }

  std::vector<cipher_suite> cipher_suites;
  cipher_suites.push_back(TLS_AES_128_GCM_SHA256);
  cipher_suites.push_back(TLS_ASCON_128_SHA256);


  std::vector<uint8_t> legacy_compression_method;
  legacy_compression_method.push_back(1);
  legacy_compression_method.push_back(0);

  std::vector<uint8_t> data;
  data.push_back(2);
  data.push_back(TLSv1_3_MAJOR);
  data.push_back(TLSv1_3_MINOR);

  Extension ext;
  ext.type = SUPPORTED_VERSIONS;
  ext.data = data;

  std::vector<Extension> extention;
  extention.push_back(ext); 

  HandshakePayload unghhhh;
  unghhhh.legacy_version              = 0x0303; // i dont like casting
  unghhhh.random                      = rand;
  unghhhh.legacy_session_id           = legacy_compression_method; // should be set by Server
  unghhhh.cipher_suites               = cipher_suites;
  unghhhh.legacy_compression_methods  = legacy_compression_method;
  unghhhh.extentions                  = extention;

  std::vector<uint8_t> payload;
  payload.resize(sizeof(unghhhh));

  memcpy(payload.data(), &unghhhh, sizeof(unghhhh));

  this->layer_.write(TLS_HANDSHAKE, payload);
}

alert_location tls_handshake_client::read_server_hello()
{
  /// \todo Read and handle ServerHello message
  std::vector<uint8_t> data;

  alert_location alert = this->layer_.read(TLS_HANDSHAKE, data, 
                                          sizeof(handshake_message_header));

  if(!alert) {
    return {local, handshake_failure};
  }

  // get legacy version
  size_t head = 0;
  if(data.size() < 3) {
    return {local, handshake_failure};
  }

  uint8_t major = data[head++];
  uint8_t minor = data[head++];

  if(major != TLSv1_2_MAJOR || minor != TLSv1_2_MINOR) {
    return {local, handshake_failure};
  }

  this->h_payload_.legacy_version = 0x0303; //forgive me


  // get random vector
  if(data.size() < head + sizeof(random_struct)) {
    return {local, handshake_failure};
  }

  random_struct tmp_rnd;
  memcpy((uint8_t*)(&tmp_rnd), data.data() + head, sizeof(random_struct));
  head += sizeof(random_struct);

  this->h_payload_.random = tmp_rnd;

  // get session id
  if(data.size() < head + (size_t)data[head] || data[head] == 0) {
    return {local, handshake_failure};
  }

  std::vector<uint8_t>tmp_lsi;
  for(unsigned int i = 1; i <= data[head]; i++) {
    tmp_lsi.push_back(data[head + i]);
  }
  head += data[head] + 1;

  this->h_payload_.legacy_session_id = tmp_lsi;

  // get cipher suite
  if(data.size() < head + 2) {
    return {local, handshake_failure};
  }

  cipher_suite tmp_ciph = {data[head++], data[head++]};

  if(tmp_ciph != TLS_AES_128_GCM_SHA256 || tmp_ciph != TLS_ASCON_128_SHA256) {
    return {local, handshake_failure};
  }

  std::vector<cipher_suite> tmp_cs;
  tmp_cs.push_back(tmp_ciph);

  this->h_payload_.cipher_suites = tmp_cs;

  // get compression method
  if(data.size() < head + (size_t)data[head] && data[head] != 1) {
    return {local, handshake_failure};
  }

  std::vector<uint8_t> tmp_compr;
  for(unsigned int i = 1 ; i <= data[head]; i++) {
    tmp_compr.push_back(data[head + i]);
  }
  head += data[head] + 1;
  if(tmp_compr[0] != 0) {
    return {local, handshake_failure}; // compression must be none
  }

  this->h_payload_.legacy_compression_methods = tmp_compr;

  // extensions shouldn't be sent

  return {local, ok};
}

void tls_handshake_client::send_finished()
{
/// \todo Send Finished message.

  std::vector<uint8_t> finished;


}

alert_location tls_handshake_client::read_finished()
{
  /// \todo Read and handle Finished message
  return {local, internal_error};
}


