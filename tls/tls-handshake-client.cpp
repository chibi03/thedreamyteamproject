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
  data.push_back(4);
  data.push_back(TLSv1_3_MAJOR);
  data.push_back(TLSv1_3_MINOR);

  Extension ext;
  ext.type = SUPPORTED_VERSIONS;
  ext.data = data;

  std::vector<Extension> extention;
  extention.push_back(ext); 

  HandshakePayload unghhhh;
  unghhhh.legacy_version              = 0x1301;
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
  return {local, internal_error};
}

alert_location tls_handshake_client::read_finished()
{
  /// \todo Read and handle Finished message
  return {local, internal_error};
}

void tls_handshake_client::send_finished()
{
/// \todo Send Finished message.
}

