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

