#include "tls-handshake-server.h"


tls_handshake_server::tls_handshake_server(tls_record_layer& layer, const psk_map& psks)
  : layer_(layer), psks_(psks), ecdh_(SECP256R1), fixed_randomness_({{0}}),
    have_fixed_randomness_(false)
{
  ecdh_.generate_key_pair();
}

tls_handshake_server::tls_handshake_server(tls_record_layer& layer, const psk_map& psks,
                                           const random_struct& fixed_randomness,
                                           const gfp_t& ecdh_private)
  : layer_(layer), psks_(psks), ecdh_(SECP256R1), fixed_randomness_(fixed_randomness),
    have_fixed_randomness_(true)
{
  ecdh_.set_private_key(ecdh_private);
}


alert_location tls_handshake_server::read_client_hello()
{
  /// \todo read the ClientHello message from the record layer and handle it
  return {local, internal_error};
}

void tls_handshake_server::send_server_hello()
{
/// \todo write the ServerHello message to the record layer
/// If have_fixed_randomness_ is false, generate random data.
/// If it is true, use fixed_randomness_ as random data.
}

void tls_handshake_server::send_finished()
{
/// \todo write the Finished message to the record layer
}

alert_location tls_handshake_server::read_finished()
{
  /// \todo read the Finished message from the record layer and handle it
  return {local, internal_error};
}

alert_location tls_handshake_server::answer_handshake()
{
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

