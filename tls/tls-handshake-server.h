#ifndef TLS_HANDSHAKE_SERVER_H
#define TLS_HANDSHAKE_SERVER_H

#include <map>
#include <vector>

#include "ecdh.h"
#include "tls-record-layer.h"
#include "tls.h"

/// Server side of the handshake
class tls_handshake_server
{
public:
  /// Instantiate new server-side handshake.
  tls_handshake_server(tls_record_layer& layer, const psk_map& psks);
  /// Instantiate new server-side handshake with fixed randomness and fixed ECDH private key.
  tls_handshake_server(tls_record_layer& layer, const psk_map& psks,
                       const random_struct& fixed_randomness, const gfp_t& ecdh_private);

  /// Run the server side of the handshake.
  alert_location answer_handshake();

private:
  alert_location read_client_hello();
  void send_server_hello();
  void send_server_hello_done();
  alert_location read_client_key_exchange();
  alert_location read_finished();
  void send_finished();

  tls_record_layer& layer_;
  const psk_map psks_;

  ecdh ecdh_;
  const random_struct fixed_randomness_;
  const bool have_fixed_randomness_;

};

#endif // TLS_HANDSHAKE_SERVER_H
