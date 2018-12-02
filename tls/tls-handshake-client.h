#ifndef TLS_HANDSHAKE_CLIENT_H
#define TLS_HANDSHAKE_CLIENT_H

#include <map>
#include <string>
#include <vector>

#include "ecdh.h"
#include "tls-record-layer.h"
#include "tls.h"

/// The client-side of the handshake protocol implementation.
class tls_handshake_client
{
public:
  /// Instantiate a new client-side handshake.
  tls_handshake_client(tls_record_layer& layer, const psk_map& psks);
  /// Instantiate a new client-side handshake with a fixed randomness and a fixed ECDH private key.
  tls_handshake_client(tls_record_layer& layer, const psk_map& psks,
                       const random_struct& fixed_randomness, const gfp_t& ecdh_private);

  /// Run the handshake for the given identities.
  alert_location start_handshake(const std::vector<std::string>& psk_identity);

private:
  void send_client_hello();
  alert_location read_server_hello();
  alert_location read_server_hello_done();
  void send_finished();
  alert_location read_finished();

  /// The underlying record layer
  tls_record_layer& layer_;
  /// All available identities.
  const psk_map psks_;

  /// ECDH instance.
  ecdh ecdh_;
  /// Fixed randomness if given.
  const random_struct fixed_randomness_;
  /// Determines if fixed randomness was given and should be used.
  const bool have_fixed_randomness_;
  /// Selected identities.
  std::vector<std::string> psk_identities_;

  HandshakePayload h_payload_;

};

#endif // TLS_HANDSHAKE_CLIENT_H
