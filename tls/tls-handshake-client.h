#ifndef TLS_HANDSHAKE_CLIENT_H
#define TLS_HANDSHAKE_CLIENT_H

#include <map>
#include <string>
#include <vector>

#include "ecdh.h"
#include "tls-record-layer.h"
#include "tls.h"
#include "hmac-sha2.h"

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

  std::vector<uint8_t> pld_calc();
  std::vector<uint8_t> ext_calc();
  void psk_calc(uint16_t &pre_key_size, std::vector<uint8_t> &pre_shared_key_vec);
  std::vector<uint8_t> expand(std::vector<uint8_t> pld, uint8_t *exp, uint16_t size, bool);
  void params_from_server(std::vector<uint8_t> server_hello);
  std::vector<uint8_t> con_message();
  hmac_sha2::digest_storage verify(std::vector<uint8_t> &messages, std::vector<uint8_t> &finished_key);

  HandshakePayload client_pld;
  std::vector<uint8_t> hello_client;
  random_struct random_data;
  handshake_message_header header;

  std::vector<uint8_t> pld; //client payload
  std::vector<uint8_t> exts; //client extensions

  std::vector<uint8_t> server_hello;
  std::vector<uint8_t> server_hello_;
  std::vector<uint8_t> server_header;

  std::vector<uint8_t> finished_server;
  cipher_suite server_cipher;
  std::vector<uint8_t> server_psk;
  std::vector<uint8_t> ecdh_shared_secret_;
  std::vector<uint8_t> server_key_share_;
};

#endif // TLS_HANDSHAKE_CLIENT_H
