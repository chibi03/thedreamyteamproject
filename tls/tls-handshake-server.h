#ifndef TLS_HANDSHAKE_SERVER_H
#define TLS_HANDSHAKE_SERVER_H

#include <map>
#include <vector>

#include "ecdh.h"
#include "tls-record-layer.h"
#include "tls.h"

/// Server side of the handshake
class tls_handshake_server {
 public:
  /// Instantiate new server-side handshake.
  tls_handshake_server(tls_record_layer &layer, const psk_map &psks);
  /// Instantiate new server-side handshake with fixed randomness and fixed ECDH private key.
  tls_handshake_server(tls_record_layer &layer, const psk_map &psks,
                       const random_struct &fixed_randomness, const gfp_t &ecdh_private);

  /// Run the server side of the handshake.
  alert_location answer_handshake();

 private:
  alert_location read_client_hello();
  alert_location process_extensions(std::vector<uint8_t> extensions);

  void send_server_hello();
  void send_server_hello_done();
  alert_location read_client_key_exchange();
  alert_location read_finished();
  void send_finished();

  tls_record_layer &layer_;
  const psk_map psks_;

  ecdh ecdh_;
  const random_struct fixed_randomness_;
  const bool have_fixed_randomness_;

  HandshakePayload received;
  //hkdf hkdf_hashing;

  /**
   * From https://github.com/randombit/botan
   * Make a uint16_t from two bytes
   * @param i0 the first byte
   * @param i1 the second byte
   * @return i0 || i1
   */
  uint16_t make_uint16(uint8_t i0, uint8_t i1) {
    return static_cast<uint16_t>((static_cast<uint16_t>(i0) << 8) | i1);
  }

};

#endif // TLS_HANDSHAKE_SERVER_H
