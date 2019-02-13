#ifndef TLS_RECORD_LAYER_H
#define TLS_RECORD_LAYER_H

#include <boost/asio.hpp>
#include <memory>

#include "tls-cipher.h"
#include "tls.h"

/// This class provides the record layer of a TLS connection. It sends and receives fragments
/// encrypted based on the current state of the connection.
class tls_record_layer
{

public:
  tls_record_layer(connection_end end, boost::asio::ip::tcp::socket&& socket);
  ~tls_record_layer();

  tls_record_layer(const tls_record_layer&) = delete;
  tls_record_layer& operator=(const tls_record_layer&) = delete;

  /// Activates the given cipher suite, i.e. updates the security parameters of the connection.
  void set_cipher_suite(cipher_suite suite);

  /// Compute the early secret using the PSK and messages. Store and return the derived secret for
  /// computing handshake traffic keys.
  std::vector<uint8_t> compute_early_secrets(const std::vector<uint8_t>& psk,
                                             const std::vector<uint8_t>& messages);
  /// Compute handshake traffic keys from internally stored early secret, DHE shared secret and
  /// messages. Store and return the derived secret for computing application data traffic keys, and
  /// also set up pending read and write state with those keys.
  std::vector<uint8_t> compute_handshake_traffic_keys(const std::vector<uint8_t>& dhe,
                                                      const std::vector<uint8_t>& messages);
  /// Compute application data traffic keys from internally stored secret and messages. Also set up
  /// pending read and write state with those keys.
  void compute_application_traffic_keys(const std::vector<uint8_t>& messages);

  /// Initialize read cipher from current traffic keys, i.e. replace current read state with pending
  /// read state.
  void update_read_key();
  /// Initialize write cipher from current traffic keys, i.e. replace current write state with
  /// pending write state.
  void update_write_key();

  /// Obtain key to create/verify Finished messages.
  std::vector<uint8_t> get_finished_key(connection_end entitiy);

  /// Read data of some content type. Unless wait_until_full is false, this function blocks until
  /// data was filled with length bytes.
  alert_location read(content_type type, std::vector<uint8_t>& data, size_t length,
                      bool wait_until_full = true);
  bool write(content_type type, const std::vector<uint8_t>& data);
  /// Write alert and disable sending.
  bool write_alert(AlertDescription alert);

  /// Decrypt an encrypted record.
  bool decrypt(const tls13_cipher::record& record, std::vector<uint8_t>& plaintext,
               content_type& type);
  /// Encrypt a fragment.
  bool encrypt(content_type type, const std::vector<uint8_t>& fragment,
               tls13_cipher::record& record);

  /// Security parameters of the connection.
  struct security_parameters
  {
    enum bulk_cipher_algorithm
    {
      BULK_CIPHER_NULL,
      ASCON,
      AESGCM
    };

    connection_end entity;
    bulk_cipher_algorithm bulk_cipher;
    uint8_t key_length;
    uint8_t iv_length;
  };
  /// Current set of security parameters
  security_parameters security_params;

  /// Defines the list of supported cipher suites and their order of preference.
  bool set_supported_cipher_suites(const cipher_suites& cs);
  /// Returns the list of supported cipher suites and their order of preference.
  const cipher_suites& get_supported_cipher_suites() const;

  //EARLY SECRET
  std::vector <uint8_t> e_secret;

  std::vector<uint8_t> s_hs_client;
  std::vector<uint8_t> s_hs_server;
  std::vector<uint8_t> h_salt;

private:
  static bool decode_header(record_layer_header& header, const std::vector<uint8_t>& data);
  static bool encode_header(std::vector<uint8_t>& data, const record_layer_header&);

  /// Read a a fragment of the desired type and store in the corresponding state.
  alert_location read(content_type desired_type);

  /// Write a record layer header to the socket
  void write_header(const record_layer_header& header);
  /// Read a record layer header from the socket
  bool read_header(record_layer_header& header);

  /// Send data via a socket. This function writes the full buffer stored in data to the socket.
  void write_to_socket(const std::vector<uint8_t>& data);

  /// Read data from a socket. This function reads data from the socket until the buffer is full.
  void read_from_socket(std::vector<uint8_t>& data);

  /// Decode a received alert.
  alert_location decode_alert(const std::vector<uint8_t>& content) const;

  /// Connection state, i.e. the cipher to be used. If cipher is null, no encryption is used.
  struct connection_state
  {
    std::shared_ptr<tls13_cipher> cipher;
  };

  /// Current read state
  connection_state current_read_state;
  /// Current write state
  connection_state current_write_state;
  /// Pending read state
  connection_state pending_read_state;
  /// Pending write state
  connection_state pending_write_state;
  /// The socket.
  boost::asio::ip::tcp::socket socket_;


  size_t hm_offset = 0;
  std::vector<uint8_t> handshake_messages;
  size_t ad_offset = 0;
  std::vector<uint8_t> application_data;

  cipher_suites cipher_suites_{TLS_ASCON_128_SHA256, TLS_AES_128_GCM_SHA256};


};

#endif // TLS_RECORD_LAYER_H
