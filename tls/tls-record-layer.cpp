#include "tls-record-layer.h"

#include "../utils/io.h"
#include "aes128gcm.h"
#include "ascon128.h"
#include "endian.h"
#include "tls-aesgcm.h"
#include "tls-ascon.h"
#include "hkdf.h"

using boost::asio::ip::tcp;

namespace
{
  constexpr std::array<cipher_suite, 2> implemented_cipher_suites{TLS_ASCON_128_SHA256,
                                                                  TLS_AES_128_GCM_SHA256};
  constexpr std::size_t MAX_FRAGMENT_LENGTH = 16384;
} // namespace

tls_record_layer::tls_record_layer(connection_end end, tcp::socket&& socket)
  : socket_(std::move(socket))
{
  security_params.entity = end;
}

tls_record_layer::~tls_record_layer() {}

bool tls_record_layer::set_supported_cipher_suites(const cipher_suites& cs)
{
  cipher_suites new_cs;

  const auto bit = std::cbegin(implemented_cipher_suites);
  const auto eit = std::cend(implemented_cipher_suites);
  for (const auto& suite : cs)
  {
    if (std::find(bit, eit, suite) == eit)
      // cipher suite is not implemented
      continue;

    if (std::find(std::begin(new_cs), std::end(new_cs), suite) == std::end(new_cs))
      new_cs.push_back(suite);
  }

  if (new_cs.empty())
    // none of the requested cipher suites is implemented
    return false;

  cipher_suites_ = std::move(new_cs);
  return true;
}

const cipher_suites& tls_record_layer::get_supported_cipher_suites() const
{
  return cipher_suites_;
}

bool tls_record_layer::decode_header(record_layer_header& header, const std::vector<uint8_t>& data)
{
  if (data.size() != sizeof(header) || data[0] < 20 || data[0] > 23)
    return false;

  header.type          = static_cast<content_type>(data[0]);
  header.version.major = data[1];
  header.version.minor = data[2];
  header.length        = (static_cast<uint16_t>(data[3]) << 8) | static_cast<uint16_t>(data[4]);

  return true;
}

bool tls_record_layer::encode_header(std::vector<uint8_t>& data, const record_layer_header& header)
{
  if (data.size() != sizeof(header))
    return false;

  data[0] = header.type;
  data[1] = header.version.major;
  data[2] = header.version.minor;
  data[3] = (header.length & 0xff00) >> 8;
  data[4] = header.length & 0xff;

  return true;
}

void tls_record_layer::write_header(const record_layer_header& header)
{
  std::vector<uint8_t> data(sizeof(record_layer_header));
  encode_header(data, header);
  write_to_socket(data);
}

bool tls_record_layer::read_header(record_layer_header& header)
{
  std::vector<uint8_t> data(sizeof(record_layer_header));
  read_from_socket(data);
  return decode_header(header, data);
}

void tls_record_layer::set_cipher_suite(cipher_suite suite)
{
  if (suite == TLS_ASCON_128_SHA256)
  {
    security_params.bulk_cipher = security_parameters::bulk_cipher_algorithm::ASCON;
    security_params.key_length  = ascon128::key_size;
    security_params.iv_length   = ascon128::nonce_size;
  }
  else if (suite == TLS_AES_128_GCM_SHA256)
  {
    security_params.bulk_cipher = security_parameters::bulk_cipher_algorithm::AESGCM;
    security_params.key_length  = aes128gcm::key_size;
    security_params.iv_length   = aes128gcm::nonce_size;
  }
}

void tls_record_layer::update_read_key()
{
  current_read_state = pending_read_state;
  pending_read_state.cipher.reset();
}

void tls_record_layer::update_write_key()
{
  current_write_state = pending_write_state;
  pending_write_state.cipher.reset();
}

bool tls_record_layer::write(content_type type, const std::vector<uint8_t>& data)
{
  const std::size_t nr_fragments = (data.size() / MAX_FRAGMENT_LENGTH) + 1;
  for (std::size_t idx = 0; idx < nr_fragments; ++idx)
  {
    const std::vector<uint8_t> fragment(
        data.begin() + MAX_FRAGMENT_LENGTH * idx,
        (idx == nr_fragments - 1) ? data.end() : (data.begin() + MAX_FRAGMENT_LENGTH * (idx + 1)));

    tls13_cipher::record record;
    if (!encrypt(type, fragment, record))
      return false;

    write_header(record.header);
    write_to_socket(record.ciphertext);
  }

  return true;
}

bool tls_record_layer::write_alert(AlertDescription alert)
{
  bool ret = write(TLS_ALERT, {AlertLevel::fatal, alert});
  // we won't send anything anymore after an alert.
  boost::system::error_code ec;
  socket_.shutdown(tcp::socket::shutdown_send, ec);
  return ret;
}

bool tls_record_layer::encrypt(content_type type, const std::vector<uint8_t>& fragment,
                               tls13_cipher::record& record)
{
  /// \todo encrypt the message
  if (security_params.bulk_cipher == security_parameters::bulk_cipher_algorithm::BULK_CIPHER_NULL) {
    record.header = {type, {TLSv1_2_MAJOR, TLSv1_2_MINOR}, (uint16_t) fragment.size()};
    record.ciphertext = fragment;
    return true;
  }
  else if(current_write_state.cipher) {
    record = current_write_state.cipher->encrypt(type, fragment);
    return true;
  }
  return false;
}

bool tls_record_layer::decrypt(const tls13_cipher::record& record, std::vector<uint8_t>& plaintext,
                               content_type& type)
{
  /// \todo Decrypt the given record using the current read cipher if set, and extract the plaintext
  /// otherwise.
  if (current_read_state.cipher) {
    auto dec = current_read_state.cipher->decrypt(record, plaintext, type);
    return dec;
  }
  plaintext = record.ciphertext;
  type = record.header.type;
  return true;
}

alert_location tls_record_layer::decode_alert(const std::vector<uint8_t>& content) const
{
  if (content.size() != 2)
    return {local, decode_error};
  const uint8_t level = content[0];
  if (level != 1 && level != 2)
    return {local, decode_error};
  return {remote, static_cast<AlertDescription>(content[1])};
}

alert_location tls_record_layer::read(content_type desired_type)
{
  tls13_cipher::record record;
  if (!read_header(record.header))
    return {local, decode_error};

  if (record.header.version != TLSv1_2)
    return {local, protocol_version};

  const std::size_t length = record.header.length;
  if (length > MAX_FRAGMENT_LENGTH)
    return {local, record_overflow};
  record.ciphertext.resize(length);
  read_from_socket(record.ciphertext);

  // decrypt fragment
  std::vector<uint8_t> plaintext;
  content_type type;
  if (decrypt(record, plaintext, type) == false)
    return {local, bad_record_mac};

  // unexpected message
  if (type != desired_type && type != TLS_ALERT)
    return {local, unexpected_message};

  switch (type)
  {
  case TLS_ALERT:
    return decode_alert(plaintext);
  case TLS_HANDSHAKE:
    handshake_messages.insert(handshake_messages.end(), plaintext.begin(), plaintext.end());
    break;
  case TLS_APPLICATION_DATA:
    application_data.insert(application_data.end(), plaintext.begin(), plaintext.end());
    break;
  default:
    return {local, decode_error};
  }
  return {local, ok};
}

alert_location tls_record_layer::read(content_type type, std::vector<uint8_t>& data, size_t length,
                                      bool block_until_full)
{
  switch (type)
  {
  case TLS_HANDSHAKE:
    // Read data until the desired amount is available.
    while (handshake_messages.size() - hm_offset < length)
    {
      const auto alert = read(TLS_HANDSHAKE);
      if (!alert)
      {
        if (alert.location == remote)
        {
          // Remote alert, so we won't receive any more data.
          boost::system::error_code ec;
          socket_.shutdown(tcp::socket::shutdown_receive, ec);
        }
        return alert;
      }
    }

    data.clear();
    data.insert(data.begin(), handshake_messages.begin() + hm_offset,
                handshake_messages.begin() + hm_offset + length);
    hm_offset += length;
    if (hm_offset > handshake_messages.size() / 2)
    {
      handshake_messages.assign(handshake_messages.begin() + hm_offset, handshake_messages.end());
      hm_offset = 0;
    }
    break;
  case TLS_APPLICATION_DATA:
  {
    // Read data until the desired amount is available or we have a least some
    // data.
    while ((block_until_full && (application_data.size() - ad_offset < length)) ||
           (application_data.size() == ad_offset))
    {
      const auto alert = read(TLS_APPLICATION_DATA);
      if (!alert)
      {
        if (alert.location == remote)
        {
          // Remote alert, so we won't receive any more data.
          boost::system::error_code ec;
          socket_.shutdown(tcp::socket::shutdown_receive, ec);
        }
        return alert;
      }
    }

    const size_t to_read = std::min(application_data.size() - ad_offset, length);
    data.clear();
    data.insert(data.begin(), application_data.begin() + ad_offset,
                application_data.begin() + ad_offset + to_read);
    ad_offset += to_read;
    if (ad_offset > application_data.size() / 2)
    {
      application_data.assign(application_data.begin() + ad_offset, application_data.end());
      ad_offset = 0;
    }
    break;
  }
  case TLS_ALERT:
    break;
  }
  return {local, ok};
}

std::vector<uint8_t> tls_record_layer::compute_early_secrets(const std::vector<uint8_t>& psk,
                                                             const std::vector<uint8_t>& messages)
{
  /// \todo compute the early secrets, see Sections 7.1 & 7.3
  std::vector <uint8_t> zerosalt (32);
  hkdf myhkdf(zerosalt, psk);
  e_secret = myhkdf.derive_secret("derived", {});

  return e_secret;
}

std::vector<uint8_t>
tls_record_layer::compute_handshake_traffic_keys(const std::vector<uint8_t>& dhe,
                                                 const std::vector<uint8_t>& messages)
{

  /// \todo compute the handshake traffic keys and initialise pending_read/write_state.cipher, see
  /// Sections 7.1 & 7.3
  ///
  /// Note that security_params.entity defines if this record layer instance is associated to a
  /// client or a server. pending_read/write_state.cipher can be updated using cipher.reset(new
  /// tls13_ascon(...)) or cipher.reset(new tls13_aes128gcm(...))

  hkdf myhkdf(e_secret,dhe);
  s_hs_server = myhkdf.derive_secret("s hs traffic", messages);
  s_hs_client = myhkdf.derive_secret("c hs traffic", messages);

  party_cipher_init(s_hs_client, s_hs_server);    

  h_salt = myhkdf.derive_secret("derived",{});
  return h_salt;
}

void tls_record_layer::compute_application_traffic_keys(const std::vector<uint8_t>& messages)
{
  /// \todo compute the application traffic keys and initialise pending_read/write_state.cipher, see
  /// Sections 7.1 & 7.3

  std::vector <uint8_t> ikm (32);
  hkdf init_hkdf(h_salt,ikm);

  std::vector<uint8_t> s_ap_server = init_hkdf.derive_secret("s ap traffic", messages);
  std::vector<uint8_t> s_ap_client = init_hkdf.derive_secret("c ap traffic", messages);

  party_cipher_init(s_ap_client, s_ap_server);    

}

std::vector<uint8_t> tls_record_layer::get_finished_key(connection_end end)
{
  /// \todo Compute keys to create/verify Finished messages, see Section 4.4.4

  std::vector<uint8_t> finished_key;

  if (end == connection_end::CLIENT){
      hkdf init_hkdf(s_hs_client);
      finished_key = init_hkdf.expand_label("finished",{},32);
  }
  if (end == connection_end::SERVER){
      hkdf init_hkdf(s_hs_server);
      finished_key = init_hkdf.expand_label("finished",{},32);
  }

  return finished_key;
}

void tls_record_layer::party_cipher_init(const std::vector<uint8_t>& client,
                                         const std::vector<uint8_t>& server){
    
  hkdf hkey_client(client), hkey_server(server);
  tls13_cipher::key_storage public_key, private_key;
  std::vector<uint8_t> key_client, key_server;

  std::vector<uint8_t> client_key = hkey_client.expand_label("key", {}, security_params.key_length);
  std::vector<uint8_t> server_key = hkey_server.expand_label("key", {}, security_params.key_length);

  if(security_params.entity == connection_end::CLIENT){
      key_client = hkey_client.expand_label("iv", {}, security_params.iv_length);
      key_server = hkey_server.expand_label("iv", {}, security_params.iv_length);
      memcpy(&public_key, client_key.data(), security_params.key_length);
      memcpy(&private_key, server_key.data(), security_params.key_length);
  }
  else{
      key_client = hkey_server.expand_label("iv", {}, security_params.iv_length);
      key_server = hkey_client.expand_label("iv", {}, security_params.iv_length);
      memcpy(&public_key, server_key.data(), security_params.key_length);
      memcpy(&private_key, client_key.data(), security_params.key_length);
  }

  if(security_params.bulk_cipher == security_parameters::bulk_cipher_algorithm::ASCON){
      pending_write_state.cipher.reset(new tls13_ascon(public_key, key_client));
      pending_read_state.cipher.reset(new tls13_ascon(private_key, key_server));
  } 
  else if(security_params.bulk_cipher == security_parameters::bulk_cipher_algorithm::AESGCM){
      pending_write_state.cipher.reset(new tls13_aesgcm(public_key, key_client));
      pending_read_state.cipher.reset(new tls13_aesgcm(private_key, key_server));
  }  
}

void tls_record_layer::write_to_socket(const std::vector<uint8_t>& data)
{
  boost::asio::write(socket_, boost::asio::buffer(data, data.size()));
}

void tls_record_layer::read_from_socket(std::vector<uint8_t>& data)
{
  boost::asio::read(socket_, boost::asio::buffer(data, data.size()));
}

