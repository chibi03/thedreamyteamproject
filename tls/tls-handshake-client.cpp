#include "tls-handshake-client.h"

#include "hkdf.h"
#include "random.h"

#include "../utils/utils.h"
#include "endian.h"

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

void tls_handshake_client::send_client_hello() {
/// \todo: Send ClientHello message
/// If have_fixed_randomness_ is false generate random data.
/// If it is true, use fixed_randomness_ as random data. In this case it is always 32 byte
/// large.
  if (!have_fixed_randomness_) {
       get_random_data(random_data.random_bytes, 32);
  } else{
      std::memcpy(&random_data.random_bytes, &fixed_randomness_, sizeof(fixed_randomness_));
  }
  std::memcpy(&(client_pld.random.random_bytes[0]), &(random_data.random_bytes[0]), sizeof(random_data.random_bytes));
  header.msg_type = CLIENT_HELLO;

  std::vector<uint8_t> pld = pld_calc();
  std::vector<uint8_t> exts = ext_calc();
  std::vector<uint8_t> psk;
  uint16_t pre_key_size;
  psk_calc(pre_key_size, psk);

  uint16_t ext_key = (uint16_t)exts.size() + sizeof((uint16_t)exts.size()) + sizeof(pre_key_size) + pre_key_size;
  uint32_t pld_ext_key = sizeof((uint16_t)pld.size()) + (uint16_t)pld.size() + ext_key;

  hello_client = expand(hello_client, (uint8_t *) &(header.msg_type), sizeof(header.msg_type), false);
  hello_client = expand(hello_client, (uint8_t *) &(pld_ext_key), sizeof(header.length), true);
  hello_client = expand(hello_client, pld.data(), (uint16_t) pld.size(), false);
  hello_client = expand(hello_client, (uint8_t *) &ext_key, sizeof(ext_key), true);
  hello_client = expand(hello_client, exts.data(), (uint16_t)exts.size(), false);
  hello_client = expand(hello_client, psk.data(), (uint16_t)psk.size(), false);

  std::vector<uint8_t> binders;
  for (auto &identity_label: psk_identities_) {
      std::vector<uint8_t> tmp_psk = psks_.at(identity_label);

      //early secret
      std::vector<uint8_t> early_secret_ = layer_.compute_early_secrets(tmp_psk, {});
      //binder key
      std::vector<uint8_t> binder_key = layer_.binder;
      hkdf hkdf(binder_key);
      std::vector<uint8_t> f_binder = hkdf.expand_label("finished", {}, binder_key.size());
      //HMAC
      auto binder = verify(hello_client, f_binder);

      uint8_t size_binder = binder.size();
      std::reverse_copy(&size_binder, &size_binder+sizeof(size_binder), std::back_inserter(binders));
      binders.insert(binders.end(), binder.data(), binder.data() + binder.size());
  }
  uint16_t binders_size = (uint16_t) binders.size();
  hello_client = expand(hello_client, (uint8_t *) &(binders_size), sizeof(binders_size), true);
  hello_client = expand(hello_client, &(binders[0]), (uint16_t )binders.size(), false);

  layer_.security_params.bulk_cipher = layer_.security_params.BULK_CIPHER_NULL;
  layer_.write(TLS_HANDSHAKE, hello_client);
}

std::vector<uint8_t> tls_handshake_client::pld_calc() {
  client_pld.legacy_version = 0x0303;
  client_pld.legacy_session_id = {};
  client_pld.cipher_suites = layer_.get_supported_cipher_suites();
  client_pld.legacy_compression_methods.push_back(0);

  auto ciphers_size = (uint16_t)(client_pld.cipher_suites.size() * sizeof(client_pld.cipher_suites[0]));
  auto ciphers_size_rev = hton(ciphers_size);
  auto session_size = (uint8_t)client_pld.legacy_session_id.size();
  auto comp_size = (uint8_t)client_pld.legacy_compression_methods.size();

  //version || random struct || session id || cipher suits || compression methods
  pld.insert(pld.end(), (uint8_t *) &(client_pld.legacy_version),
          (uint8_t *) &(client_pld.legacy_version) + sizeof(client_pld.legacy_version));
  pld.insert(pld.end(), client_pld.random.random_bytes, client_pld.random.random_bytes + sizeof(client_pld.random.random_bytes));
  pld.insert(pld.end(), &session_size, &session_size + 1);
  pld.insert(pld.end(), (uint8_t *)&ciphers_size_rev, (uint8_t *)&ciphers_size_rev + sizeof(ciphers_size_rev));
  pld.insert(pld.end(), (uint8_t *)&(client_pld.cipher_suites[0]), (uint8_t *)&(client_pld.cipher_suites[0]) + ciphers_size);
  pld.insert(pld.end(), &comp_size, &comp_size + 1);
  pld.insert(pld.end(), &(client_pld.legacy_compression_methods[0]), &(client_pld.legacy_compression_methods[0]) + comp_size);
  return pld;
}

std::vector<uint8_t> tls_handshake_client::ext_calc() {
  Extension key_share;
  key_share.type = KEY_SHARE;
  KeyShareEntry client_share;
  client_share.group = SECP_256_R1;
  client_share.data = ecdh_.get_data();

  auto key_exchange_data_len = (uint16_t)client_share.data.size();
  uint16_t size_client_share = sizeof(client_share.group) + sizeof(key_exchange_data_len) + key_exchange_data_len;
  uint16_t size_key_share = sizeof(size_client_share) + size_client_share;
  std::vector<uint8_t> keyshare;

  // type || data size) || client shares size || group secp || key exchange size || key ecdh
  std::reverse_copy((uint8_t *)&(key_share.type),
          (uint8_t *)&(key_share.type)+sizeof(key_share.type), std::back_inserter(keyshare));
  std::reverse_copy((uint8_t *)&(size_key_share),
          (uint8_t *)&(size_key_share)+sizeof(size_key_share), std::back_inserter(keyshare));
  std::reverse_copy((uint8_t *)&(size_client_share),
          (uint8_t *)&(size_client_share)+sizeof(size_client_share), std::back_inserter(keyshare));
  std::reverse_copy((uint8_t *)&(client_share.group),
          (uint8_t *)&(client_share.group)+sizeof(client_share.group), std::back_inserter(keyshare));
  std::reverse_copy((uint8_t *)&(key_exchange_data_len),
          (uint8_t *)&(key_exchange_data_len)+sizeof(key_exchange_data_len), std::back_inserter(keyshare));
  keyshare.insert(keyshare.end(), &(client_share.data[0]),
          &(client_share.data[0]) + (uint16_t)client_share.data.size());

  //hex values found at https://tls13.ulfheim.net/
  std::vector<uint8_t> supported_ver {0x00,0x2b,0x00,0x03,0x02,0x03,0x04}, psk_modes {0x00,0x2d,0x00,0x02,0x01,0x01},
  supported_groups {0x00,0x0a,0x00,0x04,0x00,0x02,0x00,0x17};

  // Key Share || Supported Versions || PSK Key Exchange Modes || Supported Groups
  exts.insert(exts.end(), &(keyshare[0]), &(keyshare[0]) + (uint16_t)keyshare.size());
  exts.insert(exts.end(), &(supported_ver[0]), &(supported_ver[0]) + (uint16_t)supported_ver.size());
  exts.insert(exts.end(), &(psk_modes[0]), &(psk_modes[0]) + (uint16_t)psk_modes.size());
  exts.insert(exts.end(), &(supported_groups[0]), &(supported_groups[0]) + (uint16_t)supported_groups.size());

  return exts;
}

void tls_handshake_client::psk_calc(uint16_t &pre_key_size, std::vector<uint8_t> &psk) {
  Extension pre_shared_key;
  pre_shared_key.type = PRE_SHARED_KEY;
  std::vector<PskIdentity> identities;
  uint16_t size_id;
  std::vector<uint8_t> ids;
  for (auto &id: psk_identities_) {
      PskIdentity identity;
      identity.identity = id;
      identity.obfuscated_ticket_age = 0;
      identities.push_back(identity);
      size_id += id.size() + sizeof(identity.obfuscated_ticket_age ) + 2; //+14 bytes 8+4+2
  }
  std::reverse_copy((uint8_t *)&(size_id),(uint8_t *)&(size_id)+sizeof(size_id), std::back_inserter(ids));
  uint16_t data_id_size;
  for (auto &id: identities) {
      data_id_size = (uint16_t)id.identity.size();
      ids = expand(ids, (uint8_t *)&(data_id_size), (uint16_t)sizeof(data_id_size), true);
      ids = expand(ids, (uint8_t *)&(id.identity[0]), (uint16_t)id.identity.size(), false);
      ids = expand(ids, (uint8_t *)&(id.obfuscated_ticket_age), (uint16_t)sizeof(id.obfuscated_ticket_age), true);
  }
  pre_key_size = sizeof(size_id) + size_id + sizeof((uint16_t)(psk_identities_.size() * 32 + 1))
          + (uint16_t)(psk_identities_.size() * 32 + 1);

  psk = expand(psk, (uint8_t *)&(pre_shared_key.type), (uint16_t)sizeof(pre_shared_key.type), true);
  psk = expand(psk, (uint8_t *)&(pre_key_size), (uint16_t)sizeof(pre_key_size), true);
  psk = expand(psk, ids.data(), (uint16_t)ids.size(), false);
}

std::vector<uint8_t> tls_handshake_client::expand(std::vector<uint8_t> pld, uint8_t *exp, uint16_t bytes, bool order) {
  if (!order) {
      pld.insert(pld.end(), exp, exp + bytes);
  } else {
      std::reverse_copy(exp, exp + bytes, std::back_inserter(pld));
  }
  return pld;
}

alert_location tls_handshake_client::read_server_hello() {
  /// \todo Read and handle ServerHello message
  layer_.read(TLS_HANDSHAKE, server_header, 4);
  layer_.read(TLS_HANDSHAKE, server_hello, 125);
  server_hello_.resize(server_hello.size() + server_header.size());
  memcpy(&server_hello_[0], &server_header[0], server_header.size());
  memcpy(&server_hello_[server_header.size()], &server_hello[0], server_hello.size());
  params_from_server(server_hello);
  return {local, ok};
}

void tls_handshake_client::params_from_server(std::vector<uint8_t> server_hello){
  //extraction of cipher and key from the server hello
  size_t index = 35;
  memcpy(&server_cipher.type[0], &server_hello[index], 2);
  index += 7;

  Extension key_share;
  uint16_t key_share_len;
  memcpy(&key_share_len, &server_hello[index], 2);
  key_share_len = ntoh(key_share_len);
  index += 2;
  key_share.data.resize(key_share_len);
  memcpy(&key_share.data[0], &server_hello[index], key_share_len);

  uint16_t exchange_len = 0;
  memcpy(&exchange_len, &key_share.data[2], 2);
  exchange_len = hton(exchange_len);
  server_key_share_.resize(exchange_len);
  memcpy(&server_key_share_[0], &key_share.data[4], exchange_len);
  index += key_share_len + 10;

  // get identity for encryption
  uint16_t identity;
  memcpy(&identity, &server_hello[index], sizeof(identity));
  identity = ntoh(identity);
  server_psk = psks_.at(psk_identities_[identity]);
}

alert_location tls_handshake_client::read_finished() {
  /// \todo Read and handle Finished message
  std::vector<uint8_t> messages(hello_client.size() + server_hello_.size());
  memcpy(&messages[0], &hello_client[0], hello_client.size());
  memcpy(&messages[hello_client.size()], &server_hello_[0], server_hello_.size());
  // rec layer cipher suite
  layer_.set_cipher_suite(server_cipher);
  // rec layer early secret
  std::vector<uint8_t> early_secret = layer_.compute_early_secrets(server_psk, messages);
  // ecdh shared secret
  ecdh_shared_secret_ = ecdh_.get_shared_secret(server_key_share_);
  // rec layer traffic keys
  layer_.compute_handshake_traffic_keys(ecdh_shared_secret_, messages);
  layer_.update_read_key();
  layer_.read(TLS_HANDSHAKE, finished_server, 36);
  return {local, ok};
}

void tls_handshake_client::send_finished() {
  /// \todo Send Finished message.
  std::vector<uint8_t> messages = con_message();
  std::vector<uint8_t> finished_key = layer_.get_finished_key(CLIENT);
  hmac_sha2::digest_storage verify_data = verify(messages, finished_key);

  std::vector<uint8_t> verify_data_vec(verify_data.size());
  memcpy(&verify_data_vec[0], &(verify_data), verify_data.size());

  handshake_message_header header;
  header.msg_type = FINISHED;
  header.length[0] = 0x00;
  header.length[1] = 0x00;
  header.length[2] = (uint8_t)verify_data_vec.size();

  std::vector<uint8_t> finished_message(verify_data_vec.size() + sizeof(header.msg_type) + sizeof(header.length));
  memcpy(&finished_message[0], &header.msg_type, sizeof(header.msg_type));
  memcpy(&finished_message[sizeof(header.msg_type)], &header.length, sizeof(header.length));
  memcpy(&finished_message[sizeof(header.msg_type) + sizeof(header.length)], &verify_data[0], verify_data.size());
  layer_.update_write_key();
  layer_.write(TLS_HANDSHAKE, finished_message);

  std::vector<uint8_t> message = con_message();
  layer_.compute_application_traffic_keys(message);
  layer_.update_write_key();
  layer_.update_read_key();
}

std::vector<uint8_t> tls_handshake_client::con_message() {
  std::vector<uint8_t> messages(hello_client.size() + server_hello_.size() + finished_server.size());
  memcpy(&messages[0], &hello_client[0], hello_client.size());
  memcpy(&messages[hello_client.size()], &server_hello_[0], server_hello_.size());
  memcpy(&messages[hello_client.size() + server_hello_.size()], &finished_server[0], finished_server.size());
  return messages;
}

hmac_sha2::digest_storage tls_handshake_client::verify(std::vector<uint8_t> &messages, std::vector<uint8_t> &key) {
  sha2 sha_2 = sha2();
  sha_2.update(messages.data(), messages.size());
  auto hashed_messages = sha_2.digest();

  hmac_sha2 hmac(key.data(), key.size());
  hmac.update(hashed_messages.data(), hashed_messages.size());
  return hmac.digest();
}


