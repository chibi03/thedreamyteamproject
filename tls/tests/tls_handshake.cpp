#include "../endian.h"
#include "../secrets.h"
#include "../tls-handshake-client.h"
#include "../tls-handshake-server.h"
#include "helpers.h"
#include "playback.h"

#include <boost/asio.hpp>
#include <future>
#include <string>
#include <thread>

#include <check.h>

using boost::asio::ip::tcp;
using util::operator""_x;
using namespace secrets;

namespace
{
  constexpr unsigned int port = 2018;

  void handle_local_alert(tls_record_layer& layer, alert_location alert)
  {
    if (alert.location == local)
      // send local alert
      layer.write_alert(alert.alert);
  }

  void handle_alert(tls_record_layer& layer, alert_location alert)
  {
    if (alert.alert != close_notify)
      // read or write failed
      handle_local_alert(layer, alert);
    else
      // reply with close_notify
      layer.write_alert(close_notify);
  }

  alert_location close_and_wait(tls_record_layer& layer)
  {
    // close our side
    layer.write_alert(close_notify);
    // … and expect close_notify from server
    std::vector<uint8_t> buf;
    return layer.read(TLS_HANDSHAKE, buf, 1);
  }

  AlertDescription
  run_server(const std::string& file,
             const std::function<void(tls_record_layer&, tls_handshake_server&)> init_fn,
             const bool with_application_data)
  {
    alert_location alert = {local, internal_error};
    std::promise<void> server_is_ready;
    auto server_is_ready_future = server_is_ready.get_future();

    // start single-connection server thread
    std::thread server_thread([&alert, &server_is_ready, with_application_data, init_fn]() {
      boost::asio::io_service io_context;
      tcp::acceptor acceptor(io_context, tcp::endpoint(tcp::v4(), port));

      // accept connection and signal that the server is ready
      tcp::socket socket(io_context);
      server_is_ready.set_value();
      acceptor.accept(socket);

      // init record layer and handshake instance
      tls_record_layer record_layer(connection_end::SERVER, std::forward<tcp::socket>(socket));
      tls_handshake_server server_handshake(record_layer, server_psks, server_random,
                                            server_ecdh_key);
      init_fn(record_layer, server_handshake);

      // run handshake
      alert = server_handshake.answer_handshake();
      if (!alert)
      {
        // handshake failed
        handle_local_alert(record_layer, alert);
        return;
      }

      if (!with_application_data)
      {
        // send close_notify and wait for reply
        std::vector<uint8_t> data;
        alert = record_layer.read(TLS_APPLICATION_DATA, data, 64, false);
        if (alert)
          // got a message, but didn't expect any
          alert = {local, unexpected_message};
        else
          handle_alert(record_layer, alert);
        return;
      }

      // send data
      std::vector<uint8_t> data;
      while ((alert = record_layer.read(TLS_APPLICATION_DATA, data, 64, false)))
      {
        if (!record_layer.write(TLS_APPLICATION_DATA, data))
        {
          alert = {local, internal_error};
          break;
        }
      }

      handle_alert(record_layer, alert);
    });
    server_is_ready_future.wait();

    // start client playback thread
    int client_ret = -1;
    std::thread client_thread([&file, &client_ret]() {
      // run playback of a client
      playback_client playback(file, port);
      client_ret = playback.run();
    });

    // wait for both threads
    client_thread.join();
    server_thread.join();

    // playback was successful
    ck_assert_uint_eq(client_ret, 0);

    return alert.alert;
  }

  AlertDescription run_server(const std::string& file, const bool with_application_data)
  {
    return run_server(file, [](tls_record_layer&, tls_handshake_server&) {}, with_application_data);
  }

  AlertDescription run_server(const std::string& file)
  {
    return run_server(file, false);
  }

  AlertDescription run_server_with_data(const std::string& file)
  {
    return run_server(file, true);
  }

  AlertDescription
  run_client(const std::string& file,
             const std::function<void(tls_record_layer&, tls_handshake_client&)> init_fn,
             const bool with_application_data = false)
  {
    int server_ret = -1;
    std::promise<void> server_is_ready;
    auto server_is_ready_future = server_is_ready.get_future();

    // start server playback thread
    std::thread server_thread([&file, &server_ret, &server_is_ready]() {
      // run playback of a server
      playback_server playback(file, port);
      server_ret = playback.run(std::move(server_is_ready));
    });
    server_is_ready_future.wait();

    // start client thread
    alert_location alert = {local, internal_error};
    std::thread client_thread([&alert, init_fn, with_application_data]() {
      boost::asio::io_service io_service;
      tcp::resolver resolver(io_service);
      tcp::resolver::query query{"localhost", std::to_string(port)};

      // connect to server
      tcp::socket socket(io_service);
      boost::asio::connect(socket, resolver.resolve(query));

      // init record layer and handshake instance
      tls_record_layer record_layer(connection_end::CLIENT, std::forward<tcp::socket>(socket));
      tls_handshake_client client(record_layer, client_psks, client_random, client_ecdh_key);
      init_fn(record_layer, client);

      // run handshake
      alert = client.start_handshake({"identity"});
      if (!alert)
      {
        // handshake failed
        handle_local_alert(record_layer, alert);
        return;
      }

      if (!with_application_data)
      {
        // send close_notify and wait for reply
        alert = close_and_wait(record_layer);
        return;
      }

      // send application data
      std::vector<uint8_t> received_data;
      for (const auto& data : secrets::application_data)
      {
        if (!record_layer.write(TLS_APPLICATION_DATA, data))
          alert = {local, internal_error};

        std::vector<uint8_t> tmp_data;
        alert = record_layer.read(TLS_APPLICATION_DATA, tmp_data, data.size());
        if (!alert)
          break;

        received_data.insert(std::end(received_data), std::begin(tmp_data), std::end(tmp_data));
      }

      if (!alert)
      {
        handle_alert(record_layer, alert);
        return;
      }
      alert = close_and_wait(record_layer);

      // compare received application data
      auto it = std::cbegin(received_data);
      for (const auto& data : secrets::application_data)
      {
        ck_assert_uint_eq(std::equal(std::begin(data), std::end(data), it), true);
        std::advance(it, data.size());
      }
    });

    // wait for both threads
    client_thread.join();
    server_thread.join();

    // playback was successful
    ck_assert_uint_eq(server_ret, 0);

    return alert.alert;
  }

  AlertDescription run_client(const std::string& file, const bool with_application_data)
  {
    return run_client(file, [](tls_record_layer&, tls_handshake_client&) {}, with_application_data);
  }

  AlertDescription run_client(const std::string& file)
  {
    return run_client(file, false);
  }

  AlertDescription run_client_with_data(const std::string& file)
  {
    return run_client(file, true);
  }
} // namespace

START_TEST(server_handshake_ok)
{
  ck_assert_uint_eq(run_server(SOURCE_DIR "data/server-handshake-ok.pb"), close_notify);
}
END_TEST

START_TEST(client_handshake_ok)
{
  ck_assert_uint_eq(run_client(SOURCE_DIR "data/client-handshake-ok.pb"), close_notify);
}
END_TEST

START_TEST(server_handshake_ok_data)
{
  ck_assert_uint_eq(run_server_with_data(SOURCE_DIR "data/server-handshake-ok-data.pb"),
                    close_notify);
}
END_TEST

START_TEST(client_handshake_ok_data)
{
  ck_assert_uint_eq(run_client_with_data(SOURCE_DIR "data/client-handshake-ok-data.pb"),
                    close_notify);
}
END_TEST

START_TEST(server_handshake_change_client_cs)
{
  ck_assert_uint_eq(run_server(SOURCE_DIR "data/server-change-client-cs.pb"), close_notify);
}
END_TEST

START_TEST(client_handshake_change_client_cs)
{
  ck_assert_uint_eq(run_client(SOURCE_DIR "data/client-change-client-cs.pb",
                               [](tls_record_layer& record_layer, tls_handshake_client&) {
                                 record_layer.set_supported_cipher_suites(
                                     {TLS_AES_128_GCM_SHA256, TLS_ASCON_128_SHA256});
                               },
                               false),
                    close_notify);
}
END_TEST

START_TEST(server_handshake_change_server_cs)
{
  ck_assert_uint_eq(run_server(SOURCE_DIR "data/server-change-server-cs.pb",
                               [](tls_record_layer& record_layer, tls_handshake_server&) {
                                 record_layer.set_supported_cipher_suites(
                                     {TLS_AES_128_GCM_SHA256, TLS_ASCON_128_SHA256});
                               },
                               false),
                    close_notify);
}
END_TEST

START_TEST(client_handshake_change_server_cs)
{
  ck_assert_uint_eq(run_client(SOURCE_DIR "data/client-change-server-cs.pb"), close_notify);
}
END_TEST


int main(int argc, char** argv)
{
  Suite* suite = suite_create("TLS");

  // Test cases for the client
  TCase* tcase = tcase_create("Client");
  tcase_add_test(tcase, client_handshake_ok);
  tcase_add_test(tcase, client_handshake_ok_data);
  tcase_add_test(tcase, client_handshake_change_client_cs);
  tcase_add_test(tcase, client_handshake_change_server_cs);
  suite_add_tcase(suite, tcase);

  // Test cases for the server
  tcase = tcase_create("Server");
  tcase_add_test(tcase, server_handshake_ok);
  tcase_add_test(tcase, server_handshake_ok_data);
  tcase_add_test(tcase, server_handshake_change_client_cs);
  tcase_add_test(tcase, server_handshake_change_server_cs);
  suite_add_tcase(suite, tcase);

  SRunner* suite_runner = srunner_create(suite);
  srunner_run(suite_runner, argc, argv);
  int number_failed = srunner_ntests_failed(suite_runner);
  srunner_free(suite_runner);

  return !number_failed ? EXIT_SUCCESS : EXIT_FAILURE;
}
