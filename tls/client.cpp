#include "../utils/utils.h"
#include "secrets.h"
#include "tls-handshake-client.h"

#include <boost/asio.hpp>
#include <iostream>
#include <string>

using boost::asio::ip::tcp;
using util::operator""_x;

namespace
{
  int close_and_wait(tls_record_layer& layer)
  {
    // close our side
    layer.write_alert(close_notify);
    // … and expect close_notify from server
    std::vector<uint8_t> buf;
    const alert_location alert_loc = layer.read(TLS_HANDSHAKE, buf, 1);
    return (alert_loc.location == remote && alert_loc.alert == close_notify) ? 0 : 5;
  }
} // namespace

int main(int argc, char** argv)
{
  if (argc != 5)
  {
    std::cout << "usage: " << argv[0] << " host port identity [connect|send-data]" << std::endl;
    return 1;
  }

  const std::string host{argv[1]}, port{argv[2]}, identity{argv[3]}, action{argv[4]};
  if (action != "connect" && action != "send-data")
  {
    std::cout << "unknown action: " << action << std::endl;
    return 1;
  }

  std::cout << "Connecting to " << host << " " << port << std::endl;
  boost::asio::io_service io_service;

  tcp::resolver resolver(io_service);
  tcp::resolver::query query{host, port};

  tcp::socket socket(io_service);
  boost::asio::connect(socket, resolver.resolve(query));
  std::cout << "... connected!" << std::endl;

  tls_record_layer record_layer(connection_end::CLIENT, std::forward<tcp::socket>(socket));
  tls_handshake_client client(record_layer, secrets::client_psks);

  std::cout << "Starting handshake" << std::endl;
  alert_location alert = client.start_handshake({identity});
  if (!alert)
  {
    std::cout << "Hanshake failed with code: " << std::dec << alert.alert << std::endl;
    if (alert.location == Location::local)
      // failure on our side, so abort
      record_layer.write_alert(alert.alert);
    return 1;
  }
  std::cout << "... completed! " << std::endl;

  if (action != "send-data")
    return close_and_wait(record_layer);

  for (const auto& data : secrets::application_data)
  {
    std::cout << "Sending message" << std::endl;
    if (!record_layer.write(TLS_APPLICATION_DATA, data))
    {
      std::cout << "Sending message failed" << std::endl;
      close_and_wait(record_layer); // TODO: other error?
      return 2;
    }

    std::cout << "Receiving message" << std::endl;
    std::vector<uint8_t> received_data;
    alert = record_layer.read(TLS_APPLICATION_DATA, received_data, data.size());
    if (!alert)
    {
      std::cout << "Failed to read " << data.size() << " bytes of application data" << std::endl;
      if (alert.location == Location::local)
      {
        // failure on our side, so abort
        record_layer.write_alert(alert.alert);
        return 3;
      }

      if (alert == close_notify)
      {
        // server initiated shutdown
        record_layer.write_alert(close_notify);
        return 0;
      }
      else
        // remote error
        return 6;
    }

    if (data != received_data)
    {
      std::cout << "Received data does not match sent data" << std::endl;
      close_and_wait(record_layer);
      return 4;
    }

    std::cout << std::string(received_data.begin(), received_data.end()) << std::endl;
  }

  return close_and_wait(record_layer);
}
