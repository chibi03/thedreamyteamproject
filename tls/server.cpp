#include "../utils/utils.h"
#include "secrets.h"
#include "tls-server.h"

#include <iostream>

using boost::asio::ip::tcp;

namespace
{
  int close_and_wait(tls_record_layer& layer)
  {
    // close our side
    layer.write_alert(close_notify);
    // … and expect close_notify from server
    std::vector<uint8_t> buf;
    const alert_location alert_loc = layer.read(TLS_ALERT, buf, 0);
    return (alert_loc.location == remote && alert_loc.alert == close_notify) ? 0 : 5;
  }

  class replay_tls_server : public server
  {
  public:
    replay_tls_server(const std::string& address, const std::string& port, const psk_map& psks)
      : server(address, port), psks_(psks)
    {
    }
    virtual ~replay_tls_server() {}

  protected:
    void handle_connection(tcp::socket&& socket) override
    {
      // Create a record layer
      tls_record_layer record_layer{connection_end::SERVER, std::forward<tcp::socket>(socket)};
      // Create a handshake handler for a server
      tls_handshake_server server{record_layer, psks_};
      // Handle handshake
      auto alert = server.answer_handshake();
      if (!alert)
      {
        std::cout << "Handshake failed with code: " << alert.alert << std::endl;
        if (alert.location == Location::local)
          record_layer.write_alert(alert.alert);
        return;
      }
      std::cout << "Handshake complete!" << std::endl;

      // Request 64 bytes and send them back
      std::vector<uint8_t> data;
      while ((alert = record_layer.read(TLS_APPLICATION_DATA, data, 64, false)))
      {
        std::cout << "Received message of " << data.size() << " bytes." << std::endl;
        if (!record_layer.write(TLS_APPLICATION_DATA, data))
        {
          std::cout << "Failed to send application data!" << std::endl;
          close_and_wait(record_layer); // TODO other alert?
          return;
        }
        std::cout << "Sending message" << std::endl;
      }

      if (alert.location == local)
      {
        std::cout << "Failed to read data:" << alert.alert << std::endl;
        record_layer.write_alert(alert.alert);
      }
      else
      {
        if (alert.alert != AlertDescription::close_notify)
          std::cout << "Received alert: " << alert << std::endl;
        else
        {
          std::cout << "Closing connection!" << std::endl;
          record_layer.write_alert(close_notify);
        }
      }
    }

  private:
    const psk_map psks_;
  };

} // namespace

int main(int argc, char** argv)
{
  if (argc != 3)
  {
    std::cout << "usage: " << argv[0] << " host port" << std::endl;
    return 1;
  }

  replay_tls_server s{argv[1], argv[2], secrets::server_psks};
  s.run();

  return 0;
}
