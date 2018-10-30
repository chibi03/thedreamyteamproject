#ifndef TLS_SERVER_HPP
#define TLS_SERVER_HPP

#include <boost/asio.hpp>
#include <string>
#include <vector>

#include "tls-handshake-server.h"

/// The top-level class of the TLS server.
class server
{
public:
  server(const server&) = delete;
  server& operator=(const server&) = delete;
  virtual ~server();

  /// Construct the server to listen on the specified TCP address and port.
  server(const std::string& address, const std::string& port);

  /// Run the server's io_service loop.
  void run();

private:
  void start_signal_wait();
  void handle_signal_wait();
  /// Perform an asynchronous accept operation.
  void start_accept();
  void handle_accept(const boost::system::error_code& ec);

  /// The io_service used to perform asynchronous operations.
  boost::asio::io_service io_service_;
  /// The signal_set is used to register for process termination notifications.
  boost::asio::signal_set signals_;
  /// Acceptor used to listen for incoming connections.
  boost::asio::ip::tcp::acceptor acceptor_;

  /// The next socket to be accepted.
  boost::asio::ip::tcp::socket socket_;

protected:
  virtual void handle_connection(boost::asio::ip::tcp::socket&& socket) = 0;
};

#endif
