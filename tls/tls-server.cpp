#include "tls-server.h"
#include <iostream>
#include <utility>

#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

using boost::asio::ip::tcp;

server::server(const std::string& address, const std::string& port)
  : io_service_(), signals_(io_service_, SIGCHLD), acceptor_(io_service_), socket_(io_service_)
{
  start_signal_wait();

  // Open the acceptor with the option to reuse the address (i.e. SO_REUSEADDR).
  tcp::resolver resolver(io_service_);
  tcp::endpoint endpoint = *resolver.resolve({address, port});
  acceptor_.open(endpoint.protocol());
  acceptor_.set_option(boost::asio::ip::tcp::acceptor::reuse_address(true));
  acceptor_.bind(endpoint);
  acceptor_.listen();
}

server::~server() {}

void server::start_signal_wait()
{
  signals_.async_wait([this](boost::system::error_code /*ec*/, int signo) {
    if (signo == SIGCHLD)
      handle_signal_wait();
  });
}

void server::handle_signal_wait()
{
  // Only the parent process should check for this signal. We can determine
  // whether we are in the parent by checking if the acceptor is still open.
  if (acceptor_.is_open())
  {
    // Reap completed child processes so that we don't end up with zombies.
    int status = 0;
    while (waitpid(-1, &status, WNOHANG) > 0)
    {
    }

    start_signal_wait();
  }
}

void server::start_accept()
{
  acceptor_.async_accept(socket_, [this](boost::system::error_code ec) { handle_accept(ec); });
}

void server::handle_accept(const boost::system::error_code& ec)
{
  // Check whether the server was stopped by a signal before this
  // completion handler had a chance to run.
  if (!acceptor_.is_open())
    return;

  if (!ec)
  {
    // Accept connection
    //
    // Inform the io_service that we are about to fork. The io_service cleans
    // up any internal resources, such as threads, that may interfere with
    // forking.
    io_service_.notify_fork(boost::asio::io_service::fork_prepare);

    if (fork() == 0)
    {
      // Inform the io_service that the fork is finished and that this is the
      // child process. The io_service uses this opportunity to create any
      // internal file descriptors that must be private to the new process.
      io_service_.notify_fork(boost::asio::io_service::fork_child);

      // The child won't be accepting new connections, so we can close the
      // acceptor. It remains open in the parent.
      acceptor_.close();

      // The child process is not interested in processing the SIGCHLD signal.
      signals_.cancel();

      // Process connection.
      handle_connection(std::forward<tcp::socket>(socket_));
    }
    else
    {
      // Inform the io_service that the fork is finished (or failed) and that
      // this is the parent process. The io_service uses this opportunity to
      // recreate any internal resources that were cleaned up during
      // preparation for the fork.
      io_service_.notify_fork(boost::asio::io_service::fork_parent);

      socket_.close();
      start_accept();
    }
  }
  else
  {
    std::cerr << "Accept error: " << ec.message() << std::endl;
    start_accept();
  }
}

void server::run()
{
  start_accept();

  // The io_service::run() call will block until all asynchronous operations
  // have finished. While the server is running, there is always at least one
  // asynchronous operation outstanding: the asynchronous accept call waiting
  // for new incoming connections.
  io_service_.run();
}
