#include "playback.h"

#include <algorithm>
#include <fstream>
#include <iostream>
#include <string>

#include "../../utils/io.h"
#include "../../utils/utils.h"

using boost::asio::ip::tcp;
using util::print_hex;

playback_base::playback_base(const std::string& data_file)
{
  std::ifstream ifs(data_file);
  if (!ifs)
    throw std::runtime_error("unable to open playback data");

  while (ifs)
  {
    playback_data data;
    util::read(ifs, data.input);
    util::read(ifs, data.data, true);

    if (ifs)
      data_.emplace_back(data);
  }
}

int playback_base::playback(tcp::socket& socket)
{
  for (const auto& playback : data_)
  {
    if (playback.input)
    {
      std::cout << "playback: waiting for input of " << playback.data.size() << " bytes"
                << std::endl;

      // read data and and compare it
      std::vector<uint8_t> buffer(playback.data.size());
      boost::asio::read(socket, boost::asio::buffer(buffer, buffer.size()));

      const auto mis =
          std::mismatch(buffer.begin(), buffer.end(), playback.data.begin(), playback.data.end());
      if (mis.first != buffer.end() || mis.second != playback.data.end())
      {
        std::cerr << "Found mismatch in byte " << std::distance(buffer.begin(), mis.first)
                  << ": got ";
        print_hex(std::cerr, *mis.first);
        std::cerr << " expected ";
        print_hex(std::cerr, *mis.second);
        std::cerr << std::endl;
        return 1;
      }
    }
    else
    {
      std::cout << "playback: writing " << playback.data.size() << " bytes" << std::endl;
      // write playback data
      boost::asio::write(socket, boost::asio::buffer(playback.data, playback.data.size()));
    }
  }

  std::cout << "playback: complete" << std::endl;
  // no longer send data
  socket.shutdown(tcp::socket::shutdown_send);

  // wait for the next read to fail
  boost::system::error_code ec;
  std::array<uint8_t, 1> buffer;
  boost::asio::read(socket, boost::asio::buffer(buffer, buffer.size()), ec);
  if (!ec)
  {
    std::cout << "playback: received data after completion" << std::endl;
    return 1;
  }

  return 0;
}

playback_server::playback_server(const std::string& data, unsigned int port)
  : playback_base(data), port_(port)
{
}

int playback_server::run(std::promise<void> is_ready)
{
  try
  {
    boost::asio::io_service io_context;
    tcp::acceptor acceptor(io_context, tcp::endpoint(tcp::v4(), port_));

    tcp::socket socket(io_context);
    is_ready.set_value();
    acceptor.accept(socket);

    return playback(socket);
  }
  catch (const std::exception& e)
  {
    std::cerr << e.what() << std::endl;
    return -1;
  }

  return 0;
}

playback_client::playback_client(const std::string& data, unsigned int port)
  : playback_base(data), port_(port)
{
}

int playback_client::run()
{
  try
  {
    boost::asio::io_service io_context;
    tcp::socket socket(io_context);
    tcp::resolver resolver(io_context);

    boost::asio::connect(
        socket, resolver.resolve(tcp::resolver::query("localhost", std::to_string(port_))));

    return playback(socket);
  }
  catch (const std::exception& e)
  {
    std::cerr << "playback error: " << e.what() << std::endl;
    return -1;
  }

  return 0;
}
