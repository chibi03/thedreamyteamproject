#ifndef PLAYBACK_H
#define PLAYBACK_H

#include <boost/asio.hpp>
#include <future>
#include <string>
#include <vector>

struct playback_data
{
  std::vector<uint8_t> data;
  bool input;
};

class playback_base
{
public:
  playback_base(const std::string& data_file);

protected:
  int playback(boost::asio::ip::tcp::socket& socket);

private:
  std::vector<playback_data> data_;
};

/// Playback server
class playback_server : public playback_base
{
public:
  playback_server(const std::string& data, unsigned int port);
  playback_server(const playback_server&) = delete;
  playback_server& operator=(const playback_server&) = delete;

  /// Run the playback server
  int run(std::promise<void> is_ready);

private:
  const unsigned int port_;
};

/// Playback client
class playback_client : public playback_base
{
public:
  playback_client(const std::string& data, unsigned int port);
  playback_client(const playback_client&) = delete;
  playback_client& operator=(const playback_client&) = delete;

  /// Run the playback client
  int run();

private:
  const unsigned int port_;
};

#endif
