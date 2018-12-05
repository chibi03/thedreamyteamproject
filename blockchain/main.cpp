#include <fstream>
#include <iostream>
#include <sstream>
#include <string>

#include "../utils/io.h"
#include "attack.h"
#include "blockchain.h"
#include "io.h"

using namespace blockchain;


namespace
{

  int print_usage(const std::string& name)
  {
    std::cout << "'" << name
              << "' usage information:\n\n"
                 "deanonymize_spender [blockchain] [pubkey]\n"
                 "deanonymize_miner [blockchain] [pubkey]\n";
    return 1;
  }

  template <class T>
  void from_str(T& t, const std::string& str)
  {
    std::istringstream iss(str);
    iss >> t;
  }

} // namespace

int main(int argc, char** argv)
{
  const std::string progname{argv[0]};
  if (argc < 2)
    return print_usage(progname);

  const std::string command{argv[1]};
  argv += 2;
  argc -= 2;

  if (command == "deanonymize_spender" && argc == 2)
  {
    const std::string blockchain_filename = argv[0];
    const std::string target_pub_filename = argv[1];

    const rs_public_key spender = deanonymize_spender(blockchain_filename);

    std::ofstream ofs(target_pub_filename);
    util::write(ofs, spender);
    if (!ofs)
    {
      std::cout << "Failed to write solution key!" << std::endl;
      return 1;
    }
  }
  else if (command == "deanonymize_miner" && argc == 2)
  {
    const std::string blockchain_filename = argv[0];
    const std::string target_pub_filename = argv[1];

    const rs_public_key receiver = deanonymize_miner(blockchain_filename);

    std::ofstream ofs(target_pub_filename);
    util::write(ofs, receiver);
    if (!ofs)
    {
      std::cout << "Failed to write solution key!" << std::endl;
      return 1;
    }
  }
  else
    return print_usage(progname);
}
