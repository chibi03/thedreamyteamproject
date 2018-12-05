#include "attack.h"

#include "../utils/io.h"
#include "ecclib-glue.h"
#include "io.h"

#include <fstream>
#include <iostream>


namespace blockchain
{

  rs_public_key deanonymize_spender(const std::string& blockchain_filename)
  {
    /// \todo
    return {};
  }

  rs_public_key deanonymize_miner(const std::string& blockchain_filename)
  {
    /// \todo Deanonymize the miner producing transactions containing incorrectly
    /// computed commitments.
    return {};
  }
} // namespace blockchain
