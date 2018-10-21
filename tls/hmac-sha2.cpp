#include "hmac-sha2.h"

hmac_sha2::hmac_sha2(const uint8_t* key, std::size_t keysize)
{
  /// \todo Initialze with given key.
    uint8_t newKey [sha2::block_size];
    sha2 head;

	if(keysize > block_size)
	{
		head.update(key, keysize);
		memcpy(newKey, head.digest().data(), digest_size);
        keysize = digest_size;
	}
	else
	{
		memcpy(newKey, key, keysize);
	}

    for(size_t i=keysize; i<block_size; ++i)
    {
        newKey[i] = 0x00;
    }
    for(size_t i=0; i<block_size; ++i)
    {
        opad[i] = newKey[i] ^ 0x5c;
        ipad[i] = newKey[i] ^ 0x36;
    }

    header.update(ipad, block_size);
}

void hmac_sha2::update(const uint8_t* bytes, std::size_t size)
{
  /// \todo Feed data to HMAC.
  header.update(bytes, size);
}

hmac_sha2::digest_storage hmac_sha2::digest()
{
  /// \todo Finalize HMAC compuation and return computed digest.
  sha2 head;

  head.update(opad, block_size);
  head.update(header.digest().data(), digest_size);

  return head.digest();
}
