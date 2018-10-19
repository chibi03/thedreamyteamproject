#include "random.h"
#include <iostream>
#include <fstream>
#include <string.h>


using std::ios;

bool get_random_data(uint8_t* data, std::size_t size)
{
  std::ifstream randomstream;
  randomstream.open("/dev/urandom", ios::in);
  if(randomstream.is_open()){
      char * buffer = new char[size];
      randomstream.read(buffer, size);
      randomstream.close();

      memcpy(data, buffer, size);
  } else {
      return false;
  }

  return true;
}
