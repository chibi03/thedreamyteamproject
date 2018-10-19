#include "random.h"
#include <iostream>
#include <fstream>
#include <cstring>
#include <string>

using namespace std;
using std::ios;

bool get_random_data(uint8_t* data, std::size_t size)
{
    ifstream randomstream;
    string filename = "/dev/urandom";

    randomstream.open(filename, ios::in);
    if(randomstream.is_open()){
        char * buffer = new char[size]; //HELP! memory leak!
        randomstream.read(buffer, size);
        randomstream.close();

        memcpy(data, buffer, size);
    }

    if (randomstream.fail()) {
        cout << "Failed to open " + filename + "! File may not exist." << endl;
        return false;
    }

    return true;
}
