#include "random.h"
#include <iostream>
#include <fstream>
#include <cstring>
#include <string>

bool get_random_data(uint8_t* data, std::size_t size)
{
    if (size) {
        sufficient_entropy();
        std::ifstream randomstream;
        std::string filename = "/dev/urandom";

        randomstream.open(filename, std::ios::in);
        if (randomstream.is_open()) {
            char *buffer = new char[size]; //HELP! memory leak!
            randomstream.read(buffer, size);
            randomstream.close();

            memcpy(data, buffer, size);
        }

        if (randomstream.fail()) {
            std::cout << "Failed to open " << filename << "! File may not exist." << std::endl;
            return false;
        }

        return true;
    }
    return false;
}

bool sufficient_entropy(){
    std::ifstream available_file("/proc/sys/kernel/random/entropy_avail");
    char first_line[256];

    if (available_file.good())
    {
        available_file.getline(first_line, 256);
    }

    available_file.close();
    std::cout << first_line  << " amount of entropy";
    return true;
}