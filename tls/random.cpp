#include "random.h"
#include <iostream>
#include <fstream>
#include <cstring>
#include <string>

/**
 * Initialises the provided data variable with a random value
 * @param data random value
 * @param size the size of the data variable
 * @return true if the generation was successful
 */
bool get_random_data(uint8_t *data, std::size_t size) {
    if (size && sufficient_entropy()) {
        std::ifstream randomstream;
        std::string filename = "/dev/urandom";

        randomstream.open(filename, std::ios::in);
        if (randomstream.good()) {
            char *buffer = new char[size];
            randomstream.read(buffer, size);
            randomstream.close();

            memcpy(data, buffer, size);
            delete[] buffer; //char array needs to be freed
        }

        if (randomstream.fail()) {
            std::cout << "Failed to open " << filename << "! File may not exist." << std::endl;
            return false;
        }

        return true;
    }
    return false;
}

/**
 * Check if sufficient entropy exists. Entropy may not have been initialized when /dev/urandom is read.
 * @return true if enough entropy available
 */
bool sufficient_entropy() {
    std::ifstream available_file("/proc/sys/kernel/random/entropy_avail");
    std::string first_line;

    if (available_file.good()) {
        std::getline(available_file, first_line);
        available_file.close();

        int available = std::stoi(first_line);
        if (available > 100) {
            return true;
        }
    }
    return false;
}