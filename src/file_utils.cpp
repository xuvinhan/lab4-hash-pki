#include "file_utils.h"

#include <fstream>
#include <iostream>
#include <sstream>
#include <iomanip>

bool read_binary_file(const std::string& path, std::vector<unsigned char>& data) {
    std::ifstream in(path, std::ios::binary);

    if (!in) {
        std::cerr << "[ERROR] Cannot open input file: " << path << "\n";
        return false;
    }

    data.assign(
        std::istreambuf_iterator<char>(in),
        std::istreambuf_iterator<char>()
    );

    return true;
}

bool write_binary_file(const std::string& path, const std::vector<unsigned char>& data) {
    std::ofstream out(path, std::ios::binary);

    if (!out) {
        std::cerr << "[ERROR] Cannot open output file: " << path << "\n";
        return false;
    }

    out.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
    return true;
}

bool write_text_file(const std::string& path, const std::string& text) {
    std::ofstream out(path, std::ios::binary);

    if (!out) {
        std::cerr << "[ERROR] Cannot open output file: " << path << "\n";
        return false;
    }

    out << text;
    return true;
}

std::string bytes_to_hex(const std::vector<unsigned char>& data) {
    std::ostringstream oss;

    for (unsigned char b : data) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
    }

    return oss.str();
}
