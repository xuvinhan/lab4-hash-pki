#pragma once

#include <string>
#include <vector>

bool read_binary_file(const std::string& path, std::vector<unsigned char>& data);
bool write_binary_file(const std::string& path, const std::vector<unsigned char>& data);
bool write_text_file(const std::string& path, const std::string& text);
std::string bytes_to_hex(const std::vector<unsigned char>& data);
