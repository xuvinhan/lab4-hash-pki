#pragma once

#include <string>
#include <vector>
#include <cstddef>

bool hash_text(
    const std::string& algo,
    const std::string& text,
    size_t shake_out_len,
    std::vector<unsigned char>& digest
);

bool hash_file_streaming(
    const std::string& algo,
    const std::string& in_path,
    size_t shake_out_len,
    std::vector<unsigned char>& digest,
    size_t& total_bytes
);

bool is_supported_hash_algorithm(const std::string& algo);
bool is_shake_algorithm(const std::string& algo);
std::string normalize_hash_algorithm(const std::string& algo);
