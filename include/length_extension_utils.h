#pragma once

#include <string>
#include <cstddef>

bool sha256_length_extension_attack(
    const std::string& original_mac_hex,
    const std::string& known_message,
    const std::string& data_to_append,
    size_t key_len_guess,
    const std::string& forged_out_path
);

bool sha256_length_extension_demo(
    const std::string& secret,
    const std::string& known_message,
    const std::string& data_to_append,
    size_t key_len_guess,
    const std::string& forged_out_path
);
