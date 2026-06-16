#pragma once

#include <string>

bool hmac_sha256_text(
    const std::string& key,
    const std::string& message
);

bool hmac_sha256_file(
    const std::string& key,
    const std::string& in_path
);
