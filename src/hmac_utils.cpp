#include "hmac_utils.h"

#include "file_utils.h"

#include <iostream>
#include <vector>
#include <string>

#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/err.h>

static void print_openssl_error(const std::string& msg) {
    std::cerr << "[ERROR] " << msg << "\n";
    ERR_print_errors_fp(stderr);
}

static bool compute_hmac_sha256(
    const std::vector<unsigned char>& key,
    const std::vector<unsigned char>& data,
    std::vector<unsigned char>& mac
) {
    mac.resize(EVP_MAX_MD_SIZE);
    unsigned int mac_len = 0;

    unsigned char* result = HMAC(
        EVP_sha256(),
        key.data(),
        static_cast<int>(key.size()),
        data.data(),
        data.size(),
        mac.data(),
        &mac_len
    );

    if (!result) {
        print_openssl_error("HMAC failed");
        return false;
    }

    mac.resize(mac_len);
    return true;
}

bool hmac_sha256_text(
    const std::string& key,
    const std::string& message
) {
    std::vector<unsigned char> key_bytes(key.begin(), key.end());
    std::vector<unsigned char> data(message.begin(), message.end());
    std::vector<unsigned char> mac;

    if (!compute_hmac_sha256(key_bytes, data, mac)) {
        return false;
    }

    std::cout << "\n>> HMAC-SHA256 RESULT <<\n";
    std::cout << "Input type  : text\n";
    std::cout << "Key size    : " << key_bytes.size() << " bytes\n";
    std::cout << "Message size: " << data.size() << " bytes\n";
    std::cout << "MAC size    : " << mac.size() << " bytes\n";
    std::cout << "MAC hex     : " << bytes_to_hex(mac) << "\n";
    std::cout << "Security    : HMAC is not vulnerable to SHA-256 length extension attack\n";

    return true;
}

bool hmac_sha256_file(
    const std::string& key,
    const std::string& in_path
) {
    std::vector<unsigned char> data;

    if (!read_binary_file(in_path, data)) {
        return false;
    }

    std::vector<unsigned char> key_bytes(key.begin(), key.end());
    std::vector<unsigned char> mac;

    if (!compute_hmac_sha256(key_bytes, data, mac)) {
        return false;
    }

    std::cout << "\n>> HMAC-SHA256 RESULT <<\n";
    std::cout << "Input type  : file\n";
    std::cout << "Input file  : " << in_path << "\n";
    std::cout << "Key size    : " << key_bytes.size() << " bytes\n";
    std::cout << "Message size: " << data.size() << " bytes\n";
    std::cout << "MAC size    : " << mac.size() << " bytes\n";
    std::cout << "MAC hex     : " << bytes_to_hex(mac) << "\n";
    std::cout << "Security    : HMAC is not vulnerable to SHA-256 length extension attack\n";

    return true;
}
