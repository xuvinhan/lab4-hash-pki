#include "length_extension_utils.h"

#include "file_utils.h"

#include <openssl/evp.h>
#include <openssl/err.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <vector>
#include <string>

static uint32_t rotr(uint32_t x, uint32_t n) {
    return (x >> n) | (x << (32 - n));
}

static uint32_t load_be32(const unsigned char* p) {
    return (static_cast<uint32_t>(p[0]) << 24) |
           (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8)  |
           (static_cast<uint32_t>(p[3]));
}

static void store_be32(uint32_t x, unsigned char* p) {
    p[0] = static_cast<unsigned char>((x >> 24) & 0xff);
    p[1] = static_cast<unsigned char>((x >> 16) & 0xff);
    p[2] = static_cast<unsigned char>((x >> 8) & 0xff);
    p[3] = static_cast<unsigned char>(x & 0xff);
}

static const uint32_t K[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
    0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
    0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
    0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
    0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
    0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
};

static void sha256_compress(uint32_t state[8], const unsigned char block[64]) {
    uint32_t w[64];

    for (int i = 0; i < 16; ++i) {
        w[i] = load_be32(block + i * 4);
    }

    for (int i = 16; i < 64; ++i) {
        uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    uint32_t a = state[0];
    uint32_t b = state[1];
    uint32_t c = state[2];
    uint32_t d = state[3];
    uint32_t e = state[4];
    uint32_t f = state[5];
    uint32_t g = state[6];
    uint32_t h = state[7];

    for (int i = 0; i < 64; ++i) {
        uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t temp1 = h + S1 + ch + K[i] + w[i];
        uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temp2 = S0 + maj;

        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}

static int hex_value(char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }

    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }

    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }

    return -1;
}

static bool hex_to_bytes(const std::string& hex, std::vector<unsigned char>& out) {
    if (hex.size() % 2 != 0) {
        return false;
    }

    out.clear();
    out.reserve(hex.size() / 2);

    for (size_t i = 0; i < hex.size(); i += 2) {
        int hi = hex_value(hex[i]);
        int lo = hex_value(hex[i + 1]);

        if (hi < 0 || lo < 0) {
            return false;
        }

        out.push_back(static_cast<unsigned char>((hi << 4) | lo));
    }

    return true;
}

static std::vector<unsigned char> sha256_padding(uint64_t message_len_bytes) {
    std::vector<unsigned char> padding;

    padding.push_back(0x80);

    while ((message_len_bytes + padding.size()) % 64 != 56) {
        padding.push_back(0x00);
    }

    uint64_t bit_len = message_len_bytes * 8;

    for (int i = 7; i >= 0; --i) {
        padding.push_back(static_cast<unsigned char>((bit_len >> (i * 8)) & 0xff));
    }

    return padding;
}

static bool parse_sha256_state_from_hex(const std::string& mac_hex, uint32_t state[8]) {
    std::vector<unsigned char> mac;

    if (!hex_to_bytes(mac_hex, mac)) {
        return false;
    }

    if (mac.size() != 32) {
        return false;
    }

    for (int i = 0; i < 8; ++i) {
        state[i] = load_be32(mac.data() + i * 4);
    }

    return true;
}

static std::vector<unsigned char> state_to_digest(uint32_t state[8]) {
    std::vector<unsigned char> digest(32);

    for (int i = 0; i < 8; ++i) {
        store_be32(state[i], digest.data() + i * 4);
    }

    return digest;
}

static bool sha256_bytes(const std::vector<unsigned char>& data, std::vector<unsigned char>& digest) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();

    if (!ctx) {
        return false;
    }

    digest.resize(32);
    unsigned int out_len = 0;
    bool ok = false;

    do {
        if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1) {
            break;
        }

        if (!data.empty()) {
            if (EVP_DigestUpdate(ctx, data.data(), data.size()) != 1) {
                break;
            }
        }

        if (EVP_DigestFinal_ex(ctx, digest.data(), &out_len) != 1) {
            break;
        }

        digest.resize(out_len);
        ok = true;

    } while (false);

    EVP_MD_CTX_free(ctx);
    return ok;
}

static bool sha256_continue_from_state(
    uint32_t state[8],
    uint64_t already_processed_len,
    const std::vector<unsigned char>& append_data,
    std::vector<unsigned char>& forged_digest
) {
    if (already_processed_len % 64 != 0) {
        std::cerr << "[ERROR] Internal length is not block aligned.\n";
        return false;
    }

    std::vector<unsigned char> data = append_data;
    std::vector<unsigned char> final_padding = sha256_padding(already_processed_len + append_data.size());

    data.insert(data.end(), final_padding.begin(), final_padding.end());

    if (data.size() % 64 != 0) {
        std::cerr << "[ERROR] Internal padding error.\n";
        return false;
    }

    for (size_t offset = 0; offset < data.size(); offset += 64) {
        sha256_compress(state, data.data() + offset);
    }

    forged_digest = state_to_digest(state);
    return true;
}

bool sha256_length_extension_attack(
    const std::string& original_mac_hex,
    const std::string& known_message,
    const std::string& data_to_append,
    size_t key_len_guess,
    const std::string& forged_out_path
) {
    uint32_t state[8];

    if (!parse_sha256_state_from_hex(original_mac_hex, state)) {
        std::cerr << "[ERROR] Invalid SHA-256 MAC hex. It must be 64 hex characters.\n";
        return false;
    }

    std::vector<unsigned char> message(known_message.begin(), known_message.end());
    std::vector<unsigned char> append(data_to_append.begin(), data_to_append.end());

    uint64_t original_total_len = static_cast<uint64_t>(key_len_guess + message.size());
    std::vector<unsigned char> glue_padding = sha256_padding(original_total_len);

    std::vector<unsigned char> forged_message = message;
    forged_message.insert(forged_message.end(), glue_padding.begin(), glue_padding.end());
    forged_message.insert(forged_message.end(), append.begin(), append.end());

    uint64_t already_processed_len = original_total_len + glue_padding.size();

    std::vector<unsigned char> forged_digest;

    if (!sha256_continue_from_state(state, already_processed_len, append, forged_digest)) {
        return false;
    }

    if (!forged_out_path.empty()) {
        if (!write_binary_file(forged_out_path, forged_message)) {
            return false;
        }
    }

    std::cout << "\n>> SHA-256 LENGTH EXTENSION ATTACK RESULT <<\n";
    std::cout << "Known message size     : " << message.size() << " bytes\n";
    std::cout << "Append data size       : " << append.size() << " bytes\n";
    std::cout << "Guessed secret length  : " << key_len_guess << " bytes\n";
    std::cout << "Glue padding size      : " << glue_padding.size() << " bytes\n";
    std::cout << "Forged message size    : " << forged_message.size() << " bytes\n";
    std::cout << "Original MAC           : " << original_mac_hex << "\n";
    std::cout << "Forged MAC             : " << bytes_to_hex(forged_digest) << "\n";

    if (!forged_out_path.empty()) {
        std::cout << "Forged message output  : " << forged_out_path << "\n";
    }

    return true;
}

bool sha256_length_extension_demo(
    const std::string& secret,
    const std::string& known_message,
    const std::string& data_to_append,
    size_t key_len_guess,
    const std::string& forged_out_path
) {
    std::vector<unsigned char> secret_bytes(secret.begin(), secret.end());
    std::vector<unsigned char> message(known_message.begin(), known_message.end());

    std::vector<unsigned char> original_input = secret_bytes;
    original_input.insert(original_input.end(), message.begin(), message.end());

    std::vector<unsigned char> original_mac;

    if (!sha256_bytes(original_input, original_mac)) {
        std::cerr << "[ERROR] Cannot compute original MAC.\n";
        return false;
    }

    std::string original_mac_hex = bytes_to_hex(original_mac);

    if (!sha256_length_extension_attack(
            original_mac_hex,
            known_message,
            data_to_append,
            key_len_guess,
            forged_out_path
        )) {
        return false;
    }

    std::vector<unsigned char> forged_message;

    if (!read_binary_file(forged_out_path, forged_message)) {
        return false;
    }

    std::vector<unsigned char> verify_input = secret_bytes;
    verify_input.insert(verify_input.end(), forged_message.begin(), forged_message.end());

    std::vector<unsigned char> real_mac;

    if (!sha256_bytes(verify_input, real_mac)) {
        std::cerr << "[ERROR] Cannot compute verification MAC.\n";
        return false;
    }

    std::cout << "\n>> LENGTH EXTENSION DEMO VERIFICATION <<\n";
    std::cout << "Real secret length     : " << secret.size() << " bytes\n";
    std::cout << "Guessed secret length  : " << key_len_guess << " bytes\n";
    std::cout << "Verification MAC       : " << bytes_to_hex(real_mac) << "\n";
    std::cout << "Verification status    : "
              << ((key_len_guess == secret.size()) ? "PASS if forged MAC matches verification MAC" : "FAIL expected because key length guess is wrong")
              << "\n";

    return true;
}
