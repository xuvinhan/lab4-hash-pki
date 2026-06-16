#include "hash_utils.h"

#include <openssl/evp.h>
#include <openssl/err.h>

#include <algorithm>
#include <cctype>
#include <fstream>
#include <iostream>

static void print_openssl_error(const std::string& msg) {
    std::cerr << "[ERROR] " << msg << "\n";
    ERR_print_errors_fp(stderr);
}

std::string normalize_hash_algorithm(const std::string& algo) {
    std::string s = algo;

    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });

    std::replace(s.begin(), s.end(), '_', '-');

    return s;
}

bool is_shake_algorithm(const std::string& algo) {
    std::string a = normalize_hash_algorithm(algo);
    return a == "shake128" || a == "shake256";
}

static const EVP_MD* get_evp_md(const std::string& algo) {
    std::string a = normalize_hash_algorithm(algo);

    if (a == "sha224") {
        return EVP_sha224();
    }

    if (a == "sha256") {
        return EVP_sha256();
    }

    if (a == "sha384") {
        return EVP_sha384();
    }

    if (a == "sha512") {
        return EVP_sha512();
    }

    if (a == "sha3-224") {
        return EVP_sha3_224();
    }

    if (a == "sha3-256") {
        return EVP_sha3_256();
    }

    if (a == "sha3-384") {
        return EVP_sha3_384();
    }

    if (a == "sha3-512") {
        return EVP_sha3_512();
    }

    if (a == "shake128") {
        return EVP_shake128();
    }

    if (a == "shake256") {
        return EVP_shake256();
    }

    return nullptr;
}

bool is_supported_hash_algorithm(const std::string& algo) {
    return get_evp_md(algo) != nullptr;
}

static bool finalize_digest(
    EVP_MD_CTX* ctx,
    const std::string& algo,
    size_t shake_out_len,
    std::vector<unsigned char>& digest
) {
    if (is_shake_algorithm(algo)) {
        if (shake_out_len == 0) {
            std::cerr << "[ERROR] SHAKE requires --outlen in bytes.\n";
            return false;
        }

        digest.resize(shake_out_len);

        if (EVP_DigestFinalXOF(ctx, digest.data(), digest.size()) != 1) {
            print_openssl_error("EVP_DigestFinalXOF failed");
            return false;
        }

        return true;
    }

    const EVP_MD* md = get_evp_md(algo);
    int digest_len = EVP_MD_get_size(md);

    if (digest_len <= 0) {
        std::cerr << "[ERROR] Invalid digest length.\n";
        return false;
    }

    digest.resize(static_cast<size_t>(digest_len));
    unsigned int out_len = 0;

    if (EVP_DigestFinal_ex(ctx, digest.data(), &out_len) != 1) {
        print_openssl_error("EVP_DigestFinal_ex failed");
        return false;
    }

    digest.resize(out_len);
    return true;
}

bool hash_text(
    const std::string& algo,
    const std::string& text,
    size_t shake_out_len,
    std::vector<unsigned char>& digest
) {
    const EVP_MD* md = get_evp_md(algo);

    if (!md) {
        std::cerr << "[ERROR] Unsupported hash algorithm: " << algo << "\n";
        return false;
    }

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();

    if (!ctx) {
        print_openssl_error("EVP_MD_CTX_new failed");
        return false;
    }

    bool ok = false;

    do {
        if (EVP_DigestInit_ex(ctx, md, nullptr) != 1) {
            print_openssl_error("EVP_DigestInit_ex failed");
            break;
        }

        if (!text.empty()) {
            if (EVP_DigestUpdate(ctx, text.data(), text.size()) != 1) {
                print_openssl_error("EVP_DigestUpdate failed");
                break;
            }
        }

        if (!finalize_digest(ctx, algo, shake_out_len, digest)) {
            break;
        }

        ok = true;

    } while (false);

    EVP_MD_CTX_free(ctx);
    return ok;
}

bool hash_file_streaming(
    const std::string& algo,
    const std::string& in_path,
    size_t shake_out_len,
    std::vector<unsigned char>& digest,
    size_t& total_bytes
) {
    const EVP_MD* md = get_evp_md(algo);

    if (!md) {
        std::cerr << "[ERROR] Unsupported hash algorithm: " << algo << "\n";
        return false;
    }

    std::ifstream in(in_path, std::ios::binary);

    if (!in) {
        std::cerr << "[ERROR] Cannot open input file: " << in_path << "\n";
        return false;
    }

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();

    if (!ctx) {
        print_openssl_error("EVP_MD_CTX_new failed");
        return false;
    }

    bool ok = false;
    total_bytes = 0;

    do {
        if (EVP_DigestInit_ex(ctx, md, nullptr) != 1) {
            print_openssl_error("EVP_DigestInit_ex failed");
            break;
        }

        const size_t buffer_size = 64 * 1024;
        std::vector<char> buffer(buffer_size);

        while (in) {
            in.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
            std::streamsize got = in.gcount();

            if (got > 0) {
                if (EVP_DigestUpdate(ctx, buffer.data(), static_cast<size_t>(got)) != 1) {
                    print_openssl_error("EVP_DigestUpdate failed");
                    break;
                }

                total_bytes += static_cast<size_t>(got);
            }
        }

        if (in.bad()) {
            std::cerr << "[ERROR] File read error: " << in_path << "\n";
            break;
        }

        if (!finalize_digest(ctx, algo, shake_out_len, digest)) {
            break;
        }

        ok = true;

    } while (false);

    EVP_MD_CTX_free(ctx);
    return ok;
}
