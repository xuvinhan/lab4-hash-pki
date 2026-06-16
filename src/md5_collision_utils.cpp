#include "md5_collision_utils.h"

#include "file_utils.h"

#include <openssl/evp.h>
#include <openssl/err.h>

#include <iostream>
#include <vector>
#include <string>

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

static bool digest_bytes(
    const std::vector<unsigned char>& data,
    const EVP_MD* md,
    std::vector<unsigned char>& digest
) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();

    if (!ctx) {
        return false;
    }

    digest.resize(EVP_MAX_MD_SIZE);
    unsigned int out_len = 0;
    bool ok = false;

    do {
        if (EVP_DigestInit_ex(ctx, md, nullptr) != 1) {
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

static bool digest_file(
    const std::string& path,
    const EVP_MD* md,
    std::vector<unsigned char>& digest
) {
    std::vector<unsigned char> data;

    if (!read_binary_file(path, data)) {
        return false;
    }

    return digest_bytes(data, md, digest);
}

static bool load_collision_messages(
    std::vector<unsigned char>& m1,
    std::vector<unsigned char>& m2
) {
    const std::string m1_hex =
        "d131dd02c5e6eec4693d9a0698aff95c2fcab58712467eab4004583eb8fb7f89"
        "55ad340609f4b30283e488832571415a085125e8f7cdc99fd91dbdf280373c5b"
        "d8823e3156348f5bae6dacd436c919c6dd53e2b487da03fd02396306d248cda0"
        "e99f33420f577ee8ce54b67080a80d1ec69821bcb6a8839396f9652b6ff72a70";

    const std::string m2_hex =
        "d131dd02c5e6eec4693d9a0698aff95c2fcab50712467eab4004583eb8fb7f89"
        "55ad340609f4b30283e4888325f1415a085125e8f7cdc99fd91dbd7280373c5b"
        "d8823e3156348f5bae6dacd436c919c6dd53e23487da03fd02396306d248cda0"
        "e99f33420f577ee8ce54b67080280d1ec69821bcb6a8839396f965ab6ff72a70";

    return hex_to_bytes(m1_hex, m1) && hex_to_bytes(m2_hex, m2);
}

bool generate_md5_collision_samples(
    const std::string& out1,
    const std::string& out2
) {
    std::vector<unsigned char> m1;
    std::vector<unsigned char> m2;

    if (!load_collision_messages(m1, m2)) {
        std::cerr << "[ERROR] Cannot load built-in MD5 collision samples.\n";
        return false;
    }

    if (!write_binary_file(out1, m1)) {
        return false;
    }

    if (!write_binary_file(out2, m2)) {
        return false;
    }

    std::vector<unsigned char> md5_1;
    std::vector<unsigned char> md5_2;
    std::vector<unsigned char> sha256_1;
    std::vector<unsigned char> sha256_2;

    if (!digest_bytes(m1, EVP_md5(), md5_1) ||
        !digest_bytes(m2, EVP_md5(), md5_2) ||
        !digest_bytes(m1, EVP_sha256(), sha256_1) ||
        !digest_bytes(m2, EVP_sha256(), sha256_2)) {
        std::cerr << "[ERROR] Digest computation failed.\n";
        return false;
    }

    std::cout << "\n>> MD5 COLLISION SAMPLE RESULT <<\n";
    std::cout << "Output file 1     : " << out1 << "\n";
    std::cout << "Output file 2     : " << out2 << "\n";
    std::cout << "File 1 size       : " << m1.size() << " bytes\n";
    std::cout << "File 2 size       : " << m2.size() << " bytes\n";
    std::cout << "Files identical   : " << ((m1 == m2) ? "YES" : "NO") << "\n";
    std::cout << "MD5 file 1        : " << bytes_to_hex(md5_1) << "\n";
    std::cout << "MD5 file 2        : " << bytes_to_hex(md5_2) << "\n";
    std::cout << "SHA-256 file 1    : " << bytes_to_hex(sha256_1) << "\n";
    std::cout << "SHA-256 file 2    : " << bytes_to_hex(sha256_2) << "\n";
    std::cout << "Collision status  : "
              << ((md5_1 == md5_2 && m1 != m2) ? "MD5 COLLISION CONFIRMED" : "NOT A COLLISION")
              << "\n";

    return true;
}

bool compare_md5_collision_files(
    const std::string& file1,
    const std::string& file2
) {
    std::vector<unsigned char> data1;
    std::vector<unsigned char> data2;

    if (!read_binary_file(file1, data1)) {
        return false;
    }

    if (!read_binary_file(file2, data2)) {
        return false;
    }

    std::vector<unsigned char> md5_1;
    std::vector<unsigned char> md5_2;
    std::vector<unsigned char> sha256_1;
    std::vector<unsigned char> sha256_2;

    if (!digest_file(file1, EVP_md5(), md5_1) ||
        !digest_file(file2, EVP_md5(), md5_2) ||
        !digest_file(file1, EVP_sha256(), sha256_1) ||
        !digest_file(file2, EVP_sha256(), sha256_2)) {
        std::cerr << "[ERROR] Digest computation failed.\n";
        return false;
    }

    std::cout << "\n>> MD5 COLLISION COMPARE RESULT <<\n";
    std::cout << "File 1            : " << file1 << "\n";
    std::cout << "File 2            : " << file2 << "\n";
    std::cout << "File 1 size       : " << data1.size() << " bytes\n";
    std::cout << "File 2 size       : " << data2.size() << " bytes\n";
    std::cout << "Files identical   : " << ((data1 == data2) ? "YES" : "NO") << "\n";
    std::cout << "MD5 file 1        : " << bytes_to_hex(md5_1) << "\n";
    std::cout << "MD5 file 2        : " << bytes_to_hex(md5_2) << "\n";
    std::cout << "SHA-256 file 1    : " << bytes_to_hex(sha256_1) << "\n";
    std::cout << "SHA-256 file 2    : " << bytes_to_hex(sha256_2) << "\n";
    std::cout << "Collision status  : "
              << ((md5_1 == md5_2 && data1 != data2) ? "MD5 COLLISION CONFIRMED" : "NOT A COLLISION")
              << "\n";

    return true;
}
