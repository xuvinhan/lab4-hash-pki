#include <iostream>
#include <string>
#include <vector>
#include <cstdlib>

#include <openssl/opensslv.h>
#include <openssl/crypto.h>

#include "hash_utils.h"
#include "file_utils.h"
#include "x509_utils.h"
#include "length_extension_utils.h"
#include "hmac_utils.h"
#include "md5_collision_utils.h"

static std::string get_arg(int argc, char* argv[], const std::string& name) {
    for (int i = 0; i < argc - 1; ++i) {
        if (std::string(argv[i]) == name) {
            return argv[i + 1];
        }
    }

    return "";
}

static bool has_flag(int argc, char* argv[], const std::string& name) {
    for (int i = 0; i < argc; ++i) {
        if (std::string(argv[i]) == name) {
            return true;
        }
    }

    return false;
}

static void print_usage() {
    std::cout << "hashtool - Lab 4 Hashing, PKI, and Practical Attacks\n\n";
    std::cout << "Usage:\n";
    std::cout << "  hashtool --version\n";
    std::cout << "  hashtool hash --algo sha256 --text \"hello\"\n";
    std::cout << "  hashtool hash --algo sha256 --in file.bin\n";
    std::cout << "  hashtool hash --algo sha3-256 --in file.bin\n";
    std::cout << "  hashtool hash --algo shake256 --outlen 64 --in file.bin\n";
    std::cout << "  hashtool hash --algo sha256 --in file.bin --out digest.bin --encode raw\n";
    std::cout << "  hashtool hash --algo sha256 --in file.bin --out digest.hex --encode hex\n";
    std::cout << "  hashtool x509 --cert cert.pem\n";
    std::cout << "  hashtool le-demo --secret secret --message msg --append data --keylen N --out forged.bin\n";
    std::cout << "  hashtool le-attack --mac sha256hex --message msg --append data --keylen N --out forged.bin\n";
    std::cout << "  hashtool hmac --key secret --message msg\n";
    std::cout << "  hashtool hmac --key secret --in file.bin\n";
    std::cout << "  hashtool md5-collision-sample --out1 a.bin --out2 b.bin\n";
    std::cout << "  hashtool md5-compare --file1 a.bin --file2 b.bin\n\n";
    std::cout << "Supported algorithms:\n";
    std::cout << "  SHA-2  : sha224, sha256, sha384, sha512\n";
    std::cout << "  SHA-3  : sha3-224, sha3-256, sha3-384, sha3-512\n";
    std::cout << "  SHAKE  : shake128, shake256\n";
}

static bool parse_size_t(const std::string& s, size_t& value) {
    if (s.empty()) {
        return false;
    }

    try {
        size_t pos = 0;
        unsigned long long parsed = std::stoull(s, &pos, 10);

        if (pos != s.size()) {
            return false;
        }

        value = static_cast<size_t>(parsed);
        return true;

    } catch (...) {
        return false;
    }
}

int main(int argc, char* argv[]) {
    if (argc >= 2 && std::string(argv[1]) == "--version") {
        std::cout << "{\n";
        std::cout << "  \"tool\": \"hashtool\",\n";
        std::cout << "  \"lab\": \"Lab 4 - Hashing, PKI, and Practical Attacks\",\n";
        std::cout << "  \"openssl\": \"" << OpenSSL_version(OPENSSL_VERSION) << "\",\n";
        std::cout << "  \"status\": \"environment ok\"\n";
        std::cout << "}\n";
        return 0;
    }

    if (argc >= 2 && std::string(argv[1]) == "md5-collision-sample") {
        std::string out1 = get_arg(argc, argv, "--out1");
        std::string out2 = get_arg(argc, argv, "--out2");

        if (out1.empty() || out2.empty()) {
            std::cerr << "[ERROR] Missing --out1 or --out2.\n";
            print_usage();
            return 1;
        }

        return generate_md5_collision_samples(out1, out2) ? 0 : 1;
    }

    if (argc >= 2 && std::string(argv[1]) == "md5-compare") {
        std::string file1 = get_arg(argc, argv, "--file1");
        std::string file2 = get_arg(argc, argv, "--file2");

        if (file1.empty() || file2.empty()) {
            std::cerr << "[ERROR] Missing --file1 or --file2.\n";
            print_usage();
            return 1;
        }

        return compare_md5_collision_files(file1, file2) ? 0 : 1;
    }

    if (argc >= 2 && std::string(argv[1]) == "x509") {
        std::string cert_path = get_arg(argc, argv, "--cert");

        if (cert_path.empty()) {
            std::cerr << "[ERROR] Missing --cert.\n";
            print_usage();
            return 1;
        }

        return parse_x509_certificate(cert_path) ? 0 : 1;
    }

    if (argc >= 2 && std::string(argv[1]) == "hmac") {
        std::string key = get_arg(argc, argv, "--key");
        std::string message = get_arg(argc, argv, "--message");
        std::string in_path = get_arg(argc, argv, "--in");

        if (key.empty()) {
            std::cerr << "[ERROR] Missing --key.\n";
            print_usage();
            return 1;
        }

        if (!message.empty() && !in_path.empty()) {
            std::cerr << "[ERROR] Use either --message or --in, not both.\n";
            return 1;
        }

        if (message.empty() && in_path.empty()) {
            std::cerr << "[ERROR] Missing input. Use --message or --in.\n";
            return 1;
        }

        if (!message.empty()) {
            return hmac_sha256_text(key, message) ? 0 : 1;
        }

        return hmac_sha256_file(key, in_path) ? 0 : 1;
    }

    if (argc >= 2 && std::string(argv[1]) == "le-demo") {
        std::string secret = get_arg(argc, argv, "--secret");
        std::string message = get_arg(argc, argv, "--message");
        std::string append = get_arg(argc, argv, "--append");
        std::string keylen_str = get_arg(argc, argv, "--keylen");
        std::string out_path = get_arg(argc, argv, "--out");

        size_t keylen = 0;

        if (secret.empty() || message.empty() || append.empty() || keylen_str.empty() || out_path.empty()) {
            std::cerr << "[ERROR] Missing arguments for le-demo.\n";
            print_usage();
            return 1;
        }

        if (!parse_size_t(keylen_str, keylen)) {
            std::cerr << "[ERROR] Invalid --keylen.\n";
            return 1;
        }

        return sha256_length_extension_demo(secret, message, append, keylen, out_path) ? 0 : 1;
    }

    if (argc >= 2 && std::string(argv[1]) == "le-attack") {
        std::string mac = get_arg(argc, argv, "--mac");
        std::string message = get_arg(argc, argv, "--message");
        std::string append = get_arg(argc, argv, "--append");
        std::string keylen_str = get_arg(argc, argv, "--keylen");
        std::string out_path = get_arg(argc, argv, "--out");

        size_t keylen = 0;

        if (mac.empty() || message.empty() || append.empty() || keylen_str.empty() || out_path.empty()) {
            std::cerr << "[ERROR] Missing arguments for le-attack.\n";
            print_usage();
            return 1;
        }

        if (!parse_size_t(keylen_str, keylen)) {
            std::cerr << "[ERROR] Invalid --keylen.\n";
            return 1;
        }

        return sha256_length_extension_attack(mac, message, append, keylen, out_path) ? 0 : 1;
    }

    if (argc >= 2 && std::string(argv[1]) == "hash") {
        std::string algo = get_arg(argc, argv, "--algo");
        std::string in_path = get_arg(argc, argv, "--in");
        std::string text = get_arg(argc, argv, "--text");
        std::string out_path = get_arg(argc, argv, "--out");
        std::string encode = get_arg(argc, argv, "--encode");
        std::string outlen_str = get_arg(argc, argv, "--outlen");

        bool stream_mode = has_flag(argc, argv, "--stream");

        if (algo.empty()) {
            std::cerr << "[ERROR] Missing --algo.\n";
            print_usage();
            return 1;
        }

        algo = normalize_hash_algorithm(algo);

        if (!is_supported_hash_algorithm(algo)) {
            std::cerr << "[ERROR] Unsupported algorithm: " << algo << "\n";
            return 1;
        }

        if (!in_path.empty() && !text.empty()) {
            std::cerr << "[ERROR] Use either --in or --text, not both.\n";
            return 1;
        }

        if (in_path.empty() && text.empty()) {
            std::cerr << "[ERROR] Missing input. Use --in file or --text \"...\".\n";
            return 1;
        }

        if (encode.empty()) {
            encode = out_path.empty() ? "hex" : "raw";
        }

        if (encode != "hex" && encode != "raw") {
            std::cerr << "[ERROR] Unsupported --encode value. Use hex or raw.\n";
            return 1;
        }

        size_t shake_out_len = 0;

        if (is_shake_algorithm(algo)) {
            if (outlen_str.empty()) {
                std::cerr << "[ERROR] SHAKE requires --outlen in bytes.\n";
                return 1;
            }

            if (!parse_size_t(outlen_str, shake_out_len) || shake_out_len == 0) {
                std::cerr << "[ERROR] Invalid --outlen value.\n";
                return 1;
            }
        }

        std::vector<unsigned char> digest;
        size_t total_bytes = 0;
        bool ok = false;

        if (!in_path.empty()) {
            ok = hash_file_streaming(algo, in_path, shake_out_len, digest, total_bytes);
        } else {
            ok = hash_text(algo, text, shake_out_len, digest);
            total_bytes = text.size();
        }

        if (!ok) {
            return 1;
        }

        std::string hex_digest = bytes_to_hex(digest);

        if (!out_path.empty()) {
            if (encode == "raw") {
                if (!write_binary_file(out_path, digest)) {
                    return 1;
                }
            } else {
                if (!write_text_file(out_path, hex_digest + "\n")) {
                    return 1;
                }
            }
        }

        std::cout << "\n>> HASH RESULT <<\n";
        std::cout << "Algorithm       : " << algo << "\n";
        std::cout << "Input type      : " << (!in_path.empty() ? "file" : "text") << "\n";

        if (!in_path.empty()) {
            std::cout << "Input file      : " << in_path << "\n";
            std::cout << "Streaming       : " << (stream_mode ? "enabled" : "default") << "\n";
        }

        std::cout << "Input size      : " << total_bytes << " bytes\n";
        std::cout << "Digest size     : " << digest.size() << " bytes\n";
        std::cout << "Digest hex      : " << hex_digest << "\n";

        if (!out_path.empty()) {
            std::cout << "Output file     : " << out_path << "\n";
            std::cout << "Output encoding : " << encode << "\n";
        }

        return 0;
    }

    print_usage();
    return 0;
}
