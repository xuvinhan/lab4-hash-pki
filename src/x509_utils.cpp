#include "x509_utils.h"

#include <iostream>
#include <string>

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/err.h>

static void print_openssl_error(const std::string& msg) {
    std::cerr << "[ERROR] " << msg << "\n";
    ERR_print_errors_fp(stderr);
}

static std::string bio_to_string(BIO* bio) {
    BUF_MEM* mem = nullptr;
    BIO_get_mem_ptr(bio, &mem);

    if (!mem || !mem->data || mem->length == 0) {
        return "";
    }

    return std::string(mem->data, mem->length);
}

static std::string x509_name_to_string(X509_NAME* name) {
    if (!name) {
        return "(null)";
    }

    BIO* bio = BIO_new(BIO_s_mem());

    if (!bio) {
        return "(BIO allocation failed)";
    }

    X509_NAME_print_ex(bio, name, 0, XN_FLAG_RFC2253);
    std::string result = bio_to_string(bio);
    BIO_free(bio);

    return result;
}

static std::string asn1_time_to_string(const ASN1_TIME* time) {
    if (!time) {
        return "(null)";
    }

    BIO* bio = BIO_new(BIO_s_mem());

    if (!bio) {
        return "(BIO allocation failed)";
    }

    ASN1_TIME_print(bio, time);
    std::string result = bio_to_string(bio);
    BIO_free(bio);

    return result;
}

static std::string serial_to_hex(X509* cert) {
    ASN1_INTEGER* serial = X509_get_serialNumber(cert);

    if (!serial) {
        return "(null)";
    }

    BIGNUM* bn = ASN1_INTEGER_to_BN(serial, nullptr);

    if (!bn) {
        return "(conversion failed)";
    }

    char* hex = BN_bn2hex(bn);
    std::string result = hex ? hex : "(conversion failed)";

    OPENSSL_free(hex);
    BN_free(bn);

    return result;
}

static X509* load_certificate_pem_or_der(const std::string& cert_path) {
    BIO* bio = BIO_new_file(cert_path.c_str(), "rb");

    if (!bio) {
        print_openssl_error("Cannot open certificate file");
        return nullptr;
    }

    X509* cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);

    if (cert) {
        return cert;
    }

    ERR_clear_error();

    bio = BIO_new_file(cert_path.c_str(), "rb");

    if (!bio) {
        print_openssl_error("Cannot reopen certificate file");
        return nullptr;
    }

    cert = d2i_X509_bio(bio, nullptr);
    BIO_free(bio);

    if (!cert) {
        print_openssl_error("Cannot parse certificate as PEM or DER");
        return nullptr;
    }

    return cert;
}

static std::string public_key_type_to_string(EVP_PKEY* pkey) {
    if (!pkey) {
        return "(null)";
    }

    int type = EVP_PKEY_base_id(pkey);

    switch (type) {
        case EVP_PKEY_RSA:
            return "RSA";
        case EVP_PKEY_EC:
            return "EC";
        case EVP_PKEY_DSA:
            return "DSA";
        case EVP_PKEY_ED25519:
            return "ED25519";
        case EVP_PKEY_ED448:
            return "ED448";
        default:
            return "Unknown";
    }
}

static void print_extension_by_nid(X509* cert, int nid, const std::string& title) {
    int loc = X509_get_ext_by_NID(cert, nid, -1);

    if (loc < 0) {
        std::cout << title << " : (not present)\n";
        return;
    }

    X509_EXTENSION* ext = X509_get_ext(cert, loc);

    if (!ext) {
        std::cout << title << " : (cannot read)\n";
        return;
    }

    BIO* bio = BIO_new(BIO_s_mem());

    if (!bio) {
        std::cout << title << " : (BIO allocation failed)\n";
        return;
    }

    if (!X509V3_EXT_print(bio, ext, 0, 0)) {
        ASN1_STRING_print(bio, X509_EXTENSION_get_data(ext));
    }

    std::string value = bio_to_string(bio);
    BIO_free(bio);

    if (value.empty()) {
        value = "(empty)";
    }

    std::cout << title << " : " << value << "\n";
}

bool parse_x509_certificate(const std::string& cert_path) {
    X509* cert = load_certificate_pem_or_der(cert_path);

    if (!cert) {
        return false;
    }

    std::cout << "\n>> X.509 CERTIFICATE RESULT <<\n";
    std::cout << "Certificate file    : " << cert_path << "\n";

    std::cout << "Subject             : "
              << x509_name_to_string(X509_get_subject_name(cert)) << "\n";

    std::cout << "Issuer              : "
              << x509_name_to_string(X509_get_issuer_name(cert)) << "\n";

    std::cout << "Serial number       : "
              << serial_to_hex(cert) << "\n";

    std::cout << "Not Before          : "
              << asn1_time_to_string(X509_get0_notBefore(cert)) << "\n";

    std::cout << "Not After           : "
              << asn1_time_to_string(X509_get0_notAfter(cert)) << "\n";

    int sig_nid = X509_get_signature_nid(cert);
    std::cout << "Signature algorithm : "
              << OBJ_nid2ln(sig_nid) << "\n";

    EVP_PKEY* pkey = X509_get_pubkey(cert);

    if (pkey) {
        std::cout << "Public key type     : "
                  << public_key_type_to_string(pkey) << "\n";

        std::cout << "Public key bits     : "
                  << EVP_PKEY_bits(pkey) << "\n";

        EVP_PKEY_free(pkey);
    } else {
        std::cout << "Public key type     : (cannot read)\n";
        std::cout << "Public key bits     : (cannot read)\n";
    }

    print_extension_by_nid(cert, NID_basic_constraints, "Basic Constraints");
    print_extension_by_nid(cert, NID_key_usage, "Key Usage");
    print_extension_by_nid(cert, NID_ext_key_usage, "Extended Key Usage");
    print_extension_by_nid(cert, NID_subject_alt_name, "Subject Alternative Name");

    X509_free(cert);
    return true;
}
