
#ifndef LIB_TRUSTED_SSL_SOCKET_SSL_X509_H
#define LIB_TRUSTED_SSL_SOCKET_SSL_X509_H

#include <sgx_error.h>
#include <openssl/x509v3.h>
#include <memory>

#define X509_MAX_NAME_SIZE 256
#define RSA_3072_PUBLIC_KEY_SIZE 650

class SSLX509 {
private:
    X509 *cert = nullptr;
    X509V3_CTX ctx{};
    EVP_PKEY *pkey = nullptr;
private:
    X509_NAME *parseName(const char *name_string);

    /* Convert the format YYYYMMDDHHMMSS to YYYYMMDDHHMMSSZ */
    char *formatDateString(const char *date_string);

public:
    SSLX509();

    ~SSLX509();

    X509 *getCert() const;

    sgx_status_t create();

    sgx_status_t setVersion(int version);

    sgx_status_t setKeyPair(EVP_PKEY *_pkey);

    sgx_status_t setSubjectName(const unsigned char *name_string);

    sgx_status_t setIssuerName(const unsigned char *name_string);

    sgx_status_t setSerialNumber(int sn);

    sgx_status_t setNotBefore(const unsigned char *date_string);

    sgx_status_t setNotAfter(const unsigned char *date_string);

    sgx_status_t prepareExtension();

    sgx_status_t addExtension(int nid, const char *value);

    sgx_status_t addCostumeExtension(const char *oid, const uint8_t *buffer, size_t size);

    sgx_status_t sign();

    sgx_status_t getCertInPEM(uint8_t *&crt, size_t *size);

    sgx_status_t load(X509 *cert);

    sgx_status_t getPublicKeyInPEM(uint8_t *&key, size_t *size);

    sgx_status_t verify(bool &result);

    sgx_status_t getCostumeExtension(const char *oid, std::shared_ptr<uint8_t> &buffer, size_t &size);
};

#endif //LIB_TRUSTED_SSL_SOCKET_SSL_X509_H
