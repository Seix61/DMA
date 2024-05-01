
#ifndef LIB_TRUSTED_SSL_SOCKET_SSL_KEY_H
#define LIB_TRUSTED_SSL_SOCKET_SSL_KEY_H

#include <sgx_error.h>
#include <openssl/ssl.h>

class SSLKey {
private:
    EVP_PKEY *pKey;

    sgx_status_t generateByEC();

    sgx_status_t generateByRSA();

public:
    SSLKey();

    ~SSLKey();

    EVP_PKEY *getPKey() const;

    sgx_status_t generate();

    sgx_status_t getPublicKeyInPEM(uint8_t *&key, size_t *size);

    sgx_status_t getPrivateKeyInPEM(uint8_t *&key, size_t *size);
};

#endif //LIB_TRUSTED_SSL_SOCKET_SSL_KEY_H
