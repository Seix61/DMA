
#ifndef LIB_TRUSTED_SSL_SOCKET_SSL_CONTEXT_H
#define LIB_TRUSTED_SSL_SOCKET_SSL_CONTEXT_H

#include <sgx_error.h>
#include <openssl/ssl.h>

class SSLContext {
private:
    const SSL_METHOD *(*method)();

    SSL_CONF_CTX *confContext = nullptr;
    SSL_CTX *context = nullptr;
private:
    sgx_status_t defaultInit();

public:
    explicit SSLContext(const SSL_METHOD *(*method)());

    virtual ~SSLContext();

    SSL_CTX *getContext() const;

    sgx_status_t create();

    sgx_status_t setSetCertCallback(int (*callback)(SSL *, void *), void *arg);
};

#endif //LIB_TRUSTED_SSL_SOCKET_SSL_CONTEXT_H
