
#ifndef LIB_TRUSTED_UTIL_SSL_H
#define LIB_TRUSTED_UTIL_SSL_H

#include <sgx_error.h>
#include <memory>
#include <ssl_socket/ssl/key.h>
#include <ssl_socket/ssl/x509.h>

class SSLUtil {
private:
    static const char *DefaultSubjectName;
    static const char *DefaultDateNotValidBefore;
    static const char *DefaultDateNotValidAfter;
public:
    static sgx_status_t defaultCertInit(const std::shared_ptr<SSLKey> &key, std::shared_ptr<SSLX509> &cert);

    static sgx_status_t getServerRandom(const SSL *session, std::shared_ptr<unsigned char> &out, size_t &size);

    static sgx_status_t getClientRandom(const SSL *session, std::shared_ptr<unsigned char> &out, size_t &size);
};

#endif //LIB_TRUSTED_UTIL_SSL_H
