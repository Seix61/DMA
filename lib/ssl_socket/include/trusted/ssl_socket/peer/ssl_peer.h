
#ifndef LIB_TRUSTED_SSL_SOCKET_PEER_SSL_PEER_H
#define LIB_TRUSTED_SSL_SOCKET_PEER_SSL_PEER_H

#include <memory>
#include <functional>
#include <ssl_socket/ssl/key.h>
#include <ssl_socket/ssl/session.h>
#include <ssl_socket/ssl/context.h>
#include <ssl_socket/ssl/x509.h>

class SSLPeer {
protected:
    std::shared_ptr<SSLKey> key;
    std::shared_ptr<SSLContext> context;
    std::function<void(std::shared_ptr<SSLSession>, int)> errorCallback = nullptr;
    int (*certVerifyCallback)(int, X509_STORE_CTX *) = defaultVerifyCallback;
    std::function<void(int)> beforeHandshakeHandler = nullptr;
    std::function<void(int)> afterHandshakeHandler = nullptr;

    static int defaultSetCertCallback(SSL *session, void *arg);

    static int defaultVerifyCallback(int pre_verify_ok, X509_STORE_CTX *ctx);

public:
    explicit SSLPeer(const SSL_METHOD *(*method)());

    virtual sgx_status_t create();

    sgx_status_t setSetCertCallback(int (*callback)(SSL *, void *));

    sgx_status_t setVerifyCallback(int (*callback)(int, X509_STORE_CTX *));

    sgx_status_t setErrorCallback(std::function<void(std::shared_ptr<SSLSession>, int)> callback);

    sgx_status_t setBeforeHandshakeHandler(std::function<void(int)> handler);

    sgx_status_t setAfterHandshakeHandler(std::function<void(int)> handler);
};

#endif //LIB_TRUSTED_SSL_SOCKET_PEER_SSL_PEER_H
