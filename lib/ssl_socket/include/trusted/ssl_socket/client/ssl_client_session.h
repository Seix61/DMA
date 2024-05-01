
#ifndef LIB_TRUSTED_SSL_SOCKET_CLIENT_SSL_CLIENT_SESSION_H
#define LIB_TRUSTED_SSL_SOCKET_CLIENT_SSL_CLIENT_SESSION_H

#include <ssl_socket/ssl/session.h>

class SSLClientSession : public SSLSession {
public:
    SSLClientSession(const std::shared_ptr<SSLContext> &context, const int &socketFd);

    sgx_status_t handshake() override;

    int getPort() const override;
};

#endif //LIB_TRUSTED_SSL_SOCKET_CLIENT_SSL_CLIENT_SESSION_H
