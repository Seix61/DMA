
#ifndef LIB_TRUSTED_SSL_SOCKET_SERVER_SSL_SERVER_SESSION_H
#define LIB_TRUSTED_SSL_SOCKET_SERVER_SSL_SERVER_SESSION_H

#include <memory>
#include <ssl_socket/ssl/session.h>
#include <ssl_socket/ssl/context.h>

class SSLServerSession : public SSLSession {
public:
    SSLServerSession(const std::shared_ptr<SSLContext> &context, const int &socketFd);

    sgx_status_t handshake() override;

    int getPort() const override;
};

#endif //LIB_TRUSTED_SSL_SOCKET_SERVER_SSL_SERVER_SESSION_H
