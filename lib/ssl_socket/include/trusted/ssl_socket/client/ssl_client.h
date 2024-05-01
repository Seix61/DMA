
#ifndef LIB_TRUSTED_SSL_SOCKET_CLIENT_SSL_CLIENT_H
#define LIB_TRUSTED_SSL_SOCKET_CLIENT_SSL_CLIENT_H

#include <ssl_socket/peer/ssl_peer.h>
#include <ssl_socket/client/socket_client.h>
#include <ssl_socket/client/ssl_client_session.h>

class SSLClient : public SSLPeer, public SocketClient {
public:
    explicit SSLClient(const char *serverName, int port);

    sgx_status_t create() override;

    sgx_status_t connect(std::shared_ptr<SSLClientSession> &session);
};

#endif //LIB_TRUSTED_SSL_SOCKET_CLIENT_SSL_CLIENT_H
