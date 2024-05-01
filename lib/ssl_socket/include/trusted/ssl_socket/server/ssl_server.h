
#ifndef LIB_TRUSTED_SSL_SOCKET_SERVER_SSL_SERVER_H
#define LIB_TRUSTED_SSL_SOCKET_SERVER_SSL_SERVER_H

#include <ssl_socket/peer/ssl_peer.h>
#include <ssl_socket/server/socket_server.h>
#include <ssl_socket/server/ssl_server_session.h>

class SSLServer : public SSLPeer, public SocketServer {
public:
    explicit SSLServer(int port);

    sgx_status_t create() override;

    sgx_status_t accept(std::shared_ptr<SSLServerSession> &session);
};

#endif //LIB_TRUSTED_SSL_SOCKET_SERVER_SSL_SERVER_H
