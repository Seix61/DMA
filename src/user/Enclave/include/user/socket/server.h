
#ifndef USER_ENCLAVE_USER_SOCKET_SERVER_H
#define USER_ENCLAVE_USER_SOCKET_SERVER_H

#include "peer.h"
#include <ssl_socket/server/ssl_server.h>

class UserServer : public UserPeer, public SSLServer {
private:
    static int setCertCallback(SSL *session, void *arg);

    static int verifyCallback(int pre_verify_ok, X509_STORE_CTX *ctx);

public:
    explicit UserServer(int port);

    sgx_status_t create() override;
};

#endif //USER_ENCLAVE_USER_SOCKET_SERVER_H
