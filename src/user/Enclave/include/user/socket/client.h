
#ifndef USER_ENCLAVE_USER_SOCKET_CLIENT_H
#define USER_ENCLAVE_USER_SOCKET_CLIENT_H

#include "peer.h"
#include <ssl_socket/client/ssl_client.h>

class UserClient : public UserPeer, public SSLClient {
private:
    static int setCertCallback(SSL *session, void *arg);

    static int verifyCallback(int pre_verify_ok, X509_STORE_CTX *ctx);

public:
    explicit UserClient(const char *serverName, int port);

    sgx_status_t create() override;
};

#endif //USER_ENCLAVE_USER_SOCKET_CLIENT_H
