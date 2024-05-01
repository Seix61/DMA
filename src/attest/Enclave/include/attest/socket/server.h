
#ifndef ATTEST_ENCLAVE_ATTEST_SOCKET_SERVER_H
#define ATTEST_ENCLAVE_ATTEST_SOCKET_SERVER_H

#include "peer.h"

#include <ssl_socket/server/ssl_server.h>

class AttestServer : public AttestPeer, public SSLServer {
private:
    static int setCertCallback(SSL *session, void *arg);

    static int verifyCallback(int pre_verify_ok, X509_STORE_CTX *ctx);

public:
    explicit AttestServer(int port);

    sgx_status_t create() override;
};

#endif //ATTEST_ENCLAVE_ATTEST_SOCKET_SERVER_H
