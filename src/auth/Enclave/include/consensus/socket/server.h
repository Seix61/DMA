
#ifndef AUTH_ENCLAVE_CONSENSUS_SOCKET_SERVER_H
#define AUTH_ENCLAVE_CONSENSUS_SOCKET_SERVER_H

#include "peer.h"
#include <ssl_socket/server/ssl_server.h>

class ConsensusServer : public ConsensusPeer, public SSLServer {
private:
    static int setCertCallback(SSL *session, void *arg);

    static int verifyCallback(int pre_verify_ok, X509_STORE_CTX *ctx);

public:
    explicit ConsensusServer(int port);

    sgx_status_t create() override;
};

#endif //AUTH_ENCLAVE_CONSENSUS_SOCKET_SERVER_H
