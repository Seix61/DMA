
#ifndef AUTH_ENCLAVE_CONSENSUS_SOCKET_CLIENT_H
#define AUTH_ENCLAVE_CONSENSUS_SOCKET_CLIENT_H

#include "peer.h"
#include <ssl_socket/client/ssl_client.h>

class ConsensusClient : public ConsensusPeer, public SSLClient {
private:
    static int setCertCallback(SSL *session, void *arg);

    static int verifyCallback(int pre_verify_ok, X509_STORE_CTX *ctx);

public:
    explicit ConsensusClient(const char *serverName, int port);

    sgx_status_t create() override;
};

#endif //AUTH_ENCLAVE_CONSENSUS_SOCKET_CLIENT_H
