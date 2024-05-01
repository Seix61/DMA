
#ifndef ATTEST_ENCLAVE_EPID_SOCKET_CLIENT_H
#define ATTEST_ENCLAVE_EPID_SOCKET_CLIENT_H

#include "peer.h"
#include <ssl_socket/client/ssl_client.h>

class EpidClient : public EpidPeer, public SSLClient {
private:
    static int setCertCallback(SSL *session, void *arg);

    static int verifyCallback(int pre_verify_ok, X509_STORE_CTX *ctx);

public:
    explicit EpidClient(const char *serverName, int port);

    sgx_status_t create() override;
};

#endif //ATTEST_ENCLAVE_EPID_SOCKET_CLIENT_H
