
#ifndef AUTH_ENCLAVE_EPID_SERVER_H
#define AUTH_ENCLAVE_EPID_SERVER_H

#include "peer.h"
#include <ssl_socket/server/ssl_server.h>

class EpidServer : public EpidPeer, public SSLServer {
private:
    static int setCertCallback(SSL *session, void *arg);

    static int verifyCallback(int pre_verify_ok, X509_STORE_CTX *ctx);

public:
    explicit EpidServer(int port);

    sgx_status_t create() override;
};

#endif //AUTH_ENCLAVE_EPID_SERVER_H
