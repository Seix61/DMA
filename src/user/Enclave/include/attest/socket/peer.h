
#ifndef USER_ENCLAVE_ATTEST_SOCKET_PEER_H
#define USER_ENCLAVE_ATTEST_SOCKET_PEER_H

#include <memory>
#include <openssl/ssl.h>
#include <sgx_report.h>

class AttestPeer {
protected:
    static int setCert(SSL *session, void *arg, const unsigned char *nonce, size_t nonce_size);

    static int verifyCert(X509 *&cert, const unsigned char *nonce, size_t nonce_size);
};

#endif //USER_ENCLAVE_ATTEST_SOCKET_PEER_H
