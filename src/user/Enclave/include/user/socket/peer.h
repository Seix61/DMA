
#ifndef USER_ENCLAVE_USER_SOCKET_PEER_H
#define USER_ENCLAVE_USER_SOCKET_PEER_H

#include <memory>
#include <openssl/ssl.h>

class UserPeer {
protected:
    static int setCert(SSL *session, void *arg, const unsigned char *peer_nonce, size_t peer_nonce_size,
                       const unsigned char *self_nonce, size_t self_nonce_size);

    static int
    verifyCert(X509 *&cert, const unsigned char *self_nonce, size_t self_nonce_size, const unsigned char *peer_nonce,
               size_t peer_nonce_size, int socketFd);
};

#endif //USER_ENCLAVE_USER_SOCKET_PEER_H
