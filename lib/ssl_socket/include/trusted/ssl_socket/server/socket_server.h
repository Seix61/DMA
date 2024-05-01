
#ifndef LIB_TRUSTED_SSL_SOCKET_SERVER_SOCKET_SERVER_H
#define LIB_TRUSTED_SSL_SOCKET_SERVER_SOCKET_SERVER_H

#include <sgx_error.h>

class SocketServer {
protected:
    int port;
    int socketFd = -1;
public:
    explicit SocketServer(int listen);

    virtual ~SocketServer();

    virtual sgx_status_t create();

    sgx_status_t accept(int &clientSocketFd) const;
};

#endif //LIB_TRUSTED_SSL_SOCKET_SERVER_SOCKET_SERVER_H
