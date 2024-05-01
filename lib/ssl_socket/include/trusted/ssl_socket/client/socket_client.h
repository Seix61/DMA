
#ifndef LIB_TRUSTED_SSL_SOCKET_CLIENT_SOCKET_CLIENT_H
#define LIB_TRUSTED_SSL_SOCKET_CLIENT_SOCKET_CLIENT_H

#include <sgx_error.h>

class SocketClient {
protected:
    const char *serverName;
    int port;
    int socketFd = -1;
public:
    explicit SocketClient(const char *serverName, int port);

    virtual ~SocketClient();

    virtual sgx_status_t create();

    sgx_status_t connect();
};

#endif //LIB_TRUSTED_SSL_SOCKET_CLIENT_SOCKET_CLIENT_H
