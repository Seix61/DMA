
#include <ssl_socket/server/socket_server.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <util/log.h>

SocketServer::SocketServer(int listen) : port(listen) {}

SocketServer::~SocketServer() {
    if (this->socketFd > 0) {
        close(this->socketFd);
    }
}

sgx_status_t SocketServer::create() {
    const int reuse = 1;
    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(this->port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    do {
        if ((this->socketFd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
#ifdef LOG_VERBOSE
            LOG_ERROR("Failed to create socket.");
#endif
            break;
        }
        if (setsockopt(this->socketFd, SOL_SOCKET, SO_REUSEADDR, (const void *) &reuse, sizeof(reuse)) < 0) {
#ifdef LOG_VERBOSE
            LOG_ERROR("Failed to set socket option.");
#endif
            break;
        }
        if (bind(this->socketFd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
#ifdef LOG_VERBOSE
            LOG_ERROR("Failed to bind socket.");
#endif
            break;
        }
        if (listen(this->socketFd, 20) < 0) {
#ifdef LOG_VERBOSE
            LOG_ERROR("Failed to open socket for listening.");
#endif
            break;
        }

        return SGX_SUCCESS;
    } while (false);

    return SGX_ERROR_UNEXPECTED;
}

sgx_status_t SocketServer::accept(int &clientSocketFd) const {
    struct sockaddr_in addr{};
    unsigned int len = sizeof(addr);

    do {
        if ((clientSocketFd = ::accept(this->socketFd, (struct sockaddr *) &addr, &len)) < 0) {
#ifdef LOG_VERBOSE
            LOG_ERROR("Failed to accept the client request.");
#endif
            break;
        }
        return SGX_SUCCESS;
    } while (false);

    return SGX_ERROR_UNEXPECTED;
}
