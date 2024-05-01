
#include <ssl_socket/client/socket_client.h>
#include <cstring>
#include <netinet/in.h>
#include <sys/socket.h>
#include <util/log.h>
#include <util/ip.h>

SocketClient::SocketClient(const char *serverName, int port) : serverName(serverName), port(port) {}

SocketClient::~SocketClient() {
    if (this->socketFd > 0) {
        close(this->socketFd);
    }
}

sgx_status_t SocketClient::create() {
    do {
        if ((this->socketFd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
#ifdef LOG_VERBOSE
            LOG_ERROR("Failed to create socket.");
#endif
            break;
        }

        return SGX_SUCCESS;
    } while (false);

    return SGX_ERROR_UNEXPECTED;
}

sgx_status_t SocketClient::connect() {
    struct sockaddr_in dest_sock{};
    dest_sock.sin_family = AF_INET;
    dest_sock.sin_port = htons(this->port);
    dest_sock.sin_addr.s_addr = IPUtil::ipAddr2ULong(this->serverName);
    bzero(&(dest_sock.sin_zero), sizeof(dest_sock.sin_zero));

    do {
        if (::connect(this->socketFd, (sockaddr *) &dest_sock, sizeof(sockaddr)) == -1) {
#ifdef LOG_VERBOSE
            LOG_ERROR("Failed to connect socket.");
#endif
            break;
        }

        return SGX_SUCCESS;
    } while (false);

    return SGX_ERROR_UNEXPECTED;
}
