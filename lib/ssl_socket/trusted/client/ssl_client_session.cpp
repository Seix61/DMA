
#include <ssl_socket/client/ssl_client_session.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <util/log.h>

SSLClientSession::SSLClientSession(const std::shared_ptr<SSLContext> &context, const int &socketFd) : SSLSession(
        context, socketFd) {}

sgx_status_t SSLClientSession::handshake() {
    int ret;

    do {
        if ((ret = SSL_connect(this->session)) != 1) {
            int error = SSL_get_error(this->session, ret);
#ifdef LOG_VERBOSE
            LOG_ERROR("SSL connect failed. Returned %d, error is %d.", ret, error);
#endif
            if (this->errorCallback) {
                this->errorCallback(shared_from_this(), error);
            }
            break;
        }
        return SGX_SUCCESS;
    } while (false);

    return SGX_ERROR_UNEXPECTED;
}

int SSLClientSession::getPort() const {
    sockaddr_in peerAddr{};
    socklen_t peerAddrLen = sizeof(peerAddr);
    if (getpeername(this->socketFd, (sockaddr *)&peerAddr, &peerAddrLen) == 0) {
        return peerAddr.sin_port;
    }
    return -1;
}
