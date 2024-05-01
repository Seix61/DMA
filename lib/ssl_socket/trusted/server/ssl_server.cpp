
#include <ssl_socket/server/ssl_server.h>
#include <util/log.h>

SSLServer::SSLServer(int port) : SSLPeer(TLS_server_method), SocketServer(port) {}

sgx_status_t SSLServer::create() {
    do {
        if (SSLPeer::create() != SGX_SUCCESS) {
#ifdef LOG_VERBOSE
            LOG_ERROR("Failed to create ssl peer.");
#endif
            break;
        }
        if (SocketServer::create() != SGX_SUCCESS) {
#ifdef LOG_VERBOSE
            LOG_ERROR("Failed to create socket server.");
#endif
            break;
        }

        return SGX_SUCCESS;
    } while (false);

    return SGX_ERROR_UNEXPECTED;
}

sgx_status_t SSLServer::accept(std::shared_ptr<SSLServerSession> &session) {
    int clientSocketFd = -1;

    do {
        if (SocketServer::accept(clientSocketFd) != SGX_SUCCESS) {
#ifdef LOG_VERBOSE
            LOG_ERROR("Failed to accept socket.");
#endif
            break;
        }
        session = std::make_shared<SSLServerSession>(this->context, clientSocketFd);
        if (session->create() != SGX_SUCCESS) {
#ifdef LOG_VERBOSE
            LOG_ERROR("Failed to create SSL session.");
#endif
            break;
        }
        if (session->setVerifyCallback(this->certVerifyCallback) != SGX_SUCCESS) {
#ifdef LOG_VERBOSE
            LOG_ERROR("Failed to set verify callback.");
#endif
            break;
        }
        if (this->errorCallback && session->setErrorCallback(this->errorCallback) != SGX_SUCCESS) {
#ifdef LOG_VERBOSE
            LOG_ERROR("Failed to set error callback.");
#endif
            break;
        }
        if (this->beforeHandshakeHandler != nullptr) {
            this->beforeHandshakeHandler(clientSocketFd);
        }
        if (session->handshake() != SGX_SUCCESS) {
#ifdef LOG_VERBOSE
            LOG_ERROR("Failed to SSL handshake.");
#endif
            break;
        }
        if (this->afterHandshakeHandler != nullptr) {
            this->afterHandshakeHandler(clientSocketFd);
        }

        return SGX_SUCCESS;
    } while (false);

    return SGX_ERROR_UNEXPECTED;
}
