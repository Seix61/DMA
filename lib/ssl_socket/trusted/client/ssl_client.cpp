
#include <ssl_socket/client/ssl_client.h>
#include <util/log.h>

SSLClient::SSLClient(const char *serverName, int port) : SSLPeer(TLS_client_method), SocketClient(serverName, port) {}

sgx_status_t SSLClient::create() {
    do {
        if (SSLPeer::create() != SGX_SUCCESS) {
#ifdef LOG_VERBOSE
            LOG_ERROR("Failed to create ssl peer.");
#endif
            break;
        }
        if (SocketClient::create() != SGX_SUCCESS) {
#ifdef LOG_VERBOSE
            LOG_ERROR("Failed to create socket client.");
#endif
            break;
        }

        return SGX_SUCCESS;
    } while (false);

    return SGX_ERROR_UNEXPECTED;
}

sgx_status_t SSLClient::connect(std::shared_ptr<SSLClientSession> &session) {
    do {
        if (SocketClient::connect() != SGX_SUCCESS) {
#ifdef LOG_VERBOSE
            LOG_ERROR("Failed to connect socket.");
#endif
            break;
        }
        session = std::make_shared<SSLClientSession>(this->context, this->socketFd);
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
            this->beforeHandshakeHandler(this->socketFd);
        }
        if (session->handshake() != SGX_SUCCESS) {
#ifdef LOG_VERBOSE
            LOG_ERROR("Failed to SSL handshake.");
#endif
            break;
        }
        if (this->afterHandshakeHandler != nullptr) {
            this->afterHandshakeHandler(this->socketFd);
        }

        return SGX_SUCCESS;
    } while (false);

    return SGX_ERROR_UNEXPECTED;
}
