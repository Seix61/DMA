
#include <ssl_socket/ssl/session.h>
#include <ssl_socket/ssl/x509.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include <util/log.h>

SSLSession::SSLSession(const std::shared_ptr<SSLContext> &context, const int &socketFd) : context(context),
                                                                                          socketFd(socketFd) {}

SSLSession::~SSLSession() {
    if (this->socketFd > 0) {
        close(this->socketFd);
    }
    if (this->session) {
        SSL_shutdown(this->session);
        SSL_free(this->session);
    }
}

sgx_status_t SSLSession::create() {
    do {
        if ((this->session = SSL_new(this->context->getContext())) == nullptr) {
#ifdef LOG_VERBOSE
            LOG_ERROR("Failed to create a new SSL session.");
#endif
            break;
        }
        SSL_set_fd(this->session, this->socketFd);
        return SGX_SUCCESS;
    } while (false);

    return SGX_ERROR_UNEXPECTED;
}

uint64_t SSLSession::getIP() const {
    sockaddr_in peerAddr{};
    socklen_t peerAddrLen = sizeof(peerAddr);
    if (getpeername(this->socketFd, (sockaddr *)&peerAddr, &peerAddrLen) == 0) {
        return peerAddr.sin_addr.s_addr;
    }
    return -1;
}

sgx_status_t SSLSession::setVerifyCallback(int (*callback)(int, X509_STORE_CTX *)) {
    SSL_set_verify(this->session, SSL_VERIFY_PEER, callback);
    return SGX_SUCCESS;
}

sgx_status_t SSLSession::setErrorCallback(std::function<void(std::shared_ptr<SSLSession>, int)> callback) {
    this->errorCallback = std::move(callback);
    return SGX_SUCCESS;
}

sgx_status_t SSLSession::read(void *buffer, size_t size) {
    int bytes_read;

    std::lock_guard<std::mutex> lock(this->socketLock);
    while ((bytes_read = SSL_read(this->session, buffer, size)) <= 0) {
        int error = SSL_get_error(this->session, bytes_read);
        if (error == SSL_ERROR_WANT_READ) {
            continue;
        }
#ifdef LOG_VERBOSE
        LOG_ERROR("Failed to SSL_read. Returned %d.", error);
#endif
        if (this->errorCallback) {
            this->errorCallback(shared_from_this(), error);
        }
        return SGX_ERROR_UNEXPECTED;
    }

    return SGX_SUCCESS;
}

sgx_status_t SSLSession::write(const void *payload, size_t size) {
    int bytes_wrote;

    std::lock_guard<std::mutex> lock(this->socketLock);
    while ((bytes_wrote = SSL_write(this->session, payload, size)) <= 0) {
        int error = SSL_get_error(this->session, bytes_wrote);
        if (error == SSL_ERROR_WANT_WRITE) {
            continue;
        }
#ifdef LOG_VERBOSE
        LOG_ERROR("Failed to SSL_write. Returned %d.", error);
#endif
        if (this->errorCallback) {
            this->errorCallback(shared_from_this(), error);
        }
        return SGX_ERROR_UNEXPECTED;
    }

    return SGX_SUCCESS;
}

void SSLSession::lock() {
    this->transactionLock.lock();
}

void SSLSession::unlock() {
    this->transactionLock.unlock();
}

int SSLSession::getSocketFd() const {
    return this->socketFd;
}
