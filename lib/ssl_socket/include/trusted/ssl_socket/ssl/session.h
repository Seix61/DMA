
#ifndef LIB_TRUSTED_SSL_SOCKET_SSL_SESSION_H
#define LIB_TRUSTED_SSL_SOCKET_SSL_SESSION_H

#include <sgx_error.h>
#include <memory>
#include <mutex>
#include <functional>
#include <ssl_socket/ssl/context.h>

class SSLSession: public std::enable_shared_from_this<SSLSession> {
private:
    std::shared_ptr<SSLContext> context;
    std::mutex socketLock;
    std::mutex transactionLock;
protected:
    int socketFd;
    SSL *session = nullptr;
    std::function<void(std::shared_ptr<SSLSession>, int)> errorCallback;
public:
    explicit SSLSession(const std::shared_ptr<SSLContext> &context, const int &socketFd);

    ~SSLSession();

    sgx_status_t create();

    int getSocketFd() const;

    uint64_t getIP() const;

    virtual int getPort() const = 0;

    sgx_status_t setVerifyCallback(int (*callback)(int, X509_STORE_CTX *));

    sgx_status_t setErrorCallback(std::function<void(std::shared_ptr<SSLSession>, int)> callback);

    virtual sgx_status_t handshake() = 0;

    void lock();

    void unlock();

    sgx_status_t read(void *buffer, size_t size);

    sgx_status_t write(const void *payload, size_t size);
};

#endif //LIB_TRUSTED_SSL_SOCKET_SSL_SESSION_H
