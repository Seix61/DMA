
#ifndef ATTEST_ENCLAVE_ATTEST_ROLE_H
#define ATTEST_ENCLAVE_ATTEST_ROLE_H

#include "attest/socket/server.h"

#include <memory>
#include <epid/types.h>

class AttestRole {
private:
    std::shared_ptr<AttestServer> server;
    int threadCount;
private:
    void serverThread();

    void handleRequest(const std::shared_ptr<SSLServerSession> &session);

    void handleTargetInfoRequest(const std::shared_ptr<SSLServerSession> &session);

    void handleQuoteRequest(const std::shared_ptr<SSLServerSession> &session);

    void handleVerifyRequest(const std::shared_ptr<SSLServerSession> &session);

    void handleRevokeSigRequest(const std::shared_ptr<SSLServerSession> &session);

protected:
    explicit AttestRole(int serverPort, int threadCount);

    sgx_status_t start();

    virtual uint32_t getAttStatusFromEpidRole() = 0;

    virtual size_t getSignatureSizeFromEpidRole() = 0;

    virtual sgx_status_t signFromEpidRole(const void *msg, size_t msgSize, EpidNonSplitSignature &signature, size_t signatureSize) = 0;

    virtual sgx_status_t verifyFromEpidRole(const EpidNonSplitSignature &signature, size_t signatureSize, const void *msg, size_t msgSize) = 0;

    virtual sgx_status_t revokeSignatureToEpidRole(const EpidNonSplitSignature &signature, size_t signatureSize) = 0;

};

#endif //ATTEST_ENCLAVE_ATTEST_ROLE_H
