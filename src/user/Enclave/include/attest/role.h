
#ifndef USER_ENCLAVE_ATTEST_ROLE_H
#define USER_ENCLAVE_ATTEST_ROLE_H

#include "attest/socket/client.h"

#include <memory>
#include <attestation/dma_quote.h>

class AttestRole {
private:
    int serverPort;
    std::shared_ptr<AttestClient> client;
    std::shared_ptr<SSLClientSession> session;
    std::mutex transactionLock;

protected:
    explicit AttestRole(int serverPort);

    sgx_status_t start();

    void createQuote(const unsigned char *reportData, size_t reportDataSize, std::shared_ptr<dma_quote> &quote, size_t &quoteSize);

    void verifyQuote(const std::shared_ptr<dma_quote> &quote, size_t quoteSize, bool &pass);

    void revokeSignature(const std::shared_ptr<uint8_t> &sig, size_t size);
};

#endif //USER_ENCLAVE_ATTEST_ROLE_H
