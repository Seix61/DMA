
#ifndef USER_ENCLAVE_NODE_H
#define USER_ENCLAVE_NODE_H

#include "attest/role.h"
#include "user/role.h"

class UserNode : private AttestRole, private UserRole {
public:
    UserNode(int id, int serverPort, const std::vector<std::string> &peers, int peerPort);

    sgx_status_t startAttestRole();

    sgx_status_t startUserRole();

    void createQuoteFromAttestRole(const unsigned char *reportData, size_t reportDataSize, std::shared_ptr<dma_quote> &quote, size_t &quoteSize);

    void verifyQuoteFromAttestRole(const std::shared_ptr<dma_quote> &quote, size_t quoteSize, bool &pass);

    void revokeSignatureToAttestRole(const std::shared_ptr<uint8_t> &sig, size_t size);
};

#endif //USER_ENCLAVE_NODE_H
