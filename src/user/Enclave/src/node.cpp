
#include "node.h"

UserNode::UserNode(int id, int serverPort, const std::vector<std::string> &peers, int peerPort) :
        AttestRole(serverPort),
        UserRole(id, peers, peerPort) {}

sgx_status_t UserNode::startAttestRole() {
    return AttestRole::start();
}

sgx_status_t UserNode::startUserRole() {
    return UserRole::start();
}

void UserNode::createQuoteFromAttestRole(const unsigned char *reportData, size_t reportDataSize,
                                         std::shared_ptr<dma_quote> &quote, size_t &quoteSize) {
    return AttestRole::createQuote(reportData, reportDataSize, quote, quoteSize);
}

void UserNode::verifyQuoteFromAttestRole(const std::shared_ptr<dma_quote> &quote, size_t quoteSize, bool &pass) {
    return AttestRole::verifyQuote(quote, quoteSize, pass);
}

void UserNode::revokeSignatureToAttestRole(const std::shared_ptr<uint8_t> &sig, size_t size) {
    return AttestRole::revokeSignature(sig, size);
}
