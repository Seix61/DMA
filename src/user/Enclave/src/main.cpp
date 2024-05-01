
#include "Enclave_t.h"
#include "api.h"
#include "node.h"

#include <map>
#include <sstream>
#include <util/memory.h>
#include <util/ip.h>

std::shared_ptr<UserNode> userNode;
std::map<int, EvidenceStoreItem> evidenceStore;
std::mutex evidenceStoreLock;

void ecall_launch_user_node(int attestConnect, int userNodeId, int userListen, size_t peerStructSize,
                            const char *peerStruct) {
    std::vector<std::string> peers;
    std::istringstream iss(std::string(peerStruct, peerStructSize));
    size_t peerCount = 0;
    iss.read((char *) &peerCount, sizeof(size_t));
    for (size_t i = 0; i < peerCount; i++) {
        size_t length = 0;
        iss.read((char *) &length, sizeof(size_t));
        char *address = (char *) malloc(length);
        iss.read(address, length);
        peers.emplace_back(address, length);
        delete address;
    }

    userNode = std::make_shared<UserNode>(
            userNodeId,
            attestConnect,
            peers,
            userListen
    );
    userNode->startAttestRole();
    userNode->startUserRole();
}

void create_quote(const unsigned char *reportData, size_t reportDataSize, std::shared_ptr<dma_quote> &quote,
                  size_t &quoteSize) {
    userNode->createQuoteFromAttestRole(reportData, reportDataSize, quote, quoteSize);
}

void verify_quote(const std::shared_ptr<dma_quote> &quote, size_t quoteSize, bool &pass) {
    userNode->verifyQuoteFromAttestRole(quote, quoteSize, pass);
}

void bind_quote(int key, const uint8_t evidence[], size_t evidence_size) {
    std::lock_guard<std::mutex> lock(evidenceStoreLock);
    auto buffer = Memory::makeShared<uint8_t>(evidence, evidence_size);
    evidenceStore[key] = {buffer, evidence_size};
}

void revoke_quote(int key) {
    std::lock_guard<std::mutex> lock(evidenceStoreLock);
    if (evidenceStore.find(key) == evidenceStore.end()) {
        return;
    }
    userNode->revokeSignatureToAttestRole(evidenceStore[key].buffer, evidenceStore[key].size);
    evidenceStore.erase(key);
}
