
#include "Enclave_t.h"
#include "node.h"
#include "api.h"

#include <sstream>
#include <memory>
#include <map>
#include <util/ip.h>
#include <general_settings.h>

std::shared_ptr<AuthNode> authNode;
bool ignoreOriginalTrust = false;
GeneralSettings::AttestationType originalAttestationType = GeneralSettings::EPID_BASED;

std::map<int, uint32_t> platformStatusStore;
std::mutex platformStatusStoreLock;

void ecall_launch_auth_node(int ignoreTrust, int useDCAP, int standalone,
                            int threadCount, int consensusNodeId, int consensusListen,
                            size_t peerStructSize, const char *peerStruct, int epidListen) {
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

    ignoreOriginalTrust = ignoreTrust == 1;
    originalAttestationType = useDCAP == 1 ? GeneralSettings::DCAP_BASED : GeneralSettings::EPID_BASED;

    authNode = std::make_shared<AuthNode>(
            consensusNodeId,
            peers,
            consensusListen,
            epidListen,
            threadCount
    );
    if (standalone == 0) {
        authNode->startConsensusRole();
        authNode->startEpidRole();
    } else {
        authNode->startInStandaloneMode();
    }
}

void record_platform_status(int socketFd, uint32_t status) {
    std::lock_guard<std::mutex> lock(platformStatusStoreLock);
    platformStatusStore[socketFd] = status;
}

uint32_t get_platform_status(int socketFd) {
    std::lock_guard<std::mutex> lock(platformStatusStoreLock);
    if (platformStatusStore.find(socketFd) == platformStatusStore.end()) {
        return -1;
    }
    return platformStatusStore.at(socketFd);
}
