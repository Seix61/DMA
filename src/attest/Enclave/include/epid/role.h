
#ifndef ATTEST_ENCLAVE_EPID_ROLE_H
#define ATTEST_ENCLAVE_EPID_ROLE_H

#include "epid/socket/client.h"

#include <cstdint>
#include <memory>
#include <sgx_error.h>
#include <epid/role/member.h>
#include <epid/role/verifier.h>

class EpidRole {
private:
    uint64_t serverIP;
    int serverPort;
    bool inited = false;
    std::mutex initLock;
    std::shared_ptr<EpidClient> client;
    std::shared_ptr<SSLClientSession> session;
    uint32_t attStatus = -1;
    std::shared_ptr<EPIDMember> member = nullptr;
    std::shared_ptr<EPIDVerifier> verifier = nullptr;
private:
    void initEpidInstance();

    sgx_status_t updateSigRl();

    sgx_status_t updateSignatureRl();

    sgx_status_t updatePrivRl();

    sgx_status_t updateRl();

protected:
    explicit EpidRole(uint64_t serverIp, int serverPort);

    sgx_status_t start();

    uint32_t getAttStatus() const;

    size_t getSignatureSize();

    sgx_status_t sign(const void *msg, size_t msgSize, EpidNonSplitSignature &signature, size_t signatureSize);

    sgx_status_t verify(const EpidNonSplitSignature &signature, size_t signatureSize, const void *msg, size_t msgSize);

    sgx_status_t revokeSignature(const EpidNonSplitSignature &signature, size_t signatureSize);
};

#endif //ATTEST_ENCLAVE_EPID_ROLE_H
