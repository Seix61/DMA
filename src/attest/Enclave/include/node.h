
#ifndef ATTEST_ENCLAVE_NODE_H
#define ATTEST_ENCLAVE_NODE_H

#include "epid/role.h"
#include "attest/role.h"

class AttestNode : private EpidRole, private AttestRole {
private:
    uint32_t getAttStatusFromEpidRole() override;

    size_t getSignatureSizeFromEpidRole() override;

    sgx_status_t
    signFromEpidRole(const void *msg, size_t msgSize, EpidNonSplitSignature &signature, size_t signatureSize) override;

    sgx_status_t verifyFromEpidRole(const EpidNonSplitSignature &signature, size_t signatureSize, const void *msg,
                                    size_t msgSize) override;

    sgx_status_t revokeSignatureToEpidRole(const EpidNonSplitSignature &signature, size_t signatureSize) override;

public:
    AttestNode(uint64_t epidIP, int epidPort, int attestPort, int attestThread);

    sgx_status_t startEpidRole();

    sgx_status_t startAttestRole();
};

#endif //ATTEST_ENCLAVE_NODE_H
