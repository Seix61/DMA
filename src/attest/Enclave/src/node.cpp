
#include "node.h"

AttestNode::AttestNode(uint64_t epidIP, int epidPort, int attestPort, int attestThread) :
        EpidRole(epidIP, epidPort),
        AttestRole(attestPort, attestThread) {}

sgx_status_t AttestNode::startEpidRole() {
    return EpidRole::start();
}

sgx_status_t AttestNode::startAttestRole() {
    return AttestRole::start();
}

uint32_t AttestNode::getAttStatusFromEpidRole() {
    return EpidRole::getAttStatus();
}

size_t AttestNode::getSignatureSizeFromEpidRole() {
    return EpidRole::getSignatureSize();
}

sgx_status_t
AttestNode::signFromEpidRole(const void *msg, size_t msgSize, EpidNonSplitSignature &signature, size_t signatureSize) {
    return EpidRole::sign(msg, msgSize, signature, signatureSize);
}

sgx_status_t
AttestNode::verifyFromEpidRole(const EpidNonSplitSignature &signature, size_t signatureSize, const void *msg,
                               size_t msgSize) {
    return EpidRole::verify(signature, signatureSize, msg, msgSize);
}

sgx_status_t AttestNode::revokeSignatureToEpidRole(const EpidNonSplitSignature &signature, size_t signatureSize) {
    return EpidRole::revokeSignature(signature, signatureSize);
}
