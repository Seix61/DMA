
#include "node.h"

AuthNode::AuthNode(int id, const std::vector<std::string> &peers, int consensusPort, int epidPort, int epidThreads) :
        ConsensusRole(id, peers, consensusPort),
        EpidRole(epidPort, epidThreads) {}

sgx_status_t AuthNode::startConsensusRole() {
    return ConsensusRole::start();
}

sgx_status_t AuthNode::startEpidRole() {
    return EpidRole::start();
}

sgx_status_t AuthNode::startInStandaloneMode() {
    auto status = EpidRole::start();
    GroupPubKey pubKey;
    IPrivKey privKey;
    EpidRole::getEPIDKeys(pubKey, privKey);
    return status;
}

bool AuthNode::isIssuerReady() {
    return EpidRole::isIssuerReady();
}

void AuthNode::getEPIDKeysFromEPIDRole(GroupPubKey &pubKey, IPrivKey &privKey) {
    EpidRole::getEPIDKeys(pubKey, privKey);
}

void AuthNode::setEPIDKeysToEPIDRole(const GroupPubKey &pubKey, const IPrivKey &privKey) {
    EpidRole::setEPIDKeys(pubKey, privKey);
}

void AuthNode::revokeMemberByPrivToEPIDRole(const FpElemStr &f) {
    EpidRole::revokeMemberByPriv(f);
}

void AuthNode::revokeMemberBySigToEPIDRole(size_t signature_size, const EpidNonSplitSignature &signature) {
    EpidRole::revokeMemberBySig(signature_size, signature);
}

void AuthNode::revokeSignatureToEPIDRole(size_t signature_size, const EpidNonSplitSignature &signature) {
    EpidRole::revokeSignature(signature_size, signature);
}

void AuthNode::revokeMemberByPrivToConsensusRole(const FpElemStr &f) {
    ConsensusRole::revokeMemberByPriv(f);
}

void AuthNode::revokeMemberBySigToConsensusRole(size_t signature_size, const EpidNonSplitSignature &signature) {
    ConsensusRole::revokeMemberBySig(signature_size, signature);
}

void AuthNode::revokeSignatureToConsensusRole(size_t signature_size, const EpidNonSplitSignature &signature) {
    ConsensusRole::revokeSignature(signature_size, signature);
}
