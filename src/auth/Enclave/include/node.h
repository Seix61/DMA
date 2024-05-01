
#ifndef AUTH_ENCLAVE_NODE_H
#define AUTH_ENCLAVE_NODE_H

#include "consensus/role.h"
#include "epid/role.h"

class AuthNode : private ConsensusRole, private EpidRole {
private:
    bool isIssuerReady() override;

    void getEPIDKeysFromEPIDRole(GroupPubKey &pubKey, IPrivKey &privKey) override;

    void setEPIDKeysToEPIDRole(const GroupPubKey &pubKey, const IPrivKey &privKey) override;

    void revokeMemberByPrivToEPIDRole(const FpElemStr &f) override;

    void revokeMemberBySigToEPIDRole(size_t signature_size, const EpidNonSplitSignature &signature) override;

    void revokeSignatureToEPIDRole(size_t signature_size, const EpidNonSplitSignature &signature) override;

    void revokeMemberByPrivToConsensusRole(const FpElemStr &f) override;

    void revokeMemberBySigToConsensusRole(size_t signature_size, const EpidNonSplitSignature &signature) override;

    void revokeSignatureToConsensusRole(size_t signature_size, const EpidNonSplitSignature &signature) override;

public:
    AuthNode(int id, const std::vector<std::string> &peers, int consensusPort, int epidPort, int epidThreads);

    sgx_status_t startConsensusRole();

    sgx_status_t startEpidRole();

    sgx_status_t startInStandaloneMode();
};

#endif //AUTH_ENCLAVE_NODE_H
