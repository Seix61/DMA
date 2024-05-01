
#ifndef AUTH_ENCLAVE_EPID_ROLE_H
#define AUTH_ENCLAVE_EPID_ROLE_H

#include "epid/socket/server.h"

#include <memory>
#include <vector>
#include <epid/types.h>
#include <epid/role/issuer.h>

class EpidRole {
private:
    std::shared_ptr<EpidServer> server;
    bool serverReady = false;
    int threadCount;
    std::mutex issuerContextLock;
    bool issuerContextSet = false;
    std::shared_ptr<EPIDIssuer> issuer = std::make_shared<EPIDIssuer>();
private:
    void serverThread();

    void createIssuer();

    void importIssuer(const GroupPubKey &pubKey, const IPrivKey &privKey);

    void handleRequest(const std::shared_ptr<SSLServerSession> &session);

    void handleAttStatusRequest(const std::shared_ptr<SSLServerSession> &session);

    void handleIssuerNonceRequest(const std::shared_ptr<SSLServerSession> &session);

    void handleGroupKeyRequest(const std::shared_ptr<SSLServerSession> &session);

    void handleMemberJoinRequest(const std::shared_ptr<SSLServerSession> &session);

    void handleRevokeMemberBySigRequest(const std::shared_ptr<SSLServerSession> &session);

    void handleRevokeSignatureRequest(const std::shared_ptr<SSLServerSession> &session);

    void handlePrivRLRequest(const std::shared_ptr<SSLServerSession> &session);

    void handleSigRLRequest(const std::shared_ptr<SSLServerSession> &session);

    void handleSignatureRLRequest(const std::shared_ptr<SSLServerSession> &session);

    void handleRLRequest(const std::shared_ptr<SSLServerSession> &session);

protected:
    explicit EpidRole(int serverPort, int threadCount);

    sgx_status_t start();

    bool isReady();

    bool isIssuerReady();

    void getEPIDKeys(GroupPubKey &pubKey, IPrivKey &privKey);

    void setEPIDKeys(const GroupPubKey &pubKey, const IPrivKey &privKey);

    void revokeMemberByPriv(const FpElemStr &f);

    void revokeMemberBySig(size_t signature_size, const EpidNonSplitSignature &signature);

    void revokeSignature(size_t signature_size, const EpidNonSplitSignature &signature);

    virtual void revokeMemberByPrivToConsensusRole(const FpElemStr &f) = 0;

    virtual void revokeMemberBySigToConsensusRole(size_t signature_size, const EpidNonSplitSignature &signature) = 0;

    virtual void revokeSignatureToConsensusRole(size_t signature_size, const EpidNonSplitSignature &signature) = 0;
};

#endif //AUTH_ENCLAVE_EPID_ROLE_H
