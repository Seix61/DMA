
#ifndef AUTH_ENCLAVE_CONSENSUS_PROTOCOL_CONSENSUS2_H
#define AUTH_ENCLAVE_CONSENSUS_PROTOCOL_CONSENSUS2_H

#include "consensus/protocol/base.h"

#include <consensus/2/consensus.h>
#include <ssl_socket/server/ssl_server_session.h>
#include <epid/types.h>

class AuthConsensus2 : protected AuthConsensus, private Consensus2 {
protected:
    explicit AuthConsensus2(int id, size_t peerCount);

    void registerPeerToConsensus2(int peerId);

    void startConsensus2();

    bool isConsensusReady();

    void revokeMemberByPriv(const FpElemStr &f);

    void revokeMemberBySig(size_t signature_size, const EpidNonSplitSignature &signature);

    void revokeSignature(size_t signature_size, const EpidNonSplitSignature &signature);

    void handleAcceptRequest(const std::shared_ptr<SSLServerSession> &session);

    void handleAcceptResponse(const std::shared_ptr<SSLServerSession> &session);

    void handleCommitRequest(const std::shared_ptr<SSLServerSession> &session);

    void handleCommitResponse(const std::shared_ptr<SSLServerSession> &session);

    void handleTryAcceptRequest(const std::shared_ptr<SSLServerSession> &session);

    void handleTryAcceptResponse(const std::shared_ptr<SSLServerSession> &session);

    void handleTryCommitRequest(const std::shared_ptr<SSLServerSession> &session);

    void handleTryCommitResponse(const std::shared_ptr<SSLServerSession> &session);

    void handleRecoverRequest(const std::shared_ptr<SSLServerSession> &session);

    void handleRecoverResponse(const std::shared_ptr<SSLServerSession> &session);

    void handlePrepareRequest(const std::shared_ptr<SSLServerSession> &session);

    void handlePrepareResponse(const std::shared_ptr<SSLServerSession> &session);

private:
    void proposeCallback(size_t size, const std::shared_ptr<char> &buffer) override;

    virtual void revokeMemberByPrivCallback(const FpElemStr &f) = 0;

    virtual void revokeMemberBySigCallback(size_t signature_size, const EpidNonSplitSignature &signature) = 0;

    virtual void revokeSignatureCallback(size_t signature_size, const EpidNonSplitSignature &signature) = 0;

    void sendAcceptMessage(int logId, size_t size, const std::shared_ptr<char> &buffer) override;

    void sendAcceptReplyMessage(int toNodeId, int logId) override;

    void sendCommitMessage(int logId, size_t size, const std::shared_ptr<char> &buffer) override;

    void sendCommitReplyMessage(int toNodeId, int logId) override;

    void sendTryAcceptMessage(int nodeId, int logId, size_t size, const std::shared_ptr<char> &buffer) override;

    void sendTryAcceptReplyMessage(int toNodeId, int nodeId, int logId) override;

    void sendTryCommitMessage(int nodeId, int logId, size_t size, const std::shared_ptr<char> &buffer) override;

    void sendTryCommitReplyMessage(int toNodeId, int nodeId, int logId) override;

    void sendRecoverMessage() override;

    void sendRecoverReplyMessage(int toNodeId, const std::map<int, int> &idIndex) override;

    void sendPrepareMessage(int nodeId, int logId) override;

    void sendPrepareReplyMessage(int toNodeId, int nodeId, int logId, size_t size, const std::shared_ptr<char> &buffer) override;

};

#endif //AUTH_ENCLAVE_CONSENSUS_PROTOCOL_CONSENSUS2_H
