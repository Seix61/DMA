
#ifndef AUTH_ENCLAVE_CONSENSUS_PROTOCOL_CONSENSUS1_H
#define AUTH_ENCLAVE_CONSENSUS_PROTOCOL_CONSENSUS1_H

#include "consensus/protocol/base.h"

#include <consensus/1/consensus.h>
#include <ssl_socket/server/ssl_server_session.h>
#include <epid/types.h>

class AuthConsensus1 : protected AuthConsensus, private Consensus1 {
protected:
    explicit AuthConsensus1(int id, size_t peerCount);

    void startConsensus1();

    virtual void getEPIDKeysCallback(GroupPubKey &pubKey, IPrivKey &privKey) = 0;

    virtual void setEPIDKeysCallback(const GroupPubKey &pubKey, const IPrivKey &privKey) = 0;

    void handleElectionRequest(const std::shared_ptr<SSLServerSession> &session);

    void handleElectionResponse(const std::shared_ptr<SSLServerSession> &session);

    void handleLeaderNotification(const std::shared_ptr<SSLServerSession> &session);

private:

    void sendElectionMessage(int term) override;

    void sendElectionReplyMessage(int toNodeId, int term) override;

    void sendLeaderNotificationMessage(int term) override;
};

#endif //AUTH_ENCLAVE_CONSENSUS_PROTOCOL_CONSENSUS1_H
