
#ifndef AUTH_ENCLAVE_CONSENSUS_ROLE_H
#define AUTH_ENCLAVE_CONSENSUS_ROLE_H

#include "consensus/protocol/consensus1.h"
#include "consensus/protocol/consensus2.h"
#include "consensus/socket/server.h"
#include "consensus/socket/client.h"

#include <vector>
#include <map>
#include <mutex>
#include <scheduler/async_task.h>
#include <ssl_socket/mgr/bi_connection_mgr.h>

class ConsensusRole : protected AuthConsensus1, protected AuthConsensus2 {
private:
    int id;
    std::vector<std::string> peers;
    int peerPort;
    bool consensusStarted = false;
    std::mutex consensusStartedLock;
    bool readyToHandleConsensusMessage = false;
    std::mutex readyToHandleConsensusMessageLock;
    std::shared_ptr<ConsensusServer> server;
    BiConnectionMgr mgr;
    std::shared_ptr<AsyncTask> connectToPeersTask;
private:
    bool isConnectedToAllPeers();

    bool isReadyToHandleConsensusMessage() override;

    void serverThread();

    void clientThread(const std::string &addr);

    void serverErrorCallback(const std::shared_ptr<SSLSession> &session, int error);

    void clientErrorCallback(const std::shared_ptr<SSLSession> &session, int error);

    void beforeHandshake(int fd);

    void afterHandshake(int fd);

    void registerServerSession(const std::shared_ptr<SSLServerSession> &session);

    void registerClientSession(const std::string &addr, const std::shared_ptr<SSLClient> &client,
                               const std::shared_ptr<SSLClientSession> &session);

    int getServerSessionId(const std::shared_ptr<SSLServerSession> &session) override;

    void startConsensus();

    void getEPIDKeysCallback(GroupPubKey &pubKey, IPrivKey &privKey) override;

    void setEPIDKeysCallback(const GroupPubKey &pubKey, const IPrivKey &privKey) override;

    void revokeMemberByPrivCallback(const FpElemStr &f) override;

    void revokeMemberBySigCallback(size_t signature_size, const EpidNonSplitSignature &signature) override;

    void revokeSignatureCallback(size_t signature_size, const EpidNonSplitSignature &signature) override;

    void unicast(int toNodeId, const void *msg, size_t msgSize) override;

    void broadcast(const void *msg, size_t msgSize) override;

    void handleRequest(const std::shared_ptr<SSLServerSession> &session);

protected:
    explicit ConsensusRole(int id, const std::vector<std::string> &peers, int peerPort);

    sgx_status_t start();

    virtual bool isIssuerReady() = 0;

    virtual void getEPIDKeysFromEPIDRole(GroupPubKey &pubKey, IPrivKey &privKey) = 0;

    virtual void setEPIDKeysToEPIDRole(const GroupPubKey &pubKey, const IPrivKey &privKey) = 0;

    virtual void revokeMemberByPrivToEPIDRole(const FpElemStr &f) = 0;

    virtual void revokeMemberBySigToEPIDRole(size_t signature_size, const EpidNonSplitSignature &signature) = 0;

    virtual void revokeSignatureToEPIDRole(size_t signature_size, const EpidNonSplitSignature &signature) = 0;
};

#endif //AUTH_ENCLAVE_CONSENSUS_ROLE_H
