
#ifndef AUTH_ENCLAVE_CONSENSUS_PROTOCOL_BASE_H
#define AUTH_ENCLAVE_CONSENSUS_PROTOCOL_BASE_H

#include <memory>
#include <ssl_socket/server/ssl_server_session.h>

class AuthConsensus {
protected:
    virtual void unicast(int toNodeId, const void *msg, size_t msgSize) = 0;

    virtual void broadcast(const void *msg, size_t msgSize) = 0;

    virtual int getServerSessionId(const std::shared_ptr<SSLServerSession> &session) = 0;

    virtual bool isReadyToHandleConsensusMessage() = 0;
};

#endif //AUTH_ENCLAVE_CONSENSUS_PROTOCOL_BASE_H
