
#include "consensus/protocol/consensus1.h"

#include <consensus/rpc/message_serializer.h>
#include <consensus/rpc/messages.h>
#include <scheduler/task_scheduler.h>
#include <util/memory.h>
#include <util/log.h>

using namespace Consensus;

AuthConsensus1::AuthConsensus1(int id, size_t peerCount) :
        Consensus1(id, peerCount,
                   300, 600,
                   150, 300) {}

void AuthConsensus1::startConsensus1() {
    this->start();
}

void AuthConsensus1::sendElectionMessage(int term) {
    auto request = BasicMessageSerializer::serialize(
            std::make_shared<LeaderElectionRequestMessage>(term)).str();
    this->broadcast(request.c_str(), request.size());
}

void AuthConsensus1::sendElectionReplyMessage(int toNodeId, int term) {
    auto response = BasicMessageSerializer::serialize(
            std::make_shared<LeaderElectionResponseMessage>(term)).str();
    this->unicast(toNodeId, response.c_str(), response.size());
}

void AuthConsensus1::sendLeaderNotificationMessage(int term) {
    GroupPubKey pubKey;
    IPrivKey privKey;
    this->getEPIDKeysCallback(pubKey, privKey);
    auto request = BasicMessageSerializer::serialize(
            std::make_shared<LeaderNotificationMessage>(term, pubKey, privKey)).str();
    this->broadcast(request.c_str(), request.size());
}

void AuthConsensus1::handleElectionRequest(const std::shared_ptr<SSLServerSession> &session) {
    session->lock();
    do {
        auto request_size = LeaderElectionRequestMessage::contentSize();
        auto request = Memory::makeShared<char>(request_size);
        if (session->read(request.get(), request_size) != SGX_SUCCESS) {
            break;
        }
        session->unlock();

        if (!this->isReadyToHandleConsensusMessage()) {
            return;
        }

        auto oss = BasicMessageSerializer::buildStream(LeaderElectionRequest, request.get(), request_size);
        auto deserialized = MessageSerializer<LeaderElectionRequestMessage>::deserialize(oss);

        return this->handleElectionMessage(this->getServerSessionId(session), deserialized->getTerm());
    } while (false);
    session->unlock();
}

void AuthConsensus1::handleElectionResponse(const std::shared_ptr<SSLServerSession> &session) {
    session->lock();
    do {
        auto request_size = LeaderElectionResponseMessage::contentSize();
        auto request = Memory::makeShared<char>(request_size);
        if (session->read(request.get(), request_size) != SGX_SUCCESS) {
            break;
        }
        session->unlock();

        if (!this->isReadyToHandleConsensusMessage()) {
            return;
        }

        auto oss = BasicMessageSerializer::buildStream(LeaderElectionResponse, request.get(), request_size);
        auto deserialized = MessageSerializer<LeaderElectionResponseMessage>::deserialize(oss);

        return this->handleElectionReplyMessage(deserialized->getTerm());
    } while (false);
    session->unlock();
}

void AuthConsensus1::handleLeaderNotification(const std::shared_ptr<SSLServerSession> &session) {
    session->lock();
    do {
        auto request_size = LeaderNotificationMessage::contentSize();
        auto request = Memory::makeShared<char>(request_size);
        if (session->read(request.get(), request_size) != SGX_SUCCESS) {
            break;
        }
        session->unlock();

        if (!this->isReadyToHandleConsensusMessage()) {
            return;
        }

        auto oss = BasicMessageSerializer::buildStream(LeaderNotification, request.get(), request_size);
        auto deserialized = MessageSerializer<LeaderNotificationMessage>::deserialize(oss);

        this->handleLeaderNotificationMessage(this->getServerSessionId(session), deserialized->getTerm());

        return this->setEPIDKeysCallback(deserialized->getPubKey(), deserialized->getPrivKey());
    } while (false);
    session->unlock();
}
