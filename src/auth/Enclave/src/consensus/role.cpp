
#include "consensus/role.h"

#include <sstream>
#include <scheduler/task_scheduler.h>
#include <consensus/rpc/message_type.h>
#include <consensus/rpc/message_base.h>
#include <util/memory.h>
#include <util/log.h>
#include <util/ip.h>

using namespace Consensus;

ConsensusRole::ConsensusRole(int id, const std::vector<std::string> &peers, int peerPort) :
        id(id),
        peers(peers),
        peerPort(peerPort),
        server(std::make_shared<ConsensusServer>(peerPort)),
        AuthConsensus1(id, peers.size()),
        AuthConsensus2(id, peers.size()),
        mgr(peers) {}

sgx_status_t ConsensusRole::start() {
    LOG_DEBUG("This id = %d", this->id);
    if (this->server->create() != SGX_SUCCESS) {
        LOG_ERROR("Failed to create SSL server.");
        return SGX_ERROR_UNEXPECTED;
    }
    if (this->server->setErrorCallback(std::bind(&ConsensusRole::serverErrorCallback, this, std::placeholders::_1, std::placeholders::_2)) != SGX_SUCCESS) {
        LOG_ERROR("Failed to set error callback.");
        return SGX_ERROR_UNEXPECTED;
    }
    if (this->server->setBeforeHandshakeHandler(std::bind(&ConsensusRole::beforeHandshake, this, std::placeholders::_1)) != SGX_SUCCESS) {
        LOG_ERROR("Failed to set before handshake handler.");
        return SGX_ERROR_UNEXPECTED;
    }
    if (this->server->setAfterHandshakeHandler(std::bind(&ConsensusRole::afterHandshake, this, std::placeholders::_1)) != SGX_SUCCESS) {
        LOG_ERROR("Failed to set after handshake handler.");
        return SGX_ERROR_UNEXPECTED;
    }
    for (int i = 0; i < this->peers.size(); i++) {
        TaskScheduler::executeDetachedTask([this] {
            this->serverThread();
        });
    }
    this->connectToPeersTask = std::make_shared<AsyncTask>([this] {
        for (const auto &peer: this->peers) {
            TaskScheduler::executeDetachedTask([this, peer] {
                this->clientThread(peer);
            });
        }
        TaskScheduler::executeDelayedTask(this->connectToPeersTask, 10000);
    });
    TaskScheduler::executeDelayedTask(this->connectToPeersTask, 2000);
    return SGX_SUCCESS;
}

bool ConsensusRole::isConnectedToAllPeers() {
    int connected = 0;
    for (const auto &peer: this->peers) {
        if (this->mgr.isConnected(peer)) {
            connected++;
        }
    }
    return connected == this->peers.size();
}

bool ConsensusRole::isReadyToHandleConsensusMessage() {
    std::lock_guard<std::mutex> lock(this->readyToHandleConsensusMessageLock);
    if (!this->readyToHandleConsensusMessage) {
        this->readyToHandleConsensusMessage = this->isConnectedToAllPeers();
    }
    return this->readyToHandleConsensusMessage;
}

void ConsensusRole::serverErrorCallback(const std::shared_ptr<SSLSession> &session, int error) {
    auto nodeId = this->mgr.getIdBySession(std::static_pointer_cast<SSLServerSession>(session));
    LOG_ERROR("Server session error at node = %d with error = %d", nodeId, error);
    this->mgr.antiRegister(nodeId);
}

void ConsensusRole::clientErrorCallback(const std::shared_ptr<SSLSession> &session, int error) {
    auto nodeId = this->mgr.getIdBySession(std::static_pointer_cast<SSLClientSession>(session));
    LOG_ERROR("Client session error at node = %d with error = %d", nodeId, error);
    this->mgr.antiRegister(nodeId);
}

void ConsensusRole::beforeHandshake(int fd) {
    LOG_DEBUG("beforeHandshake %d", fd);
}

void ConsensusRole::afterHandshake(int fd) {
    LOG_DEBUG("afterHandshake %d", fd);
}

void ConsensusRole::serverThread() {
    while (true) {
        std::shared_ptr<SSLServerSession> session;
        if (this->server->accept(session) != SGX_SUCCESS) {
            LOG_ERROR("Failed to accept.");
            continue;
        }
        TaskScheduler::executeDetachedTask([this, session] {
            this->registerServerSession(session);
        });
    }
}

void ConsensusRole::clientThread(const std::string &addr) {
    if (this->mgr.isClientConnected(addr)) {
        return;
    }
    auto serverName = IPUtil::parseIpFormAddr(addr.c_str());
    auto port = IPUtil::parsePortFormAddr(addr.c_str());
    if (port == -1) {
        port = this->peerPort;
    }
    auto client = std::make_shared<ConsensusClient>(serverName, port);
    if (client->create() != SGX_SUCCESS) {
        LOG_ERROR("Failed to create SSL client.");
        return;
    }
    if (client->setErrorCallback(std::bind(&ConsensusRole::clientErrorCallback, this, std::placeholders::_1, std::placeholders::_2)) != SGX_SUCCESS) {
        LOG_ERROR("Failed to set error callback.");
        return;
    }
    if (client->setBeforeHandshakeHandler(std::bind(&ConsensusRole::beforeHandshake, this, std::placeholders::_1)) != SGX_SUCCESS) {
        LOG_ERROR("Failed to set before handshake handler.");
        return;
    }
    if (client->setAfterHandshakeHandler(std::bind(&ConsensusRole::afterHandshake, this, std::placeholders::_1)) != SGX_SUCCESS) {
        LOG_ERROR("Failed to set after handshake handler.");
        return;
    }
    std::shared_ptr<SSLClientSession> session;
    if (client->connect(session) != SGX_SUCCESS) {
        LOG_ERROR("Failed to connect to %s:%d.", serverName, port);
        return;
    }
    TaskScheduler::executeDetachedTask([this, addr, client, session] {
        this->registerClientSession(addr, client, session);
    });
}

void ConsensusRole::registerServerSession(const std::shared_ptr<SSLServerSession> &session) {
    auto size = sizeof(this->id);
    auto read = Memory::makeShared<int>(size);
    if (session->read(read.get(), size) != SGX_SUCCESS) {
        return;
    }
    if (session->write(&this->id, size) != SGX_SUCCESS) {
        return;
    }
    this->mgr.registerServer(std::string(IPUtil::uLong2IpAddr(session->getIP())), session);
    this->mgr.bindSession(session, *read);
    TaskScheduler::executeDetachedTask([this, session] {
        this->handleRequest(session);
    });
    this->startConsensus();
}

void ConsensusRole::registerClientSession(const std::string &addr, const std::shared_ptr<SSLClient> &client,
                                          const std::shared_ptr<SSLClientSession> &session) {
    auto size = sizeof(this->id);
    if (session->write(&this->id, size) != SGX_SUCCESS) {
        return;
    }
    auto read = Memory::makeShared<int>(size);
    if (session->read(read.get(), size) != SGX_SUCCESS) {
        return;
    }
    this->mgr.registerClient(addr, client, session);
    this->mgr.bindSession(session, *read);
    this->startConsensus();
}

int ConsensusRole::getServerSessionId(const std::shared_ptr<SSLServerSession> &session) {
    return this->mgr.getIdBySession(session);
}

void ConsensusRole::startConsensus() {
    std::lock_guard<std::mutex> lock(this->consensusStartedLock);
    if (this->consensusStarted) {
        return;
    }
    if (!this->isReadyToHandleConsensusMessage()) {
        return;
    }
    for (auto i : this->mgr.getIds()) {
        this->registerPeerToConsensus2(i);
    }
    this->startConsensus1();
    while (true) {
        if (this->isIssuerReady()) {
            break;
        }
    }
    this->startConsensus2();
    this->consensusStarted = true;
}

void ConsensusRole::unicast(int toNodeId, const void *msg, size_t msgSize) {
    if (toNodeId < 0 || msgSize <= 0 || !msg) {
        return;
    }
    if (const auto session = this->mgr.getClientSessionById(toNodeId)) {
        session->write(msg, msgSize);
    }
}

void ConsensusRole::broadcast(const void *msg, size_t msgSize) {
    if (msgSize <= 0 || !msg) {
        return;
    }
    for (const auto &session: this->mgr.getClientSessions()) {
        if (session) {
            session->write(msg, msgSize);
        }
    }
}

void ConsensusRole::handleRequest(const std::shared_ptr<SSLServerSession> &session) {
    while (true) {
        auto size = MessageBase::serializedSize();
        auto message = Memory::makeShared<MessageType>(size);
        if (session->read(message.get(), size) != SGX_SUCCESS) {
            break;
        }
        switch (*message) {
            case LeaderElectionRequest:
                this->handleElectionRequest(session);
                break;
            case LeaderElectionResponse:
                this->handleElectionResponse(session);
                break;
            case LeaderNotification:
                this->handleLeaderNotification(session);
                break;
            case AcceptRequest:
                this->handleAcceptRequest(session);
                break;
            case AcceptResponse:
                this->handleAcceptResponse(session);
                break;
            case CommitRequest:
                this->handleCommitRequest(session);
                break;
            case CommitResponse:
                this->handleCommitResponse(session);
                break;
            case TryAcceptRequest:
                this->handleTryAcceptRequest(session);
                break;
            case TryAcceptResponse:
                this->handleTryAcceptResponse(session);
                break;
            case TryCommitRequest:
                this->handleTryCommitRequest(session);
                break;
            case TryCommitResponse:
                this->handleTryCommitResponse(session);
                break;
            case RecoverRequest:
                this->handleRecoverRequest(session);
                break;
            case RecoverResponse:
                this->handleRecoverResponse(session);
                break;
            case PrepareRequest:
                this->handlePrepareRequest(session);
                break;
            case PrepareResponse:
                this->handlePrepareResponse(session);
                break;
            case Default:
            default:
                break;
        }
    }
}

void ConsensusRole::getEPIDKeysCallback(GroupPubKey &pubKey, IPrivKey &privKey) {
    return getEPIDKeysFromEPIDRole(pubKey, privKey);
}

void ConsensusRole::setEPIDKeysCallback(const GroupPubKey &pubKey, const IPrivKey &privKey) {
    return setEPIDKeysToEPIDRole(pubKey, privKey);
}

void ConsensusRole::revokeMemberByPrivCallback(const FpElemStr &f) {
    return revokeMemberByPrivToEPIDRole(f);
}

void ConsensusRole::revokeMemberBySigCallback(size_t signature_size, const EpidNonSplitSignature &signature) {
    return revokeMemberBySigToEPIDRole(signature_size, signature);
}

void ConsensusRole::revokeSignatureCallback(size_t signature_size, const EpidNonSplitSignature &signature) {
    return revokeSignatureToEPIDRole(signature_size, signature);
}
