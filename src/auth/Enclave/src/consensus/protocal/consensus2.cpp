
#include "consensus/protocol/consensus2.h"

#include <consensus/rpc/message_serializer.h>
#include <consensus/rpc/messages.h>
#include <util/log.h>
#include <util/codec/base64.h>

using namespace Consensus;

AuthConsensus2::AuthConsensus2(int id, size_t peerCount) : Consensus2(id, peerCount) {}

void AuthConsensus2::registerPeerToConsensus2(int peerId) {
    this->registerPeer(peerId);
}

void AuthConsensus2::startConsensus2() {
    this->recover();
}

bool AuthConsensus2::isConsensusReady() {
    return false;
}

void AuthConsensus2::revokeMemberByPriv(const FpElemStr &f) {
    int type = 0;
    size_t size = sizeof(int) + sizeof(FpElemStr);
    auto buffer = Memory::makeShared<char>(size);
    memcpy(buffer.get(), &type, sizeof(int));
    memcpy(buffer.get() + sizeof(int), &f, sizeof(FpElemStr));
    this->propose(size, buffer);
}

void AuthConsensus2::revokeMemberBySig(size_t signature_size, const EpidNonSplitSignature &signature) {
    int type = 1;
    size_t size = sizeof(int) + signature_size;
    auto buffer = Memory::makeShared<char>(size);
    memcpy(buffer.get(), &type, sizeof(int));
    memcpy(buffer.get() + sizeof(int), &signature, signature_size);
    this->propose(size, buffer);
}

void AuthConsensus2::revokeSignature(size_t signature_size, const EpidNonSplitSignature &signature) {
    int type = 2;
    size_t size = sizeof(int) + signature_size;
    auto buffer = Memory::makeShared<char>(size);
    memcpy(buffer.get(), &type, sizeof(int));
    memcpy(buffer.get() + sizeof(int), &signature, signature_size);
    this->propose(size, buffer);
}

void AuthConsensus2::proposeCallback(size_t size, const std::shared_ptr<char> &buffer) {
    if (size <= 0 || buffer == nullptr) {
        LOG_WARN("proposeCallback called with empty buffer. skipped.");
        return;
    }
//    LOG_DEBUG("commitLogToDatabase called. buffer = %s", Codec::Base64::encode(buffer.get(), size).c_str());
    int type;
    size_t targetSize = size - sizeof(int);
    auto target = Memory::makeShared<char>(targetSize);
    memcpy(&type, buffer.get(), sizeof(int));
    memcpy(target.get(), buffer.get() + sizeof(int), targetSize);
    if (type == 0) {
        this->revokeMemberByPrivCallback(*((FpElemStr *) target.get()));
    } else if (type == 1) {
        this->revokeMemberBySigCallback(targetSize, *(EpidNonSplitSignature *) target.get());
    } else {
        this->revokeSignatureCallback(targetSize, *(EpidNonSplitSignature *) target.get());
    }
}

void AuthConsensus2::sendAcceptMessage(int logId, size_t size, const std::shared_ptr<char> &buffer) {
    if (size <= 0 || buffer == nullptr) {
        LOG_WARN("sendAcceptMessage called with empty buffer. skipped.");
        return;
    }
//    LOG_DEBUG("sendAcceptMessage called. buffer = %s", Codec::Base64::encode(buffer.get(), size).c_str());
    auto request = BasicMessageSerializer::serialize(
            std::make_shared<AcceptRequestMessage>(logId, size, buffer)).str();
    this->broadcast(request.c_str(), request.size());
}

void AuthConsensus2::sendAcceptReplyMessage(int toNodeId, int logId) {
    auto request = BasicMessageSerializer::serialize(
            std::make_shared<AcceptResponseMessage>(logId)).str();
    this->unicast(toNodeId, request.c_str(), request.size());
}

void AuthConsensus2::sendCommitMessage(int logId, size_t size, const std::shared_ptr<char> &buffer) {
    if (size <= 0 || buffer == nullptr) {
        LOG_WARN("sendCommitMessage called with empty buffer. skipped.");
        return;
    }
//    LOG_DEBUG("sendCommitMessage called. buffer = %s", Codec::Base64::encode(buffer.get(), size).c_str());
    auto request = BasicMessageSerializer::serialize(
            std::make_shared<CommitRequestMessage>(logId, size, buffer)).str();
    this->broadcast(request.c_str(), request.size());
}

void AuthConsensus2::sendCommitReplyMessage(int toNodeId, int logId) {
    auto request = BasicMessageSerializer::serialize(
            std::make_shared<CommitResponseMessage>(logId)).str();
    this->unicast(toNodeId, request.c_str(), request.size());
}

void AuthConsensus2::sendTryAcceptMessage(int nodeId, int logId, size_t size, const std::shared_ptr<char> &buffer) {
    if (size <= 0 || buffer == nullptr) {
        LOG_WARN("sendTryAcceptMessage called with empty buffer. skipped.");
        return;
    }
//    LOG_DEBUG("sendTryAcceptMessage called. buffer = %s", Codec::Base64::encode(buffer.get(), size).c_str());
    auto request = BasicMessageSerializer::serialize(
            std::make_shared<TryAcceptRequestMessage>(nodeId, logId, size, buffer)).str();
    this->broadcast(request.c_str(), request.size());
}

void AuthConsensus2::sendTryAcceptReplyMessage(int toNodeId, int nodeId, int logId) {
    auto request = BasicMessageSerializer::serialize(
            std::make_shared<TryAcceptResponseMessage>(nodeId, logId)).str();
    this->unicast(toNodeId, request.c_str(), request.size());
}

void AuthConsensus2::sendTryCommitMessage(int nodeId, int logId, size_t size, const std::shared_ptr<char> &buffer) {
    if (size <= 0 || buffer == nullptr) {
        LOG_WARN("sendTryCommitMessage called with empty buffer. skipped.");
        return;
    }
//    LOG_DEBUG("sendTryCommitMessage called. buffer = %s", Codec::Base64::encode(buffer.get(), size).c_str());
    auto request = BasicMessageSerializer::serialize(
            std::make_shared<TryCommitRequestMessage>(nodeId, logId, size, buffer)).str();
    this->broadcast(request.c_str(), request.size());
}

void AuthConsensus2::sendTryCommitReplyMessage(int toNodeId, int nodeId, int logId) {
    auto request = BasicMessageSerializer::serialize(
            std::make_shared<TryCommitResponseMessage>(nodeId, logId)).str();
    this->unicast(toNodeId, request.c_str(), request.size());
}

void AuthConsensus2::sendRecoverMessage() {
    auto request = BasicMessageSerializer::serialize(
            std::make_shared<RecoverRequestMessage>()).str();
    this->broadcast(request.c_str(), request.size());
}

void AuthConsensus2::sendRecoverReplyMessage(int toNodeId, const std::map<int, int> &idIndex) {
    auto request = BasicMessageSerializer::serialize(
            std::make_shared<RecoverResponseMessage>(idIndex)).str();
    this->unicast(toNodeId, request.c_str(), request.size());
}

void AuthConsensus2::sendPrepareMessage(int nodeId, int logId) {
    auto request = BasicMessageSerializer::serialize(
            std::make_shared<PrepareRequestMessage>(nodeId, logId)).str();
    this->broadcast(request.c_str(), request.size());
}

void AuthConsensus2::sendPrepareReplyMessage(int toNodeId, int nodeId, int logId, size_t size, const std::shared_ptr<char> &buffer) {
    auto request = BasicMessageSerializer::serialize(
            std::make_shared<PrepareResponseMessage>(nodeId, logId, size, buffer)).str();
    this->unicast(toNodeId, request.c_str(), request.size());
}

void AuthConsensus2::handleAcceptRequest(const std::shared_ptr<SSLServerSession> &session) {
    session->lock();
    do {
        auto static_size = AcceptRequestMessage::staticSize();
        auto static_part = Memory::makeShared<char>(static_size);
        if (session->read(static_part.get(), static_size) != SGX_SUCCESS) {
            break;
        }
        size_t dynamic_size;
        if (session->read(&dynamic_size, sizeof(size_t)) != SGX_SUCCESS) {
            break;
        }
        auto dynamic_part = Memory::makeShared<char>(dynamic_size);
        if (session->read(dynamic_part.get(), dynamic_size) != SGX_SUCCESS) {
            break;
        }
        session->unlock();

        if (!isReadyToHandleConsensusMessage()) {
            return;
        }

        auto oss = BasicMessageSerializer::buildStream(AcceptRequest, static_part.get(), static_size);
        BasicMessageSerializer::appendStream(oss, &dynamic_size, sizeof(size_t));
        BasicMessageSerializer::appendStream(oss, dynamic_part.get(), dynamic_size);
        auto deserialized = MessageSerializer<AcceptRequestMessage>::deserialize(oss);

        return this->handleAcceptMessage(this->getServerSessionId(session),
                                         deserialized->getLogId(),
                                         deserialized->getSize(), deserialized->getBuffer());
    } while (false);
    session->unlock();
}

void AuthConsensus2::handleAcceptResponse(const std::shared_ptr<SSLServerSession> &session) {
    session->lock();
    do {
        auto request_size = AcceptResponseMessage::contentSize();
        auto request = Memory::makeShared<char>(request_size);
        if (session->read(request.get(), request_size) != SGX_SUCCESS) {
            break;
        }
        session->unlock();

        if (!isReadyToHandleConsensusMessage()) {
            return;
        }

        auto oss = BasicMessageSerializer::buildStream(AcceptResponse, request.get(), request_size);
        auto deserialized = MessageSerializer<AcceptResponseMessage>::deserialize(oss);

        return this->handleAcceptReplyMessage(this->getServerSessionId(session), deserialized->getLogId());
    } while (false);
    session->unlock();
}

void AuthConsensus2::handleCommitRequest(const std::shared_ptr<SSLServerSession> &session) {
    session->lock();
    do {
        auto static_size = CommitRequestMessage::staticSize();
        auto static_part = Memory::makeShared<char>(static_size);
        if (session->read(static_part.get(), static_size) != SGX_SUCCESS) {
            break;
        }
        size_t dynamic_size;
        if (session->read(&dynamic_size, sizeof(size_t)) != SGX_SUCCESS) {
            break;
        }
        auto dynamic_part = Memory::makeShared<char>(dynamic_size);
        if (session->read(dynamic_part.get(), dynamic_size) != SGX_SUCCESS) {
            break;
        }
        session->unlock();

        if (!isReadyToHandleConsensusMessage()) {
            return;
        }

        auto oss = BasicMessageSerializer::buildStream(CommitRequest, static_part.get(), static_size);
        BasicMessageSerializer::appendStream(oss, &dynamic_size, sizeof(size_t));
        BasicMessageSerializer::appendStream(oss, dynamic_part.get(), dynamic_size);
        auto deserialized = MessageSerializer<CommitRequestMessage>::deserialize(oss);

        return this->handleCommitMessage(this->getServerSessionId(session),
                                         deserialized->getLogId(),
                                         deserialized->getSize(), deserialized->getBuffer());
    } while (false);
    session->unlock();
}

void AuthConsensus2::handleCommitResponse(const std::shared_ptr<SSLServerSession> &session) {
    session->lock();
    do {
        auto request_size = CommitResponseMessage::contentSize();
        auto request = Memory::makeShared<char>(request_size);
        if (session->read(request.get(), request_size) != SGX_SUCCESS) {
            break;
        }
        session->unlock();

        if (!isReadyToHandleConsensusMessage()) {
            return;
        }

        auto oss = BasicMessageSerializer::buildStream(CommitResponse, request.get(), request_size);
        auto deserialized = MessageSerializer<CommitResponseMessage>::deserialize(oss);

        return this->handleCommitReplyMessage(this->getServerSessionId(session), deserialized->getLogId());
    } while (false);
    session->unlock();
}

void AuthConsensus2::handleTryAcceptRequest(const std::shared_ptr<SSLServerSession> &session) {
    session->lock();
    do {
        auto static_size = TryAcceptRequestMessage::staticSize();
        auto static_part = Memory::makeShared<char>(static_size);
        if (session->read(static_part.get(), static_size) != SGX_SUCCESS) {
            break;
        }
        size_t dynamic_size;
        if (session->read(&dynamic_size, sizeof(size_t)) != SGX_SUCCESS) {
            break;
        }
        auto dynamic_part = Memory::makeShared<char>(dynamic_size);
        if (session->read(dynamic_part.get(), dynamic_size) != SGX_SUCCESS) {
            break;
        }
        session->unlock();

        if (!isReadyToHandleConsensusMessage()) {
            return;
        }

        auto oss = BasicMessageSerializer::buildStream(TryAcceptRequest, static_part.get(), static_size);
        BasicMessageSerializer::appendStream(oss, &dynamic_size, sizeof(size_t));
        BasicMessageSerializer::appendStream(oss, dynamic_part.get(), dynamic_size);
        auto deserialized = MessageSerializer<TryAcceptRequestMessage>::deserialize(oss);

        return this->handleTryAcceptMessage(this->getServerSessionId(session),
                                            deserialized->getNodeId(), deserialized->getLogId(),
                                            deserialized->getSize(), deserialized->getBuffer());
    } while (false);
    session->unlock();
}

void AuthConsensus2::handleTryAcceptResponse(const std::shared_ptr<SSLServerSession> &session) {
    session->lock();
    do {
        auto request_size = TryAcceptResponseMessage::contentSize();
        auto request = Memory::makeShared<char>(request_size);
        if (session->read(request.get(), request_size) != SGX_SUCCESS) {
            break;
        }
        session->unlock();

        if (!isReadyToHandleConsensusMessage()) {
            return;
        }

        auto oss = BasicMessageSerializer::buildStream(TryAcceptResponse, request.get(), request_size);
        auto deserialized = MessageSerializer<TryAcceptResponseMessage>::deserialize(oss);

        return this->handleTryAcceptReplyMessage(this->getServerSessionId(session),
                                                 deserialized->getNodeId(), deserialized->getLogId());
    } while (false);
    session->unlock();
}

void AuthConsensus2::handleTryCommitRequest(const std::shared_ptr<SSLServerSession> &session) {
    session->lock();
    do {
        auto static_size = TryCommitRequestMessage::staticSize();
        auto static_part = Memory::makeShared<char>(static_size);
        if (session->read(static_part.get(), static_size) != SGX_SUCCESS) {
            break;
        }
        size_t dynamic_size;
        if (session->read(&dynamic_size, sizeof(size_t)) != SGX_SUCCESS) {
            break;
        }
        auto dynamic_part = Memory::makeShared<char>(dynamic_size);
        if (session->read(dynamic_part.get(), dynamic_size) != SGX_SUCCESS) {
            break;
        }
        session->unlock();

        if (!isReadyToHandleConsensusMessage()) {
            return;
        }

        auto oss = BasicMessageSerializer::buildStream(TryCommitRequest, static_part.get(), static_size);
        BasicMessageSerializer::appendStream(oss, &dynamic_size, sizeof(size_t));
        BasicMessageSerializer::appendStream(oss, dynamic_part.get(), dynamic_size);
        auto deserialized = MessageSerializer<TryCommitRequestMessage>::deserialize(oss);

        return this->handleTryCommitMessage(this->getServerSessionId(session),
                                            deserialized->getNodeId(), deserialized->getLogId(),
                                            deserialized->getSize(), deserialized->getBuffer());
    } while (false);
    session->unlock();
}

void AuthConsensus2::handleTryCommitResponse(const std::shared_ptr<SSLServerSession> &session) {
    session->lock();
    do {
        auto request_size = TryCommitResponseMessage::contentSize();
        auto request = Memory::makeShared<char>(request_size);
        if (session->read(request.get(), request_size) != SGX_SUCCESS) {
            break;
        }
        session->unlock();

        if (!isReadyToHandleConsensusMessage()) {
            return;
        }

        auto oss = BasicMessageSerializer::buildStream(TryCommitResponse, request.get(), request_size);
        auto deserialized = MessageSerializer<TryCommitResponseMessage>::deserialize(oss);

        return this->handleTryCommitReplyMessage(this->getServerSessionId(session),
                                                 deserialized->getNodeId(), deserialized->getLogId());
    } while (false);
    session->unlock();
}

void AuthConsensus2::handleRecoverRequest(const std::shared_ptr<SSLServerSession> &session) {
    this->handleRecoverMessage(this->getServerSessionId(session));
}

void AuthConsensus2::handleRecoverResponse(const std::shared_ptr<SSLServerSession> &session) {
    session->lock();
    do {
        size_t count;
        if (session->read(&count, sizeof(size_t)) != SGX_SUCCESS) {
            break;
        }
        size_t dynamic_size = count * sizeof(int) * 2;
        auto dynamic_part = Memory::makeShared<char>(dynamic_size);
        if (session->read(dynamic_part.get(), dynamic_size) != SGX_SUCCESS) {
            break;
        }
        session->unlock();

        if (!isReadyToHandleConsensusMessage()) {
            return;
        }

        auto oss = BasicMessageSerializer::buildStream(RecoverResponse, &count, sizeof(size_t));
        BasicMessageSerializer::appendStream(oss, dynamic_part.get(), dynamic_size);
        auto deserialized = MessageSerializer<RecoverResponseMessage>::deserialize(oss);

        return this->handleRecoverReplyMessage(deserialized->getIdIndex());
    } while (false);
    session->unlock();
}

void AuthConsensus2::handlePrepareRequest(const std::shared_ptr<SSLServerSession> &session) {
    session->lock();
    do {
        auto request_size = PrepareRequestMessage::contentSize();
        auto request = Memory::makeShared<char>(request_size);
        if (session->read(request.get(), request_size) != SGX_SUCCESS) {
            break;
        }
        session->unlock();

        if (!isReadyToHandleConsensusMessage()) {
            return;
        }

        auto oss = BasicMessageSerializer::buildStream(PrepareRequest, request.get(), request_size);
        auto deserialized = MessageSerializer<PrepareRequestMessage>::deserialize(oss);

        return this->handlePrepareMessage(this->getServerSessionId(session),
                                          deserialized->getNodeId(), deserialized->getLogId());
    } while (false);
    session->unlock();
}

void AuthConsensus2::handlePrepareResponse(const std::shared_ptr<SSLServerSession> &session) {
    session->lock();
    do {
        auto static_size = PrepareResponseMessage::staticSize();
        auto static_part = Memory::makeShared<char>(static_size);
        if (session->read(static_part.get(), static_size) != SGX_SUCCESS) {
            break;
        }
        size_t dynamic_size;
        if (session->read(&dynamic_size, sizeof(size_t)) != SGX_SUCCESS) {
            break;
        }
        auto dynamic_part = Memory::makeShared<char>(dynamic_size);
        if (session->read(dynamic_part.get(), dynamic_size) != SGX_SUCCESS) {
            break;
        }
        session->unlock();

        if (!isReadyToHandleConsensusMessage()) {
            return;
        }

        auto oss = BasicMessageSerializer::buildStream(PrepareResponse, static_part.get(), static_size);
        BasicMessageSerializer::appendStream(oss, &dynamic_size, sizeof(size_t));
        BasicMessageSerializer::appendStream(oss, dynamic_part.get(), dynamic_size);
        auto deserialized = MessageSerializer<PrepareResponseMessage>::deserialize(oss);

        return this->handlePrepareReplyMessage(deserialized->getNodeId(),
                                               deserialized->getLogId(),
                                               deserialized->getSize(), deserialized->getBuffer());
    } while (false);
    session->unlock();
}
