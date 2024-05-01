
#include "epid/role.h"
#include "api.h"

#include <epid/rpc/message_serializer.h>
#include <epid/rpc/messages.h>
#include <scheduler/task_scheduler.h>
#include <util/memory.h>
#include <util/codec/base64.h>
#include <util/log.h>

using namespace Epid;

EpidRole::EpidRole(int serverPort, int threadCount) :
        threadCount(threadCount),
        server(std::make_shared<EpidServer>(serverPort)) {}

sgx_status_t EpidRole::start() {
    if (server->create() != SGX_SUCCESS) {
        LOG_ERROR("Failed to create SSL server.");
        return SGX_ERROR_UNEXPECTED;
    }
    for (int i = 0; i < this->threadCount; i++) {
        TaskScheduler::executeDetachedTask([this] {
            this->serverThread();
        });
    }
    this->serverReady = true;
    return SGX_SUCCESS;
}

void EpidRole::serverThread() {
    while (true) {
        std::shared_ptr<SSLServerSession> session;
        if (server->accept(session) != SGX_SUCCESS) {
            LOG_ERROR("Failed to accept.");
            continue;
        }
        TaskScheduler::executeDetachedTask([this, session] {
            this->handleRequest(session);
        });
    }
}

void EpidRole::handleRequest(const std::shared_ptr<SSLServerSession> &session) {
    while (true) {
        auto size = MessageBase::serializedSize();
        auto message = Memory::makeShared<MessageType>(size);
        if (session->read(message.get(), size) != SGX_SUCCESS) {
            break;
        }
        switch (*message) {
            case AttStatusRequest:
                this->handleAttStatusRequest(session);
                break;
            case IssuerNonceRequest:
                this->handleIssuerNonceRequest(session);
                break;
            case GroupKeyRequest:
                this->handleGroupKeyRequest(session);
                break;
            case MemberJoinRequest:
                this->handleMemberJoinRequest(session);
                break;
            case RevokeMemberBySigRequest:
                this->handleRevokeMemberBySigRequest(session);
                break;
            case RevokeSignatureRequest:
                this->handleRevokeSignatureRequest(session);
                break;
            case PrivRLRequest:
                this->handlePrivRLRequest(session);
                break;
            case SigRLRequest:
                this->handleSigRLRequest(session);
                break;
            case SignatureRLRequest:
                this->handleSignatureRLRequest(session);
                break;
            case RLRequest:
                this->handleRLRequest(session);
                break;
            case Default:
            default:
                break;
        }
    }
}

bool EpidRole::isReady() {
    return this->serverReady && this->isIssuerReady();
}

bool EpidRole::isIssuerReady() {
    std::lock_guard<std::mutex> lock(issuerContextLock);
    return issuerContextSet;
}

void EpidRole::createIssuer() {
    std::lock_guard<std::mutex> lock(issuerContextLock);
    if (this->issuerContextSet) {
        return;
    }
    if (this->issuer->create() != SGX_SUCCESS) {
        LOG_ERROR("Failed to create EPID issuer.");
        return;
    }
    this->issuerContextSet = true;
    LOG_INFO("EpidIssuer created.");
}

void EpidRole::importIssuer(const GroupPubKey &pubKey, const IPrivKey &privKey) {
    std::lock_guard<std::mutex> lock(issuerContextLock);
    if (this->issuerContextSet) {
        return;
    }
    if (this->issuer->import(pubKey, privKey) != SGX_SUCCESS) {
        LOG_ERROR("Failed to import EPID issuer.");
        return;
    }
    this->issuerContextSet = true;
    LOG_INFO("EpidIssuer imported.");
}

void EpidRole::getEPIDKeys(GroupPubKey &pubKey, IPrivKey &privKey) {
    if (!this->issuerContextSet) {
        this->createIssuer();
    }
    GroupPubKey pub{};
    IPrivKey priv{};
    if (this->issuer->exportGroupPubKey(pub) != SGX_SUCCESS) {
        LOG_ERROR("Failed to export public key.");
        return;
    }
    if (this->issuer->exportIssueKey(priv) != SGX_SUCCESS) {
        LOG_ERROR("Failed to export issuer key.");
        return;
    }
    pubKey = pub;
    privKey = priv;
}

void EpidRole::setEPIDKeys(const GroupPubKey &pubKey, const IPrivKey &privKey) {
    if (!this->issuerContextSet) {
        this->importIssuer(pubKey, privKey);
    }
}

void EpidRole::revokeMemberByPriv(const FpElemStr &f) {
    if (this->issuer->revokeMemberByPriv(f) != SGX_SUCCESS) {
        LOG_ERROR("Failed to revoke member by private.");
    }
    LOG_DEBUG("revokeMemberByPriv called. f = %s", Codec::Base64::encode((char *)&f, sizeof(f)).c_str());
}

void EpidRole::revokeMemberBySig(size_t signature_size, const EpidNonSplitSignature &signature) {
    if (this->issuer->revokeMemberBySig(signature) != SGX_SUCCESS) {
        LOG_ERROR("Failed to revoke member by signature.");
    }
    LOG_DEBUG("revokeMemberBySig called. signature = %s", Codec::Base64::encode((char *)&signature, signature_size).c_str());
}

void EpidRole::revokeSignature(size_t signature_size, const EpidNonSplitSignature &signature) {
    if (this->issuer->revokeSignature(signature, signature_size) != SGX_SUCCESS) {
        LOG_ERROR("Failed to revoke signature.");
    }
    LOG_DEBUG("revokeSignature called. signature = %s", Codec::Base64::encode((char *)&signature, signature_size).c_str());
}

void EpidRole::handleAttStatusRequest(const std::shared_ptr<SSLServerSession> &session) {
    auto status = get_platform_status(session->getSocketFd());
    auto response = BasicMessageSerializer::serialize(std::make_shared<AttStatusResponseMessage>(status)).str();
    session->write(response.c_str(), response.size());
}

void EpidRole::handleIssuerNonceRequest(const std::shared_ptr<SSLServerSession> &session) {
    if (!this->issuerContextSet) {
        return;
    }

    IssuerNonce nonce{};
    if (this->issuer->generateNonce(nonce) != SGX_SUCCESS) {
        LOG_ERROR("Failed to generateNonce.");
    }

    auto response = BasicMessageSerializer::serialize(std::make_shared<IssuerNonceResponseMessage>(nonce)).str();
    session->write(response.c_str(), response.size());
}

void EpidRole::handleGroupKeyRequest(const std::shared_ptr<SSLServerSession> &session) {
    if (!this->issuerContextSet) {
        return;
    }

    GroupPubKey pubKey{};
    if (this->issuer->exportGroupPubKey(pubKey) != SGX_SUCCESS) {
        LOG_ERROR("Failed to exportGroupPubKey.");
    }

    auto response = BasicMessageSerializer::serialize(std::make_shared<GroupKeyResponseMessage>(pubKey)).str();
    session->write(response.c_str(), response.size());
}

void EpidRole::handleMemberJoinRequest(const std::shared_ptr<SSLServerSession> &session) {
    if (!this->issuerContextSet) {
        return;
    }

    auto request_size = JoinRequestMessage::contentSize();
    auto request = Memory::makeShared<char>(request_size);
    if (session->read(request.get(), request_size) != SGX_SUCCESS) {
        return;
    }

    auto oss = BasicMessageSerializer::buildStream(MemberJoinRequest, request.get(), request_size);
    auto deserialized = MessageSerializer<JoinRequestMessage>::deserialize(oss);

    MembershipCredential credential{};
    if (this->issuer->certifyMembership(deserialized->getRequest(), deserialized->getNonce(), credential) != SGX_SUCCESS) {
        LOG_ERROR("Failed to certifyMembership.");
    }

    auto response = BasicMessageSerializer::serialize(std::make_shared<JoinResponseMessage>(credential)).str();
    session->write(response.c_str(), response.size());
}

void EpidRole::handleRevokeMemberBySigRequest(const std::shared_ptr<SSLServerSession> &session) {
    if (!this->issuerContextSet) {
        return;
    }

    size_t dynamic_size;
    if (session->read(&dynamic_size, sizeof(size_t)) != SGX_SUCCESS) {
        return;
    }
    auto dynamic_part = Memory::makeShared<char>(dynamic_size);
    if (session->read(dynamic_part.get(), dynamic_size) != SGX_SUCCESS) {
        return;
    }

    auto oss = BasicMessageSerializer::buildStream(RevokeMemberBySigRequest, &dynamic_size, sizeof(size_t));
    BasicMessageSerializer::appendStream(oss, dynamic_part.get(), dynamic_size);
    auto deserialized = MessageSerializer<RevokeMemberBySigRequestMessage>::deserialize(oss);

    this->revokeMemberBySigToConsensusRole(deserialized->getSize(), deserialized->getSignature());
}

void EpidRole::handleRevokeSignatureRequest(const std::shared_ptr<SSLServerSession> &session) {
    if (!this->issuerContextSet) {
        return;
    }

    size_t dynamic_size;
    if (session->read(&dynamic_size, sizeof(size_t)) != SGX_SUCCESS) {
        return;
    }
    auto dynamic_part = Memory::makeShared<char>(dynamic_size);
    if (session->read(dynamic_part.get(), dynamic_size) != SGX_SUCCESS) {
        return;
    }

    auto oss = BasicMessageSerializer::buildStream(RevokeSignatureRequest, &dynamic_size, sizeof(size_t));
    BasicMessageSerializer::appendStream(oss, dynamic_part.get(), dynamic_size);
    auto deserialized = MessageSerializer<RevokeSignatureRequestMessage>::deserialize(oss);

    this->revokeSignatureToConsensusRole(deserialized->getSize(), deserialized->getSignature());
}

void EpidRole::handlePrivRLRequest(const std::shared_ptr<SSLServerSession> &session) {
    if (!this->issuerContextSet) {
        return;
    }

    size_t size;
    if (this->issuer->getPrivRlSize(size) != SGX_SUCCESS) {
        LOG_ERROR("Failed to getPrivRlSize.");
    }
    auto rl = Memory::makeShared<PrivRl>(size);
    if (this->issuer->getPrivRl(rl.get(), size) != SGX_SUCCESS) {
        LOG_ERROR("Failed to getPrivRl.");
    }

    auto response = BasicMessageSerializer::serialize(std::make_shared<PrivRLResponseMessage>(size, rl)).str();
    session->write(response.c_str(), response.size());
}

void EpidRole::handleSigRLRequest(const std::shared_ptr<SSLServerSession> &session) {
    if (!this->issuerContextSet) {
        return;
    }

    size_t size;
    if (this->issuer->getSigRlSize(size) != SGX_SUCCESS) {
        LOG_ERROR("Failed to getSigRlSize.");
    }
    auto rl = Memory::makeShared<SigRl>(size);
    if (this->issuer->getSigRl(rl.get(), size) != SGX_SUCCESS) {
        LOG_ERROR("Failed to getSigRl.");
    }

    auto response = BasicMessageSerializer::serialize(std::make_shared<SigRLResponseMessage>(size, rl)).str();
    session->write(response.c_str(), response.size());
}

void EpidRole::handleSignatureRLRequest(const std::shared_ptr<SSLServerSession> &session) {
    if (!this->issuerContextSet) {
        return;
    }

    size_t size;
    std::shared_ptr<uint8_t> rl;
    if (this->issuer->getSignatureRl(rl, size) != SGX_SUCCESS) {
        LOG_ERROR("Failed to getSignatureRl.");
    }

    auto response = BasicMessageSerializer::serialize(std::make_shared<SignatureRLResponseMessage>(size, rl)).str();
    session->write(response.c_str(), response.size());
}

void EpidRole::handleRLRequest(const std::shared_ptr<SSLServerSession> &session) {
    if (!this->issuerContextSet) {
        return;
    }

    size_t sigRlSize;
    if (this->issuer->getSigRlSize(sigRlSize) != SGX_SUCCESS) {
        LOG_ERROR("Failed to getSigRlSize.");
    }
    auto sigRl = Memory::makeShared<SigRl>(sigRlSize);
    if (this->issuer->getSigRl(sigRl.get(), sigRlSize) != SGX_SUCCESS) {
        LOG_ERROR("Failed to getSigRl.");
    }

    size_t privRlSize;
    if (this->issuer->getPrivRlSize(privRlSize) != SGX_SUCCESS) {
        LOG_ERROR("Failed to getPrivRlSize.");
    }
    auto privRl = Memory::makeShared<PrivRl>(privRlSize);
    if (this->issuer->getPrivRl(privRl.get(), privRlSize) != SGX_SUCCESS) {
        LOG_ERROR("Failed to getPrivRl.");
    }

    size_t signatureRlSize;
    std::shared_ptr<uint8_t> signatureRl;
    if (this->issuer->getSignatureRl(signatureRl, signatureRlSize) != SGX_SUCCESS) {
        LOG_ERROR("Failed to getSignatureRl.");
    }

    auto response = BasicMessageSerializer::serialize(std::make_shared<RLResponseMessage>(sigRlSize, sigRl, privRlSize, privRl, signatureRlSize, signatureRl)).str();
    session->write(response.c_str(), response.size());
}
