
#include "epid/role.h"

#include <epid/rpc/message_serializer.h>
#include <epid/rpc/messages.h>
#include <scheduler/task_scheduler.h>
#include <util/ip.h>
#include <util/log.h>
#include <util/codec/base64.h>

using namespace Epid;

EpidRole::EpidRole(uint64_t serverIp, int serverPort) : serverIP(serverIp), serverPort(serverPort) {}

sgx_status_t EpidRole::start() {
    this->client = std::make_shared<EpidClient>(IPUtil::uLong2IpAddr(serverIP), serverPort);
    if (this->client->create() != SGX_SUCCESS) {
        LOG_ERROR("Failed to create SSL client.");
        return SGX_ERROR_UNEXPECTED;
    }
    if (this->client->connect(this->session) != SGX_SUCCESS) {
        LOG_ERROR("Failed to connect to server.");
    }
    TaskScheduler::executeDetachedTask([this] {
        this->initEpidInstance();
    });
    return SGX_SUCCESS;
}

void EpidRole::initEpidInstance() {
    std::lock_guard<std::mutex> iLock(this->initLock);
    if (this->inited) {
        return;
    }
    do {
        {
            this->session->lock();
            auto request = BasicMessageSerializer::serialize(std::make_shared<AttStatusRequestMessage>()).str();
            if (this->session->write(request.c_str(), request.size()) != SGX_SUCCESS) {
                break;
            }
            auto response_size = AttStatusResponseMessage::serializedSize();
            auto response = Memory::makeShared<char>(response_size);
            if (this->session->read(response.get(), response_size) != SGX_SUCCESS) {
                break;
            }
            this->session->unlock();
            auto oss = BasicMessageSerializer::buildStream(response.get(), response_size);
            auto deserialized = MessageSerializer<AttStatusResponseMessage>::deserialize(oss);
            this->attStatus = deserialized->getStatus();
        }

        GroupPubKey pubKey{};
        {
            this->session->lock();
            auto request = BasicMessageSerializer::serialize(std::make_shared<GroupKeyRequestMessage>()).str();
            if (this->session->write(request.c_str(), request.size()) != SGX_SUCCESS) {
                break;
            }
            auto response_size = GroupKeyResponseMessage::serializedSize();
            auto response = Memory::makeShared<char>(response_size);
            if (this->session->read(response.get(), response_size) != SGX_SUCCESS) {
                break;
            }
            this->session->unlock();
            auto oss = BasicMessageSerializer::buildStream(response.get(), response_size);
            auto deserialized = MessageSerializer<GroupKeyResponseMessage>::deserialize(oss);
            pubKey = deserialized->getPubKey();
        }
        if ((this->member = std::make_shared<EPIDMember>(pubKey)) == nullptr) {
            LOG_ERROR("Failed to malloc EPID member.");
            return;
        }
        if (this->member->create() != SGX_SUCCESS) {
            LOG_ERROR("Failed to create EPID member.");
            return;
        }
        if ((this->verifier = std::make_shared<EPIDVerifier>(pubKey)) == nullptr) {
            LOG_ERROR("Failed to malloc EPID verifier.");
            return;
        }
        if (this->verifier->create() != SGX_SUCCESS) {
            LOG_ERROR("Failed to create EPID verifier.");
            return;
        }
        IssuerNonce nonce{};
        {
            this->session->lock();
            auto request = BasicMessageSerializer::serialize(std::make_shared<IssuerNonceRequestMessage>()).str();
            if (this->session->write(request.c_str(), request.size()) != SGX_SUCCESS) {
                break;
            }
            auto response_size = IssuerNonceResponseMessage::serializedSize();
            auto response = Memory::makeShared<char>(response_size);
            if (this->session->read(response.get(), response_size) != SGX_SUCCESS) {
                break;
            }
            this->session->unlock();
            auto oss = BasicMessageSerializer::buildStream(response.get(), response_size);
            auto deserialized = MessageSerializer<IssuerNonceResponseMessage>::deserialize(oss);
            nonce = deserialized->getNonce();
        }
        NoneSplitJoinRequest joinRequest{};
        if (this->member->createJoinRequest(nonce, joinRequest) != SGX_SUCCESS) {
            LOG_ERROR("Failed to create join request.");
            return;
        }
        MembershipCredential credential{};
        {
            this->session->lock();
            auto request = BasicMessageSerializer::serialize(std::make_shared<JoinRequestMessage>(joinRequest, nonce)).str();
            if (this->session->write(request.c_str(), request.size()) != SGX_SUCCESS) {
                break;
            }
            auto response_size = JoinResponseMessage::serializedSize();
            auto response = Memory::makeShared<char>(response_size);
            if (this->session->read(response.get(), response_size) != SGX_SUCCESS) {
                break;
            }
            this->session->unlock();
            auto oss = BasicMessageSerializer::buildStream(response.get(), response_size);
            auto deserialized = MessageSerializer<JoinResponseMessage>::deserialize(oss);
            credential = deserialized->getCredential();
        }
        if (this->member->provision(credential) != SGX_SUCCESS) {
            LOG_ERROR("Failed to provision member.");
            return;
        }
        this->inited = true;
        LOG_INFO("EpidInstance inited.");
    } while (false);

    this->session->unlock();
}

sgx_status_t EpidRole::updateSigRl() {
    std::shared_ptr<SigRl> sigRl;
    do {
        this->session->lock();
        auto request = BasicMessageSerializer::serialize(std::make_shared<SigRLRequestMessage>()).str();
        if (this->session->write(request.c_str(), request.size()) != SGX_SUCCESS) {
            break;
        }

        auto static_size = SigRLResponseMessage::serializedSize();
        auto static_part = Memory::makeShared<char>(static_size);
        if (this->session->read(static_part.get(), static_size) != SGX_SUCCESS) {
            break;
        }
        size_t dynamic_size;
        if (this->session->read(&dynamic_size, sizeof(size_t)) != SGX_SUCCESS) {
            break;
        }
        auto dynamic_part = Memory::makeShared<char>(dynamic_size);
        if (this->session->read(dynamic_part.get(), dynamic_size) != SGX_SUCCESS) {
            break;
        }
        this->session->unlock();

        auto oss = BasicMessageSerializer::buildStream(static_part.get(), static_size);
        BasicMessageSerializer::appendStream(oss, &dynamic_size, sizeof(size_t));
        BasicMessageSerializer::appendStream(oss, dynamic_part.get(), dynamic_size);
        auto deserialized = MessageSerializer<SigRLResponseMessage>::deserialize(oss);

        sigRl = deserialized->getRl();
//        LOG_DEBUG("SigRL[%d] received = %s", deserialized->getSize(), Codec::Base64::encode((char *)sigRl.get(), deserialized->getSize()).c_str());

        if (this->member->setSigRl(sigRl.get()) != SGX_SUCCESS) {
            LOG_ERROR("Failed to setSigRl for member.");
            return SGX_ERROR_UNEXPECTED;
        }
        if (this->verifier->setSigRl(sigRl.get()) != SGX_SUCCESS) {
            LOG_ERROR("Failed to setSigRl for verifier.");
            return SGX_ERROR_UNEXPECTED;
        }

        return SGX_SUCCESS;
    } while (false);

    this->session->unlock();
    return SGX_ERROR_UNEXPECTED;
}

sgx_status_t EpidRole::updateSignatureRl() {
    std::shared_ptr<uint8_t> sigRl;
    do {
        this->session->lock();
        auto request = BasicMessageSerializer::serialize(std::make_shared<SignatureRLRequestMessage>()).str();
        if (this->session->write(request.c_str(), request.size()) != SGX_SUCCESS) {
            break;
        }

        auto static_size = SigRLResponseMessage::serializedSize();
        auto static_part = Memory::makeShared<char>(static_size);
        if (this->session->read(static_part.get(), static_size) != SGX_SUCCESS) {
            break;
        }
        size_t dynamic_size;
        if (this->session->read(&dynamic_size, sizeof(size_t)) != SGX_SUCCESS) {
            break;
        }
        auto dynamic_part = Memory::makeShared<char>(dynamic_size);
        if (this->session->read(dynamic_part.get(), dynamic_size) != SGX_SUCCESS) {
            break;
        }
        this->session->unlock();

        auto oss = BasicMessageSerializer::buildStream(static_part.get(), static_size);
        BasicMessageSerializer::appendStream(oss, &dynamic_size, sizeof(size_t));
        BasicMessageSerializer::appendStream(oss, dynamic_part.get(), dynamic_size);
        auto deserialized = MessageSerializer<SignatureRLResponseMessage>::deserialize(oss);

        sigRl = deserialized->getRl();
//        LOG_DEBUG("SignatureRL[%d] received = %s", deserialized->getSize(), Codec::Base64::encode((char *)sigRl.get(), deserialized->getSize()).c_str());

        if (this->verifier->setSignatureRl(sigRl) != SGX_SUCCESS) {
            LOG_ERROR("Failed to setSignatureRl for verifier.");
            return SGX_ERROR_UNEXPECTED;
        }

        return SGX_SUCCESS;
    } while (false);

    this->session->unlock();
    return SGX_ERROR_UNEXPECTED;
}

sgx_status_t EpidRole::updatePrivRl() {
    std::shared_ptr<PrivRl> privRl;
    do {
        this->session->lock();
        auto request = BasicMessageSerializer::serialize(std::make_shared<PrivRLRequestMessage>()).str();
        if (this->session->write(request.c_str(), request.size()) != SGX_SUCCESS) {
            break;
        }

        auto static_size = PrivRLResponseMessage::serializedSize();
        auto static_part = Memory::makeShared<char>(static_size);
        if (this->session->read(static_part.get(), static_size) != SGX_SUCCESS) {
            break;
        }
        size_t dynamic_size;
        if (this->session->read(&dynamic_size, sizeof(size_t)) != SGX_SUCCESS) {
            break;
        }
        auto dynamic_part = Memory::makeShared<char>(dynamic_size);
        if (this->session->read(dynamic_part.get(), dynamic_size) != SGX_SUCCESS) {
            break;
        }
        this->session->unlock();

        auto oss = BasicMessageSerializer::buildStream(static_part.get(), static_size);
        BasicMessageSerializer::appendStream(oss, &dynamic_size, sizeof(size_t));
        BasicMessageSerializer::appendStream(oss, dynamic_part.get(), dynamic_size);
        auto deserialized = MessageSerializer<PrivRLResponseMessage>::deserialize(oss);

        privRl = deserialized->getRl();

        if (this->verifier->setPrivRl(privRl.get()) != SGX_SUCCESS) {
            LOG_ERROR("Failed to setPrivRl for verifier.");
            return SGX_ERROR_UNEXPECTED;
        }

        return SGX_SUCCESS;
    } while (false);

    this->session->unlock();
    return SGX_ERROR_UNEXPECTED;
}

sgx_status_t EpidRole::updateRl() {
    std::shared_ptr<SigRl> sigRl;
    std::shared_ptr<PrivRl> privRl;
    std::shared_ptr<uint8_t> signatureRl;
    do {
        this->session->lock();
        auto request = BasicMessageSerializer::serialize(std::make_shared<RLRequestMessage>()).str();
        if (this->session->write(request.c_str(), request.size()) != SGX_SUCCESS) {
            break;
        }

        auto static_size = RLRequestMessage::serializedSize();
        auto static_part = Memory::makeShared<char>(static_size);
        if (this->session->read(static_part.get(), static_size) != SGX_SUCCESS) {
            break;
        }
        auto oss = BasicMessageSerializer::buildStream(static_part.get(), static_size);

        for (int i = 0; i < 3; i++) {
            size_t dynamic_size;
            if (this->session->read(&dynamic_size, sizeof(size_t)) != SGX_SUCCESS) {
                break;
            }
            auto dynamic_part = Memory::makeShared<char>(dynamic_size);
            if (this->session->read(dynamic_part.get(), dynamic_size) != SGX_SUCCESS) {
                break;
            }
            BasicMessageSerializer::appendStream(oss, &dynamic_size, sizeof(size_t));
            BasicMessageSerializer::appendStream(oss, dynamic_part.get(), dynamic_size);
        }

        this->session->unlock();

        auto deserialized = MessageSerializer<RLResponseMessage>::deserialize(oss);

        sigRl = deserialized->getSigRl();
        privRl = deserialized->getPrivRl();
        signatureRl = deserialized->getSignatureRl();

        if (this->member->setSigRl(sigRl.get()) != SGX_SUCCESS) {
            LOG_ERROR("Failed to setSigRl for member.");
            return SGX_ERROR_UNEXPECTED;
        }
        if (this->verifier->setSigRl(sigRl.get()) != SGX_SUCCESS) {
            LOG_ERROR("Failed to setSigRl for verifier.");
            return SGX_ERROR_UNEXPECTED;
        }
        if (this->verifier->setPrivRl(privRl.get()) != SGX_SUCCESS) {
            LOG_ERROR("Failed to setPrivRl for verifier.");
            return SGX_ERROR_UNEXPECTED;
        }
        if (this->verifier->setSignatureRl(signatureRl) != SGX_SUCCESS) {
            LOG_ERROR("Failed to setSignatureRl for verifier.");
            return SGX_ERROR_UNEXPECTED;
        }

        return SGX_SUCCESS;
    } while (false);

    this->session->unlock();
    return SGX_ERROR_UNEXPECTED;
}

uint32_t EpidRole::getAttStatus() const {
    return this->attStatus;
}

size_t EpidRole::getSignatureSize() {
    if (!this->inited) {
        return 0;
    }
    if (this->updateSigRl() != SGX_SUCCESS) {
        LOG_ERROR("Failed to update SigRl.");
        return 0;
    }
    size_t size;
    if (this->member->getSigSize(size) != SGX_SUCCESS) {
        LOG_ERROR("Failed to getSigSize.");
        return 0;
    }
    return size;
}

sgx_status_t EpidRole::sign(const void *msg, size_t msgSize, EpidNonSplitSignature &signature, size_t signatureSize) {
    auto ret = this->member->sign(msg, msgSize, nullptr, 0, signature, signatureSize);
    LOG_DEBUG("calling member->sign %s", Codec::Base64::encode((char *)&signature, signatureSize).c_str());
    return ret;
}

sgx_status_t
EpidRole::verify(const EpidNonSplitSignature &signature, size_t signatureSize, const void *msg, size_t msgSize) {
    if (this->updateRl() != SGX_SUCCESS) {
        LOG_ERROR("Failed to update Rl.");
        return SGX_ERROR_UNEXPECTED;
    }
    LOG_DEBUG("calling verifier->verify %s", Codec::Base64::encode((char *)&signature, signatureSize).c_str());
    return this->verifier->verify(signature, signatureSize, msg, msgSize);
}

sgx_status_t EpidRole::revokeSignature(const EpidNonSplitSignature &signature, size_t signatureSize) {
    do {
        this->session->lock();
        auto request = BasicMessageSerializer::serialize(std::make_shared<RevokeSignatureRequestMessage>(signatureSize, signature)).str();
        if (this->session->write(request.c_str(), request.size()) != SGX_SUCCESS) {
            break;
        }
        this->session->unlock();

        return SGX_SUCCESS;
    } while (false);

    this->session->unlock();
    return SGX_ERROR_UNEXPECTED;
}
