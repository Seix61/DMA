
#include "attest/role.h"

#include <attestation/rpc/message_serializer.h>
#include <attestation/rpc/messages.h>
#include <util/sgx/attestation_helper.h>
#include <util/sgx/dump.h>
#include <util/memory.h>
#include <util/log.h>

using namespace Attestation;

AttestRole::AttestRole(int serverPort) : serverPort(serverPort) {}

sgx_status_t AttestRole::start() {
    this->client = std::make_shared<AttestClient>(serverPort);
    if (this->client->create() != SGX_SUCCESS) {
        LOG_ERROR("Failed to create SSL client.");
        return SGX_ERROR_UNEXPECTED;
    }
    if (this->client->connect(this->session) != SGX_SUCCESS) {
        LOG_ERROR("Failed to connect to server.");
        return SGX_ERROR_UNEXPECTED;
    }
    return SGX_SUCCESS;
}

void AttestRole::createQuote(const unsigned char *reportData, size_t reportDataSize, std::shared_ptr<dma_quote> &quote, size_t &quoteSize) {
    if (this->session == nullptr) {
        quote = nullptr;
        quoteSize = 0;
        LOG_ERROR("Failed to createQuote cause attest server disconnected.");
        return;
    }
    std::lock_guard<std::mutex> lock(transactionLock);
    auto targetInfo = Memory::makeShared<sgx_target_info_t>(sizeof(sgx_target_info_t));
    {
        auto request = BasicMessageSerializer::serialize(std::make_shared<TargetInfoRequestMessage>()).str();
        if (this->session->write(request.c_str(), request.size()) != SGX_SUCCESS) {
            return;
        }
        auto response_size = TargetInfoResponseMessage::serializedSize();
        auto response = Memory::makeShared<char>(response_size);
        if (this->session->read(response.get(), response_size) != SGX_SUCCESS) {
            return;
        }
        auto oss = BasicMessageSerializer::buildStream(response.get(), response_size);
        auto deserialized = MessageSerializer<TargetInfoResponseMessage>::deserialize(oss);
        auto ti = deserialized->getTargetInfo();
        memcpy(targetInfo.get(), &ti, sizeof(sgx_target_info_t));
    }

    std::shared_ptr<sgx_report_t> report;
    SgxAttestationHelper::createSelfReport(targetInfo, reportData, reportDataSize, report);
    {
        auto request = BasicMessageSerializer::serialize(std::make_shared<QuoteRequestMessage>(*report)).str();
        if (this->session->write(request.c_str(), request.size()) != SGX_SUCCESS) {
            return;
        }
        auto static_size = QuoteResponseMessage::serializedSize();
        auto static_part = Memory::makeShared<char>(static_size);
        if (this->session->read(static_part.get(), static_size) != SGX_SUCCESS) {
            return;
        }
        size_t dynamic_size;
        if (this->session->read(&dynamic_size, sizeof(size_t)) != SGX_SUCCESS) {
            return;
        }
        auto dynamic_part = Memory::makeShared<char>(dynamic_size);
        if (this->session->read(dynamic_part.get(), dynamic_size) != SGX_SUCCESS) {
            return;
        }

        auto oss = BasicMessageSerializer::buildStream(static_part.get(), static_size);
        BasicMessageSerializer::appendStream(oss, &dynamic_size, sizeof(size_t));
        BasicMessageSerializer::appendStream(oss, dynamic_part.get(), dynamic_size);
        auto deserialized = MessageSerializer<QuoteResponseMessage>::deserialize(oss);
        quote = deserialized->getQuote();
        quoteSize = deserialized->getSize();
    }
}

void AttestRole::verifyQuote(const std::shared_ptr<dma_quote> &quote, size_t quoteSize, bool &pass) {
    if (this->session == nullptr) {
        pass = false;
        LOG_ERROR("Failed to verifyQuote cause attest server disconnected.");
        return;
    }
    std::lock_guard<std::mutex> lock(transactionLock);
    auto request = BasicMessageSerializer::serialize(std::make_shared<VerifyRequestMessage>(quoteSize, quote)).str();
    if (this->session->write(request.c_str(), request.size()) != SGX_SUCCESS) {
        return;
    }

    auto response_size = VerifyResponseMessage::serializedSize();
    auto response = Memory::makeShared<char>(response_size);
    if (this->session->read(response.get(), response_size) != SGX_SUCCESS) {
        return;
    }

    auto oss = BasicMessageSerializer::buildStream(response.get(), response_size);
    auto deserialized = MessageSerializer<VerifyResponseMessage>::deserialize(oss);
    pass = deserialized->isPass();
}

void AttestRole::revokeSignature(const std::shared_ptr<uint8_t> &sig, size_t size) {
    if (this->session == nullptr) {
        LOG_ERROR("Failed to revokeSignature cause attest server disconnected.");
        return;
    }
    std::lock_guard<std::mutex> lock(transactionLock);

    auto request = BasicMessageSerializer::serialize(std::make_shared<RevokeSigRequestMessage>(size, *((EpidNonSplitSignature *)sig.get()))).str();
    if (this->session->write(request.c_str(), request.size()) != SGX_SUCCESS) {
        return;
    }
}
