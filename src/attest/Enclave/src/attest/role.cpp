
#include "attest/role.h"

#include <attestation/rpc/message_serializer.h>
#include <attestation/rpc/messages.h>
#include <scheduler/task_scheduler.h>
#include <epid/types.h>
#include <util/sgx/attestation_helper.h>
#include <util/codec/base64.h>
#include <util/memory.h>
#include <util/log.h>
#include <sgx_utils.h>

using namespace Attestation;

AttestRole::AttestRole(int serverPort, int threadCount) :
        threadCount(threadCount),
        server(std::make_shared<AttestServer>(serverPort)) {}

sgx_status_t AttestRole::start() {
    if (server->create() != SGX_SUCCESS) {
        LOG_ERROR("Failed to create SSL server.");
        return SGX_ERROR_UNEXPECTED;
    }
    for (int i = 0; i < this->threadCount; i++) {
        TaskScheduler::executeDetachedTask([this] {
            this->serverThread();
        });
    }
    return SGX_SUCCESS;
}

void AttestRole::serverThread() {
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

void AttestRole::handleRequest(const std::shared_ptr<SSLServerSession> &session) {
    while (true) {
        auto size = MessageBase::serializedSize();
        auto message = Memory::makeShared<MessageType>(size);
        if (session->read(message.get(), size) != SGX_SUCCESS) {
            break;
        }
        switch (*message) {
            case TargetInfoRequest:
                this->handleTargetInfoRequest(session);
                break;
            case QuoteRequest:
                this->handleQuoteRequest(session);
                break;
            case VerifyRequest:
                this->handleVerifyRequest(session);
                break;
            case RevokeSigRequest:
                this->handleRevokeSigRequest(session);
            case Default:
            default:
                break;
        }
    }
}

void AttestRole::handleTargetInfoRequest(const std::shared_ptr<SSLServerSession> &session) {
    sgx_target_info_t targetInfo;
    if (sgx_self_target(&targetInfo) != SGX_SUCCESS) {
        LOG_ERROR("Failed to sgx_self_target.");
    }
//    LOG_DEBUG("%s", SgxDump::targetInfoToString(&targetInfo).c_str());

    auto response = BasicMessageSerializer::serialize(std::make_shared<TargetInfoResponseMessage>(targetInfo)).str();
    session->write(response.c_str(), response.size());
}

void AttestRole::handleQuoteRequest(const std::shared_ptr<SSLServerSession> &session) {
    auto request_size = QuoteRequestMessage::contentSize();
    auto request = Memory::makeShared<char>(request_size);
    session->read(request.get(), request_size);

    auto oss = BasicMessageSerializer::buildStream(QuoteRequest, request.get(), request_size);
    auto deserialized = MessageSerializer<QuoteRequestMessage>::deserialize(oss);

    sgx_report_t report = deserialized->getReport();
//    LOG_DEBUG("%s", SgxDump::sgxReportToString(&report).c_str());

    sgx_status_t call_ret;
    if ((call_ret = sgx_verify_report(&report)) != SGX_SUCCESS) {
        LOG_ERROR("Failed to sgx_verify_report. Returned 0x%X.", call_ret);
    }

    dma_signed_data plainText{};
    plainText.platform_status = this->getAttStatusFromEpidRole();
    memcpy(&plainText.report_body, &report.body, sizeof(sgx_report_body_t));

    size_t signatureSize = this->getSignatureSizeFromEpidRole();
    EpidNonSplitSignature signature;
    if (this->signFromEpidRole(&plainText, sizeof(plainText), signature, signatureSize) != SGX_SUCCESS) {
        LOG_ERROR("Failed to signFromEpidRole.");
    }

    size_t quoteSize = sizeof(plainText) + sizeof(uint32_t) + signatureSize;
    auto quote = Memory::makeShared<dma_quote>(quoteSize);
    memcpy(&quote->platform_status, &plainText.platform_status, sizeof(uint32_t));
    memcpy(&quote->report_body, &report.body, sizeof(sgx_report_body_t));
    memcpy(&quote->signature_len, &signatureSize, sizeof(size_t));
    memcpy(quote->signature, &signature, signatureSize);

    auto response = BasicMessageSerializer::serialize(std::make_shared<QuoteResponseMessage>(quoteSize, quote)).str();
    session->write(response.c_str(), response.size());
}

void AttestRole::handleVerifyRequest(const std::shared_ptr<SSLServerSession> &session) {
    size_t dynamic_size;
    session->read(&dynamic_size, sizeof(size_t));
    auto dynamic_part = Memory::makeShared<char>(dynamic_size);
    session->read(dynamic_part.get(), dynamic_size);

    auto oss = BasicMessageSerializer::buildStream(VerifyRequest, &dynamic_size, sizeof(size_t));
    BasicMessageSerializer::appendStream(oss, dynamic_part.get(), dynamic_size);
    auto deserialized = MessageSerializer<VerifyRequestMessage>::deserialize(oss);

    auto quote = deserialized->getQuote();

    dma_signed_data plainText{};
    memcpy(&plainText.platform_status, &quote->platform_status, sizeof(uint32_t));
    memcpy(&plainText.report_body, &quote->report_body, sizeof(sgx_report_body_t));

    auto signature = Memory::makeShared<EpidNonSplitSignature>(quote->signature_len);
    memcpy(signature.get(), quote->signature, quote->signature_len);

    sgx_status_t status = this->verifyFromEpidRole(*signature, quote->signature_len, &plainText, sizeof(plainText));

    auto response = BasicMessageSerializer::serialize(std::make_shared<VerifyResponseMessage>(status == SGX_SUCCESS)).str();
    session->write(response.c_str(), response.size());
}

void AttestRole::handleRevokeSigRequest(const std::shared_ptr<SSLServerSession> &session) {
    size_t dynamic_size;
    session->read(&dynamic_size, sizeof(size_t));
    auto dynamic_part = Memory::makeShared<char>(dynamic_size);
    session->read(dynamic_part.get(), dynamic_size);

    auto oss = BasicMessageSerializer::buildStream(RevokeSigRequest, &dynamic_size, sizeof(size_t));
    BasicMessageSerializer::appendStream(oss, dynamic_part.get(), dynamic_size);
    auto deserialized = MessageSerializer<RevokeSigRequestMessage>::deserialize(oss);

    this->revokeSignatureToEpidRole(deserialized->getSignature(), deserialized->getSize());
}
