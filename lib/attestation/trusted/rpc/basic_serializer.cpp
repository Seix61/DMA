
#include <attestation/rpc/basic_serializer.h>
#include <attestation/rpc/messages.h>

namespace Attestation {
    std::ostringstream BasicMessageSerializer::serialize(const std::shared_ptr<MessageBase> &ptr) {
        std::ostringstream oss;
        MessageType type = ptr->getType();
        oss.write(reinterpret_cast<const char *>(&type), sizeof(type));
        ptr->serialize(oss);
        return oss;
    }

    std::shared_ptr<MessageBase> BasicMessageSerializer::deserialize(std::istringstream &iss) {
        std::shared_ptr<MessageBase> ptr;
        MessageType type;
        iss.read(reinterpret_cast<char *>(&type), sizeof(type));
        switch (type) {
            case TargetInfoRequest:
                ptr = std::make_shared<TargetInfoRequestMessage>();
                break;
            case TargetInfoResponse:
                ptr = std::make_shared<TargetInfoResponseMessage>();
                break;
            case QuoteRequest:
                ptr = std::make_shared<QuoteRequestMessage>();
                break;
            case QuoteResponse:
                ptr = std::make_shared<QuoteResponseMessage>();
                break;
            case VerifyRequest:
                ptr = std::make_shared<VerifyRequestMessage>();
                break;
            case VerifyResponse:
                ptr = std::make_shared<VerifyResponseMessage>();
                break;
            case RevokeSigRequest:
                ptr = std::make_shared<RevokeSigRequestMessage>();
                break;
            case Default:
            default:
                ptr = std::make_shared<MessageBase>(Default);
                break;
        }
        ptr->deserialize(iss);
        return ptr;
    }

    std::shared_ptr<MessageBase> BasicMessageSerializer::deserialize(std::ostringstream &oss) {
        std::istringstream iss(oss.str());
        return deserialize(iss);
    }

    std::ostringstream BasicMessageSerializer::buildStream(MessageType type, const void *msg, size_t msg_size) {
        std::ostringstream oss;
        oss.write((char *)&type, sizeof(MessageType));
        oss.write((char *)msg, msg_size);
        return oss;
    }

    std::ostringstream BasicMessageSerializer::buildStream(const void *msg, size_t msg_size) {
        std::ostringstream oss;
        oss.write((char *)msg, msg_size);
        return oss;
    }

    void BasicMessageSerializer::appendStream(std::ostringstream &oss, const void *msg, size_t msg_size) {
        oss.write((char *)msg, msg_size);
    }
}
