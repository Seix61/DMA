
#include <epid/rpc/basic_serializer.h>
#include <epid/rpc/messages.h>

namespace Epid {
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
            case AttStatusRequest:
                ptr = std::make_shared<AttStatusRequestMessage>();
                break;
            case AttStatusResponse:
                ptr = std::make_shared<AttStatusResponseMessage>();
                break;
            case IssuerNonceRequest:
                ptr = std::make_shared<IssuerNonceRequestMessage>();
                break;
            case IssuerNonceResponse:
                ptr = std::make_shared<IssuerNonceResponseMessage>();
                break;
            case GroupKeyRequest:
                ptr = std::make_shared<GroupKeyRequestMessage>();
                break;
            case GroupKeyResponse:
                ptr = std::make_shared<GroupKeyResponseMessage>();
                break;
            case MemberJoinRequest:
                ptr = std::make_shared<JoinRequestMessage>();
                break;
            case MemberJoinResponse:
                ptr = std::make_shared<JoinResponseMessage>();
                break;
            case RevokeMemberBySigRequest:
                ptr = std::make_shared<RevokeMemberBySigRequestMessage>();
                break;
            case RevokeSignatureRequest:
                ptr = std::make_shared<RevokeSignatureRequestMessage>();
                break;
            case PrivRLRequest:
                ptr = std::make_shared<PrivRLRequestMessage>();
                break;
            case PrivRLResponse:
                ptr = std::make_shared<PrivRLResponseMessage>();
                break;
            case SigRLRequest:
                ptr = std::make_shared<SigRLRequestMessage>();
                break;
            case SigRLResponse:
                ptr = std::make_shared<SigRLResponseMessage>();
                break;
            case SignatureRLRequest:
                ptr = std::make_shared<SignatureRLRequestMessage>();
                break;
            case SignatureRLResponse:
                ptr = std::make_shared<SignatureRLResponseMessage>();
                break;
            case RLRequest:
                ptr = std::make_shared<RLRequestMessage>();
                break;
            case RLResponse:
                ptr = std::make_shared<RLResponseMessage>();
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
