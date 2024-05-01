
#include <consensus/rpc/basic_serializer.h>
#include <consensus/rpc/messages.h>

namespace Consensus {
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
            case LeaderElectionRequest:
                ptr = std::make_shared<LeaderElectionRequestMessage>();
                break;
            case LeaderElectionResponse:
                ptr = std::make_shared<LeaderElectionResponseMessage>();
                break;
            case LeaderNotification:
                ptr = std::make_shared<LeaderNotificationMessage>();
                break;
            case AcceptRequest:
                ptr = std::make_shared<AcceptRequestMessage>();
                break;
            case AcceptResponse:
                ptr = std::make_shared<AcceptResponseMessage>();
                break;
            case CommitRequest:
                ptr = std::make_shared<CommitRequestMessage>();
                break;
            case CommitResponse:
                ptr = std::make_shared<CommitResponseMessage>();
                break;
            case TryAcceptRequest:
                ptr = std::make_shared<TryAcceptRequestMessage>();
                break;
            case TryAcceptResponse:
                ptr = std::make_shared<TryAcceptResponseMessage>();
                break;
            case TryCommitRequest:
                ptr = std::make_shared<TryCommitRequestMessage>();
                break;
            case TryCommitResponse:
                ptr = std::make_shared<TryCommitResponseMessage>();
                break;
            case RecoverRequest:
                ptr = std::make_shared<RecoverRequestMessage>();
                break;
            case RecoverResponse:
                ptr = std::make_shared<RecoverResponseMessage>();
                break;
            case PrepareRequest:
                ptr = std::make_shared<PrepareRequestMessage>();
                break;
            case PrepareResponse:
                ptr = std::make_shared<PrepareResponseMessage>();
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

    void BasicMessageSerializer::appendStream(std::ostringstream &oss, const void *msg, size_t msg_size) {
        oss.write((char *)msg, msg_size);
    }
}
