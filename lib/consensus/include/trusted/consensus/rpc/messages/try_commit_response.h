
#ifndef LIB_TRUSTED_CONSENSUS_RPC_MESSAGE_TRY_COMMIT_RESPONSE_H
#define LIB_TRUSTED_CONSENSUS_RPC_MESSAGE_TRY_COMMIT_RESPONSE_H

#include <cstdint>
#include <consensus/rpc/message_base.h>
#include <util/memory.h>

namespace Consensus {
    class TryCommitResponseMessage : public MessageBase {
    private:
        int nodeId;
        int logId;
    public:
        TryCommitResponseMessage() : MessageBase(TryCommitResponse), nodeId(-1), logId(-1) {}

        explicit TryCommitResponseMessage(int nodeId, int logId)
                : MessageBase(TryCommitResponse), nodeId(nodeId), logId(logId) {}

        int getNodeId() const {
            return nodeId;
        }

        int getLogId() const {
            return logId;
        }

        void serialize(std::ostringstream &oss) const override {
            oss.write((char *) &nodeId, sizeof(nodeId));
            oss.write((char *) &logId, sizeof(logId));
        }

        void deserialize(std::istringstream &iss) override {
            iss.read((char *) &nodeId, sizeof(nodeId));
            iss.read((char *) &logId, sizeof(logId));
        }

        static size_t contentSize() {
            return sizeof(nodeId) + sizeof(logId);
        }

        static size_t serializedSize() {
            return MessageBase::serializedSize() + contentSize();
        }
    };
}

#endif //LIB_TRUSTED_CONSENSUS_RPC_MESSAGE_TRY_COMMIT_RESPONSE_H
