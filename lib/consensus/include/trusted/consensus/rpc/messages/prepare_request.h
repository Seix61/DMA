
#ifndef LIB_TRUSTED_CONSENSUS_RPC_MESSAGE_PREPARE_REQUEST_H
#define LIB_TRUSTED_CONSENSUS_RPC_MESSAGE_PREPARE_REQUEST_H

#include <cstdint>
#include <consensus/rpc/message_base.h>
#include <util/memory.h>

namespace Consensus {
    class PrepareRequestMessage : public MessageBase {
    private:
        int nodeId;
        int logId;
    public:
        PrepareRequestMessage() : MessageBase(PrepareRequest), nodeId(-1), logId(-1) {}

        explicit PrepareRequestMessage(int nodeId, int logId) :
                MessageBase(PrepareRequest), nodeId(nodeId), logId(logId) {}

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

#endif //LIB_TRUSTED_CONSENSUS_RPC_MESSAGE_PREPARE_REQUEST_H