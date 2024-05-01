
#ifndef LIB_TRUSTED_CONSENSUS_RPC_MESSAGE_PREPARE_RESPONSE_H
#define LIB_TRUSTED_CONSENSUS_RPC_MESSAGE_PREPARE_RESPONSE_H

#include <cstdint>
#include <consensus/rpc/message_base.h>
#include <util/memory.h>

namespace Consensus {
    class PrepareResponseMessage : public MessageBase {
    private:
        int nodeId;
        int logId;
        size_t size;
        std::shared_ptr<char> buffer;
    public:
        PrepareResponseMessage() : MessageBase(PrepareResponse), nodeId(-1), logId(-1), size(0), buffer() {}

        explicit PrepareResponseMessage(int nodeId, int logId, size_t size, const std::shared_ptr<char> &buffer)
                : MessageBase(PrepareResponse), nodeId(nodeId), logId(logId), size(size), buffer(buffer) {}

        int getNodeId() const {
            return nodeId;
        }

        int getLogId() const {
            return logId;
        }

        size_t getSize() const {
            return size;
        }

        const std::shared_ptr<char> &getBuffer() const {
            return buffer;
        }

        void serialize(std::ostringstream &oss) const override {
            oss.write((char *) &nodeId, sizeof(nodeId));
            oss.write((char *) &logId, sizeof(logId));
            oss.write((char *) &size, sizeof(size));
            oss.write(buffer.get(), size);
        }

        void deserialize(std::istringstream &iss) override {
            iss.read((char *) &nodeId, sizeof(nodeId));
            iss.read((char *) &logId, sizeof(logId));
            iss.read((char *) &size, sizeof(size));
            buffer = Memory::makeShared<char>(size);
            iss.read(buffer.get(), size);
        }

        static size_t staticSize() {
            return sizeof(nodeId) + sizeof(logId);
        }

        static size_t contentSize() {
            return sizeof(nodeId) + sizeof(logId) + sizeof(size);
        }

        static size_t serializedSize() {
            return MessageBase::serializedSize() + contentSize();
        }
    };
}

#endif //LIB_TRUSTED_CONSENSUS_RPC_MESSAGE_PREPARE_RESPONSE_H
