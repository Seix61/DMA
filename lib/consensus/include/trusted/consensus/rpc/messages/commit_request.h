
#ifndef LIB_TRUSTED_CONSENSUS_RPC_MESSAGE_COMMIT_REQUEST_H
#define LIB_TRUSTED_CONSENSUS_RPC_MESSAGE_COMMIT_REQUEST_H

#include <cstdint>
#include <consensus/rpc/message_base.h>
#include <util/memory.h>

namespace Consensus {
    class CommitRequestMessage : public MessageBase {
    private:
        int logId;
        size_t size;
        std::shared_ptr<char> buffer;
    public:
        CommitRequestMessage() : MessageBase(CommitRequest), logId(-1), size(0), buffer() {}

        explicit CommitRequestMessage(int logId, size_t size, const std::shared_ptr<char> &buffer)
                : MessageBase(CommitRequest), logId(logId), size(size), buffer(buffer) {}


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
            oss.write((char *) &logId, sizeof(logId));
            oss.write((char *) &size, sizeof(size));
            oss.write(buffer.get(), size);
        }

        void deserialize(std::istringstream &iss) override {
            iss.read((char *) &logId, sizeof(logId));
            iss.read((char *) &size, sizeof(size));
            buffer = Memory::makeShared<char>(size);
            iss.read(buffer.get(), size);
        }

        static size_t staticSize() {
            return sizeof(logId);
        }

        static size_t contentSize() {
            return sizeof(logId) + sizeof(size);
        }

        static size_t serializedSize() {
            return MessageBase::serializedSize() + contentSize();
        }
    };
}

#endif //LIB_TRUSTED_CONSENSUS_RPC_MESSAGE_COMMIT_REQUEST_H
