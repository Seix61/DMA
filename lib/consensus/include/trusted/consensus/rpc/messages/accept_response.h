
#ifndef LIB_TRUSTED_CONSENSUS_RPC_MESSAGE_ACCEPT_RESPONSE_H
#define LIB_TRUSTED_CONSENSUS_RPC_MESSAGE_ACCEPT_RESPONSE_H

#include <cstdint>
#include <consensus/rpc/message_base.h>
#include <util/memory.h>

namespace Consensus {
    class AcceptResponseMessage : public MessageBase {
    private:
        int logId;
    public:
        AcceptResponseMessage() : MessageBase(AcceptResponse), logId(-1) {}

        explicit AcceptResponseMessage(int logId)
                : MessageBase(AcceptResponse), logId(logId) {}

        int getLogId() const {
            return logId;
        }

        void serialize(std::ostringstream &oss) const override {
            oss.write((char *) &logId, sizeof(logId));
        }

        void deserialize(std::istringstream &iss) override {
            iss.read((char *) &logId, sizeof(logId));
        }

        static size_t contentSize() {
            return sizeof(logId);
        }

        static size_t serializedSize() {
            return MessageBase::serializedSize() + contentSize();
        }
    };
}

#endif //LIB_TRUSTED_CONSENSUS_RPC_MESSAGE_ACCEPT_RESPONSE_H
