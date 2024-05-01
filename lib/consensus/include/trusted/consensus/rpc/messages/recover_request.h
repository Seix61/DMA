
#ifndef LIB_TRUSTED_CONSENSUS_RPC_MESSAGE_RECOVER_REQUEST_H
#define LIB_TRUSTED_CONSENSUS_RPC_MESSAGE_RECOVER_REQUEST_H

#include <cstdint>
#include <consensus/rpc/message_base.h>
#include <util/memory.h>

namespace Consensus {
    class RecoverRequestMessage : public MessageBase {
    public:
        RecoverRequestMessage() : MessageBase(RecoverRequest) {}

        void serialize(std::ostringstream &oss) const override {}

        void deserialize(std::istringstream &iss) override {}

        static size_t contentSize() {
            return 0;
        }

        static size_t serializedSize() {
            return MessageBase::serializedSize() + contentSize();
        }
    };
}

#endif //LIB_TRUSTED_CONSENSUS_RPC_MESSAGE_RECOVER_REQUEST_H
