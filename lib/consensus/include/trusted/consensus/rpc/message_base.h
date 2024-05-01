
#ifndef LIB_TRUSTED_CONSENSUS_RPC_MESSAGE_BASE_H
#define LIB_TRUSTED_CONSENSUS_RPC_MESSAGE_BASE_H

#include <libcxx/sstream>
#include <consensus/rpc/message_type.h>

namespace Consensus {
    class MessageBase {
    protected:
        MessageType type;
    public:
        explicit MessageBase(MessageType type) : type(type) {}

        MessageType getType() const {
            return type;
        }

        virtual void serialize(std::ostringstream &oss) const {}

        virtual void deserialize(std::istringstream &iss) {}

        static size_t contentSize() {
            return 0;
        }

        static size_t serializedSize() {
            return sizeof(MessageType);
        }
    };
}

#endif //LIB_TRUSTED_CONSENSUS_RPC_MESSAGE_BASE_H
