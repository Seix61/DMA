
#ifndef LIB_TRUSTED_CONSENSUS_RPC_MESSAGE_SERIALIZER_H
#define LIB_TRUSTED_CONSENSUS_RPC_MESSAGE_SERIALIZER_H

#include <consensus/rpc/basic_serializer.h>

namespace Consensus {
    template<typename T>
    class MessageSerializer {
        static_assert(std::is_base_of<MessageBase, T>::value, "T must be a subclass of Message");
    public:
        static std::ostringstream serialize(const std::shared_ptr<T> &ptr) {
            return BasicMessageSerializer::serialize(ptr);
        }

        static std::shared_ptr<T> deserialize(std::istringstream &iss) {
            return std::dynamic_pointer_cast<T>(BasicMessageSerializer::deserialize(iss));
        }

        static std::shared_ptr<T> deserialize(std::ostringstream &oss) {
            return std::dynamic_pointer_cast<T>(BasicMessageSerializer::deserialize(oss));
        }
    };
}

#endif //LIB_TRUSTED_CONSENSUS_RPC_MESSAGE_SERIALIZER_H
