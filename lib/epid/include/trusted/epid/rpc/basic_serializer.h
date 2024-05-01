
#ifndef LIB_TRUSTED_EPID_RPC_BASIC_MESSAGE_SERIALIZER_H
#define LIB_TRUSTED_EPID_RPC_BASIC_MESSAGE_SERIALIZER_H

#include <sstream>
#include <epid/rpc/message_base.h>

namespace Epid {
    class BasicMessageSerializer {
    public:
        static std::ostringstream serialize(const std::shared_ptr<MessageBase> &ptr);

        static std::shared_ptr<MessageBase> deserialize(std::istringstream &iss);

        static std::shared_ptr<MessageBase> deserialize(std::ostringstream &oss);

        static std::ostringstream buildStream(MessageType type, const void *msg, size_t msg_size);

        static std::ostringstream buildStream(const void *msg, size_t msg_size);

        static void appendStream(std::ostringstream &oss, const void *msg, size_t msg_size);
    };
}

#endif //LIB_TRUSTED_EPID_RPC_BASIC_MESSAGE_SERIALIZER_H
