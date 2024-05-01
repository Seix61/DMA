
#ifndef LIB_TRUSTED_EPID_RPC_MESSAGE_ATT_STATUS_REQUEST_H
#define LIB_TRUSTED_EPID_RPC_MESSAGE_ATT_STATUS_REQUEST_H

#include <cstdint>
#include <epid/rpc/message_base.h>
#include <util/memory.h>

namespace Epid {
    class AttStatusRequestMessage : public MessageBase {
    public:
        AttStatusRequestMessage() : MessageBase(AttStatusRequest) {}

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

#endif //LIB_TRUSTED_EPID_RPC_MESSAGE_ATT_STATUS_REQUEST_H
