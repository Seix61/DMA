
#ifndef LIB_TRUSTED_ATTESTATION_RPC_MESSAGE_TARGET_INFO_REQUEST_H
#define LIB_TRUSTED_ATTESTATION_RPC_MESSAGE_TARGET_INFO_REQUEST_H

#include <attestation/rpc/message_base.h>

namespace Attestation {
    class TargetInfoRequestMessage : public MessageBase {
    public:
        TargetInfoRequestMessage() : MessageBase(TargetInfoRequest) {}

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

#endif //LIB_TRUSTED_ATTESTATION_RPC_MESSAGE_TARGET_INFO_REQUEST_H
