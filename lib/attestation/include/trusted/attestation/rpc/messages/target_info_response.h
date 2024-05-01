
#ifndef LIB_TRUSTED_ATTESTATION_RPC_MESSAGE_TARGET_INFO_RESPONSE_H
#define LIB_TRUSTED_ATTESTATION_RPC_MESSAGE_TARGET_INFO_RESPONSE_H

#include <attestation/rpc/message_base.h>
#include <sgx_report.h>

namespace Attestation {
    class TargetInfoResponseMessage : public MessageBase {
    private:
        sgx_target_info_t targetInfo;
    public:
        TargetInfoResponseMessage() : MessageBase(TargetInfoResponse), targetInfo({}) {}

        explicit TargetInfoResponseMessage(const sgx_target_info_t &targetInfo) :
                MessageBase(TargetInfoResponse), targetInfo(targetInfo) {}

        const sgx_target_info_t &getTargetInfo() const {
            return targetInfo;
        }

        void serialize(std::ostringstream &oss) const override {
            oss.write((char *) &targetInfo, sizeof(targetInfo));
        }

        void deserialize(std::istringstream &iss) override {
            iss.read((char *) &targetInfo, sizeof(targetInfo));
        }

        static size_t contentSize() {
            return sizeof(targetInfo);
        }

        static size_t serializedSize() {
            return MessageBase::serializedSize() + contentSize();
        }
    };
}

#endif //LIB_TRUSTED_ATTESTATION_RPC_MESSAGE_TARGET_INFO_RESPONSE_H
