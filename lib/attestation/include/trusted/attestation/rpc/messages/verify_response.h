
#ifndef LIB_TRUSTED_ATTESTATION_RPC_MESSAGE_VERIFY_RESPONSE_H
#define LIB_TRUSTED_ATTESTATION_RPC_MESSAGE_VERIFY_RESPONSE_H

#include <attestation/rpc/message_base.h>

namespace Attestation {
    class VerifyResponseMessage : public MessageBase {
    private:
        bool pass;
    public:
        VerifyResponseMessage() : MessageBase(VerifyResponse), pass(false) {}

        explicit VerifyResponseMessage(bool pass) :
                MessageBase(VerifyResponse), pass(pass) {}

        bool isPass() const {
            return pass;
        }

        void serialize(std::ostringstream &oss) const override {
            oss.write((char *) &pass, sizeof(pass));
        }

        void deserialize(std::istringstream &iss) override {
            iss.read((char *) &pass, sizeof(pass));
        }

        static size_t contentSize() {
            return sizeof(pass);
        }

        static size_t serializedSize() {
            return MessageBase::serializedSize() + contentSize();
        }
    };
}

#endif //LIB_TRUSTED_ATTESTATION_RPC_MESSAGE_VERIFY_RESPONSE_H
