
#ifndef LIB_TRUSTED_EPID_RPC_MESSAGE_JOIN_RESPONSE_H
#define LIB_TRUSTED_EPID_RPC_MESSAGE_JOIN_RESPONSE_H

#include <cstdint>
#include <epid/rpc/message_base.h>
#include <util/memory.h>
#include <epid/types.h>

namespace Epid {
    class JoinResponseMessage : public MessageBase {
    private:
        MembershipCredential credential;
    public:
        JoinResponseMessage() : MessageBase(MemberJoinResponse), credential({}) {}

        explicit JoinResponseMessage(const MembershipCredential &credential) :
                MessageBase(MemberJoinResponse), credential(credential) {}

        const MembershipCredential &getCredential() const {
            return credential;
        }

        void serialize(std::ostringstream &oss) const override {
            oss.write((char *) &credential, sizeof(credential));
        }

        void deserialize(std::istringstream &iss) override {
            iss.read((char *) &credential, sizeof(credential));
        }

        static size_t contentSize() {
            return sizeof(credential);
        }

        static size_t serializedSize() {
            return MessageBase::serializedSize() + contentSize();
        }
    };
}

#endif //LIB_TRUSTED_EPID_RPC_MESSAGE_JOIN_RESPONSE_H
